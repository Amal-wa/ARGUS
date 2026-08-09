from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.core.events import build_sqlalchemy_event_logger
from app.core.database import build_async_session_factory
from app.core.isolation_forest_client import IsolationForestClient
from app.core.opa_client import OpaClient, build_opa_ssl_context
from app.core.redis_client import create_redis_client
from app.core.security import JWTVerifier
from app.core.settings import GatewaySettings
from app.core.repositories import (
    AuthorizationRepository,
    DocumentRepository,
    MonitoringRepository,
    OrderRepository,
    RefreshTokenRepository,
    UserMfaRepository,
    UserRepository,
)
from app.core.vault import VaultTransitClient
from app.middleware.gateway import GatewayMiddleware, GatewayServices
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.routers.auth import router as auth_router
from app.routers.documents import router as documents_router
from app.routers.mfa import router as mfa_router
from app.routers.monitoring import router as monitoring_router
from app.routers.orders import router as orders_router
from app.routers.users import router as users_router
from app.services.auth import AuthService
from app.services.authorization import AuthorizationService
from app.services.feature_vector import FeatureVectorService
from app.services.mfa_challenge import MfaChallengeService
from app.services.mfa_enrollment import MfaEnrollmentService
from app.services.token_service import TokenService

logger = logging.getLogger(__name__)


def build_app(
    settings: GatewaySettings | None = None,
    *,
    redis_client=None,
    event_logger=None,
    vault_client=None,
) -> FastAPI:
    settings = settings or GatewaySettings()
    app = FastAPI(title="Zero Trust API Gateway")

    redis_client = redis_client or create_redis_client(settings.redis_url)
    vault_client = vault_client or VaultTransitClient(
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_token,
        key_name=settings.vault_transit_key_name,
    )
    engine, session_factory = build_async_session_factory(settings.database_url)
    event_logger = event_logger or build_sqlalchemy_event_logger(session_factory)
    security = JWTVerifier(settings=settings, redis_client=redis_client, vault_client=vault_client)
    repository = AuthorizationRepository(session_factory)
    feature_vector_service = FeatureVectorService(redis_client=redis_client)
    # mTLS is mandatory whenever opa_url is https:// (the docker-compose
    # default) -- derived from the URL scheme rather than a second, separate
    # flag, so "https:// but mTLS disabled" can't exist as a contradictory
    # config state. Only a deliberately-downgraded http:// OPA_URL (local
    # debugging without the Docker stack/certs) skips it.
    opa_ssl_context = (
        build_opa_ssl_context(
            client_cert_path=settings.opa_client_cert_path,
            client_key_path=settings.opa_client_key_path,
            ca_cert_path=settings.opa_ca_cert_path,
        )
        if settings.opa_url.startswith("https://")
        else None
    )
    opa_client = OpaClient(
        base_url=settings.opa_url,
        decision_path=settings.opa_decision_path,
        ssl_context=opa_ssl_context,
    )
    scoring_client = IsolationForestClient(base_url=settings.isolation_forest_url, score_path=settings.isolation_forest_score_path)
    authorization_service = AuthorizationService(
        redis_client=redis_client,
        opa_client=opa_client,
        scoring_client=scoring_client,
        feature_vector_service=feature_vector_service,
        repository=repository,
        settings=settings,
    )
    user_mfa_repository = UserMfaRepository(session_factory)
    mfa_enrollment_service = MfaEnrollmentService(
        vault_client=vault_client,
        repository=user_mfa_repository,
        settings=settings,
    )
    mfa_challenge_service = MfaChallengeService(
        redis_client=redis_client,
        repository=user_mfa_repository,
        enrollment=mfa_enrollment_service,
        settings=settings,
    )
    user_repository = UserRepository(session_factory)
    refresh_token_repository = RefreshTokenRepository(session_factory)
    token_service = TokenService(vault_client=vault_client, settings=settings)
    auth_service = AuthService(
        user_repository=user_repository,
        refresh_token_repository=refresh_token_repository,
        token_service=token_service,
        settings=settings,
        user_mfa_repository=user_mfa_repository,
    )
    document_repository = DocumentRepository(session_factory)
    order_repository = OrderRepository(session_factory)
    monitoring_repository = MonitoringRepository(session_factory)
    app.state.gateway_services = GatewayServices(
        settings=settings,
        security=security,
        redis_client=redis_client,
        event_logger=event_logger,
        authorization_service=authorization_service,
        feature_vector_service=feature_vector_service,
        mfa_challenge_service=mfa_challenge_service,
        mfa_enrollment_service=mfa_enrollment_service,
        auth_service=auth_service,
        user_repository=user_repository,
        document_repository=document_repository,
        order_repository=order_repository,
        monitoring_repository=monitoring_repository,
    )
    app.add_middleware(GatewayMiddleware)
    # CORSMiddleware is added AFTER GatewayMiddleware on purpose. Starlette
    # builds the middleware stack by wrapping in REVERSE add-order, so the
    # LAST middleware added ends up OUTERMOST -- i.e. it sees every request
    # first, before GatewayMiddleware. That's required here: a CORS preflight
    # is an OPTIONS request with no Authorization header, and if
    # GatewayMiddleware ran first it would 401 the preflight before
    # CORSMiddleware ever got a chance to answer it (the browser would then
    # report a CORS failure, masking the real 401). With CORSMiddleware
    # outermost, it intercepts and answers every OPTIONS preflight directly
    # -- GatewayMiddleware, and the JWT check inside it, never runs for
    # those requests at all. For normal (non-preflight) requests,
    # CORSMiddleware just adds the Access-Control-Allow-Origin header to
    # whatever response GatewayMiddleware/the route produced (200, 401, 403,
    # ... all get it) once the Origin header matches an allowed origin.
    #
    # allow_origins is never "*": combined with allow_credentials=True (needed
    # so the dashboard's Authorization header survives the CORS check), a
    # wildcard origin is a well-known anti-pattern -- it would let ANY site the
    # browser visits call this API using the logged-in user's cookies/session
    # (browsers refuse to combine "*" with credentialed requests in the spec,
    # but some proxies/older behavior make relying on that refusal alone
    # risky; the explicit allowlist is the actual control). cors_allowed_origins
    # is empty by default -- same fail-closed discipline as trusted_proxies --
    # so CORS is opt-in per deployment via CORS_ALLOWED_ORIGINS, never
    # silently permissive.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allowed_origins),
        # allow_credentials=True is required for BOTH auth mechanisms the
        # dashboard uses: the Authorization header on /monitoring/* (readable
        # by JS, sent explicitly) and the httpOnly refresh cookie on /auth/*
        # (never readable by JS, sent automatically by the browser only when
        # the request is made with credentials: 'include' AND the request's
        # origin is on this allowlist). Never allow_origins=["*"] -- see the
        # comment below, and note it's doubly true now: with the cookie in
        # play, a wildcard origin wouldn't just leak an Authorization header,
        # it would let any site ride the logged-in admin's session cookie too.
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        # X-Requested-With is the CSRF header /auth/refresh and /auth/logout
        # require (see app/routers/auth.py) -- it must be explicitly
        # allow-listed here or the browser's preflight for those requests
        # fails before the request is ever sent.
        allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    )
    # Added third/last -> outermost (see the CORSMiddleware comment above for
    # why Starlette's reverse add-order matters here): every response leaving
    # this process, including CORS preflights and GatewayMiddleware's own
    # 401/403s, gets these headers stamped on before it reaches the browser.
    app.add_middleware(SecurityHeadersMiddleware, hsts_enabled=settings.refresh_cookie_secure)
    app.include_router(mfa_router)
    app.include_router(auth_router)
    app.include_router(documents_router)
    app.include_router(orders_router)
    app.include_router(users_router)
    app.include_router(monitoring_router)

    @app.on_event("startup")
    async def _startup() -> None:
        try:
            await redis_client.ping()
        except Exception:
            logger.exception("Redis connectivity check failed at startup; refusing to start")
            raise

        try:
            async with session_factory() as session:
                await session.execute(text("SELECT 1"))
        except Exception:
            logger.exception("PostgreSQL connectivity check failed at startup; refusing to start")
            raise

        try:
            await security.initialize()
        except Exception:
            logger.exception("Vault public key fetch failed at startup; refusing to start")
            raise

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = build_app()
