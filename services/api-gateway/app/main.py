from __future__ import annotations

import logging

from fastapi import FastAPI
from sqlalchemy import text

from app.core.events import build_sqlalchemy_event_logger
from app.core.database import build_async_session_factory
from app.core.isolation_forest_client import IsolationForestClient
from app.core.opa_client import OpaClient
from app.core.redis_client import create_redis_client
from app.core.security import JWTVerifier
from app.core.settings import GatewaySettings
from app.core.repositories import AuthorizationRepository
from app.core.vault import VaultTransitClient
from app.middleware.gateway import GatewayMiddleware, GatewayServices
from app.services.authorization import AuthorizationService
from app.services.feature_vector import FeatureVectorService

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
    opa_client = OpaClient(base_url=settings.opa_url, decision_path=settings.opa_decision_path)
    scoring_client = IsolationForestClient(base_url=settings.isolation_forest_url, score_path=settings.isolation_forest_score_path)
    authorization_service = AuthorizationService(
        redis_client=redis_client,
        opa_client=opa_client,
        scoring_client=scoring_client,
        feature_vector_service=feature_vector_service,
        repository=repository,
    )
    app.state.gateway_services = GatewayServices(
        settings=settings,
        security=security,
        redis_client=redis_client,
        event_logger=event_logger,
        authorization_service=authorization_service,
    )
    app.add_middleware(GatewayMiddleware)

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
