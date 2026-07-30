from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.events import EventPayload
from app.core.errors import OpaUnavailableError, ScoringUnavailableError
from app.core.repositories import DocumentRepository, MonitoringRepository, OrderRepository, UserRepository
from app.core.security import JWTVerificationError, JWTVerifier, extract_bearer_token
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext, resolve_client_ip
from app.middleware.jti_blacklist import check_jti_blacklist
from app.middleware.rate_limit import enforce_ip_rate_limit, enforce_user_rate_limit
from app.services.auth import AuthService
from app.services.authorization import AuthorizationService
from app.services.feature_vector import FeatureVectorService
from app.services.mfa_challenge import MfaChallengeService
from app.services.mfa_enrollment import MfaEnrollmentService

# Four routing tiers, in increasing order of trust required:
#
# 1. PUBLIC_PATHS           -> call_next immediately. No checks at all (e.g. /health).
# 2. AUTH_PATHS             -> IP rate limit only, no JWT, no OPA. These endpoints
#                              (/auth/login, /auth/refresh, /auth/logout) are what
#                              ISSUE/rotate/revoke a session, so they structurally
#                              cannot require a (possibly already-expired) access
#                              token -- refresh and logout authenticate off the
#                              httpOnly refresh cookie instead (see routers/auth.py).
#                              An unrated login endpoint is a brute-force target, so
#                              IP rate limiting still applies to all three.
# 3. GATEWAY_INTERNAL_PATHS -> full pre-OPA pipeline (JWT verify, user rate limit,
#                              JTI blacklist) but skip OPA authorize. These belong
#                              to the authentication/MFA plane, not the business
#                              plane (e.g. /mfa/enroll, /mfa/challenge/verify) --
#                              RBAC rules like reader-can't-POST would otherwise
#                              lock a reader out of their own step-up flow.
# 4. Everything else        -> the full pipeline, ending in OPA authorize.
#
# Orthogonal to the above: an `mfa_enrollment`-scoped token (issued by
# AuthService.login for an account with no user_mfa row yet -- mandatory MFA)
# is confined to POST /mfa/enroll ONLY, regardless of which tier the path would
# otherwise fall into. This is what makes enrollment mandatory rather than
# advisory: without it, a stolen password would let an attacker log in and
# enroll THEIR OWN TOTP secret on an unprotected account, satisfying every
# future step-up challenge. See the `claims.scope == "mfa_enrollment"` check
# below, evaluated before the GATEWAY_INTERNAL_PATHS tier.
#
# NOTE: per-request JWT replay checking (SETNX used:jti) has been removed from
# this pipeline. The access token is now deliberately reusable for its whole TTL
# (see AuthService/token_service) -- single-use semantics belong on the refresh
# token, where they are the correct security property (rotation + reuse
# detection), not on every request. check_jti_blacklist (immediate revocation)
# is unaffected and still runs on every authenticated request.
PUBLIC_PATHS = {"/health"}
AUTH_PATHS = {"/auth/login", "/auth/refresh", "/auth/logout"}
GATEWAY_INTERNAL_PATHS = {"/mfa/enroll", "/mfa/challenge/verify"}


@dataclass(slots=True)
class GatewayServices:
    settings: GatewaySettings
    security: JWTVerifier
    redis_client: object
    event_logger: object
    authorization_service: AuthorizationService
    feature_vector_service: FeatureVectorService
    mfa_challenge_service: MfaChallengeService
    mfa_enrollment_service: MfaEnrollmentService
    auth_service: AuthService
    user_repository: UserRepository
    document_repository: DocumentRepository
    order_repository: OrderRepository
    monitoring_repository: MonitoringRepository


class GatewayMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        services: GatewayServices = request.app.state.gateway_services
        context = RequestContext(
            trace_id=uuid4(),
            method=request.method.upper(),
            path=request.url.path,
            ip_address=resolve_client_ip(request, services.settings.trusted_proxies),
        )
        request.state.gateway_context = context

        rate_result = await enforce_ip_rate_limit(
            context=context,
            settings=services.settings,
            redis_client=services.redis_client,
            event_logger=services.event_logger,
        )
        if rate_result.exceeded:
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)

        if context.path in AUTH_PATHS:
            return await call_next(request)

        authorization = request.headers.get("authorization")
        token = extract_bearer_token(authorization)
        if token is None:
            return JSONResponse({"detail": "authentication required"}, status_code=401)

        try:
            claims = await services.security.verify(token)
        except JWTVerificationError as exc:
            await services.event_logger.write(
                EventPayload(
                    trace_id=context.trace_id,
                    user_id=exc.trusted_user_id,
                    ip_address=context.ip_address,
                    http_method=context.method,
                    request_path=context.path,
                    latency_ms=context.latency_ms(),
                    http_status=401,
                    event_type="auth_failed",
                    error_code="auth_failed",
                    error_message=str(exc),
                )
            )
            return JSONResponse({"detail": "invalid token"}, status_code=401)

        context.claims = claims
        request.state.gateway_context = context

        rate_result = await enforce_user_rate_limit(
            context=context,
            settings=services.settings,
            redis_client=services.redis_client,
            event_logger=services.event_logger,
        )
        if rate_result.exceeded:
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)

        revoked = await check_jti_blacklist(context=context, redis_client=services.redis_client, event_logger=services.event_logger)
        if revoked is not None:
            return JSONResponse({"detail": "token revoked"}, status_code=401)

        if claims.scope == "mfa_enrollment":
            # Confinement for the enrollment-gate token (see AuthService.login):
            # it may do exactly one thing -- enroll -- and nothing else. Without
            # this, the token would fall through to GATEWAY_INTERNAL_PATHS /
            # the full OPA pipeline like any other authenticated token, and the
            # whole point of gating full access behind enrollment would be lost.
            if context.path != "/mfa/enroll":
                await services.event_logger.write(
                    EventPayload(
                        trace_id=context.trace_id,
                        user_id=context.claims.subject,
                        ip_address=context.ip_address,
                        http_method=context.method,
                        request_path=context.path,
                        latency_ms=context.latency_ms(),
                        http_status=403,
                        event_type="mfa_failed",
                        error_code="enrollment_scope_violation",
                        error_message="mfa_enrollment-scoped token used outside POST /mfa/enroll",
                    )
                )
                return JSONResponse({"detail": "mfa_enrollment_required"}, status_code=403)
            return await call_next(request)

        if context.path in GATEWAY_INTERNAL_PATHS:
            return await call_next(request)

        try:
            outcome = await services.authorization_service.authorize(request=request, context=context)
        except (OpaUnavailableError, ScoringUnavailableError) as exc:
            # Distinct event_type per origin -- OPA and Isolation Forest are
            # different services with different on-call owners, and collapsing
            # a scoring outage into "opa_unavailable" would misdirect incident
            # response toward OPA when isolation-forest is the one actually down.
            event_type = "opa_unavailable" if isinstance(exc, OpaUnavailableError) else "scoring_unavailable"
            await services.event_logger.write(
                EventPayload(
                    trace_id=context.trace_id,
                    user_id=context.claims.subject,
                    ip_address=context.ip_address,
                    http_method=context.method,
                    request_path=context.path,
                    latency_ms=context.latency_ms(),
                    http_status=503,
                    event_type=event_type,
                    error_code=event_type,
                    error_message=str(exc),
                )
            )
            return JSONResponse({"detail": "authorization service unavailable"}, status_code=503)

        if outcome.decision.name == "ALLOW":
            response = await call_next(request)
            return response
        if outcome.decision.name == "DENY":
            return JSONResponse(outcome.response_payload or {"detail": "access denied"}, status_code=403)

        challenge_id = await services.mfa_challenge_service.create_challenge(context, outcome.risk_ctx)
        if challenge_id is None:
            await services.event_logger.write(
                EventPayload(
                    trace_id=context.trace_id,
                    user_id=context.claims.subject,
                    ip_address=context.ip_address,
                    http_method=context.method,
                    request_path=context.path,
                    latency_ms=context.latency_ms(),
                    http_status=403,
                    event_type="mfa_failed",
                    error_code="mfa_not_enrolled",
                    error_message="Step-up required but user has no MFA enrollment",
                )
            )
            return JSONResponse({"detail": "mfa_not_configured"}, status_code=403)

        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=context.claims.subject,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=401,
                event_type="step_up_required",
                error_code="step_up_required",
                error_message="Step-up MFA challenge issued",
            )
        )
        return JSONResponse({"detail": "step_up_required", "challenge_id": challenge_id}, status_code=401)
