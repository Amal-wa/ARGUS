from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.events import EventPayload
from app.core.errors import OpaUnavailableError
from app.core.security import JWTVerificationError, JWTVerifier, extract_bearer_token
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext
from app.middleware.jti_blacklist import check_jti_blacklist
from app.middleware.rate_limit import enforce_ip_rate_limit, enforce_user_rate_limit
from app.middleware.replay import check_replay
from app.services.authorization import AuthorizationService
from app.services.mfa_challenge import MfaChallengeService
from app.services.mfa_enrollment import MfaEnrollmentService

PUBLIC_PATHS = {"/health"}
GATEWAY_INTERNAL_PATHS = {"/mfa/enroll", "/mfa/challenge/verify"}


@dataclass(slots=True)
class GatewayServices:
    settings: GatewaySettings
    security: JWTVerifier
    redis_client: object
    event_logger: object
    authorization_service: AuthorizationService
    mfa_challenge_service: MfaChallengeService
    mfa_enrollment_service: MfaEnrollmentService


class GatewayMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        services: GatewayServices = request.app.state.gateway_services
        context = RequestContext(
            trace_id=uuid4(),
            method=request.method.upper(),
            path=request.url.path,
            ip_address=getattr(getattr(request, "client", None), "host", "127.0.0.1"),
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

        replay = await check_replay(context=context, settings=services.settings, redis_client=services.redis_client, event_logger=services.event_logger)
        if replay is not None:
            return JSONResponse({"detail": "replay detected"}, status_code=401)

        if context.path in GATEWAY_INTERNAL_PATHS:
            return await call_next(request)

        try:
            outcome = await services.authorization_service.authorize(request=request, context=context)
        except OpaUnavailableError as exc:
            await services.event_logger.write(
                EventPayload(
                    trace_id=context.trace_id,
                    user_id=context.claims.subject,
                    ip_address=context.ip_address,
                    http_method=context.method,
                    request_path=context.path,
                    latency_ms=context.latency_ms(),
                    http_status=503,
                    event_type="opa_unavailable",
                    error_code="opa_unavailable",
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
