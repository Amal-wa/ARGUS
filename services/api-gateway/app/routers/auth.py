from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.events import EventPayload
from app.services.auth import LoginStatus, RefreshStatus

router = APIRouter()


@router.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")

    services = request.app.state.gateway_services
    context = request.state.gateway_context

    result = await services.auth_service.login(email, password)

    if result.status == LoginStatus.INVALID_CREDENTIALS:
        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=None,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=401,
                event_type="auth_failed",
                error_code="invalid_credentials",
                error_message="Invalid email or password",
            )
        )
        return JSONResponse({"detail": "invalid credentials"}, status_code=401)

    if result.status == LoginStatus.ACCOUNT_LOCKED:
        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=None,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=429,
                event_type="auth_failed",
                error_code="account_locked",
                error_message="Account temporarily locked due to repeated failed logins",
            )
        )
        return JSONResponse({"detail": "account locked"}, status_code=429)

    return {
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "token_type": "bearer",
        "expires_in": result.expires_in,
    }


@router.post("/auth/refresh")
async def refresh(request: Request):
    body = await request.json()
    refresh_token = body.get("refresh_token")

    services = request.app.state.gateway_services
    context = request.state.gateway_context

    result = await services.auth_service.refresh(refresh_token)

    if result.status == RefreshStatus.REUSE_DETECTED:
        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=result.user_id,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=401,
                event_type="replay_detected",
                error_code="refresh_token_reused",
                error_message="A consumed refresh token was presented again; token family revoked",
            )
        )
        return JSONResponse({"detail": "invalid refresh token"}, status_code=401)

    if result.status == RefreshStatus.INVALID:
        return JSONResponse({"detail": "invalid refresh token"}, status_code=401)

    return {
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "token_type": "bearer",
        "expires_in": result.expires_in,
    }
