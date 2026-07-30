from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.events import EventPayload
from app.core.refresh_cookie import REFRESH_COOKIE_NAME, clear_refresh_cookie, set_refresh_cookie
from app.services.auth import LoginStatus, RefreshStatus

router = APIRouter()

# CSRF defence for the two cookie-authenticated, state-changing endpoints
# below (/auth/refresh, /auth/logout). httpOnly stops JS from reading the
# refresh cookie, but a cookie is attached by the browser to ANY request to
# this origin -- including one triggered by a page on a completely different
# site. Requiring this custom header is sufficient *because* the strict
# CORS_ALLOWED_ORIGINS allowlist (see app/main.py) already exists: setting a
# non-CORS-safelisted header on a cross-origin fetch/XHR forces a preflight,
# and the allowlist rejects any origin that isn't explicitly trusted -- so an
# attacker's page can never get this header onto the wire for our origin in
# the first place. This is a matched pair with the allowlist: do not remove
# either one without reconsidering the other.
CSRF_HEADER_NAME = "x-requested-with"
CSRF_HEADER_VALUE = "argus-dashboard"


def _csrf_header_present(request: Request) -> bool:
    return request.headers.get(CSRF_HEADER_NAME) == CSRF_HEADER_VALUE


@router.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")

    services = request.app.state.gateway_services
    context = request.state.gateway_context

    result = await services.auth_service.login(email, password)

    if result.status == LoginStatus.INVALID_CREDENTIALS:
        # IP-scoped, not user-scoped -- see FeatureVectorService.record_auth_failure.
        # There is no verified identity at all at this point (wrong password,
        # or the email isn't even registered), so IP is the only trustworthy key.
        # attempted_email is passed through as audit-only info (see that
        # method's comment) -- never used as the counting key itself.
        await services.feature_vector_service.record_auth_failure(context.ip_address, attempted_email=email)
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
                attempted_email=email,
            )
        )
        return JSONResponse({"detail": "invalid credentials"}, status_code=401)

    if result.status == LoginStatus.ACCOUNT_LOCKED:
        # This request itself carried a wrong password too (see
        # AuthService.login -- ACCOUNT_LOCKED is only returned after a failed
        # password check, either because it just tripped the lockout
        # threshold or because a prior request already had), so it counts as
        # an auth failure from this IP exactly like INVALID_CREDENTIALS does.
        await services.feature_vector_service.record_auth_failure(context.ip_address, attempted_email=email)
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
                attempted_email=email,
            )
        )
        return JSONResponse({"detail": "account locked"}, status_code=429)

    if result.status == LoginStatus.MFA_ENROLLMENT_REQUIRED:
        # No refresh token exists at this stage (see AuthService.login) --
        # nothing to set as a cookie yet.
        return {
            "enrollment_token": result.enrollment_token,
            "token_type": "bearer",
            "mfa_enrollment_required": True,
        }

    response = JSONResponse(
        {
            "access_token": result.access_token,
            "token_type": "bearer",
            "expires_in": result.expires_in,
            # refresh_token is deliberately NOT in the body -- it only ever
            # travels as the httpOnly cookie set below, so JS (including
            # injected/XSS JS) can never read it.
        }
    )
    set_refresh_cookie(response, result.refresh_token, request)
    return response


@router.post("/auth/refresh")
async def refresh(request: Request):
    if not _csrf_header_present(request):
        return JSONResponse({"detail": "missing csrf header"}, status_code=403)

    refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)

    services = request.app.state.gateway_services
    context = request.state.gateway_context

    if refresh_token is None:
        return JSONResponse({"detail": "invalid refresh token"}, status_code=401)

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
        response = JSONResponse({"detail": "invalid refresh token"}, status_code=401)
        clear_refresh_cookie(response, request)
        return response

    if result.status == RefreshStatus.INVALID:
        # Covers expired/revoked/unknown tokens -- in every case the cookie
        # in the browser is dead, so clear it rather than leaving it to be
        # replayed against this endpoint forever.
        response = JSONResponse({"detail": "invalid refresh token"}, status_code=401)
        clear_refresh_cookie(response, request)
        return response

    response = JSONResponse(
        {
            "access_token": result.access_token,
            "token_type": "bearer",
            "expires_in": result.expires_in,
        }
    )
    set_refresh_cookie(response, result.refresh_token, request)
    return response


@router.post("/auth/logout")
async def logout(request: Request):
    # Same CSRF posture as /auth/refresh: this is also a cookie-authenticated,
    # state-changing endpoint (it revokes a live refresh token server-side),
    # so it gets the same defence.
    if not _csrf_header_present(request):
        return JSONResponse({"detail": "missing csrf header"}, status_code=403)

    services = request.app.state.gateway_services
    refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)
    if refresh_token is not None:
        # A logout that only clears client state while leaving a valid
        # refresh token alive server-side is not a logout.
        await services.auth_service.logout(refresh_token)

    response = JSONResponse({"detail": "logged out"})
    clear_refresh_cookie(response, request)
    return response
