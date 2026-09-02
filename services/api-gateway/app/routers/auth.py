from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.events import EventPayload
from app.core.refresh_cookie import REFRESH_COOKIE_NAME, clear_refresh_cookie, set_refresh_cookie
from app.schemas.common import ErrorDetail
from app.services.auth import LoginStatus, RefreshStatus

router = APIRouter(tags=["auth"])


class TokenResponse(BaseModel):
    """Access token only -- the refresh token is never in a JSON body, it
    travels solely as an httpOnly `refresh_token` cookie (see set_refresh_cookie)."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MfaEnrollmentRequiredResponse(BaseModel):
    """Returned instead of a real session when the account has no MFA
    enrolled yet -- enrollment_token is scoped to POST /mfa/enroll only."""

    enrollment_token: str
    token_type: str = "bearer"
    mfa_enrollment_required: bool = True


class LogoutResponse(BaseModel):
    detail: str

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


@router.post(
    "/auth/login",
    response_model=TokenResponse | MfaEnrollmentRequiredResponse,
    responses={401: {"model": ErrorDetail, "description": "Invalid credentials or account locked (deliberately identical body/status for both -- see comment below)"}},
    summary="Log in",
    description=(
        "Returns a real access token, OR (if the account has no MFA enrolled yet) an enrollment_token "
        "scoped to POST /mfa/enroll only -- never both. The refresh token is never in this body, only "
        "in an httpOnly cookie."
    ),
)
async def login(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")

    services = request.app.state.gateway_services
    context = request.state.gateway_context

    result = await services.auth_service.login(email, password)

    if result.status in (LoginStatus.INVALID_CREDENTIALS, LoginStatus.ACCOUNT_LOCKED):
        # IP-scoped, not user-scoped -- see FeatureVectorService.record_auth_failure.
        # There is no verified identity at all at this point (wrong password,
        # locked account, or the email isn't even registered), so IP is the
        # only trustworthy key. attempted_email is passed through as
        # audit-only info (see that method's comment) -- never used as the
        # counting key itself.
        await services.feature_vector_service.record_auth_failure(context.ip_address, attempted_email=email)
        if result.status == LoginStatus.ACCOUNT_LOCKED:
            error_code = "account_locked"
            error_message = "Account temporarily locked due to repeated failed logins"
        else:
            error_code = "invalid_credentials"
            error_message = "Invalid email or password"
        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=None,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                # Reflects what was ACTUALLY sent below (401) -- distinguishing
                # the two cases lives entirely in error_code/error_message for
                # an authenticated analyst reading /monitoring/audit, not in
                # the wire response. See the comment on the return below.
                http_status=401,
                event_type="auth_failed",
                error_code=error_code,
                error_message=error_message,
                attempted_email=email,
            )
        )
        # Deliberately identical response regardless of which branch produced
        # it -- an unauthenticated caller must never be able to tell "wrong
        # password" apart from "this real account is locked". Account lockout
        # state (users.locked_until) only ever exists for a real account row,
        # so a distinguishable status/body (or, before this fix, a
        # distinguishable TIMING -- the locked branch used to skip the
        # Argon2id check entirely) let a caller enumerate registered emails
        # by deliberately tripping the lockout threshold. Proven live, closed
        # here and in AuthService.login (which now always runs the real
        # Argon2id check even for an already-locked account). See SECURITY.md.
        return JSONResponse({"detail": "invalid credentials"}, status_code=401)

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


@router.post(
    "/auth/refresh",
    response_model=TokenResponse,
    responses={
        401: {"model": ErrorDetail, "description": "Missing/invalid/expired/reused refresh token -- cookie is cleared in the response"},
        403: {"model": ErrorDetail, "description": "Missing X-Requested-With CSRF header"},
    },
    summary="Rotate the refresh token",
    description="Reads the refresh token from the httpOnly cookie (never the body), rotates it, sets a new cookie.",
)
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


@router.post(
    "/auth/logout",
    response_model=LogoutResponse,
    responses={403: {"model": ErrorDetail, "description": "Missing X-Requested-With CSRF header"}},
    summary="Log out",
    description="Revokes the presented refresh token's whole family server-side and clears the cookie.",
)
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
