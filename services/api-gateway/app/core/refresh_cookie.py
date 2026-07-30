from __future__ import annotations

from fastapi import Request, Response

REFRESH_COOKIE_NAME = "refresh_token"
# Scoped to /auth so the cookie is never sent on /monitoring or business
# routes -- those are Bearer-token-only, and there's no reason for the
# refresh token to travel on requests that can't use it. Note this is
# independent of which endpoint SETS the cookie (e.g. POST /mfa/enroll, which
# is not itself under /auth) -- the Path attribute only governs where the
# cookie is later SENT.
REFRESH_COOKIE_PATH = "/auth"


def set_refresh_cookie(response: Response, refresh_token: str, request: Request) -> None:
    settings = request.app.state.gateway_services.settings
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=settings.refresh_token_ttl_days * 24 * 60 * 60,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
    )


def clear_refresh_cookie(response: Response, request: Request) -> None:
    settings = request.app.state.gateway_services.settings
    # Attributes must match the ones set_cookie used above -- the browser
    # only overwrites/deletes a cookie when Path (and Domain, unset here)
    # match exactly; a mismatched Path would silently leave the real cookie
    # in place while "clearing" nothing.
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
    )
