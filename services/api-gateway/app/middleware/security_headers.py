from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Paths that need FastAPI's default (CDN-hosted) Swagger UI / ReDoc assets to
# actually render -- a blanket "default-src 'none'" CSP would leave these as a
# blank page. Everything else in this API is pure JSON with no legitimate
# reason to load a script, stylesheet, image, or frame from anywhere.
DOCS_PATHS = frozenset({"/docs", "/redoc", "/openapi.json"})

# Scoped to exactly what FastAPI's default docs HTML actually requests (Swagger
# UI bundle/CSS from jsdelivr, ReDoc's Google Fonts, the tiangolo favicon) --
# not a general-purpose relaxation. Verify against a real browser's console
# after any FastAPI/swagger-ui-dist version bump: the exact asset hosts are an
# upstream implementation detail, not a contract this file controls.
_DOCS_CSP = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "font-src https://fonts.gstatic.com; "
    "connect-src 'self'"
)
# The real API surface: nothing here ever legitimately serves script/style/
# image/frame content, so lock it down completely rather than enumerating
# sources that don't apply.
_API_CSP = "default-src 'none'; frame-ancestors 'none'"


def _csp_for(path: str) -> str:
    return _DOCS_CSP if path in DOCS_PATHS else _API_CSP


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Stamps standard defensive response headers onto every response --
    added last in app/main.py so it's outermost (Starlette wraps in reverse
    add-order, see the CORSMiddleware comment there) and sees the final
    response from every other layer: GatewayMiddleware's 401/403s, CORS
    preflight 200s, route handlers, and unhandled-exception responses alike.

    hsts_enabled mirrors settings.refresh_cookie_secure -- the project's
    existing single "is this deployment on HTTPS" signal (see settings.py) --
    rather than a second, separately-configured flag. Sending HSTS over plain
    HTTP is harmless to real browsers (they ignore it on non-HTTPS responses)
    but is confusing noise during local curl/dev testing, so it's gated the
    same way REFRESH_COOKIE_SECURE already is: false by default, true in prod.
    """

    def __init__(self, app, *, hsts_enabled: bool) -> None:
        super().__init__(app)
        self._hsts_enabled = hsts_enabled

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        # Both set: X-Frame-Options for older clients, frame-ancestors (part
        # of the CSP below too) as the CSP-native, modern-browser-preferred
        # equivalent. Belt and suspenders, not redundancy.
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = _csp_for(request.url.path)

        if self._hsts_enabled:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

        return response
