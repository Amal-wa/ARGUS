from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app.core.redis_client import InMemoryRedis
from app.core.security import JWTVerifier
from app.core.settings import GatewaySettings
from app.middleware.gateway import GatewayMiddleware, GatewayServices
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.schemas.authorization import OpaDecision
from app.services.authorization import AuthorizationOutcome
from app.services.feature_vector import FeatureVectorService

ALLOWED_ORIGIN = "http://localhost:5173"


@dataclass(slots=True)
class Recorder:
    items: list = field(default_factory=list)

    async def write(self, payload):
        self.items.append(payload)


@dataclass(slots=True)
class FakeAuthorizationService:
    async def authorize(self, request, context):
        return AuthorizationOutcome(decision=OpaDecision.ALLOW)


@dataclass(slots=True)
class FakeVault:
    async def fetch_public_key(self):
        raise NotImplementedError("not exercised -- no JWT is ever verified in these tests")


def _build_test_app(*, hsts_enabled: bool = False) -> FastAPI:
    """Same rationale as test_cors.py's _build_test_app: exercises the real
    GatewayMiddleware + CORSMiddleware + SecurityHeadersMiddleware, added in
    the exact order app/main.py uses, against a minimal app instead of the
    real build_app() (which eagerly touches a real DB connection this local
    dev venv can't make)."""
    settings = GatewaySettings(
        cors_allowed_origins=frozenset({ALLOWED_ORIGIN}), rate_limit_ip_limit=1000, rate_limit_user_limit=1000
    )
    redis = InMemoryRedis()
    security = JWTVerifier(settings=settings, redis_client=redis, vault_client=FakeVault())

    app = FastAPI()
    app.state.gateway_services = GatewayServices(
        settings=settings,
        security=security,
        redis_client=redis,
        event_logger=Recorder(),
        authorization_service=FakeAuthorizationService(),
        feature_vector_service=FeatureVectorService(redis_client=redis),
        mfa_challenge_service=None,
        mfa_enrollment_service=None,
        auth_service=None,
        user_repository=None,
        document_repository=None,
        order_repository=None,
        monitoring_repository=None,
    )

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/documents")
    async def documents():
        return {"documents": []}

    # Stand-in for the real /docs -- SecurityHeadersMiddleware only looks at
    # the path, so a plain route registered at that path is enough to prove
    # the docs-specific CSP branch fires.
    @app.get("/docs")
    async def fake_docs():
        return {"swagger": "ui"}

    app.add_middleware(GatewayMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[ALLOWED_ORIGIN],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts_enabled=hsts_enabled)
    return app


def _client(*, hsts_enabled: bool = False) -> TestClient:
    return TestClient(_build_test_app(hsts_enabled=hsts_enabled))


def test_api_route_gets_strict_csp_and_defensive_headers():
    client = _client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "geolocation=()" in response.headers["permissions-policy"]
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_docs_route_gets_a_relaxed_csp_permitting_the_swagger_ui_cdn():
    client = _client()

    # /docs requires a bearer token just like everything else here (Zero-Trust
    # -- confirmed live: GET /docs 401s without one), so this asserts on the
    # 401 response, not a 200. SecurityHeadersMiddleware picks the CSP from
    # the request path alone, independent of the auth outcome.
    response = client.get("/docs")

    assert response.status_code == 401
    csp = response.headers["content-security-policy"]
    assert "cdn.jsdelivr.net" in csp
    assert csp != "default-src 'none'; frame-ancestors 'none'"


def test_hsts_absent_by_default():
    client = _client(hsts_enabled=False)

    response = client.get("/health")

    assert "strict-transport-security" not in response.headers


def test_hsts_present_when_enabled():
    client = _client(hsts_enabled=True)

    response = client.get("/health")

    assert response.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains"


def test_headers_present_even_on_a_401_from_gateway_middleware():
    client = _client()

    response = client.get("/documents")  # no bearer token -> 401 from GatewayMiddleware

    assert response.status_code == 401
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_headers_present_on_a_cors_preflight():
    client = _client()

    response = client.options(
        "/documents",
        headers={"Origin": ALLOWED_ORIGIN, "Access-Control-Request-Method": "GET"},
    )

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
