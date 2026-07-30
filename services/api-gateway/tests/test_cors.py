from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app.core.redis_client import InMemoryRedis
from app.core.security import JWTVerifier
from app.core.settings import GatewaySettings
from app.middleware.gateway import GatewayMiddleware, GatewayServices
from app.schemas.authorization import OpaDecision
from app.services.authorization import AuthorizationOutcome
from app.services.feature_vector import FeatureVectorService

ALLOWED_ORIGIN = "http://localhost:5173"
DISALLOWED_ORIGIN = "http://evil.example"


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
        raise NotImplementedError("not exercised by CORS tests -- no JWT is ever verified")


def _build_test_app(cors_allowed_origins: frozenset[str]) -> FastAPI:
    """Mirrors app/main.py's middleware wiring exactly (GatewayMiddleware
    added first / inner, CORSMiddleware added second / outer) against a
    minimal app, instead of the real build_app().

    build_app() unconditionally calls create_async_engine(DATABASE_URL),
    which eagerly imports asyncpg even without connecting -- and asyncpg has
    no prebuilt wheel for this local Windows/Python-3.14 dev venv and no
    compiler toolchain to build one from source. That's a local-environment
    gap, not a code issue: the real Docker image has asyncpg installed and
    the live gateway container has been running real Postgres queries all
    session (see the live-verification notes elsewhere). This test exercises
    the actual GatewayMiddleware and a real Starlette CORSMiddleware, added
    in the same order as main.py, driven through TestClient's real ASGI
    stack -- just without the DB-touching parts of build_app() that aren't
    relevant to CORS behavior anyway.
    """
    settings = GatewaySettings(
        cors_allowed_origins=cors_allowed_origins, rate_limit_ip_limit=1000, rate_limit_user_limit=1000
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

    @app.post("/auth/login")
    async def login():
        return {"access_token": "x", "refresh_token": "y", "token_type": "bearer", "expires_in": 900}

    @app.get("/documents")
    async def documents():
        return {"documents": []}

    # Same order as app/main.py: GatewayMiddleware added first (inner),
    # CORSMiddleware added second -- Starlette wraps in reverse add-order, so
    # the last-added middleware is OUTERMOST and sees every request first.
    app.add_middleware(GatewayMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
    return app


def _client(cors_allowed_origins: frozenset[str] = frozenset({ALLOWED_ORIGIN})) -> TestClient:
    return TestClient(_build_test_app(cors_allowed_origins))


def test_allowed_origin_gets_cors_header_on_public_route():
    client = _client()

    response = client.get("/health", headers={"Origin": ALLOWED_ORIGIN})

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_disallowed_origin_does_not_get_cors_header():
    client = _client()

    response = client.get("/health", headers={"Origin": DISALLOWED_ORIGIN})

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_no_origins_configured_means_no_cors_header_even_for_the_dashboard_origin():
    # CORS_ALLOWED_ORIGINS unset (default "") -- fail-closed, same discipline
    # as TRUSTED_PROXIES with an empty allowlist.
    client = _client(cors_allowed_origins=frozenset())

    response = client.get("/health", headers={"Origin": ALLOWED_ORIGIN})

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_preflight_options_on_login_succeeds_without_jwt():
    client = _client()

    response = client.options(
        "/auth/login",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    assert response.headers.get("access-control-allow-methods") is not None


def test_preflight_options_on_a_jwt_protected_route_also_bypasses_auth():
    # /documents normally requires a bearer token for GET (full pipeline,
    # tier 4 -- see gateway.py). A preflight OPTIONS against it must still
    # succeed with NO token anywhere in the request -- the real evidence
    # that CORSMiddleware is outer of GatewayMiddleware, not just that
    # AUTH_PATHS happen to be lenient.
    client = _client()

    response = client.options(
        "/documents", headers={"Origin": ALLOWED_ORIGIN, "Access-Control-Request-Method": "GET"}
    )

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN


def test_cors_header_present_even_on_401_from_gateway_middleware():
    # A real (non-preflight) GET with no token still gets 401 from
    # GatewayMiddleware -- but CORSMiddleware, being outer, still stamps the
    # header onto that 401 response so the browser can actually see the 401
    # instead of reporting an opaque CORS failure.
    client = _client()

    response = client.get("/documents", headers={"Origin": ALLOWED_ORIGIN})

    assert response.status_code == 401
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
