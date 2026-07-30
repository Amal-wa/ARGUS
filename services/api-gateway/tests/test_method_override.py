from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.redis_client import InMemoryRedis
from app.core.request_matching import request_action
from app.core.security import JWTVerifier
from app.core.settings import GatewaySettings
from app.middleware.gateway import GatewayMiddleware, GatewayServices
from app.schemas.authorization import OpaDecision
from app.services.authorization import AuthorizationOutcome
from app.services.feature_vector import FeatureVectorService

# Section 3.b: verify the HTTP method-override attack surface is absent.
#
# request_action() (app/core/request_matching.py) derives the RBAC action
# purely from `method: str` -- it never inspects headers or query params, so
# there is structurally no way for a header/param to change the action
# computed for a given request. And GatewayMiddleware builds `context.method`
# directly from `request.method.upper()` (the real ASGI/HTTP verb Starlette
# parsed), never from any header. FastAPI/Starlette do not implement method
# override by default. These tests confirm both facts rather than assume them.


def test_request_action_ignores_headers_it_was_never_given():
    # request_action's signature is (method: str) -- it is physically
    # impossible for it to consult a header, since none is passed in.
    assert request_action("POST") == "create"
    assert request_action("DELETE") == "delete"


@dataclass(slots=True)
class Recorder:
    items: list = field(default_factory=list)

    async def write(self, payload):
        self.items.append(payload)


@dataclass(slots=True)
class FakeVault:
    public_key: object

    async def fetch_public_key(self):
        return self.public_key


@dataclass(slots=True)
class RecordingAuthorizationService:
    seen_methods: list = field(default_factory=list)

    async def authorize(self, request, context):
        self.seen_methods.append(context.method)
        return AuthorizationOutcome(decision=OpaDecision.ALLOW)


class FakeApp:
    def __init__(self, gateway_services):
        self.state = SimpleNamespace(gateway_services=gateway_services)


class FakeRequest:
    def __init__(self, app, *, method, path, token, extra_headers):
        self.app = app
        self.method = method
        self.url = SimpleNamespace(path=path)
        headers = {"authorization": f"Bearer {token}"}
        headers.update(extra_headers)
        self.headers = headers
        self.client = SimpleNamespace(host="10.0.0.9")
        self.state = SimpleNamespace()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_token(private_key: Ed25519PrivateKey) -> str:
    now = int(time.time())
    claims = {
        "sub": str(uuid4()), "iss": "zt-api-gateway", "aud": "zt-api",
        "iat": now, "exp": now + 900, "jti": str(uuid4()), "role": "admin",
    }
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signature = private_key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
    return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


async def _call_next_success(request):
    return SimpleNamespace(status_code=200)


def test_method_override_header_does_not_change_the_authorized_action():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        private_key = Ed25519PrivateKey.generate()
        vault = FakeVault(private_key.public_key())
        settings = GatewaySettings(rate_limit_ip_limit=100, rate_limit_user_limit=200, jwk_refresh_lock_ttl_seconds=30)
        security = JWTVerifier(settings=settings, redis_client=redis, vault_client=vault)
        authz = RecordingAuthorizationService()
        services = GatewayServices(
            settings=settings,
            security=security,
            redis_client=redis,
            event_logger=recorder,
            authorization_service=authz,
            feature_vector_service=FeatureVectorService(redis_client=redis),
            mfa_challenge_service=None,
            mfa_enrollment_service=None,
            auth_service=None,
            user_repository=None,
            document_repository=None,
            order_repository=None,
            monitoring_repository=None,
        )
        app = FakeApp(services)
        token = _make_token(private_key)

        # A POST carrying a method-override header claiming DELETE.
        request = FakeRequest(
            app,
            method="POST",
            path="/documents/123",
            token=token,
            extra_headers={"x-http-method-override": "DELETE"},
        )

        await GatewayMiddleware(app=None).dispatch(request, _call_next_success)

        # The action the gateway actually authorized must reflect the REAL verb
        # (POST -> create), never the header's claimed override (DELETE -> delete).
        assert authz.seen_methods == ["POST"]
        assert request_action(authz.seen_methods[0]) == "create"

    asyncio.run(_run())
