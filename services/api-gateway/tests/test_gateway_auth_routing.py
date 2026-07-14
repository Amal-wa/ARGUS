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
from app.core.settings import GatewaySettings
from app.middleware.gateway import GatewayMiddleware, GatewayServices
from app.schemas.authorization import OpaDecision
from app.services.authorization import AuthorizationOutcome


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
class FakeAuthorizationService:
    decision: OpaDecision = OpaDecision.ALLOW
    calls: int = 0

    async def authorize(self, request, context):
        self.calls += 1
        return AuthorizationOutcome(decision=self.decision)


class FakeApp:
    def __init__(self, gateway_services):
        self.state = SimpleNamespace(gateway_services=gateway_services)


class FakeRequest:
    def __init__(self, app, *, method="GET", path="/documents/123", token=None, ip="10.0.0.9"):
        self.app = app
        self.method = method
        self.url = SimpleNamespace(path=path)
        self.headers = {"authorization": f"Bearer {token}"} if token else {}
        self.client = SimpleNamespace(host=ip)
        self.state = SimpleNamespace()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_token(private_key: Ed25519PrivateKey, claims: dict) -> str:
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signature = private_key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
    return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


def _claims(**overrides) -> dict:
    now = int(time.time())
    defaults = dict(
        sub=str(uuid4()), iss="zt-api-gateway", aud="zt-api",
        iat=now, exp=now + 900, jti=str(uuid4()), role="reader",
    )
    defaults.update(overrides)
    return defaults


def _settings() -> GatewaySettings:
    return GatewaySettings(rate_limit_ip_limit=100, rate_limit_user_limit=200, jwk_refresh_lock_ttl_seconds=30)


def _services(redis, recorder, authorization_service, private_key) -> GatewayServices:
    settings = _settings()
    vault = FakeVault(private_key.public_key())
    from app.core.security import JWTVerifier

    security = JWTVerifier(settings=settings, redis_client=redis, vault_client=vault)
    return GatewayServices(
        settings=settings,
        security=security,
        redis_client=redis,
        event_logger=recorder,
        authorization_service=authorization_service,
        mfa_challenge_service=None,
        mfa_enrollment_service=None,
        auth_service=None,
        user_repository=None,
        document_repository=None,
        order_repository=None,
    )


async def _call_next_success(request):
    return SimpleNamespace(status_code=200)


def test_auth_path_reachable_without_token():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        private_key = Ed25519PrivateKey.generate()
        services = _services(redis, recorder, FakeAuthorizationService(), private_key)
        app = FakeApp(services)
        request = FakeRequest(app, method="POST", path="/auth/login")

        response = await GatewayMiddleware(app=None).dispatch(request, _call_next_success)

        assert response.status_code == 200

    asyncio.run(_run())


def test_auth_path_is_still_ip_rate_limited():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        private_key = Ed25519PrivateKey.generate()
        services = _services(redis, recorder, FakeAuthorizationService(), private_key)
        services.settings.rate_limit_ip_limit = 1
        app = FakeApp(services)

        first = await GatewayMiddleware(app=None).dispatch(
            FakeRequest(app, method="POST", path="/auth/login"), _call_next_success
        )
        second = await GatewayMiddleware(app=None).dispatch(
            FakeRequest(app, method="POST", path="/auth/login"), _call_next_success
        )

        assert first.status_code == 200
        assert second.status_code == 429

    asyncio.run(_run())


def test_reused_access_token_now_succeeds_on_business_route():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        private_key = Ed25519PrivateKey.generate()
        fake_authz = FakeAuthorizationService()
        services = _services(redis, recorder, fake_authz, private_key)
        app = FakeApp(services)

        token = _make_token(private_key, _claims())

        first = await GatewayMiddleware(app=None).dispatch(
            FakeRequest(app, path="/documents/123", token=token), _call_next_success
        )
        second = await GatewayMiddleware(app=None).dispatch(
            FakeRequest(app, path="/documents/123", token=token), _call_next_success
        )

        # This is the whole point of the change: the old per-request replay
        # check would have rejected the second use with a 401. It must not anymore.
        assert first.status_code == 200
        assert second.status_code == 200
        assert fake_authz.calls == 2

    asyncio.run(_run())


def test_blacklisted_jti_still_rejected():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        private_key = Ed25519PrivateKey.generate()
        services = _services(redis, recorder, FakeAuthorizationService(), private_key)
        app = FakeApp(services)

        jti = uuid4()
        token = _make_token(private_key, _claims(jti=str(jti)))
        await redis.set(f"revoked:jti:{jti}", "1")

        response = await GatewayMiddleware(app=None).dispatch(
            FakeRequest(app, path="/documents/123", token=token), _call_next_success
        )

        assert response.status_code == 401

    asyncio.run(_run())
