from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.redis_client import InMemoryRedis
from app.core.security import JWTVerifier
from app.core.settings import GatewaySettings
from app.services.token_service import TokenService, hash_refresh_token


@dataclass(slots=True)
class FakeSigningVault:
    private_key: Ed25519PrivateKey

    async def sign(self, key_name: str, payload: bytes) -> bytes:
        return self.private_key.sign(payload)

    async def fetch_public_key(self):
        return self.private_key.public_key()


def _settings(**overrides) -> GatewaySettings:
    defaults = dict(access_token_ttl_minutes=15, refresh_token_ttl_days=7)
    defaults.update(overrides)
    return GatewaySettings(**defaults)


def test_issue_access_token_round_trips_through_jwt_verifier():
    async def _run():
        private_key = Ed25519PrivateKey.generate()
        vault = FakeSigningVault(private_key)
        settings = _settings()
        token_service = TokenService(vault_client=vault, settings=settings)
        user_id = uuid4()

        access_token = await token_service.issue_access_token(user_id=user_id, role="reader")

        verifier = JWTVerifier(settings=settings, redis_client=InMemoryRedis(), vault_client=vault)
        verified = await verifier.verify(access_token)

        assert verified.subject == user_id
        assert verified.role == "reader"
        assert verified.issuer == settings.jwt_issuer
        assert verified.audience == settings.jwt_audience
        assert verified.expires_at - verified.issued_at == 15 * 60

    asyncio.run(_run())


def test_issue_access_token_uses_fresh_jti_each_time():
    async def _run():
        private_key = Ed25519PrivateKey.generate()
        vault = FakeSigningVault(private_key)
        settings = _settings()
        token_service = TokenService(vault_client=vault, settings=settings)
        user_id = uuid4()

        token_a = await token_service.issue_access_token(user_id=user_id, role="reader")
        token_b = await token_service.issue_access_token(user_id=user_id, role="reader")

        verifier = JWTVerifier(settings=settings, redis_client=InMemoryRedis(), vault_client=vault)
        verified_a = await verifier.verify(token_a)
        verified_b = await verifier.verify(token_b)

        assert verified_a.jti != verified_b.jti

    asyncio.run(_run())


def test_issue_refresh_token_has_high_entropy_and_correct_hash():
    settings = _settings(refresh_token_ttl_days=7)
    token_service = TokenService(vault_client=None, settings=settings)

    token, token_hash, expires_at = token_service.issue_refresh_token()

    assert len(token) >= 32
    assert token_hash == hash_refresh_token(token)

    token2, _, _ = token_service.issue_refresh_token()
    assert token != token2


def test_issue_refresh_token_expiry_matches_settings():
    from datetime import datetime, timedelta, timezone

    settings = _settings(refresh_token_ttl_days=7)
    token_service = TokenService(vault_client=None, settings=settings)

    _, _, expires_at = token_service.issue_refresh_token()

    expected = datetime.now(timezone.utc) + timedelta(days=7)
    assert abs((expires_at - expected).total_seconds()) < 5
