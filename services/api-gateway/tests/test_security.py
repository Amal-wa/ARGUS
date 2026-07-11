from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.redis_client import InMemoryRedis
from app.core.security import JWTVerificationError, JWTVerifier, extract_bearer_token
from app.core.settings import GatewaySettings


def _b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _make_token(private_key: Ed25519PrivateKey, claims: dict[str, object]) -> str:
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_segment = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signature = private_key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
    return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


@dataclass(slots=True)
class FakeVault:
    public_key: object
    fetch_count: int = 0

    async def fetch_public_key(self):
        self.fetch_count += 1
        return self.public_key


def _settings() -> GatewaySettings:
    return GatewaySettings(
        rate_limit_ip_limit=3,
        rate_limit_user_limit=5,
        jwk_refresh_lock_ttl_seconds=30,
    )


def test_extract_bearer_token():
    assert extract_bearer_token("Bearer abc.def.ghi") == "abc.def.ghi"
    assert extract_bearer_token("Basic abc") is None
    assert extract_bearer_token(None) is None


def test_verify_valid_token():
    async def _run():
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        verifier = JWTVerifier(settings=_settings(), redis_client=InMemoryRedis(), vault_client=FakeVault(public_key))
        token = _make_token(
            private_key,
            {
                "sub": str(uuid4()),
                "iss": "zt-api-gateway",
                "aud": "zt-api",
                "iat": int(time.time()),
                "exp": int(time.time()) + 60,
                "jti": str(uuid4()),
                "role": "user",
            },
        )

        verified = await verifier.verify(token)

        assert isinstance(verified.subject, UUID)
        assert verified.role == "user"
        assert verified.audience == "zt-api"

    asyncio.run(_run())


def test_verify_invalid_signature_uses_refresh_lock_and_rejects():
    async def _run():
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        other_private_key = Ed25519PrivateKey.generate()
        verifier = JWTVerifier(settings=_settings(), redis_client=InMemoryRedis(), vault_client=FakeVault(public_key))
        token = _make_token(
            other_private_key,
            {
                "sub": str(uuid4()),
                "iss": "zt-api-gateway",
                "aud": "zt-api",
                "iat": int(time.time()),
                "exp": int(time.time()) + 60,
                "jti": str(uuid4()),
                "role": "user",
            },
        )

        with pytest.raises(JWTVerificationError) as excinfo:
            await verifier.verify(token)

        assert excinfo.value.pre_signature is True

    asyncio.run(_run())


def test_malformed_token_does_not_refresh_vault_or_lock():
    async def _run():
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        vault = FakeVault(public_key)
        redis = InMemoryRedis()
        verifier = JWTVerifier(settings=_settings(), redis_client=redis, vault_client=vault)
        token = "abc.def"

        with pytest.raises(JWTVerificationError) as excinfo:
            await verifier.verify(token)

        assert excinfo.value.pre_signature is True
        assert vault.fetch_count == 1
        assert await redis.exists("jwk:refresh:lock") is False

    asyncio.run(_run())
