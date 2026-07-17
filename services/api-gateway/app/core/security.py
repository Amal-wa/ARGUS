from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.redis_client import RedisLike
from app.core.settings import GatewaySettings
from app.core.vault import VaultTransitClient


class JWTVerificationError(Exception):
    def __init__(self, message: str, *, pre_signature: bool, trusted_user_id: UUID | None = None):
        super().__init__(message)
        self.pre_signature = pre_signature
        self.trusted_user_id = trusted_user_id


class SignatureVerificationError(JWTVerificationError):
    def __init__(self, message: str, *, pre_signature: bool, trusted_user_id: UUID | None = None):
        super().__init__(message, pre_signature=pre_signature, trusted_user_id=trusted_user_id)


@dataclass(slots=True)
class VerifiedJWT:
    subject: UUID
    issuer: str
    audience: str
    issued_at: int
    expires_at: int
    jti: UUID
    role: str
    risk_ctx: Any | None
    raw_claims: dict[str, Any]
    # None for a normal access token. "mfa_enrollment" for the short-lived,
    # single-purpose token issued by an un-enrolled login -- confined by the
    # gateway to POST /mfa/enroll only (see GatewayMiddleware).
    scope: str | None = None


def _base64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


@dataclass(slots=True)
class JWTVerifier:
    settings: GatewaySettings
    redis_client: RedisLike
    vault_client: VaultTransitClient
    _public_key: Ed25519PublicKey | None = None

    async def initialize(self) -> None:
        self._public_key = await self.vault_client.fetch_public_key()

    async def verify(self, token: str) -> VerifiedJWT:
        if self._public_key is None:
            await self.initialize()
        try:
            return self._verify_with_key(token, self._public_key)
        except SignatureVerificationError as first_error:
            if not await self._refresh_lock():
                raise first_error
            self._public_key = await self.vault_client.fetch_public_key()
            return self._verify_with_key(token, self._public_key)

    async def _refresh_lock(self) -> bool:
        return await self.redis_client.set(
            "jwk:refresh:lock",
            "1",
            nx=True,
            ex=self.settings.jwk_refresh_lock_ttl_seconds,
        )

    def _verify_with_key(self, token: str, public_key: Ed25519PublicKey) -> VerifiedJWT:
        try:
            header_segment, payload_segment, signature_segment = token.split(".")
        except ValueError as exc:
            raise JWTVerificationError("Token must contain three JWT segments", pre_signature=True) from exc

        try:
            header = json.loads(_base64url_decode(header_segment))
            payload = json.loads(_base64url_decode(payload_segment))
            signature = _base64url_decode(signature_segment)
        except Exception as exc:
            raise JWTVerificationError("Token is not valid base64url JSON", pre_signature=True) from exc

        if header.get("alg") != "EdDSA":
            raise JWTVerificationError("JWT algorithm must be EdDSA", pre_signature=True)

        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        try:
            public_key.verify(signature, signing_input)
        except InvalidSignature as exc:
            raise SignatureVerificationError("JWT signature verification failed", pre_signature=True) from exc

        return self._validate_claims(payload)

    def _validate_claims(self, payload: dict[str, Any]) -> VerifiedJWT:
        now = int(time.time())
        trusted_user_id: UUID | None = None

        try:
            subject = UUID(str(payload["sub"]))
            issuer = str(payload["iss"])
            audience_value = payload["aud"]
            audience = audience_value[0] if isinstance(audience_value, list) else str(audience_value)
            issued_at = int(payload["iat"])
            expires_at = int(payload["exp"])
            jti = UUID(str(payload["jti"]))
            role = str(payload["role"])
            risk_ctx = payload.get("risk_ctx")
            scope = payload.get("scope")
            trusted_user_id = subject
        except Exception as exc:
            raise JWTVerificationError("JWT claims are incomplete or invalid", pre_signature=False, trusted_user_id=trusted_user_id) from exc

        if issuer != self.settings.jwt_issuer:
            raise JWTVerificationError("JWT issuer mismatch", pre_signature=False, trusted_user_id=trusted_user_id)
        if audience != self.settings.jwt_audience:
            raise JWTVerificationError("JWT audience mismatch", pre_signature=False, trusted_user_id=trusted_user_id)
        if issued_at > now:
            raise JWTVerificationError("JWT iat is in the future", pre_signature=False, trusted_user_id=trusted_user_id)
        if expires_at <= now:
            raise JWTVerificationError("JWT is expired", pre_signature=False, trusted_user_id=trusted_user_id)

        return VerifiedJWT(
            subject=subject,
            issuer=issuer,
            audience=audience,
            issued_at=issued_at,
            expires_at=expires_at,
            jti=jti,
            role=role,
            risk_ctx=risk_ctx,
            raw_claims=payload,
            scope=scope,
        )


def extract_bearer_token(authorization_header: str | None) -> str | None:
    if not authorization_header:
        return None
    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None
