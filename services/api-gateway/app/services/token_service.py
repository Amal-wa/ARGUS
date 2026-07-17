from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from app.core.settings import GatewaySettings
from app.core.vault import VaultTransitClient


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class TokenService:
    vault_client: VaultTransitClient
    settings: GatewaySettings

    async def issue_access_token(self, *, user_id: UUID, role: str) -> str:
        now = int(time.time())
        payload = {
            "sub": str(user_id),
            "iss": self.settings.jwt_issuer,
            "aud": self.settings.jwt_audience,
            "iat": now,
            "exp": now + self.settings.access_token_ttl_minutes * 60,
            "jti": str(uuid4()),
            "role": role,
        }
        return await self._sign_jwt(payload)

    async def issue_enrollment_token(self, *, user_id: UUID, role: str) -> str:
        """Short-lived, single-purpose token for an un-enrolled account fresh
        off password verification -- confined by the Gateway to POST
        /mfa/enroll only (see GatewayMiddleware). Never grants access to any
        business route; the account only gets a normal access token once
        enrollment succeeds."""
        now = int(time.time())
        payload = {
            "sub": str(user_id),
            "iss": self.settings.jwt_issuer,
            "aud": self.settings.jwt_audience,
            "iat": now,
            "exp": now + self.settings.enrollment_token_ttl_minutes * 60,
            "jti": str(uuid4()),
            "role": role,
            "scope": "mfa_enrollment",
        }
        return await self._sign_jwt(payload)

    async def _sign_jwt(self, payload: dict) -> str:
        header = {"alg": "EdDSA", "typ": "JWT"}
        header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_segment = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")

        signature = await self.vault_client.sign(self.settings.vault_transit_key_name, signing_input)
        signature_segment = _b64url(signature)

        return f"{header_segment}.{payload_segment}.{signature_segment}"

    def issue_refresh_token(self) -> tuple[str, str, datetime]:
        """Returns (plaintext_token, token_hash, expires_at). The plaintext token
        exists only in this return value and in the client's hands -- it is never
        persisted; only its SHA-256 hash is stored. SHA-256 (not Argon2id) is
        correct here: the token already has 256 bits of cryptographic entropy and
        is not brute-forceable by nature -- Argon2id's deliberate slowness exists
        to protect low-entropy human passwords, and would only burn CPU here."""
        token = secrets.token_urlsafe(32)
        token_hash = hash_refresh_token(token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=self.settings.refresh_token_ttl_days)
        return token, token_hash, expires_at
