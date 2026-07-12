from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from app.core.errors import MfaAlreadyEnrolledError
from app.core.repositories import UserMfaRepository
from app.core.settings import GatewaySettings
from app.core.totp import generate_totp_secret, secret_to_base32
from app.core.vault import VaultTransitClient


@dataclass(slots=True)
class MfaEnrollmentService:
    vault_client: VaultTransitClient
    repository: UserMfaRepository
    settings: GatewaySettings

    async def enroll(self, user_id: UUID) -> str:
        existing = await self.repository.get(user_id)
        if existing is not None:
            raise MfaAlreadyEnrolledError(f"user {user_id} is already enrolled in MFA")

        secret = generate_totp_secret()
        ciphertext = await self.vault_client.encrypt(self.settings.vault_totp_key_name, secret)
        await self.repository.create(user_id, ciphertext)
        return secret_to_base32(secret)

    async def get_decrypted_secret(self, user_id: UUID) -> bytes | None:
        record = await self.repository.get(user_id)
        if record is None:
            return None
        return await self.vault_client.decrypt(self.settings.vault_totp_key_name, record.totp_secret_ciphertext)
