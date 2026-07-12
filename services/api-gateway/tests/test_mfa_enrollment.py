from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass, field
from uuid import UUID, uuid4

import pytest

from app.core.errors import MfaAlreadyEnrolledError
from app.core.repositories import UserMfaRecord
from app.core.settings import GatewaySettings
from app.services.mfa_enrollment import MfaEnrollmentService


@dataclass(slots=True)
class FakeVaultTransitClient:
    """Deterministic fake: 'encrypts' by base64-tagging the plaintext, 'decrypts' by reversing it."""

    encrypt_calls: list[tuple[str, bytes]] = field(default_factory=list)
    decrypt_calls: list[tuple[str, str]] = field(default_factory=list)

    async def encrypt(self, key_name: str, plaintext: bytes) -> str:
        self.encrypt_calls.append((key_name, plaintext))
        return f"vault:v1:{base64.b64encode(plaintext).decode('ascii')}"

    async def decrypt(self, key_name: str, ciphertext: str) -> bytes:
        self.decrypt_calls.append((key_name, ciphertext))
        encoded = ciphertext.removeprefix("vault:v1:")
        return base64.b64decode(encoded)


@dataclass(slots=True)
class RecordingUserMfaRepository:
    records: dict[UUID, UserMfaRecord] = field(default_factory=dict)

    async def get(self, user_id: UUID):
        return self.records.get(user_id)

    async def create(self, user_id: UUID, totp_secret_ciphertext: str) -> None:
        self.records[user_id] = UserMfaRecord(
            user_id=user_id,
            totp_secret_ciphertext=totp_secret_ciphertext,
            failed_attempts=0,
            locked_until=None,
        )


def _settings() -> GatewaySettings:
    return GatewaySettings(vault_totp_key_name="totp-encryption")


def test_enroll_stores_ciphertext_and_returns_valid_base32_secret():
    async def _run():
        vault = FakeVaultTransitClient()
        repository = RecordingUserMfaRepository()
        service = MfaEnrollmentService(vault_client=vault, repository=repository, settings=_settings())
        user_id = uuid4()

        base32_secret = await service.enroll(user_id)

        assert len(vault.encrypt_calls) == 1
        key_name, plaintext = vault.encrypt_calls[0]
        assert key_name == "totp-encryption"

        stored = repository.records[user_id]
        assert stored.totp_secret_ciphertext.startswith("vault:v1:")

        # base32_secret must decode back to the exact plaintext that was encrypted.
        padded = base32_secret + "=" * (-len(base32_secret) % 8)
        assert base64.b32decode(padded) == plaintext

    asyncio.run(_run())


def test_enroll_already_enrolled_raises_and_does_not_overwrite():
    async def _run():
        vault = FakeVaultTransitClient()
        repository = RecordingUserMfaRepository()
        service = MfaEnrollmentService(vault_client=vault, repository=repository, settings=_settings())
        user_id = uuid4()

        await service.enroll(user_id)
        original_ciphertext = repository.records[user_id].totp_secret_ciphertext

        with pytest.raises(MfaAlreadyEnrolledError):
            await service.enroll(user_id)

        assert repository.records[user_id].totp_secret_ciphertext == original_ciphertext
        assert len(vault.encrypt_calls) == 1

    asyncio.run(_run())


def test_get_decrypted_secret_returns_none_when_not_enrolled():
    async def _run():
        vault = FakeVaultTransitClient()
        repository = RecordingUserMfaRepository()
        service = MfaEnrollmentService(vault_client=vault, repository=repository, settings=_settings())

        assert await service.get_decrypted_secret(uuid4()) is None
        assert len(vault.decrypt_calls) == 0

    asyncio.run(_run())


def test_get_decrypted_secret_round_trips_through_enrollment():
    async def _run():
        vault = FakeVaultTransitClient()
        repository = RecordingUserMfaRepository()
        service = MfaEnrollmentService(vault_client=vault, repository=repository, settings=_settings())
        user_id = uuid4()

        await service.enroll(user_id)
        _, original_plaintext = vault.encrypt_calls[0]

        decrypted = await service.get_decrypted_secret(user_id)

        assert decrypted == original_plaintext

    asyncio.run(_run())
