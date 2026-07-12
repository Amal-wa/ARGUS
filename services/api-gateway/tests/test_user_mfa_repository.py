from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from app.core.repositories import UserMfaRecord


@dataclass(slots=True)
class InMemoryUserMfaRepository:
    """Test double reproducing UserMfaRepository's contract, including the
    atomic increment/lockout semantics of its real UPDATE ... RETURNING statement."""

    records: dict[UUID, UserMfaRecord] = field(default_factory=dict)

    async def get(self, user_id: UUID) -> UserMfaRecord | None:
        return self.records.get(user_id)

    async def create(self, user_id: UUID, totp_secret_ciphertext: str) -> None:
        self.records[user_id] = UserMfaRecord(
            user_id=user_id,
            totp_secret_ciphertext=totp_secret_ciphertext,
            failed_attempts=0,
            locked_until=None,
        )

    async def record_failed_attempt(
        self, user_id: UUID, *, max_attempts: int, lockout_duration_minutes: int
    ) -> UserMfaRecord:
        record = self.records[user_id]
        incremented = record.failed_attempts + 1
        if incremented >= max_attempts:
            record.failed_attempts = 0
            record.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_duration_minutes)
        else:
            record.failed_attempts = incremented
        return record

    async def reset_on_success(self, user_id: UUID) -> None:
        record = self.records[user_id]
        record.failed_attempts = 0
        record.locked_until = None


def test_get_returns_none_for_unknown_user():
    async def _run():
        repo = InMemoryUserMfaRepository()
        assert await repo.get(uuid4()) is None

    asyncio.run(_run())


def test_get_returns_record_after_create():
    async def _run():
        repo = InMemoryUserMfaRepository()
        user_id = uuid4()

        await repo.create(user_id, "vault:v1:ciphertext")
        record = await repo.get(user_id)

        assert record is not None
        assert record.user_id == user_id
        assert record.totp_secret_ciphertext == "vault:v1:ciphertext"
        assert record.failed_attempts == 0
        assert record.locked_until is None

    asyncio.run(_run())


def test_record_failed_attempt_increments_without_reaching_limit():
    async def _run():
        repo = InMemoryUserMfaRepository()
        user_id = uuid4()
        await repo.create(user_id, "vault:v1:ciphertext")

        record = await repo.record_failed_attempt(user_id, max_attempts=3, lockout_duration_minutes=15)

        assert record.failed_attempts == 1
        assert record.locked_until is None

    asyncio.run(_run())


def test_record_failed_attempt_locks_and_resets_counter_at_max_attempts():
    async def _run():
        repo = InMemoryUserMfaRepository()
        user_id = uuid4()
        await repo.create(user_id, "vault:v1:ciphertext")

        await repo.record_failed_attempt(user_id, max_attempts=3, lockout_duration_minutes=15)
        await repo.record_failed_attempt(user_id, max_attempts=3, lockout_duration_minutes=15)
        record = await repo.record_failed_attempt(user_id, max_attempts=3, lockout_duration_minutes=15)

        assert record.failed_attempts == 0
        assert record.locked_until is not None
        assert record.locked_until > datetime.now(timezone.utc)

    asyncio.run(_run())


def test_two_lockout_cycles_in_sequence():
    async def _run():
        repo = InMemoryUserMfaRepository()
        user_id = uuid4()
        await repo.create(user_id, "vault:v1:ciphertext")

        for _ in range(3):
            record = await repo.record_failed_attempt(user_id, max_attempts=3, lockout_duration_minutes=15)
        assert record.failed_attempts == 0
        assert record.locked_until is not None

        # Simulate the lockout window clearing (caller's responsibility to check
        # locked_until, but the counter itself must be able to lock again).
        for _ in range(3):
            record = await repo.record_failed_attempt(user_id, max_attempts=3, lockout_duration_minutes=15)
        assert record.failed_attempts == 0
        assert record.locked_until is not None

    asyncio.run(_run())


def test_reset_on_success_clears_attempts_and_lock():
    async def _run():
        repo = InMemoryUserMfaRepository()
        user_id = uuid4()
        await repo.create(user_id, "vault:v1:ciphertext")
        await repo.record_failed_attempt(user_id, max_attempts=3, lockout_duration_minutes=15)
        await repo.record_failed_attempt(user_id, max_attempts=3, lockout_duration_minutes=15)

        await repo.reset_on_success(user_id)
        record = await repo.get(user_id)

        assert record.failed_attempts == 0
        assert record.locked_until is None

    asyncio.run(_run())
