from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from app.core.repositories import UserRecord


@dataclass(slots=True)
class InMemoryUserRepository:
    """Test double reproducing UserRepository's contract, including the atomic
    increment/lockout semantics of its real UPDATE ... RETURNING statement --
    same pattern as InMemoryUserMfaRepository in test_user_mfa_repository.py."""

    records_by_email: dict[str, UserRecord] = field(default_factory=dict)

    async def get_by_email(self, email: str) -> UserRecord | None:
        return self.records_by_email.get(email)

    async def get_by_id(self, user_id: UUID) -> UserRecord | None:
        for record in self.records_by_email.values():
            if record.user_id == user_id:
                return record
        return None

    async def record_failed_login(self, user_id: UUID, *, max_attempts: int, lockout_minutes: int) -> UserRecord:
        record = next(r for r in self.records_by_email.values() if r.user_id == user_id)
        incremented = record.failed_login_attempts + 1
        if incremented >= max_attempts:
            record.failed_login_attempts = 0
            record.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        else:
            record.failed_login_attempts = incremented
        return record

    async def reset_login_attempts(self, user_id: UUID) -> None:
        record = next(r for r in self.records_by_email.values() if r.user_id == user_id)
        record.failed_login_attempts = 0
        record.locked_until = None


def _user(email: str = "reader@zt.local", **overrides) -> UserRecord:
    defaults = dict(
        user_id=uuid4(),
        email=email,
        password_hash="argon2-hash-placeholder",
        role="reader",
        is_active=True,
        failed_login_attempts=0,
        locked_until=None,
    )
    defaults.update(overrides)
    return UserRecord(**defaults)


def test_get_by_email_returns_none_for_unknown_email():
    async def _run():
        repo = InMemoryUserRepository()
        assert await repo.get_by_email("nobody@zt.local") is None

    asyncio.run(_run())


def test_get_by_email_and_get_by_id_return_the_record():
    async def _run():
        user = _user()
        repo = InMemoryUserRepository(records_by_email={user.email: user})

        assert await repo.get_by_email(user.email) is user
        assert await repo.get_by_id(user.user_id) is user

    asyncio.run(_run())


def test_record_failed_login_increments_without_reaching_limit():
    async def _run():
        user = _user()
        repo = InMemoryUserRepository(records_by_email={user.email: user})

        updated = await repo.record_failed_login(user.user_id, max_attempts=5, lockout_minutes=15)

        assert updated.failed_login_attempts == 1
        assert updated.locked_until is None

    asyncio.run(_run())


def test_record_failed_login_locks_and_resets_counter_at_max_attempts():
    async def _run():
        user = _user()
        repo = InMemoryUserRepository(records_by_email={user.email: user})

        for _ in range(4):
            await repo.record_failed_login(user.user_id, max_attempts=5, lockout_minutes=15)
        updated = await repo.record_failed_login(user.user_id, max_attempts=5, lockout_minutes=15)

        assert updated.failed_login_attempts == 0
        assert updated.locked_until is not None
        assert updated.locked_until > datetime.now(timezone.utc)

    asyncio.run(_run())


def test_reset_login_attempts_clears_attempts_and_lock():
    async def _run():
        user = _user(failed_login_attempts=3, locked_until=datetime.now(timezone.utc) + timedelta(minutes=5))
        repo = InMemoryUserRepository(records_by_email={user.email: user})

        await repo.reset_login_attempts(user.user_id)
        record = await repo.get_by_id(user.user_id)

        assert record.failed_login_attempts == 0
        assert record.locked_until is None

    asyncio.run(_run())
