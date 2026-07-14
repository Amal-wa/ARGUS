from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.core.repositories import RefreshTokenRecord


@dataclass(slots=True)
class InMemoryRefreshTokenRepository:
    """Test double reproducing RefreshTokenRepository's contract, including the
    atomic single-use semantics of its real conditional UPDATE ... RETURNING."""

    records: dict[str, RefreshTokenRecord] = field(default_factory=dict)

    async def create(self, token_hash, family_id, user_id, expires_at) -> None:
        self.records[token_hash] = RefreshTokenRecord(
            token_hash=token_hash,
            family_id=family_id,
            user_id=user_id,
            issued_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            used_at=None,
            revoked=False,
        )

    async def get(self, token_hash: str) -> RefreshTokenRecord | None:
        return self.records.get(token_hash)

    async def consume(self, token_hash: str) -> bool:
        record = self.records.get(token_hash)
        if record is None:
            return False
        now = datetime.now(timezone.utc)
        if record.used_at is not None or record.revoked or record.expires_at <= now:
            return False
        record.used_at = now
        return True

    async def revoke_family(self, family_id) -> None:
        for record in self.records.values():
            if record.family_id == family_id:
                record.revoked = True


def test_create_and_get_round_trip():
    async def _run():
        repo = InMemoryRefreshTokenRepository()
        family_id = uuid4()
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        await repo.create("hash-1", family_id, user_id, expires_at)
        record = await repo.get("hash-1")

        assert record is not None
        assert record.family_id == family_id
        assert record.user_id == user_id
        assert record.used_at is None
        assert record.revoked is False

    asyncio.run(_run())


def test_consume_succeeds_once_and_fails_second_time():
    async def _run():
        repo = InMemoryRefreshTokenRepository()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        await repo.create("hash-1", uuid4(), uuid4(), expires_at)

        first = await repo.consume("hash-1")
        second = await repo.consume("hash-1")

        assert first is True
        assert second is False

    asyncio.run(_run())


def test_consume_fails_for_unknown_hash():
    async def _run():
        repo = InMemoryRefreshTokenRepository()
        assert await repo.consume("nonexistent") is False

    asyncio.run(_run())


def test_consume_fails_for_expired_token():
    async def _run():
        repo = InMemoryRefreshTokenRepository()
        expired_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await repo.create("hash-1", uuid4(), uuid4(), expired_at)

        assert await repo.consume("hash-1") is False

    asyncio.run(_run())


def test_consume_fails_for_revoked_token():
    async def _run():
        repo = InMemoryRefreshTokenRepository()
        family_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        await repo.create("hash-1", family_id, uuid4(), expires_at)
        await repo.revoke_family(family_id)

        assert await repo.consume("hash-1") is False

    asyncio.run(_run())


def test_revoke_family_revokes_every_token_in_the_family():
    async def _run():
        repo = InMemoryRefreshTokenRepository()
        family_id = uuid4()
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        await repo.create("hash-1", family_id, user_id, expires_at)
        await repo.create("hash-2", family_id, user_id, expires_at)
        await repo.create("hash-other-family", uuid4(), user_id, expires_at)

        await repo.revoke_family(family_id)

        assert (await repo.get("hash-1")).revoked is True
        assert (await repo.get("hash-2")).revoked is True
        assert (await repo.get("hash-other-family")).revoked is False

    asyncio.run(_run())


def test_concurrent_consume_only_one_succeeds():
    async def _run():
        repo = InMemoryRefreshTokenRepository()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        await repo.create("hash-1", uuid4(), uuid4(), expires_at)

        results = await asyncio.gather(*[repo.consume("hash-1") for _ in range(10)])

        assert sum(1 for r in results if r) == 1

    asyncio.run(_run())
