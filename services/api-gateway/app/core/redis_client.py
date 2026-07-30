from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol


class RedisLike(Protocol):
    async def ping(self) -> bool: ...

    async def incr(self, key: str) -> int: ...

    async def expire(self, key: str, seconds: int) -> bool: ...

    async def ttl(self, key: str) -> int: ...

    async def exists(self, key: str) -> bool: ...

    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: Any, *, ex: int | None = None, nx: bool = False) -> bool: ...

    async def delete(self, key: str) -> int: ...

    async def sadd(self, key: str, *members: str) -> int: ...

    async def scard(self, key: str) -> int: ...

    async def zadd(self, key: str, mapping: dict[str, float]) -> int: ...

    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> int: ...

    async def zrange(self, key: str, start: int, end: int, *, withscores: bool = False) -> list[Any]: ...


@dataclass(slots=True)
class _RedisEntry:
    value: Any


@dataclass(slots=True)
class InMemoryRedis:
    _strings: dict[str, _RedisEntry] = field(default_factory=dict)
    _sets: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    _sorted_sets: dict[str, dict[str, float]] = field(default_factory=lambda: defaultdict(dict))
    # Expiry is tracked per-key here rather than inside _RedisEntry, since sets
    # and sorted sets need it too, not just strings -- real Redis EXPIRE
    # applies to a key regardless of its type.
    _expires_at: dict[str, datetime] = field(default_factory=dict)

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _purge_expired(self, key: str) -> None:
        expires_at = self._expires_at.get(key)
        if expires_at is not None and expires_at <= self._now():
            self._strings.pop(key, None)
            self._sets.pop(key, None)
            self._sorted_sets.pop(key, None)
            self._expires_at.pop(key, None)

    async def ping(self) -> bool:
        return True

    async def incr(self, key: str) -> int:
        self._purge_expired(key)
        entry = self._strings.get(key)
        current = int(entry.value) if entry is not None else 0
        current += 1
        self._strings[key] = _RedisEntry(str(current))
        return current

    async def expire(self, key: str, seconds: int) -> bool:
        self._purge_expired(key)
        if key not in self._strings and key not in self._sets and key not in self._sorted_sets:
            return False
        self._expires_at[key] = self._now() + timedelta(seconds=seconds)
        return True

    async def ttl(self, key: str) -> int:
        """Mirrors real Redis's TTL command: -2 if the key doesn't exist, -1
        if it exists with no expiry, otherwise seconds remaining (rounded
        down). Lets tests assert a key carries an expiry without reaching
        into this fake's private storage."""
        self._purge_expired(key)
        if key not in self._strings and key not in self._sets and key not in self._sorted_sets:
            return -2
        expires_at = self._expires_at.get(key)
        if expires_at is None:
            return -1
        return max(0, int((expires_at - self._now()).total_seconds()))

    async def exists(self, key: str) -> bool:
        self._purge_expired(key)
        return key in self._strings or key in self._sets or key in self._sorted_sets

    async def get(self, key: str) -> str | None:
        self._purge_expired(key)
        entry = self._strings.get(key)
        return None if entry is None else str(entry.value)

    async def set(self, key: str, value: Any, *, ex: int | None = None, nx: bool = False) -> bool:
        self._purge_expired(key)
        if nx and await self.exists(key):
            return False
        self._strings[key] = _RedisEntry(value)
        self._sets.pop(key, None)
        self._sorted_sets.pop(key, None)
        if ex is not None:
            self._expires_at[key] = self._now() + timedelta(seconds=ex)
        else:
            self._expires_at.pop(key, None)
        return True

    async def delete(self, key: str) -> int:
        self._purge_expired(key)
        existed = key in self._strings or key in self._sets or key in self._sorted_sets
        self._strings.pop(key, None)
        self._sets.pop(key, None)
        self._sorted_sets.pop(key, None)
        self._expires_at.pop(key, None)
        return 1 if existed else 0

    async def sadd(self, key: str, *members: str) -> int:
        self._purge_expired(key)
        members_set = self._sets[key]
        before = len(members_set)
        members_set.update(members)
        self._strings.pop(key, None)
        return len(members_set) - before

    async def scard(self, key: str) -> int:
        self._purge_expired(key)
        return len(self._sets.get(key, set()))

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        self._purge_expired(key)
        score_map = self._sorted_sets[key]
        added = 0
        for member, score in mapping.items():
            if member not in score_map:
                added += 1
            score_map[member] = float(score)
        self._strings.pop(key, None)
        return added

    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> int:
        self._purge_expired(key)
        score_map = self._sorted_sets.get(key)
        if not score_map:
            return 0
        removed = [member for member, score in score_map.items() if min_score <= score <= max_score]
        for member in removed:
            score_map.pop(member, None)
        return len(removed)

    async def zrange(self, key: str, start: int, end: int, *, withscores: bool = False) -> list[Any]:
        self._purge_expired(key)
        score_map = self._sorted_sets.get(key, {})
        ordered = sorted(score_map.items(), key=lambda item: (item[1], item[0]))
        if end == -1:
            sliced = ordered[start:]
        else:
            sliced = ordered[start : end + 1]
        if withscores:
            return [(member, score) for member, score in sliced]
        return [member for member, _ in sliced]


def create_redis_client(redis_url: str):
    try:
        from redis.asyncio import Redis
    except ImportError as exc:  # pragma: no cover - exercised only in deployment images.
        raise RuntimeError("redis.asyncio is not available") from exc

    return Redis.from_url(redis_url, decode_responses=True)
