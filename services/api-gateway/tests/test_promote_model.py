from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from app.core.redis_client import InMemoryRedis
from scripts.promote_model import ACTIVE_THRESHOLD_KEY, ACTIVE_VERSION_KEY, PromotionError, promote_model


@dataclass(slots=True)
class FakeModelRegistryRepository:
    score_distributions: dict[str, dict[str, float] | None] = field(default_factory=dict)

    async def get_score_distribution(self, version: str) -> dict[str, float] | None:
        return self.score_distributions.get(version)


def test_promote_calibrated_version_sets_both_keys():
    async def _run():
        redis = InMemoryRedis()
        await redis.set(ACTIVE_VERSION_KEY, "v0")
        await redis.set(ACTIVE_THRESHOLD_KEY, "0.60")
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 500, "min": 0.590, "p50": 0.607, "p95": 0.644, "p98": 0.651, "max": 0.666},
            }
        )

        result = await promote_model(repository, redis, "v1")

        assert result.version == "v1"
        assert result.threshold == pytest.approx(0.651)
        assert result.previous_version == "v0"
        assert result.previous_threshold == "0.60"
        assert await redis.get(ACTIVE_VERSION_KEY) == "v1"
        assert await redis.get(ACTIVE_THRESHOLD_KEY) == str(0.651)

    asyncio.run(_run())


def test_promote_uncalibrated_version_aborts_and_sets_nothing():
    async def _run():
        redis = InMemoryRedis()
        await redis.set(ACTIVE_VERSION_KEY, "v0")
        await redis.set(ACTIVE_THRESHOLD_KEY, "0.60")
        repository = FakeModelRegistryRepository(score_distributions={"v2": None})

        with pytest.raises(PromotionError):
            await promote_model(repository, redis, "v2")

        assert await redis.get(ACTIVE_VERSION_KEY) == "v0"
        assert await redis.get(ACTIVE_THRESHOLD_KEY) == "0.60"

    asyncio.run(_run())


def test_promote_unknown_version_aborts_and_sets_nothing():
    async def _run():
        redis = InMemoryRedis()
        repository = FakeModelRegistryRepository(score_distributions={})

        with pytest.raises(PromotionError):
            await promote_model(repository, redis, "does-not-exist")

        assert await redis.get(ACTIVE_VERSION_KEY) is None
        assert await redis.get(ACTIVE_THRESHOLD_KEY) is None

    asyncio.run(_run())


def test_promote_version_with_distribution_missing_p98_aborts():
    async def _run():
        redis = InMemoryRedis()
        repository = FakeModelRegistryRepository(
            score_distributions={"v3": {"samples_scored": 10, "min": 0.1, "max": 0.9}}
        )

        with pytest.raises(PromotionError):
            await promote_model(repository, redis, "v3")

        assert await redis.get(ACTIVE_VERSION_KEY) is None

    asyncio.run(_run())
