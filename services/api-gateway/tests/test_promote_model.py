from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

import pytest

from app.core.redis_client import InMemoryRedis
from scripts.promote_model import (
    ACTIVE_SCORE_BREAKPOINTS_KEY,
    ACTIVE_THRESHOLD_KEY,
    ACTIVE_VERSION_KEY,
    CANDIDATE_VERSION_KEY,
    EVER_ACTIVE_KEY,
    PromotionError,
    promote_model,
)


def _linear_breakpoints(low: float, high: float, n: int = 101) -> list[float]:
    step = (high - low) / (n - 1)
    return [low + i * step for i in range(n)]


@dataclass(slots=True)
class FakeModelRegistryRepository:
    score_distributions: dict[str, dict[str, object] | None] = field(default_factory=dict)
    # Defaults to 16 (the current gateway vector width) for any version not
    # explicitly overridden, so existing tests that don't care about this
    # guard don't all need updating.
    feature_dims: dict[str, int] = field(default_factory=dict)
    # L2 gate: defaults to 0 (no rejected canary reviews) for any version not
    # explicitly overridden -- every pre-L2 test in this file exercises the
    # statistical checks with no opinion on canary review state, and must
    # keep passing unchanged now that promote_model unconditionally calls
    # this too. Real-DB coverage of the actual SQL lives in
    # test_promote_model_canary_gate.py, not here.
    rejected_canary_counts: dict[str, int] = field(default_factory=dict)

    async def get_score_distribution(self, version: str) -> dict[str, object] | None:
        return self.score_distributions.get(version)

    async def get_feature_dims(self, version: str) -> int | None:
        if version not in self.score_distributions:
            return None
        return self.feature_dims.get(version, 16)

    async def count_rejected_canary_reviews(self, version: str) -> int:
        return self.rejected_canary_counts.get(version, 0)


def test_promote_calibrated_version_sets_both_keys():
    async def _run():
        redis = InMemoryRedis()
        await redis.set(ACTIVE_VERSION_KEY, "v0")
        await redis.set(ACTIVE_THRESHOLD_KEY, "0.60")
        breakpoints = _linear_breakpoints(0.590, 0.666)
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {
                    "samples_scored": 500,
                    "min": 0.590,
                    "p50": 0.607,
                    "p95": 0.644,
                    "p98": 0.651,
                    "max": 0.666,
                    "percentile_breakpoints": breakpoints,
                },
            }
        )

        result = await promote_model(repository, redis, "v1")

        expected_threshold = (0.651 - 0.590) / (0.666 - 0.590)
        assert result.version == "v1"
        assert result.threshold == pytest.approx(expected_threshold, abs=1e-3)
        assert result.score_breakpoints == breakpoints
        assert result.previous_version == "v0"
        assert result.previous_threshold == "0.60"
        assert await redis.get(ACTIVE_VERSION_KEY) == "v1"
        assert float(await redis.get(ACTIVE_THRESHOLD_KEY)) == pytest.approx(expected_threshold, abs=1e-3)
        assert json.loads(await redis.get(ACTIVE_SCORE_BREAKPOINTS_KEY)) == breakpoints

    asyncio.run(_run())


def test_promote_degenerate_distribution_aborts():
    async def _run():
        redis = InMemoryRedis()
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {
                    "samples_scored": 3,
                    "min": 0.6,
                    "p50": 0.6,
                    "p95": 0.6,
                    "p98": 0.6,
                    "max": 0.6,
                    "percentile_breakpoints": [0.6] * 101,  # degenerate: single point
                },
            }
        )

        with pytest.raises(PromotionError):
            await promote_model(repository, redis, "v1")

        assert await redis.get(ACTIVE_VERSION_KEY) is None

    asyncio.run(_run())


def test_promote_non_monotonic_breakpoints_aborts():
    async def _run():
        redis = InMemoryRedis()
        breakpoints = _linear_breakpoints(0.590, 0.666)
        breakpoints[50], breakpoints[51] = breakpoints[51], breakpoints[50]  # corrupt: not sorted
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 500, "p98": 0.651, "percentile_breakpoints": breakpoints},
            }
        )

        with pytest.raises(PromotionError):
            await promote_model(repository, redis, "v1")

        assert await redis.get(ACTIVE_VERSION_KEY) is None

    asyncio.run(_run())


def test_promote_missing_breakpoints_aborts():
    async def _run():
        redis = InMemoryRedis()
        # p98 present (old-style calibration, from before this feature existed)
        # but no percentile_breakpoints -- must not silently fall back.
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 500, "min": 0.590, "p98": 0.651, "max": 0.666},
            }
        )

        with pytest.raises(PromotionError):
            await promote_model(repository, redis, "v1")

        assert await redis.get(ACTIVE_VERSION_KEY) is None

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


def test_promote_clears_candidate_when_it_matches_the_promoted_version():
    async def _run():
        redis = InMemoryRedis()
        await redis.set(CANDIDATE_VERSION_KEY, "v1")
        breakpoints = _linear_breakpoints(0.590, 0.666)
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 500, "p98": 0.651, "percentile_breakpoints": breakpoints},
            }
        )

        result = await promote_model(repository, redis, "v1")

        assert result.cleared_candidate is True
        assert await redis.get(CANDIDATE_VERSION_KEY) is None

    asyncio.run(_run())


def test_promote_leaves_a_different_candidate_untouched():
    async def _run():
        redis = InMemoryRedis()
        await redis.set(CANDIDATE_VERSION_KEY, "v2")  # a separate, still-pending candidate
        breakpoints = _linear_breakpoints(0.590, 0.666)
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 500, "p98": 0.651, "percentile_breakpoints": breakpoints},
            }
        )

        result = await promote_model(repository, redis, "v1")

        assert result.cleared_candidate is False
        assert await redis.get(CANDIDATE_VERSION_KEY) == "v2"

    asyncio.run(_run())


def test_promote_dimension_mismatch_aborts_and_sets_nothing():
    async def _run():
        redis = InMemoryRedis()
        await redis.set(ACTIVE_VERSION_KEY, "v0")
        await redis.set(ACTIVE_THRESHOLD_KEY, "0.60")
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 10061, "p98": 0.651},
            },
            feature_dims={"v1": 20},  # old, pre-rebuild layout
        )

        with pytest.raises(PromotionError):
            await promote_model(repository, redis, "v1")

        assert await redis.get(ACTIVE_VERSION_KEY) == "v0"
        assert await redis.get(ACTIVE_THRESHOLD_KEY) == "0.60"

    asyncio.run(_run())


def test_promote_sets_ever_active_flag():
    async def _run():
        redis = InMemoryRedis()
        breakpoints = _linear_breakpoints(0.590, 0.666)
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 500, "p98": 0.651, "percentile_breakpoints": breakpoints},
            }
        )

        assert await redis.get(EVER_ACTIVE_KEY) is None

        await promote_model(repository, redis, "v1")

        assert await redis.get(EVER_ACTIVE_KEY) == "1"

    asyncio.run(_run())


def test_promote_ever_active_flag_survives_active_version_loss():
    """The exact incident this flag exists for: model:active_version lost
    independently of promotion (accidental deletion, incident) -- see
    policies/risk/adaptive_access.rego's model_unavailable rule. The flag
    must NOT be cleared alongside it."""

    async def _run():
        redis = InMemoryRedis()
        breakpoints = _linear_breakpoints(0.590, 0.666)
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 500, "p98": 0.651, "percentile_breakpoints": breakpoints},
            }
        )
        await promote_model(repository, redis, "v1")

        await redis.delete(ACTIVE_VERSION_KEY)

        assert await redis.get(EVER_ACTIVE_KEY) == "1"

    asyncio.run(_run())


def test_promote_aborted_promotion_does_not_set_ever_active_flag():
    async def _run():
        redis = InMemoryRedis()
        repository = FakeModelRegistryRepository(score_distributions={"v1": None})

        with pytest.raises(PromotionError):
            await promote_model(repository, redis, "v1")

        assert await redis.get(EVER_ACTIVE_KEY) is None

    asyncio.run(_run())


def test_promote_blocked_by_rejected_canary_review():
    async def _run():
        redis = InMemoryRedis()
        breakpoints = _linear_breakpoints(0.590, 0.666)
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 500, "p98": 0.651, "percentile_breakpoints": breakpoints},
            },
            rejected_canary_counts={"v1": 2},
        )

        with pytest.raises(PromotionError, match="2 rejected canary review"):
            await promote_model(repository, redis, "v1")

        assert await redis.get(ACTIVE_VERSION_KEY) is None

    asyncio.run(_run())


def test_promote_statistical_checks_fire_before_canary_gate():
    # Ordering proof: a version with BOTH no score_distribution AND a
    # rejected canary review must fail on the score_distribution error, not
    # the canary one -- the statistical checks are already-fetched, single-
    # row lookups this function needs anyway, checked before the gate spends
    # a separate query on "did a human object" about a model that might not
    # even be calibrated yet (see promote_model's comment on this ordering).
    async def _run():
        redis = InMemoryRedis()
        repository = FakeModelRegistryRepository(
            score_distributions={"v1": None},
            rejected_canary_counts={"v1": 5},
        )

        with pytest.raises(PromotionError, match="no score_distribution yet"):
            await promote_model(repository, redis, "v1")

    asyncio.run(_run())


def test_promote_with_no_candidate_set_reports_not_cleared():
    async def _run():
        redis = InMemoryRedis()
        breakpoints = _linear_breakpoints(0.590, 0.666)
        repository = FakeModelRegistryRepository(
            score_distributions={
                "v1": {"samples_scored": 500, "p98": 0.651, "percentile_breakpoints": breakpoints},
            }
        )

        result = await promote_model(repository, redis, "v1")

        assert result.cleared_candidate is False
        assert await redis.get(CANDIDATE_VERSION_KEY) is None

    asyncio.run(_run())
