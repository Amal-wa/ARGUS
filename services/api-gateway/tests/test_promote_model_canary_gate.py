from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from uuid import uuid4

import pytest
from sqlalchemy import delete, insert, select, text

from app.core.database import build_async_session_factory
from app.core.redis_client import InMemoryRedis
from app.models.tables import canary_validation_log_table
from scripts.promote_model import (
    ACTIVE_VERSION_KEY,
    PromotionError,
    SqlAlchemyModelRegistryRepository,
    promote_model,
)

# Real SQL against a real Postgres for L2's new query specifically
# (count_rejected_canary_reviews) -- a Fake can prove promote_model() calls
# it and reacts to its return value (see test_promote_model.py), but not
# that the actual WHERE clause (candidate_model_version match, review_status
# = 'rejected' only) behaves correctly against real rows. Run from INSIDE
# the api-gateway container, same reason/command as test_canary_review.py's
# module docstring: asyncpg has no wheel for this host's Windows/Python-3.14
# venv.
DATABASE_URL = os.getenv("GATEWAY_TEST_DATABASE_URL", "postgresql+asyncpg://postgres:admin@postgres:5432/zt_db")


@dataclass(slots=True)
class _FixedStats:
    """Fully controlled score_distribution/feature_dims -- these tests are
    about the canary gate, not the already-covered statistical checks (see
    test_promote_model.py), so every version here is pre-calibrated with a
    valid distribution rather than inserting fake ml_model_registry rows
    into the live table."""

    score_distributions: dict[str, dict[str, object]] = field(default_factory=dict)

    async def get_score_distribution(self, version: str) -> dict[str, object] | None:
        return self.score_distributions.get(version)

    async def get_feature_dims(self, version: str) -> int | None:
        return 16 if version in self.score_distributions else None


@dataclass(slots=True)
class _HybridRepository:
    """Combines _FixedStats (controlled, no ml_model_registry writes) with
    the REAL SqlAlchemyModelRegistryRepository for count_rejected_canary_reviews
    -- this file's whole point is to exercise the real SQL for the new gate
    through the actual promote_model() orchestration, not to also fabricate
    ml_model_registry rows in the live table."""

    stats: _FixedStats
    real: SqlAlchemyModelRegistryRepository

    async def get_score_distribution(self, version: str) -> dict[str, object] | None:
        return await self.stats.get_score_distribution(version)

    async def get_feature_dims(self, version: str) -> int | None:
        return await self.stats.get_feature_dims(version)

    async def count_rejected_canary_reviews(self, version: str) -> int:
        return await self.real.count_rejected_canary_reviews(version)


def _linear_breakpoints(low: float, high: float, n: int = 101) -> list[float]:
    step = (high - low) / (n - 1)
    return [low + i * step for i in range(n)]


def _valid_distribution() -> dict[str, object]:
    breakpoints = _linear_breakpoints(0.590, 0.666)
    return {"samples_scored": 500, "p98": 0.651, "percentile_breakpoints": breakpoints}


def _build_repo():
    try:
        engine, session_factory = build_async_session_factory(DATABASE_URL)
    except (ModuleNotFoundError, ImportError) as exc:
        pytest.skip(f"asyncpg driver unavailable in this environment: {exc}")
    return engine, SqlAlchemyModelRegistryRepository(session_factory), session_factory


async def _require_db(session_factory) -> None:
    try:
        async with session_factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        pytest.skip(f"live Postgres not reachable at {DATABASE_URL}: {exc}")


async def _insert_row(session_factory, *, candidate_model_version: str, review_status: str) -> int:
    async with session_factory() as session:
        result = await session.execute(
            insert(canary_validation_log_table)
            .values(
                trace_id=uuid4(),
                production_model_version="v_gate_prod",
                candidate_model_version=candidate_model_version,
                production_risk_score=0.5,
                candidate_risk_score=0.5,
                review_status=review_status,
            )
            .returning(canary_validation_log_table.c.id)
        )
        row_id = result.scalar_one()
        await session.commit()
    return row_id


async def _delete_rows(session_factory, row_ids: list[int]) -> None:
    if not row_ids:
        return
    async with session_factory() as session:
        await session.execute(delete(canary_validation_log_table).where(canary_validation_log_table.c.id.in_(row_ids)))
        await session.commit()


async def _count_rows(session_factory) -> int:
    from sqlalchemy import func

    async with session_factory() as session:
        return (await session.execute(select(func.count()).select_from(canary_validation_log_table))).scalar_one()


def test_bootstrap_zero_rows_passes_the_gate():
    # THE most important case: v1's real, current state (no comparison ever
    # ran -- Mode A/no active model yet writes no canary_validation_log rows
    # at all, see canary-validator's _run_calibration). A brand-new,
    # never-compared candidate_model_version must promote normally.
    engine, real_repo, session_factory = _build_repo()

    async def _run():
        await _require_db(session_factory)
        version = f"v_gate_bootstrap_{uuid4().hex[:8]}"
        redis = InMemoryRedis()
        repo = _HybridRepository(stats=_FixedStats({version: _valid_distribution()}), real=real_repo)

        result = await promote_model(repo, redis, version)

        assert result.version == version
        assert await redis.get(ACTIVE_VERSION_KEY) == version
        await engine.dispose()

    asyncio.run(_run())


def test_only_confirmed_pending_no_review_required_passes_the_gate():
    engine, real_repo, session_factory = _build_repo()

    async def _run():
        await _require_db(session_factory)
        version = f"v_gate_clean_{uuid4().hex[:8]}"
        row_ids = [
            await _insert_row(session_factory, candidate_model_version=version, review_status="confirmed"),
            await _insert_row(session_factory, candidate_model_version=version, review_status="pending"),
            await _insert_row(session_factory, candidate_model_version=version, review_status="no_review_required"),
        ]
        try:
            redis = InMemoryRedis()
            repo = _HybridRepository(stats=_FixedStats({version: _valid_distribution()}), real=real_repo)

            result = await promote_model(repo, redis, version)

            assert result.version == version
            assert await redis.get(ACTIVE_VERSION_KEY) == version
        finally:
            await _delete_rows(session_factory, row_ids)
            await engine.dispose()

    asyncio.run(_run())


def test_rejected_row_blocks_promotion_with_explicit_message():
    engine, real_repo, session_factory = _build_repo()

    async def _run():
        await _require_db(session_factory)
        version = f"v_gate_rejected_{uuid4().hex[:8]}"
        row_ids = [
            await _insert_row(session_factory, candidate_model_version=version, review_status="confirmed"),
            await _insert_row(session_factory, candidate_model_version=version, review_status="rejected"),
        ]
        try:
            redis = InMemoryRedis()
            repo = _HybridRepository(stats=_FixedStats({version: _valid_distribution()}), real=real_repo)

            with pytest.raises(PromotionError, match=rf"{version}.*1 rejected canary review"):
                await promote_model(repo, redis, version)

            assert await redis.get(ACTIVE_VERSION_KEY) is None
        finally:
            await _delete_rows(session_factory, row_ids)
            await engine.dispose()

    asyncio.run(_run())


def test_rejected_row_for_a_different_candidate_version_does_not_block():
    # Scoping proof: the gate must key on candidate_model_version, not be a
    # global "any rejection anywhere" check.
    engine, real_repo, session_factory = _build_repo()

    async def _run():
        await _require_db(session_factory)
        version = f"v_gate_scoped_{uuid4().hex[:8]}"
        other_version = f"v_gate_other_{uuid4().hex[:8]}"
        row_ids = [
            await _insert_row(session_factory, candidate_model_version=other_version, review_status="rejected"),
        ]
        try:
            redis = InMemoryRedis()
            repo = _HybridRepository(stats=_FixedStats({version: _valid_distribution()}), real=real_repo)

            result = await promote_model(repo, redis, version)

            assert result.version == version
            assert await redis.get(ACTIVE_VERSION_KEY) == version
        finally:
            await _delete_rows(session_factory, row_ids)
            await engine.dispose()

    asyncio.run(_run())


def test_non_regression_row_count_unchanged():
    engine, real_repo, session_factory = _build_repo()

    async def _run():
        await _require_db(session_factory)
        before = await _count_rows(session_factory)

        version = f"v_gate_cleanup_{uuid4().hex[:8]}"
        row_id = await _insert_row(session_factory, candidate_model_version=version, review_status="rejected")
        redis = InMemoryRedis()
        repo = _HybridRepository(stats=_FixedStats({version: _valid_distribution()}), real=real_repo)

        with pytest.raises(PromotionError):
            await promote_model(repo, redis, version)

        await _delete_rows(session_factory, [row_id])
        after = await _count_rows(session_factory)
        await engine.dispose()
        assert after == before

    asyncio.run(_run())
