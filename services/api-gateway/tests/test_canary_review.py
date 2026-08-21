from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import delete, func, insert, select, text

from app.core.database import build_async_session_factory
from app.core.repositories import MonitoringRepository
from app.models.tables import canary_validation_log_table
from app.routers.monitoring import CanaryReviewRequest

# Real SQL against a real Postgres, deliberately NOT the Fake-repository
# pattern the rest of this service's tests use -- a Fake can prove wiring
# (a parameter reaches a call), but the thing under test here is the raw
# UPDATE ... WHERE review_status = 'pending' ... RETURNING semantics itself,
# and specifically that a second call against an already-reviewed row does
# NOT silently overwrite it. No Fake can stand in for that.
#
# Run from INSIDE the api-gateway container (`docker exec zt-api poetry run
# pytest tests/test_canary_review.py -v`): the host venv has no asyncpg
# wheel for this Windows/Python-3.14 setup (see test_cors.py's
# _build_test_app docstring for the same constraint), but the container's
# image has it and `services/api-gateway` is live-bind-mounted into it
# (docker-compose.yml `- ../services/api-gateway:/app`), so this file is
# visible there with no rebuild.
DATABASE_URL = os.getenv("GATEWAY_TEST_DATABASE_URL", "postgresql+asyncpg://postgres:admin@postgres:5432/zt_db")


def _build_repo():
    # create_async_engine resolves the asyncpg driver plugin immediately at
    # construction, unlike the sync create_engine/psycopg2 path -- so a
    # missing driver (this host's venv, see the module docstring) raises
    # here, before any connection is ever attempted. Caught the same way a
    # real connection failure is below, so the whole suite skips cleanly on
    # a host without asyncpg instead of erroring out.
    try:
        engine, session_factory = build_async_session_factory(DATABASE_URL)
    except (ModuleNotFoundError, ImportError) as exc:
        pytest.skip(f"asyncpg driver unavailable in this environment: {exc}")
    return engine, session_factory, MonitoringRepository(session_factory)


async def _require_db(session_factory) -> None:
    try:
        async with session_factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        pytest.skip(f"live Postgres not reachable at {DATABASE_URL}: {exc}")


async def _insert_row(session_factory, *, review_status: str = "pending") -> int:
    async with session_factory() as session:
        result = await session.execute(
            insert(canary_validation_log_table)
            .values(
                trace_id=uuid4(),
                production_model_version="v0",
                candidate_model_version="v_test_review",
                production_risk_score=0.5,
                candidate_risk_score=0.5,
                review_status=review_status,
            )
            .returning(canary_validation_log_table.c.id)
        )
        row_id = result.scalar_one()
        await session.commit()
    return row_id


async def _fetch_row(session_factory, row_id: int):
    async with session_factory() as session:
        return (
            await session.execute(
                select(
                    canary_validation_log_table.c.review_status,
                    canary_validation_log_table.c.reviewed_by,
                    canary_validation_log_table.c.reviewed_at,
                ).where(canary_validation_log_table.c.id == row_id)
            )
        ).one()


async def _delete_row(session_factory, row_id: int) -> None:
    async with session_factory() as session:
        await session.execute(delete(canary_validation_log_table).where(canary_validation_log_table.c.id == row_id))
        await session.commit()


async def _count_rows(session_factory) -> int:
    async with session_factory() as session:
        return (await session.execute(select(func.count()).select_from(canary_validation_log_table))).scalar_one()


def test_pending_row_can_be_confirmed():
    engine, session_factory, repo = _build_repo()

    async def _run():
        await _require_db(session_factory)
        row_id = await _insert_row(session_factory, review_status="pending")
        try:
            outcome = await repo.update_canary_review_status(
                row_id, review_status="confirmed", reviewed_by="admin1@zt.local"
            )
            assert outcome.status == "updated"
            assert outcome.reviewed_at is not None

            persisted = await _fetch_row(session_factory, row_id)
            assert persisted.review_status == "confirmed"
            assert persisted.reviewed_by == "admin1@zt.local"
            assert persisted.reviewed_at is not None
        finally:
            await _delete_row(session_factory, row_id)
            await engine.dispose()

    asyncio.run(_run())


def test_pending_row_can_be_rejected():
    engine, session_factory, repo = _build_repo()

    async def _run():
        await _require_db(session_factory)
        row_id = await _insert_row(session_factory, review_status="pending")
        try:
            outcome = await repo.update_canary_review_status(
                row_id, review_status="rejected", reviewed_by="admin2@zt.local"
            )
            assert outcome.status == "updated"

            persisted = await _fetch_row(session_factory, row_id)
            assert persisted.review_status == "rejected"
            assert persisted.reviewed_by == "admin2@zt.local"
        finally:
            await _delete_row(session_factory, row_id)
            await engine.dispose()

    asyncio.run(_run())


def test_nonexistent_id_returns_not_found():
    engine, session_factory, repo = _build_repo()

    async def _run():
        await _require_db(session_factory)
        # An id extremely unlikely to exist -- canary_validation_log.id is a
        # BigInteger identity column starting near 1; this is real, not a
        # placeholder, since the table is confirmed empty this session.
        outcome = await repo.update_canary_review_status(
            999_999_999, review_status="confirmed", reviewed_by="admin1@zt.local"
        )
        await engine.dispose()
        assert outcome.status == "not_found"

    asyncio.run(_run())


def test_already_confirmed_row_is_not_silently_overwritten():
    # The design decision documented in update_canary_review_status's
    # docstring: a row already confirmed/rejected is a settled audit record.
    # A second PATCH must report the conflict, not quietly replace who
    # reviewed it and when.
    engine, session_factory, repo = _build_repo()

    async def _run():
        await _require_db(session_factory)
        row_id = await _insert_row(session_factory, review_status="confirmed")
        try:
            before = await _fetch_row(session_factory, row_id)
            assert before.reviewed_by is None  # inserted directly, never reviewed through the endpoint
            assert before.reviewed_at is None

            outcome = await repo.update_canary_review_status(
                row_id, review_status="rejected", reviewed_by="admin2@zt.local"
            )
            assert outcome.status == "already_reviewed"
            assert outcome.existing_status == "confirmed"

            after = await _fetch_row(session_factory, row_id)
            # Untouched: still 'confirmed', still no reviewer/timestamp --
            # proves the UPDATE's WHERE review_status = 'pending' clause
            # actually prevented the write, not just that the router
            # would have reported a conflict on top of a real overwrite.
            assert after.review_status == "confirmed"
            assert after.reviewed_by is None
            assert after.reviewed_at is None
        finally:
            await _delete_row(session_factory, row_id)
            await engine.dispose()

    asyncio.run(_run())


def test_already_rejected_row_is_not_silently_overwritten():
    engine, session_factory, repo = _build_repo()

    async def _run():
        await _require_db(session_factory)
        row_id = await _insert_row(session_factory, review_status="rejected")
        try:
            outcome = await repo.update_canary_review_status(
                row_id, review_status="confirmed", reviewed_by="admin1@zt.local"
            )
            assert outcome.status == "already_reviewed"
            assert outcome.existing_status == "rejected"

            after = await _fetch_row(session_factory, row_id)
            assert after.review_status == "rejected"
        finally:
            await _delete_row(session_factory, row_id)
            await engine.dispose()

    asyncio.run(_run())


def test_invalid_review_status_rejected_by_pydantic_validation():
    # This is the same validation FastAPI runs on every request body before
    # the route handler ever executes -- a ValidationError here IS what
    # becomes a 422 at the HTTP layer, not a separate code path re-tested at
    # the transport level. No DB needed for this one.
    with pytest.raises(ValidationError):
        CanaryReviewRequest(review_status="maybe")


def test_pending_and_no_review_required_are_not_writable_targets():
    # The two states canary-validator itself assigns at insertion must not
    # be settable through this endpoint -- it's a human decision surface,
    # not a way to reset a row back to an initial state.
    with pytest.raises(ValidationError):
        CanaryReviewRequest(review_status="pending")
    with pytest.raises(ValidationError):
        CanaryReviewRequest(review_status="no_review_required")


def test_non_regression_row_count_unchanged_after_full_cycle():
    # Insert -> review -> delete: canary_validation_log's total count must be
    # identical before and after, proving this test suite (and the endpoint
    # it exercises) leaves no trace in the live table.
    engine, session_factory, repo = _build_repo()

    async def _run():
        await _require_db(session_factory)
        before = await _count_rows(session_factory)

        row_id = await _insert_row(session_factory, review_status="pending")
        outcome = await repo.update_canary_review_status(
            row_id, review_status="confirmed", reviewed_by="admin1@zt.local"
        )
        assert outcome.status == "updated"
        await _delete_row(session_factory, row_id)

        after = await _count_rows(session_factory)
        await engine.dispose()
        assert after == before

    asyncio.run(_run())
