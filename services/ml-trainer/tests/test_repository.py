from __future__ import annotations

import hashlib
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

from app.repository import SqlMlTrainerRepository

# Real SQL against a real Postgres, deliberately NOT the Fake-repository
# pattern the rest of this service's tests use (see test_trainer.py) -- a
# Fake can prove wiring (a parameter reaches a call), but the thing actually
# under test here is the raw SQL WHERE clause itself: Postgres ARRAY 1-based
# indexing (feature_vector[8]) against the real column type, and its
# cohabitation with the existing excluded_user_ids clause in the same query.
# No Fake can stand in for that. Points at the docker-compose stack's
# Postgres by default (host-side port 5433, per CLAUDE.md); every test skips
# outright if that's unreachable, rather than failing, so `pytest` still
# works offline for everything else in this service.
DATABASE_URL = os.getenv("ML_TRAINER_TEST_DATABASE_URL", "postgresql://postgres:admin@localhost:5433/zt_db")


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(DATABASE_URL)
    try:
        with eng.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        pytest.skip(f"live Postgres not reachable at {DATABASE_URL}: {exc}")
    yield eng
    eng.dispose()


def _feature_vector(resource_access: float) -> list[float]:
    # 16-dim vector (chk_feature_vector_size); only index 7 (0-based Python) /
    # 8 (1-based SQL) matters for this filter -- every other dimension is
    # inert filler.
    vector = [0.0] * 16
    vector[7] = resource_access
    return vector


def _row_hash(seed: str) -> str:
    # opa_decision_log.row_hash is UNIQUE NOT NULL, VARCHAR(64) -- a real
    # tamper-evidence chain value isn't needed for this test (nothing here
    # exercises verify_audit_integrity.py), just a distinct 64-char string
    # per row so the constraint is satisfied.
    return hashlib.sha256(seed.encode()).hexdigest()


class _SeededFixture:
    """Inserts one real user + N (opa_decision_log, ml_training_samples) row
    pairs, committed for real (a second connection -- the repository under
    test -- must see them, and Postgres's default READ COMMITTED isolation
    means an uncommitted row in one connection's transaction is invisible to
    another), then deletes every row it created in teardown by the exact ids
    it tracked. Never touches any row it didn't insert itself -- this
    project's own ml_training_samples data (protected by this session's own
    backup/reset discipline) is never at risk from these tests."""

    def __init__(self, engine):
        self._engine = engine
        self.user_id = uuid4()
        self.email = f"test_repo_{uuid4().hex[:8]}@zt.local"
        self._trace_ids: list = []

    def __enter__(self):
        with self._engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users (user_id, email, password_hash, role) "
                    "VALUES (:user_id, :email, 'x', 'reader')"
                ),
                {"user_id": self.user_id, "email": self.email},
            )
        return self

    def add_sample(self, resource_access: float, *, excluded_user_id=None) -> None:
        """Inserts one opa_decision_log row + one ml_training_samples row
        for this fixture's user (or excluded_user_id, if given, to build a
        row belonging to a DIFFERENT user for the cohabitation test) at the
        given feature_vector[8] value."""
        trace_id = uuid4()
        user_id = excluded_user_id if excluded_user_id is not None else self.user_id
        with self._engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO opa_decision_log "
                    "(trace_id, user_id, jti, role, resource, action, ip_address, "
                    "decision, policy_name, latency_ms, prev_hash, row_hash) "
                    "VALUES (:trace_id, :user_id, :jti, 'reader', '/documents/1', 'read', '10.0.0.1', "
                    "'allow', 'risk_allow', 10, :prev_hash, :row_hash)"
                ),
                {
                    "trace_id": trace_id,
                    "user_id": user_id,
                    "jti": uuid4(),
                    "prev_hash": _row_hash(f"prev-{trace_id}"),
                    "row_hash": _row_hash(f"row-{trace_id}"),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO ml_training_samples (trace_id, feature_vector, created_at) "
                    "VALUES (:trace_id, :feature_vector, NOW())"
                ),
                {"trace_id": trace_id, "feature_vector": _feature_vector(resource_access)},
            )
        self._trace_ids.append(trace_id)

    def __exit__(self, *exc_info):
        with self._engine.begin() as connection:
            connection.execute(
                text("DELETE FROM ml_training_samples WHERE trace_id = ANY(:trace_ids)"),
                {"trace_ids": self._trace_ids},
            )
            connection.execute(
                text("DELETE FROM opa_decision_log WHERE trace_id = ANY(:trace_ids)"),
                {"trace_ids": self._trace_ids},
            )
            connection.execute(text("DELETE FROM users WHERE user_id = :user_id"), {"user_id": self.user_id})


def _count(repository: SqlMlTrainerRepository, *, excluded_user_ids=(), max_resource_access=None) -> int:
    return len(
        repository.load_training_samples(
            window_days=30, excluded_user_ids=list(excluded_user_ids), max_resource_access=max_resource_access
        )
    )


# Every test below reads a DELTA (count after inserting fixture rows minus a
# baseline count taken just before), never an exact row list. The live
# zt_db this points at already carries thousands of real rows from this
# session's own traffic-generator runs (including, as it happens, real
# resource_access values that overlap the exact numbers used below -- 8, 31,
# 207) -- an exact-list assertion would be flaky by construction against
# that backdrop. A delta isolates exactly what this test's own inserted rows
# contributed, independent of whatever else is already in the table.


def test_max_resource_access_excludes_above_threshold_keeps_at_or_below(engine):
    repository = SqlMlTrainerRepository(engine)
    baseline = _count(repository, max_resource_access=30)
    with _SeededFixture(engine) as fixture:
        fixture.add_sample(30.0)  # at threshold -- must be KEPT (<=, not <)
        fixture.add_sample(31.0)  # just above -- must be EXCLUDED

        after = _count(repository, max_resource_access=30)

    assert after - baseline == 1


def test_max_resource_access_none_disables_filter_retrocompat(engine):
    repository = SqlMlTrainerRepository(engine)
    baseline = _count(repository, max_resource_access=None)
    with _SeededFixture(engine) as fixture:
        fixture.add_sample(30.0)
        fixture.add_sample(31.0)
        fixture.add_sample(9999.0)

        after = _count(repository, max_resource_access=None)

    assert after - baseline == 3


def test_realistic_attack_and_normal_values(engine):
    # Mirrors the live-verified reader8@zt.local scenario-A burst (up to 207)
    # against real normal traffic (observed ceiling 11, this session's own
    # live query) -- not arbitrary numbers.
    repository = SqlMlTrainerRepository(engine)
    baseline = _count(repository, max_resource_access=30)
    with _SeededFixture(engine) as fixture:
        fixture.add_sample(207.0)  # attack (reader8 burst max)
        fixture.add_sample(8.0)  # normal

        after = _count(repository, max_resource_access=30)

    assert after - baseline == 1


def test_max_resource_access_cohabits_with_excluded_user_ids(engine):
    # Both filters must apply TOGETHER (AND), not OR / not-either. A second
    # user's row at a normal value (8.0) is excluded purely by identity; the
    # fixture user's own row at 31.0 is excluded purely by behavior. Neither
    # filter alone would produce this delta -- proves both WHERE conditions
    # are live in the same query, not one silently short-circuiting the other.
    repository = SqlMlTrainerRepository(engine)
    other_user_id = uuid4()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (user_id, email, password_hash, role) "
                "VALUES (:user_id, :email, 'x', 'reader')"
            ),
            {"user_id": other_user_id, "email": f"test_repo_other_{uuid4().hex[:8]}@zt.local"},
        )
    try:
        baseline = _count(repository, excluded_user_ids=[other_user_id], max_resource_access=30)
        with _SeededFixture(engine) as fixture:
            fixture.add_sample(5.0)  # fixture user, normal value -- KEPT
            fixture.add_sample(31.0)  # fixture user, above threshold -- excluded by behavior
            fixture.add_sample(8.0, excluded_user_id=other_user_id)  # other user, normal value -- excluded by identity

            after = _count(repository, excluded_user_ids=[other_user_id], max_resource_access=30)

        assert after - baseline == 1
    finally:
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM users WHERE user_id = :user_id"), {"user_id": other_user_id})
