"""Verify the tamper-evidence hash chain on opa_decision_log.

Run explicitly:
    poetry run python scripts/verify_audit_integrity.py
or, against the docker-compose stack:
    docker compose run --rm api-gateway poetry run python scripts/verify_audit_integrity.py

Walks the entire opa_decision_log table in id order, re-deriving each row's
row_hash from its own fields plus the previous row's hash (see
app/core/audit_hash_chain.py::compute_row_hash -- the same function
AuthorizationRepository.write_decision uses when it first writes a row) and
comparing against what was actually stored. Exits 0 with a summary line if
the whole chain verifies; exits 1, naming the first row whose hash doesn't
match, otherwise. A mismatch means either that row's own columns were
altered after the fact, or its prev_hash was re-pointed to a different
parent -- both are exactly what this chain exists to make detectable.

Read-only: this script never writes anything. Safe to run at any time,
against a live stack, on any schedule (cron, CI, ad hoc after an incident).

No real database is used in this project's own test suite (see
tests/test_verify_audit_integrity.py -- a hand-written in-memory fake repository,
same convention as every other test here), so the DB-touching parts of this
script (SqlAlchemyAuditLogRepository) are exercised live, not in CI --
verify_chain() itself, the actual chain-walking logic, is what the tests
cover directly.
"""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import select

from app.core.audit_hash_chain import GENESIS_HASH, compute_row_hash
from app.core.database import build_async_session_factory
from app.core.settings import GatewaySettings
from app.models.tables import opa_decision_log_table


@dataclass(slots=True)
class AuditLogRow:
    id: int
    timestamp: object
    trace_id: object
    user_id: object
    jti: object
    role: str
    resource: str
    action: str
    ip_address: str
    risk_score: float | None
    model_version: str | None
    is_anomaly: str
    decision: str
    policy_name: str
    reason: str | None
    latency_ms: int
    prev_hash: str
    row_hash: str


class AuditLogRepository(Protocol):
    async def fetch_all_rows_in_order(self) -> list[AuditLogRow]:
        """Every row in opa_decision_log, ordered by id ascending -- the same
        order the chain was written in."""
        ...


@dataclass(slots=True)
class SqlAlchemyAuditLogRepository:
    session_factory: object

    async def fetch_all_rows_in_order(self) -> list[AuditLogRow]:
        stmt = select(opa_decision_log_table).order_by(opa_decision_log_table.c.id.asc())
        async with self.session_factory() as session:
            rows = (await session.execute(stmt)).all()
        return [
            AuditLogRow(
                id=row.id,
                timestamp=row.timestamp,
                trace_id=row.trace_id,
                user_id=row.user_id,
                jti=row.jti,
                role=row.role,
                resource=row.resource,
                action=row.action,
                ip_address=str(row.ip_address),
                risk_score=row.risk_score,
                model_version=row.model_version,
                is_anomaly=row.is_anomaly,
                decision=row.decision,
                policy_name=row.policy_name,
                reason=row.reason,
                latency_ms=row.latency_ms,
                prev_hash=row.prev_hash,
                row_hash=row.row_hash,
            )
            for row in rows
        ]


@dataclass(slots=True)
class VerificationResult:
    total_rows: int
    broken_row_id: int | None
    reason: str | None
    # How many rows PASSED before broken_row_id (0 if the very first row
    # fails) -- distinct from total_rows, which is the whole table's size
    # regardless of where a break happens. Added after main()'s error
    # message previously read "(60836 rows checked before the break)" while
    # actually reporting total_rows -- i.e. the WHOLE table, not how many
    # were genuinely verified before verify_chain returned early. Equals
    # total_rows exactly when the chain is fully intact (both branches of
    # verify_chain below set it explicitly, on purpose -- no default here
    # that could silently paper over a call site that forgets it).
    verified_rows: int


async def verify_chain(repository: AuditLogRepository) -> VerificationResult:
    rows = await repository.fetch_all_rows_in_order()

    expected_prev_hash = GENESIS_HASH
    for verified_rows, row in enumerate(rows):
        if row.prev_hash != expected_prev_hash:
            return VerificationResult(
                total_rows=len(rows),
                broken_row_id=row.id,
                reason=(
                    f"prev_hash does not match the previous row's row_hash "
                    f"(expected {expected_prev_hash!r}, got {row.prev_hash!r}) -- chain re-pointed or a row is missing"
                ),
                verified_rows=verified_rows,
            )

        recomputed = compute_row_hash(
            prev_hash=row.prev_hash,
            trace_id=row.trace_id,
            user_id=row.user_id,
            jti=row.jti,
            role=row.role,
            resource=row.resource,
            action=row.action,
            ip_address=row.ip_address,
            risk_score=row.risk_score,
            model_version=row.model_version,
            is_anomaly=row.is_anomaly,
            decision=row.decision,
            policy_name=row.policy_name,
            reason=row.reason,
            latency_ms=row.latency_ms,
            timestamp=row.timestamp,
        )
        if recomputed != row.row_hash:
            return VerificationResult(
                total_rows=len(rows),
                broken_row_id=row.id,
                reason="row_hash does not match the recomputed hash -- this row's own content was altered",
                verified_rows=verified_rows,
            )

        expected_prev_hash = row.row_hash

    return VerificationResult(total_rows=len(rows), broken_row_id=None, reason=None, verified_rows=len(rows))


async def main() -> None:
    settings = GatewaySettings()
    engine, session_factory = build_async_session_factory(settings.database_url)
    repository = SqlAlchemyAuditLogRepository(session_factory)

    try:
        result = await verify_chain(repository)
    finally:
        await engine.dispose()

    if result.broken_row_id is not None:
        raise SystemExit(
            f"AUDIT TRAIL INTEGRITY BROKEN at opa_decision_log.id={result.broken_row_id}: "
            f"{result.reason} ({result.verified_rows} of {result.total_rows} rows verified before the break)"
        )

    print(f"OK: {result.total_rows} rows verified, chain intact from genesis to tail")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("usage: verify_audit_integrity.py")
    asyncio.run(main())
