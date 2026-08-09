from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.core.audit_hash_chain import GENESIS_HASH, compute_row_hash
from scripts.verify_audit_integrity import AuditLogRow, verify_chain


@dataclass(slots=True)
class FakeAuditLogRepository:
    rows: list[AuditLogRow] = field(default_factory=list)

    async def fetch_all_rows_in_order(self) -> list[AuditLogRow]:
        return self.rows


def _row_kwargs(i: int) -> dict:
    return dict(
        trace_id=uuid4(),
        user_id=uuid4(),
        jti=uuid4(),
        role="reader",
        resource=f"/documents/{i}",
        action="read",
        ip_address="10.0.0.1",
        risk_score=0.5,
        model_version="v4",
        is_anomaly="none",
        decision="allow",
        policy_name="risk_allow",
        reason=None,
        latency_ms=10 + i,
        timestamp=datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=i),
    )


def _build_valid_chain(n: int) -> list[AuditLogRow]:
    """Builds a genuinely valid chain using the REAL compute_row_hash --
    exactly what write_decision would have produced -- rather than hand-
    crafting hash strings, so these tests exercise the real algorithm."""
    rows: list[AuditLogRow] = []
    prev_hash = GENESIS_HASH
    for i in range(n):
        kwargs = _row_kwargs(i)
        row_hash = compute_row_hash(prev_hash=prev_hash, **kwargs)
        rows.append(AuditLogRow(id=i + 1, prev_hash=prev_hash, row_hash=row_hash, **kwargs))
        prev_hash = row_hash
    return rows


def test_verify_chain_empty_table_is_ok():
    result = asyncio.run(verify_chain(FakeAuditLogRepository(rows=[])))

    assert result.broken_row_id is None
    assert result.total_rows == 0


def test_verify_chain_valid_chain_is_ok():
    rows = _build_valid_chain(5)

    result = asyncio.run(verify_chain(FakeAuditLogRepository(rows=rows)))

    assert result.broken_row_id is None
    assert result.total_rows == 5


def test_verify_chain_detects_an_altered_field_without_recomputed_hash():
    rows = _build_valid_chain(5)
    # Tamper with row 3's content directly (e.g. a hand-run UPDATE) without
    # recomputing its row_hash -- exactly what this feature exists to catch.
    rows[2].decision = "deny"

    result = asyncio.run(verify_chain(FakeAuditLogRepository(rows=rows)))

    assert result.broken_row_id == 3
    assert "row_hash" in result.reason


def test_verify_chain_detects_a_forged_prev_hash_link():
    rows = _build_valid_chain(5)
    # Re-point row 4's prev_hash to a different (fabricated) parent, as would
    # happen if a row were deleted and the chain "healed" by hand.
    rows[3].prev_hash = "f" * 64

    result = asyncio.run(verify_chain(FakeAuditLogRepository(rows=rows)))

    assert result.broken_row_id == 4
    assert "prev_hash" in result.reason


def test_verify_chain_detects_first_row_not_chained_from_genesis():
    rows = _build_valid_chain(3)
    rows[0].prev_hash = "0" * 64  # not GENESIS_HASH

    result = asyncio.run(verify_chain(FakeAuditLogRepository(rows=rows)))

    assert result.broken_row_id == 1
    assert "prev_hash" in result.reason


def test_verify_chain_stops_at_the_first_break_not_a_later_one():
    rows = _build_valid_chain(5)
    rows[1].decision = "deny"  # breaks row 2
    rows[3].action = "write"  # also breaks row 4, but row 2 comes first

    result = asyncio.run(verify_chain(FakeAuditLogRepository(rows=rows)))

    assert result.broken_row_id == 2
