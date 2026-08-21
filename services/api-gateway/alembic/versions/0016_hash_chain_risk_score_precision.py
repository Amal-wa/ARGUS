"""Re-derive opa_decision_log's hash chain with the risk_score precision fix.

Migration 0015 introduced the tamper-evidence chain, but write_decision hashed
risk_score using the raw Python double it had in hand at insert time -- before
that value is stored into risk_score's actual column type, `real` (single
precision, see 0001_initial_mirror.py). Postgres silently truncates on INSERT,
so every later reader (verify_audit_integrity.py included) sees a different
value than the one that was hashed, and the row's row_hash never matches
again. Ironically, 0015's OWN backfill (below) was unaffected: it read
risk_score FROM THE DB (already truncated) before hashing, so every row that
existed at the time 0015 ran verifies fine. The bug only affects rows written
live, via write_decision, after 0015 shipped -- deterministically, on every
one of them that has a non-null risk_score, starting from the very first.

Found live: verify_audit_integrity.py flagged opa_decision_log.id=53197 as
"altered". It wasn't -- prev_hash/row_hash linkage across it and every row
after it stayed perfectly consistent (each row's prev_hash correctly matched
the row before it's stored row_hash), and rows with risk_score=NULL in the
same range verified fine throughout. That's the signature of a systematic
hashing bug, not tampering: a real attacker altering one row's content, or
re-pointing one row's prev_hash, doesn't also happen to re-sign every
downstream row to keep the chain looking unbroken.

app/core/audit_hash_chain.py::compute_row_hash now rounds risk_score to
single precision (via _single_precision) before formatting it, matching what
the column will actually persist. That fixes every row written from here on,
but every row already written since 0015 -- including the ones that happen to
already verify by coincidence (risk_score=NULL, or a score whose full-
precision and truncated forms happen to format identically) -- has a
row_hash computed under the OLD, buggy rule. Chain re-derivation cannot be
partial: this walks the ENTIRE table from GENESIS_HASH again, exactly like
0015's own backfill, using the corrected algorithm throughout. For every row
that existed before 0015 ran, this is a no-op (their risk_score was already
read from the DB at `real` precision by 0015's backfill, so rounding it to
single precision again changes nothing) -- only rows affected by the actual
bug get a different, now-correct, row_hash.

Same "frozen copy, never import from app.core" discipline as 0015 -- see that
migration's docstring for why. This file's copy of compute_row_hash is NOT
0015's unfixed copy re-run verbatim; it is a NEW frozen copy with the fix
baked in, since the whole point of this migration is to apply the corrected
algorithm. Future algorithm changes must, in turn, get their own new
migration and their own new frozen copy -- this one must not be edited again
after the fact either, by the same discipline.

Revision ID: 0016_hash_chain_precision
Revises: 0015_opa_decision_log_hash_chain
Create Date: 2026-08-13

Note: the revision id below is deliberately shorter than the migration's
filename -- same reason as 0013/0014 (see those files' own comments):
alembic_version.version_num is `character varying(32)`, and this file's full
name is longer than that.
"""
from __future__ import annotations

import hashlib
import struct

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0016_hash_chain_precision"
down_revision = "0015_opa_decision_log_hash_chain"
branch_labels = None
depends_on = None

# Frozen copy -- see module docstring. Must byte-for-byte match
# app.core.audit_hash_chain.GENESIS_HASH's value; this literal must never be
# edited after the fact.
_GENESIS_HASH = hashlib.sha256(b"zt-project-opa-decision-log-genesis").hexdigest()


def _single_precision_frozen(value: float) -> float:
    """Frozen copy of app.core.audit_hash_chain._single_precision -- see
    that function's docstring for why risk_score must round-trip through
    IEEE-754 single precision before being hashed."""
    return struct.unpack("<f", struct.pack("<f", value))[0]


def _compute_row_hash_frozen(
    *,
    prev_hash: str,
    trace_id,
    user_id,
    jti,
    role: str,
    resource: str,
    action: str,
    ip_address: str,
    risk_score,
    model_version,
    is_anomaly: str,
    decision: str,
    policy_name: str,
    reason,
    latency_ms: int,
    timestamp,
) -> str:
    """Frozen copy of app.core.audit_hash_chain.compute_row_hash's algorithm,
    AS FIXED BY THIS MIGRATION -- see module docstring for why this is
    duplicated, not imported, and why (unlike 0015's copy) this one already
    includes the risk_score precision fix."""
    canonical = "|".join(
        [
            prev_hash,
            str(trace_id),
            str(user_id),
            str(jti),
            role,
            resource,
            action,
            ip_address,
            "" if risk_score is None else f"{_single_precision_frozen(risk_score):.10f}",
            model_version or "",
            is_anomaly,
            decision,
            policy_name,
            reason or "",
            str(latency_ms),
            timestamp.isoformat(),
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def upgrade() -> None:
    bind = op.get_bind()
    opa_decision_log = sa.table(
        "opa_decision_log",
        sa.column("id", sa.BigInteger),
        sa.column("timestamp", sa.DateTime(timezone=True)),
        sa.column("trace_id", postgresql.UUID(as_uuid=True)),
        sa.column("user_id", postgresql.UUID(as_uuid=True)),
        sa.column("jti", postgresql.UUID(as_uuid=True)),
        sa.column("role", sa.String),
        sa.column("resource", sa.String),
        sa.column("action", sa.String),
        sa.column("ip_address", postgresql.INET),
        sa.column("risk_score", sa.Float),
        sa.column("model_version", sa.String),
        sa.column("is_anomaly", sa.String),
        sa.column("decision", sa.String),
        sa.column("policy_name", sa.Text),
        sa.column("reason", sa.Text),
        sa.column("latency_ms", sa.Integer),
        sa.column("prev_hash", sa.String),
        sa.column("row_hash", sa.String),
    )

    rows = bind.execute(
        sa.select(
            opa_decision_log.c.id,
            opa_decision_log.c.timestamp,
            opa_decision_log.c.trace_id,
            opa_decision_log.c.user_id,
            opa_decision_log.c.jti,
            opa_decision_log.c.role,
            opa_decision_log.c.resource,
            opa_decision_log.c.action,
            opa_decision_log.c.ip_address,
            opa_decision_log.c.risk_score,
            opa_decision_log.c.model_version,
            opa_decision_log.c.is_anomaly,
            opa_decision_log.c.decision,
            opa_decision_log.c.policy_name,
            opa_decision_log.c.reason,
            opa_decision_log.c.latency_ms,
        ).order_by(opa_decision_log.c.id.asc())
    ).fetchall()

    prev_hash = _GENESIS_HASH
    for row in rows:
        row_hash = _compute_row_hash_frozen(
            prev_hash=prev_hash,
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
            timestamp=row.timestamp,
        )
        bind.execute(
            opa_decision_log.update()
            .where(opa_decision_log.c.id == row.id)
            .values(prev_hash=prev_hash, row_hash=row_hash)
        )
        prev_hash = row_hash


def downgrade() -> None:
    # Deliberately a no-op, not a restore of 0015's pre-fix hashes: this
    # migration doesn't change the schema (0015 already added prev_hash/
    # row_hash), only the VALUES, and those values are strictly more correct
    # than what came before. Reverting to hashes computed by a known-buggy
    # algorithm would recreate the exact incident this migration fixes.
    pass
