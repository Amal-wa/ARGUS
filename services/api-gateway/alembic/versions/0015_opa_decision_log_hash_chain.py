"""Add prev_hash/row_hash tamper-evidence chain to opa_decision_log.

The decision-audit trail (opa_decision_log) is a plain Postgres table today
-- anyone with DB access (a compromised service, a careless manual UPDATE)
can silently rewrite history with nothing to notice. This migration adds a
SHA-256 hash chain: each row's row_hash covers every other column on that
row PLUS prev_hash (the row_hash of whichever row was the current tail when
this one was written, or a fixed GENESIS_HASH for the very first row ever).
Altering any past row, or re-pointing a row's prev_hash to a different
parent, breaks the chain from that point forward -- detectable by
scripts/verify_audit_integrity.py without a separate audit-of-the-audit-log
system. See app/core/audit_hash_chain.py for the hashing algorithm itself
(used by app/core/repositories.py::AuthorizationRepository.write_decision
going forward) and scripts/verify_audit_integrity.py for verification.

GENESIS_HASH and the hashing algorithm are DELIBERATELY duplicated below
rather than imported from app.core.audit_hash_chain: a migration must stay
frozen forever, reproducing exactly what ran at the time it was applied,
even if that module's algorithm is ever revised later for new rows. This is
the same "mirror and keep in sync by hand" discipline services/dashboard's
types.ts already uses across the Python/TS boundary -- just applied across
the app-code/migration-history boundary instead. If you ever change
compute_row_hash's algorithm, this file's copy must NOT change to match; a
NEW migration would instead re-chain from that point forward.

Existing rows (from all traffic generated before this migration) are
backfilled in application-level Python, in ascending id order, from
GENESIS_HASH -- there's no way to express iterative hash chaining in plain
SQL. Columns are added nullable first, backfilled, then tightened to
NOT NULL, same two-step pattern as 0014_event_anomaly_subject's `subject`
column.

Revision ID: 0015_opa_decision_log_hash_chain
Revises: 0014_event_anomaly_subject
Create Date: 2026-08-05
"""

from __future__ import annotations

import hashlib

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0015_opa_decision_log_hash_chain"
down_revision = "0014_event_anomaly_subject"
branch_labels = None
depends_on = None

# Frozen copy -- see module docstring. Must byte-for-byte match
# app.core.audit_hash_chain.GENESIS_HASH's value AT THE TIME THIS MIGRATION
# WAS WRITTEN (pinned in that module's own test); this literal must never be
# edited after the fact.
_GENESIS_HASH = hashlib.sha256(b"zt-project-opa-decision-log-genesis").hexdigest()


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
    """Frozen copy of app.core.audit_hash_chain.compute_row_hash's algorithm
    -- see module docstring for why this is duplicated, not imported."""
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
            "" if risk_score is None else f"{risk_score:.10f}",
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
    op.add_column("opa_decision_log", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column("opa_decision_log", sa.Column("row_hash", sa.String(length=64), nullable=True))

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

    op.alter_column("opa_decision_log", "prev_hash", existing_type=sa.String(length=64), nullable=False)
    op.alter_column("opa_decision_log", "row_hash", existing_type=sa.String(length=64), nullable=False)
    # SHA-256 collisions are not a realistic risk at this scale -- this
    # constraint's real purpose is to make a write-path LOGIC bug (e.g. two
    # rows computed against a stale prev_hash) impossible to insert silently,
    # rather than to guard against a cryptographic break.
    op.create_unique_constraint("uq_opa_decision_log_row_hash", "opa_decision_log", ["row_hash"])


def downgrade() -> None:
    op.drop_constraint("uq_opa_decision_log_row_hash", "opa_decision_log", type_="unique")
    op.drop_column("opa_decision_log", "row_hash")
    op.drop_column("opa_decision_log", "prev_hash")
