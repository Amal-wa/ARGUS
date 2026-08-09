from __future__ import annotations

import hashlib
from datetime import datetime
from uuid import UUID

# Seed for the very first row's prev_hash -- there is no real previous row
# for it to chain from. Pinned as a literal constant (see
# tests/test_audit_hash_chain.py::test_genesis_hash_is_a_pinned_constant) so
# an accidental change to the seed string is caught immediately.
# alembic/versions/0015_opa_decision_log_hash_chain.py hand-copies this exact
# value rather than importing this module -- a migration must stay frozen
# even if this file's algorithm ever changes later; see that file's comment.
GENESIS_HASH = hashlib.sha256(b"zt-project-opa-decision-log-genesis").hexdigest()


def compute_row_hash(
    *,
    prev_hash: str,
    trace_id: UUID,
    user_id: UUID,
    jti: UUID,
    role: str,
    resource: str,
    action: str,
    ip_address: str,
    risk_score: float | None,
    model_version: str | None,
    is_anomaly: str,
    decision: str,
    policy_name: str,
    reason: str | None,
    latency_ms: int,
    timestamp: datetime,
) -> str:
    """Tamper-evidence hash for one opa_decision_log row, chained to the row
    before it via prev_hash. Changing ANY field on a past row -- or
    re-pointing prev_hash to a different parent -- changes this row's hash,
    which then no longer matches what the NEXT row's prev_hash committed to
    at write time. scripts/verify_audit_integrity.py walks the whole table
    re-deriving this function's output and comparing.

    Pure and synchronous on purpose: no DB, no I/O -- the only piece of the
    hash-chaining feature this project's test convention (no real DB in any
    test, see repositories.py's write_decision) can exercise directly.

    risk_score is formatted with fixed precision (f"{x:.10f}"), not
    repr()/str() -- this guarantees the exact same string is produced both
    when write_decision computes a row's hash at insert time and when
    verify_audit_integrity.py recomputes it later after reading the column
    back (possibly through a different driver/Decimal path); repr()'s
    "shortest round-trip" float formatting is not guaranteed identical
    between two independent read paths of the same stored value.
    """
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
