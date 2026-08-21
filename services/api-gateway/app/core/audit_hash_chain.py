from __future__ import annotations

import hashlib
import struct
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


def _single_precision(value: float) -> float:
    """Round-trips a Python double through IEEE-754 single precision --
    i.e. exactly what happens the moment a value is stored in and read back
    from a Postgres `real` column, which risk_score always is (opa_decision_log,
    event_anomaly, ml_training_samples, canary_validation_log all declare it
    `sa.REAL()`, see alembic/versions/0001_initial_mirror.py). Without this,
    compute_row_hash formats the caller's full-precision double, but every
    reader (verify_audit_integrity.py, or literally any other query) only
    ever sees the column's already-truncated value -- the two `.10f` strings
    differ, so the hash "breaks" on every row with a non-null risk_score,
    deterministically, forever, starting from the first row write_decision
    ever wrote after the hash chain shipped. Found live: opa_decision_log.id
    53197 (the first post-migration row with a score) failed
    verify_audit_integrity.py while its neighbours with risk_score=NULL
    verified fine, and prev_hash/row_hash linkage across the "broken" rows
    was otherwise perfectly intact -- the signature of a precision bug, not
    tampering. See 0016_hash_chain_risk_score_precision.py for the
    migration that re-derives the chain with this fix applied."""
    return struct.unpack("<f", struct.pack("<f", value))[0]


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
    repr()/str() -- repr()'s "shortest round-trip" float formatting is not
    guaranteed identical between two independent read paths of the same
    stored value. That alone isn't sufficient, though: risk_score is always
    a Postgres `real` (single-precision) column, so it must ALSO be rounded
    to single precision before formatting -- see _single_precision's
    docstring for the incident this fixes (a full-precision double hashed
    at write time will never again match what any later reader sees once
    the column has truncated it).
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
            "" if risk_score is None else f"{_single_precision(risk_score):.10f}",
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
