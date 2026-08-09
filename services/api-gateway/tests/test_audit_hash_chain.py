from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.audit_hash_chain import GENESIS_HASH, compute_row_hash


def _base_kwargs() -> dict:
    return dict(
        prev_hash=GENESIS_HASH,
        trace_id=uuid4(),
        user_id=uuid4(),
        jti=uuid4(),
        role="reader",
        resource="/documents/abc",
        action="read",
        ip_address="10.0.0.1",
        risk_score=0.42,
        model_version="v4",
        is_anomaly="none",
        decision="allow",
        policy_name="risk_allow",
        reason=None,
        latency_ms=12,
        timestamp=datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc),
    )


def test_genesis_hash_is_a_pinned_constant():
    # Catches an accidental change to the seed string -- migration 0015 hand
    # -copies this exact literal, so a drift here would silently make the
    # verification script flag every pre-existing row as tampered.
    assert GENESIS_HASH == "1bdddc3a3fd05b9d9ae430708ddd2f4c584e396d135d9e63e765e5b687a13df3"


def test_compute_row_hash_is_deterministic():
    kwargs = _base_kwargs()

    assert compute_row_hash(**kwargs) == compute_row_hash(**kwargs)


def test_compute_row_hash_changes_with_prev_hash():
    a = compute_row_hash(**_base_kwargs())
    b = compute_row_hash(**{**_base_kwargs(), "prev_hash": "a" * 64})

    assert a != b


@pytest.mark.parametrize(
    "field,new_value",
    [
        ("trace_id", uuid4()),
        ("user_id", uuid4()),
        ("jti", uuid4()),
        ("role", "admin"),
        ("resource", "/orders/xyz"),
        ("action", "create"),
        ("ip_address", "10.0.0.2"),
        ("risk_score", 0.99),
        ("model_version", "v5"),
        ("is_anomaly", "classified"),
        ("decision", "deny"),
        ("policy_name", "rbac_deny"),
        ("reason", "insufficient role"),
        ("latency_ms", 999),
        ("timestamp", datetime(2026, 8, 5, 12, 0, 1, tzinfo=timezone.utc)),
    ],
)
def test_compute_row_hash_changes_when_any_field_changes(field, new_value):
    baseline = compute_row_hash(**_base_kwargs())
    changed = compute_row_hash(**{**_base_kwargs(), field: new_value})

    assert baseline != changed, f"changing {field!r} did not change the hash"


def test_compute_row_hash_handles_none_risk_score_and_reason():
    # risk_score is None for /monitoring/* routes (exempt from ML scoring);
    # reason is None whenever OPA doesn't supply one. Must not raise, and
    # must still be distinguishable from an all-empty-string variant.
    kwargs = {**_base_kwargs(), "risk_score": None, "reason": None}

    result = compute_row_hash(**kwargs)

    assert isinstance(result, str)
    assert len(result) == 64  # sha256 hex digest length
    assert result != compute_row_hash(**{**kwargs, "risk_score": 0.0})
