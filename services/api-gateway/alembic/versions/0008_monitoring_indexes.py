"""Add opa_decision_log indexes needed by the monitoring endpoints.

opa_decision_log had no index on `timestamp` at all -- every monitoring query
(the live decision feed's `since`-based polling, the stats window, the risk
timeline, the audit page) filters and/or orders by it, and the table is
append-only and grows without bound. Also index (user_id, timestamp) for
per-user risk-timeline/audit lookups and (decision, timestamp) for the
step_up alerts feed.

Revision ID: 0008_monitoring_indexes
Revises: 0007_business_resources
Create Date: 2026-07-19
"""

from __future__ import annotations

from alembic import op


revision = "0008_monitoring_indexes"
down_revision = "0007_business_resources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("idx_opa_decision_log_timestamp", "opa_decision_log", ["timestamp"])
    op.create_index("idx_opa_decision_log_user_timestamp", "opa_decision_log", ["user_id", "timestamp"])
    op.create_index("idx_opa_decision_log_decision_timestamp", "opa_decision_log", ["decision", "timestamp"])


def downgrade() -> None:
    op.drop_index("idx_opa_decision_log_decision_timestamp", table_name="opa_decision_log")
    op.drop_index("idx_opa_decision_log_user_timestamp", table_name="opa_decision_log")
    op.drop_index("idx_opa_decision_log_timestamp", table_name="opa_decision_log")
