"""Make event_anomaly.id_log nullable -- authentication anomalies have no decision to reference.

behavioral-detector (services/behavioral-detector) needs to record 'authentication'
anomalies (password spraying: one IP, many distinct target accounts) detected from
auth_failed_accounts:ip:{ip}. That signal comes from failed /auth/login attempts,
which are pre-auth and never reach AuthorizationService -- there is structurally no
opa_decision_log row to set id_log to for this one anomaly_type. The other three
types (resource_access, network, authorization) always have a real decision to
reference and keep doing so; only authentication anomalies get id_log = NULL.

Revision ID: 0013_id_log_nullable
Revises: 0012_attempted_email
Create Date: 2026-08-01

Note: alembic_version.version_num is VARCHAR(32) (Alembic's default), so the
revision id below is deliberately shorter than the migration's filename.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0013_id_log_nullable"
down_revision = "0012_attempted_email"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("event_anomaly", "id_log", existing_type=sa.BigInteger(), nullable=True)


def downgrade() -> None:
    # Would fail if any authentication-type row (id_log IS NULL) exists by
    # then -- deliberate: a downgrade should surface that data loss rather
    # than silently deleting those rows to make the column NOT NULL again.
    op.alter_column("event_anomaly", "id_log", existing_type=sa.BigInteger(), nullable=False)
