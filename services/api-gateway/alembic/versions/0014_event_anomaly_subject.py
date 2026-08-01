"""Add event_anomaly.subject -- a stable dedup identity, decoupled from id_log.

behavioral-detector (services/behavioral-detector) needs to deduplicate repeat
detections of the SAME ongoing anomaly across scan ticks (every 60s, while the
underlying Redis key stays above threshold within its 300s TTL window). Using
id_log for this (join to opa_decision_log.user_id) turned out to only work for
3 of the 4 anomaly_type values -- 'authentication' has no id_log at all (see
0013_event_anomaly_id_log_nullable), so it needed a second, inconsistent dedup
path (an unindexed contributing_features->>'attacker_ip' JSONB lookup).

subject is the stable identity ALL 4 anomaly types already have one of:
user_id (as text) for resource_access/network/authorization, the attacker IP
for authentication. id_log goes back to its original, narrower purpose --
letting an analyst find the specific request a resource_access/network/
authorization anomaly came from -- now fully decoupled from deduplication.

Backfill: every existing row (all resource_access, all with a real id_log at
the time of writing) gets subject = the referencing decision's user_id.

Revision ID: 0014_event_anomaly_subject
Revises: 0013_id_log_nullable
Create Date: 2026-08-01

Note: alembic_version.version_num is VARCHAR(32) (Alembic's default), so the
revision id below is deliberately shorter than the migration's filename.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0014_event_anomaly_subject"
down_revision = "0013_id_log_nullable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("event_anomaly", sa.Column("subject", sa.Text(), nullable=True))
    op.execute(
        "UPDATE event_anomaly ea SET subject = odl.user_id::text "
        "FROM opa_decision_log odl WHERE odl.id = ea.id_log AND ea.subject IS NULL"
    )
    op.alter_column("event_anomaly", "subject", existing_type=sa.Text(), nullable=False)
    op.create_index(
        "idx_event_anomaly_subject",
        "event_anomaly",
        ["anomaly_type", "subject", "timestamp"],
    )


def downgrade() -> None:
    op.drop_index("idx_event_anomaly_subject", table_name="event_anomaly")
    op.drop_column("event_anomaly", "subject")
