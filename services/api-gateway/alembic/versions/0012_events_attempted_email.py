"""Add events.attempted_email -- distinguish password spraying from bruteforce.

Live replay of the traffic-generator's scenario B (one attacker IP, 25 distinct
target accounts, one failed attempt each) showed this attack produces ZERO rows
in opa_decision_log (it's all pre-auth, so it never reaches AuthorizationService)
and, worse, the ONLY persisted trace -- events (event_type='auth_failed') -- had
no way to tell "25 failures on 1 account" from "25 failures on 25 accounts": all
25 rows came back with user_id NULL (correct -- there's no verified identity on
a failed login) and no other column carried the attempted identity. auth_failed:
ip:{ip} (Redis, 300s TTL) has the same blind spot, and expires long before an
analyst investigating after the fact would look.

attempted_email records the email the caller supplied, independent of whether it
was valid -- this is audit trail, not identity: it lets a query group by
(ip_address, attempted_email) to count distinct accounts targeted from one IP,
the actual signature of spraying vs. a single-account bruteforce. Never used as
an authorization or rate-limit key (see FeatureVectorService.record_auth_failure's
comment on why IP, not email, is the trustworthy key there) -- this column is for
after-the-fact investigation only.

Revision ID: 0012_attempted_email
Revises: 0011_scoring_unavailable
Create Date: 2026-07-30

Note: alembic_version.version_num is VARCHAR(32) (Alembic's default), so the
revision id below is deliberately shorter than the migration's filename.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0012_attempted_email"
down_revision = "0011_scoring_unavailable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("events", sa.Column("attempted_email", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("events", "attempted_email")
