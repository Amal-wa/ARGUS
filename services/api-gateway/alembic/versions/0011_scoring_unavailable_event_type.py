"""Add 'scoring_unavailable' to the event_type enum.

IsolationForestClient used to raise OpaUnavailableError (from core/errors.py)
whenever Isolation Forest itself was unreachable, so GatewayMiddleware's single
except OpaUnavailableError clause logged every scoring outage as event_type
opa_unavailable -- a real Isolation Forest incident would misdirect on-call to
OPA. IsolationForestClient now raises a dedicated ScoringUnavailableError, and
this migration adds the event_type value GatewayMiddleware logs it under.

Postgres 15 (pgvector/pgvector:pg15, see docker-compose.yml) allows
ALTER TYPE ... ADD VALUE inside a transaction as long as the new value isn't
also used in that same transaction, which this migration doesn't do.

Revision ID: 0011_scoring_unavailable
Revises: 0010_registry_feature_dims
Create Date: 2026-07-26

Note: alembic_version.version_num is VARCHAR(32) (Alembic's default), so the
revision id below is deliberately shorter than the migration's filename.
"""
from __future__ import annotations

from alembic import op

revision = "0011_scoring_unavailable"
down_revision = "0010_registry_feature_dims"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'scoring_unavailable'")


def downgrade() -> None:
    # Postgres has no DROP VALUE for enums; downgrading would require
    # recreating the type and every column that uses it. Left as a no-op --
    # an unused enum value is harmless, unlike a lossy rebuild.
    pass
