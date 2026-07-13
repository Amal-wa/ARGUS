"""Add ml_model_registry.score_distribution.

Revision ID: 0005_model_score_distribution
Revises: 0004_ml_model_registry
Create Date: 2026-07-13
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0005_model_score_distribution"
down_revision = "0004_ml_model_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ml_model_registry", sa.Column("score_distribution", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("ml_model_registry", "score_distribution")
