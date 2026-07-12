"""Add the ml_model_registry table.

Revision ID: 0004_ml_model_registry
Revises: 0003_user_mfa
Create Date: 2026-07-12
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0004_ml_model_registry"
down_revision = "0003_user_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ml_model_registry",
        sa.Column("model_version", sa.String(length=50), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("training_window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("training_window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("training_samples", sa.Integer(), nullable=False),
        sa.Column("hyperparameters", postgresql.JSONB(), nullable=False),
        sa.CheckConstraint("training_samples > 0", name="ck_ml_model_registry_training_samples"),
    )


def downgrade() -> None:
    op.drop_table("ml_model_registry")
