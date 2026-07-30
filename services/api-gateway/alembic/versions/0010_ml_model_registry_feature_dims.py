"""Add ml_model_registry.feature_dims -- guard against dimension-mismatched promotion.

scripts/promote_model.py only ever checked that score_distribution["p98"] existed.
Nothing stopped `promote_model.py v1` from succeeding even though v1 was trained on
the old 20-dimension feature vector layout (see 0009_feature_vector_16_dims and
CLAUDE.md) -- isolation-forest would load that model, receive 16-dim vectors from
the Gateway, and every /score call would raise inside ModelStore.score() with no
try/except around it, a 500 on all scored traffic until someone manually re-promoted
a compatible version.

feature_dims records the dimensionality the model was actually trained on, so
promote_model.py can refuse a mismatch outright instead of relying on operators
remembering which versions predate the 16-dim rebuild.

Backfill: every existing row except v1 was trained under the current 16-dim
regime (v1 is the sole known 20-dim holdout -- see CLAUDE.md's feature vector
history). Set the whole table to 16, then override v1 to 20 specifically.

Revision ID: 0010_registry_feature_dims
Revises: 0009_feature_vector_16_dims
Create Date: 2026-07-26

Note: alembic_version.version_num is VARCHAR(32) (Alembic's default), so the
revision id below is deliberately shorter than the migration's filename.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0010_registry_feature_dims"
down_revision = "0009_feature_vector_16_dims"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ml_model_registry", sa.Column("feature_dims", sa.Integer(), nullable=True))
    op.execute("UPDATE ml_model_registry SET feature_dims = 16")
    op.execute("UPDATE ml_model_registry SET feature_dims = 20 WHERE model_version = 'v1'")
    op.alter_column("ml_model_registry", "feature_dims", nullable=False)


def downgrade() -> None:
    op.drop_column("ml_model_registry", "feature_dims")
