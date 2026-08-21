"""Add ml_model_registry.training_quality -- an automatic model quality signal.

Until now, whether a newly trained model actually separates normal from
anomalous behavior was never measured automatically: canary-validator's
score_distribution is written LATER, against a DIFFERENT (production) model's
live traffic, and the ROC AUC figures referenced in CLAUDE.md were one-off
manual measurements from a traffic-generator replay, not something the
pipeline itself computes on every training run. Two versions could only be
compared by eyeballing canary_validation_log after the fact.

training_quality is computed by ml-trainer itself, in the SAME run that
produces the model artifact (see app/trainer.py::evaluate_holdout_quality),
and stored in the SAME INSERT as every other ml_model_registry column --
unlike score_distribution, this doesn't need a later UPDATE from another
service. Nullable: a training run with too few samples to hold out a
statistically meaningful evaluation split is a legitimate, expected outcome,
not a data gap -- same discipline already applied to score_distribution.

Revision ID: 0017_training_quality
Revises: 0016_hash_chain_precision
Create Date: 2026-08-14
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0017_training_quality"
down_revision = "0016_hash_chain_precision"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ml_model_registry", sa.Column("training_quality", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("ml_model_registry", "training_quality")
