"""Shrink ml_training_samples.feature_vector from 20 to 16 dimensions.

The feature vector was rebuilt: a spec-to-implementation audit found only
6 of the 17 originally-designed concepts actually implemented (five slots
were permanently 0.0), and three signals the attack scenarios depend on
(raw-resource cardinality, inter-request interval mean/std-dev, distinct
HTTP methods, IP-scoped auth failures) were missing outright. The revised,
fully-implemented layout is 11 numeric + 5 one-hot = 16 dimensions -- see
app/services/feature_vector.py's module-level index map for the exact
order, and CLAUDE.md for which of the original 17 concepts were dropped
and why.

Existing rows are unusable under the new layout (the dimensions no longer
mean the same thing), so this also truncates the table rather than trying
to migrate old rows forward. opa_decision_log is NOT touched -- it's the
audit trail, independent of feature_vector shape.

Revision ID: 0009_feature_vector_16_dims
Revises: 0008_monitoring_indexes
Create Date: 2026-07-25
"""

from __future__ import annotations

from alembic import op

revision = "0009_feature_vector_16_dims"
down_revision = "0008_monitoring_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("TRUNCATE TABLE ml_training_samples RESTART IDENTITY")
    op.drop_constraint("chk_feature_vector_size", "ml_training_samples", type_="check")
    op.create_check_constraint(
        "chk_feature_vector_size",
        "ml_training_samples",
        "cardinality(feature_vector) = 16",
    )


def downgrade() -> None:
    op.execute("TRUNCATE TABLE ml_training_samples RESTART IDENTITY")
    op.drop_constraint("chk_feature_vector_size", "ml_training_samples", type_="check")
    op.create_check_constraint(
        "chk_feature_vector_size",
        "ml_training_samples",
        "cardinality(feature_vector) = 20",
    )
