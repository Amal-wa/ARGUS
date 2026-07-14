"""Add password lockout columns to users and the refresh_tokens table.

Revision ID: 0006_auth
Revises: 0005_model_score_distribution
Create Date: 2026-07-13
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0006_auth"
down_revision = "0005_model_score_distribution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("failed_login_attempts", sa.SmallInteger(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint("ck_users_failed_login_attempts", "users", "failed_login_attempts >= 0")

    op.create_table(
        "refresh_tokens",
        sa.Column("token_hash", sa.Text(), primary_key=True),
        sa.Column("family_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), server_default=sa.text("FALSE"), nullable=False),
    )
    op.create_index("idx_refresh_tokens_family_id", "refresh_tokens", ["family_id"])
    op.create_index("idx_refresh_tokens_user_id", "refresh_tokens", ["user_id"])


def downgrade() -> None:
    op.drop_index("idx_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_index("idx_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_constraint("ck_users_failed_login_attempts", "users", type_="check")
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_attempts")
