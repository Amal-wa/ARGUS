"""Add documents and orders tables (business resources for the traffic generator).

Revision ID: 0007_business_resources
Revises: 0006_auth
Create Date: 2026-07-14
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0007_business_resources"
down_revision = "0006_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "documents",
        sa.Column("document_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.user_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.text("FALSE"), nullable=False),
    )
    op.create_index("idx_documents_owner_id", "documents", ["owner_id"])

    op.create_table(
        "orders",
        sa.Column("order_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.user_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("status", sa.String(length=50), server_default=sa.text("'pending'"), nullable=False),
        sa.Column("amount", sa.Numeric(12, 2), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.text("FALSE"), nullable=False),
        sa.CheckConstraint("amount >= 0", name="ck_orders_amount"),
    )
    op.create_index("idx_orders_owner_id", "orders", ["owner_id"])


def downgrade() -> None:
    op.drop_index("idx_orders_owner_id", table_name="orders")
    op.drop_table("orders")
    op.drop_index("idx_documents_owner_id", table_name="documents")
    op.drop_table("documents")
