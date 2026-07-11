"""Initial mirror of the locked gateway schema.

Revision ID: 0001_initial_mirror
Revises:
Create Date: 2026-07-08
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial_mirror"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # Each enum is created explicitly, exactly once, here. The column-bound
    # copies below use create_type=False so op.create_table(...) does not
    # attempt to auto-create the type a second time (which raised
    # DuplicateObjectError since both creations target the same connection).
    postgresql.ENUM(
        "rate_limit_ip_exceeded",
        "rate_limit_user_exceeded",
        "auth_failed",
        "token_revoked_used",
        "replay_detected",
        "mfa_locked",
        "mfa_failed",
        "opa_unavailable",
        "step_up_required",
        "challenge_expired",
        "totp_replay_detected",
        name="event_type",
    ).create(bind, checkfirst=True)
    postgresql.ENUM("GET", "POST", "PUT", "PATCH", "DELETE", name="http_method_type").create(bind, checkfirst=True)
    postgresql.ENUM("allow", "deny", "step_up", name="decision_type").create(bind, checkfirst=True)
    postgresql.ENUM("none", "pending_classification", "classified", name="anomaly_status").create(bind, checkfirst=True)
    postgresql.ENUM(
        "behavioral",
        "authentication",
        "authorization",
        "network",
        "resource_access",
        name="anomaly_type",
    ).create(bind, checkfirst=True)
    postgresql.ENUM("low", "medium", "high", "critical", name="severity_level").create(bind, checkfirst=True)
    postgresql.ENUM("pending", "no_review_required", "confirmed", "rejected", name="canary_review_status").create(bind, checkfirst=True)

    event_type = postgresql.ENUM(
        "rate_limit_ip_exceeded",
        "rate_limit_user_exceeded",
        "auth_failed",
        "token_revoked_used",
        "replay_detected",
        "mfa_locked",
        "mfa_failed",
        "opa_unavailable",
        "step_up_required",
        "challenge_expired",
        "totp_replay_detected",
        name="event_type",
        create_type=False,
    )
    http_method_type = postgresql.ENUM("GET", "POST", "PUT", "PATCH", "DELETE", name="http_method_type", create_type=False)
    decision_type = postgresql.ENUM("allow", "deny", "step_up", name="decision_type", create_type=False)
    anomaly_status = postgresql.ENUM("none", "pending_classification", "classified", name="anomaly_status", create_type=False)
    anomaly_type = postgresql.ENUM(
        "behavioral",
        "authentication",
        "authorization",
        "network",
        "resource_access",
        name="anomaly_type",
        create_type=False,
    )
    severity_level = postgresql.ENUM("low", "medium", "high", "critical", name="severity_level", create_type=False)
    canary_review_status = postgresql.ENUM(
        "pending", "no_review_required", "confirmed", "rejected", name="canary_review_status", create_type=False
    )

    op.create_table("roles", sa.Column("role_name", sa.String(length=100), primary_key=True))
    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("trace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=False),
        sa.Column("http_method", http_method_type, nullable=False),
        sa.Column("request_path", sa.Text(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("event_type", event_type, nullable=False),
    )
    op.create_index("idx_events_trace_id", "events", ["trace_id"])
    op.create_index("idx_events_user_timestamp", "events", ["user_id", sa.text("timestamp DESC")])
    op.create_index("idx_events_ip_timestamp", "events", ["ip_address", sa.text("timestamp DESC")])
    op.create_index("idx_events_type_timestamp", "events", ["event_type", sa.text("timestamp DESC")])
    op.create_index("idx_events_timestamp", "events", [sa.text("timestamp DESC")])

    op.create_table(
        "opa_decision_log",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("trace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("jti", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=100), nullable=False),
        sa.Column("resource", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=False),
        sa.Column("risk_score", sa.REAL(), nullable=True),
        sa.Column("model_version", sa.String(length=50), nullable=True),
        sa.Column("is_anomaly", anomaly_status, nullable=False, server_default=sa.text("'none'::anomaly_status")),
        sa.Column("decision", decision_type, nullable=False),
        sa.Column("policy_name", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.CheckConstraint("risk_score >= 0.0 AND risk_score <= 1.0", name="ck_opa_decision_log_risk_score"),
    )

    op.create_table(
        "event_anomaly",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("id_log", sa.BigInteger(), sa.ForeignKey("opa_decision_log.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("anomaly_type", anomaly_type, nullable=False),
        sa.Column("risk_score", sa.REAL(), nullable=False),
        sa.Column("severity", severity_level, nullable=False),
        sa.Column("contributing_features", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint("risk_score >= 0.0 AND risk_score <= 1.0", name="ck_event_anomaly_risk_score"),
    )
    op.create_index("idx_event_anomaly_timestamp", "event_anomaly", [sa.text("timestamp DESC")])
    op.create_index("idx_event_anomaly_type", "event_anomaly", ["anomaly_type"])
    op.create_index("idx_event_anomaly_severity", "event_anomaly", ["severity"])
    op.create_index("idx_event_anomaly_log", "event_anomaly", ["id_log"])

    op.create_table(
        "ml_training_samples",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("trace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("feature_vector", postgresql.ARRAY(sa.REAL()), nullable=False),
        sa.Column("risk_score", sa.REAL(), nullable=True),
        sa.Column("model_version", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.CheckConstraint("cardinality(feature_vector) = 20", name="chk_feature_vector_size"),
        sa.CheckConstraint("risk_score >= 0.0 AND risk_score <= 1.0", name="ck_ml_training_samples_risk_score"),
    )
    op.create_index("idx_ml_training_trace", "ml_training_samples", ["trace_id"])
    op.create_index("idx_ml_training_created_at", "ml_training_samples", [sa.text("created_at DESC")])
    op.create_index("idx_ml_training_model_version", "ml_training_samples", ["model_version"])

    op.create_table(
        "canary_validation_log",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("trace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("production_model_version", sa.String(length=50), nullable=False),
        sa.Column("candidate_model_version", sa.String(length=50), nullable=False),
        sa.Column("production_risk_score", sa.REAL(), nullable=False),
        sa.Column("candidate_risk_score", sa.REAL(), nullable=False),
        sa.Column("review_status", canary_review_status, nullable=False, server_default=sa.text("'pending'::canary_review_status")),
        sa.Column("reviewed_by", sa.String(length=100), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.CheckConstraint("production_risk_score >= 0.0 AND production_risk_score <= 1.0", name="ck_canary_validation_log_production_risk_score"),
        sa.CheckConstraint("candidate_risk_score >= 0.0 AND candidate_risk_score <= 1.0", name="ck_canary_validation_log_candidate_risk_score"),
    )


def downgrade() -> None:
    op.drop_index("idx_ml_training_model_version", table_name="ml_training_samples")
    op.drop_index("idx_ml_training_created_at", table_name="ml_training_samples")
    op.drop_index("idx_ml_training_trace", table_name="ml_training_samples")
    op.drop_table("ml_training_samples")
    op.drop_index("idx_event_anomaly_log", table_name="event_anomaly")
    op.drop_index("idx_event_anomaly_severity", table_name="event_anomaly")
    op.drop_index("idx_event_anomaly_type", table_name="event_anomaly")
    op.drop_index("idx_event_anomaly_timestamp", table_name="event_anomaly")
    op.drop_table("event_anomaly")
    op.drop_table("canary_validation_log")
    op.drop_table("opa_decision_log")
    op.drop_index("idx_events_timestamp", table_name="events")
    op.drop_index("idx_events_type_timestamp", table_name="events")
    op.drop_index("idx_events_ip_timestamp", table_name="events")
    op.drop_index("idx_events_user_timestamp", table_name="events")
    op.drop_index("idx_events_trace_id", table_name="events")
    op.drop_table("events")
    op.drop_table("roles")

    bind = op.get_bind()
    postgresql.ENUM(name="canary_review_status").drop(bind, checkfirst=True)
    postgresql.ENUM(name="severity_level").drop(bind, checkfirst=True)
    postgresql.ENUM(name="anomaly_type").drop(bind, checkfirst=True)
    postgresql.ENUM(name="anomaly_status").drop(bind, checkfirst=True)
    postgresql.ENUM(name="decision_type").drop(bind, checkfirst=True)
    postgresql.ENUM(name="http_method_type").drop(bind, checkfirst=True)
    postgresql.ENUM(name="event_type").drop(bind, checkfirst=True)
