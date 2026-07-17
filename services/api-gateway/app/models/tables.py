from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Numeric,
    SmallInteger,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID


metadata = MetaData()

event_type_enum = Enum(
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
)

http_method_enum = Enum("GET", "POST", "PUT", "PATCH", "DELETE", name="http_method_type")
decision_type_enum = Enum("allow", "deny", "step_up", name="decision_type")
anomaly_status_enum = Enum("none", "pending_classification", "classified", name="anomaly_status")

anomaly_type_enum = Enum("behavioral", "authentication", "authorization", "network", "resource_access", name="anomaly_type")
severity_level_enum = Enum("low", "medium", "high", "critical", name="severity_level")
canary_review_status_enum = Enum("pending", "no_review_required", "confirmed", "rejected", name="canary_review_status")

roles_table = Table(
    "roles",
    metadata,
    Column("role_name", String(length=100), primary_key=True),
)

users_table = Table(
    "users",
    metadata,
    Column("user_id", UUID(as_uuid=True), primary_key=True),
    Column("email", String(length=255), nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("role", String(length=100), ForeignKey("roles.role_name"), nullable=False),
    Column("is_active", Boolean, nullable=False, server_default=text("TRUE")),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("last_login", DateTime(timezone=True), nullable=True),
    Column("failed_login_attempts", SmallInteger, nullable=False, server_default=text("0")),
    Column("locked_until", DateTime(timezone=True), nullable=True),
    UniqueConstraint("email", name="uq_user_email"),
    CheckConstraint("failed_login_attempts >= 0", name="ck_users_failed_login_attempts"),
)

refresh_tokens_table = Table(
    "refresh_tokens",
    metadata,
    Column("token_hash", Text, primary_key=True),
    Column("family_id", UUID(as_uuid=True), nullable=False),
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False),
    Column("issued_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True), nullable=True),
    Column("revoked", Boolean, nullable=False, server_default=text("FALSE")),
)

Index("idx_refresh_tokens_family_id", refresh_tokens_table.c.family_id)
Index("idx_refresh_tokens_user_id", refresh_tokens_table.c.user_id)

user_mfa_table = Table(
    "user_mfa",
    metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), primary_key=True),
    Column("totp_secret_ciphertext", Text, nullable=False),
    Column("failed_attempts", SmallInteger, nullable=False, server_default=text("0")),
    Column("locked_until", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    CheckConstraint("failed_attempts >= 0", name="ck_user_mfa_failed_attempts"),
)

events_table = Table(
    "events",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("trace_id", UUID(as_uuid=True), nullable=False),
    Column("timestamp", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("user_id", UUID(as_uuid=True), nullable=True),
    Column("ip_address", INET, nullable=False),
    Column("http_method", http_method_enum, nullable=False),
    Column("request_path", Text, nullable=False),
    Column("latency_ms", Integer, nullable=False),
    Column("http_status", Integer, nullable=False),
    Column("error_code", Text, nullable=True),
    Column("error_message", Text, nullable=True),
    Column("event_type", event_type_enum, nullable=False),
)

Index("idx_events_trace_id", events_table.c.trace_id)
Index("idx_events_user_timestamp", events_table.c.user_id, events_table.c.timestamp.desc())
Index("idx_events_ip_timestamp", events_table.c.ip_address, events_table.c.timestamp.desc())
Index("idx_events_type_timestamp", events_table.c.event_type, events_table.c.timestamp.desc())
Index("idx_events_timestamp", events_table.c.timestamp.desc())

opa_decision_log_table = Table(
    "opa_decision_log",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("timestamp", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("trace_id", UUID(as_uuid=True), nullable=False),
    Column("user_id", UUID(as_uuid=True), nullable=False),
    Column("jti", UUID(as_uuid=True), nullable=False),
    Column("role", String(length=100), nullable=False),
    Column("resource", String(length=255), nullable=False),
    Column("action", String(length=50), nullable=False),
    Column("ip_address", INET, nullable=False),
    Column("risk_score", Float, nullable=True),
    Column("model_version", String(length=50), nullable=True),
    Column("is_anomaly", anomaly_status_enum, nullable=False, server_default=text("'none'::anomaly_status")),
    Column("decision", decision_type_enum, nullable=False),
    Column("policy_name", Text, nullable=False),
    Column("reason", Text, nullable=True),
    Column("latency_ms", Integer, nullable=False),
    CheckConstraint("risk_score >= 0.0 AND risk_score <= 1.0", name="ck_opa_decision_log_risk_score"),
)

Index("idx_opa_decision_log_timestamp", opa_decision_log_table.c.timestamp)
Index("idx_opa_decision_log_user_timestamp", opa_decision_log_table.c.user_id, opa_decision_log_table.c.timestamp)
Index("idx_opa_decision_log_decision_timestamp", opa_decision_log_table.c.decision, opa_decision_log_table.c.timestamp)

event_anomaly_table = Table(
    "event_anomaly",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("id_log", BigInteger, ForeignKey("opa_decision_log.id", ondelete="RESTRICT"), nullable=False),
    Column("timestamp", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("anomaly_type", anomaly_type_enum, nullable=False),
    Column("risk_score", Float, nullable=False),
    Column("severity", severity_level_enum, nullable=False),
    Column("contributing_features", JSONB, nullable=False),
    CheckConstraint("risk_score >= 0.0 AND risk_score <= 1.0", name="ck_event_anomaly_risk_score"),
)

Index("idx_event_anomaly_timestamp", event_anomaly_table.c.timestamp.desc())
Index("idx_event_anomaly_type", event_anomaly_table.c.anomaly_type)
Index("idx_event_anomaly_severity", event_anomaly_table.c.severity)
Index("idx_event_anomaly_log", event_anomaly_table.c.id_log)

ml_training_samples_table = Table(
    "ml_training_samples",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("trace_id", UUID(as_uuid=True), nullable=False),
    Column("feature_vector", ARRAY(Float), nullable=False),
    Column("risk_score", Float, nullable=True),
    Column("model_version", String(length=50), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    CheckConstraint("cardinality(feature_vector) = 20", name="chk_feature_vector_size"),
)

Index("idx_ml_training_trace", ml_training_samples_table.c.trace_id)
Index("idx_ml_training_created_at", ml_training_samples_table.c.created_at.desc())
Index("idx_ml_training_model_version", ml_training_samples_table.c.model_version)

canary_validation_log_table = Table(
    "canary_validation_log",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("trace_id", UUID(as_uuid=True), nullable=False),
    Column("production_model_version", String(length=50), nullable=False),
    Column("candidate_model_version", String(length=50), nullable=False),
    Column("production_risk_score", Float, nullable=False),
    Column("candidate_risk_score", Float, nullable=False),
    Column("review_status", canary_review_status_enum, nullable=False, server_default=text("'pending'::canary_review_status")),
    Column("reviewed_by", String(length=100), nullable=True),
    Column("reviewed_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    CheckConstraint("production_risk_score >= 0.0 AND production_risk_score <= 1.0", name="ck_canary_validation_log_production_risk_score"),
    CheckConstraint("candidate_risk_score >= 0.0 AND candidate_risk_score <= 1.0", name="ck_canary_validation_log_candidate_risk_score"),
)

ml_model_registry_table = Table(
    "ml_model_registry",
    metadata,
    Column("model_version", String(length=50), primary_key=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("training_window_start", DateTime(timezone=True), nullable=False),
    Column("training_window_end", DateTime(timezone=True), nullable=False),
    Column("training_samples", Integer, nullable=False),
    Column("hyperparameters", JSONB, nullable=False),
    Column("score_distribution", JSONB, nullable=True),
    CheckConstraint("training_samples > 0", name="ck_ml_model_registry_training_samples"),
)

documents_table = Table(
    "documents",
    metadata,
    Column("document_id", UUID(as_uuid=True), primary_key=True),
    Column("owner_id", UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT"), nullable=False),
    Column("title", String(length=255), nullable=False),
    Column("content", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("is_deleted", Boolean, nullable=False, server_default=text("FALSE")),
)

Index("idx_documents_owner_id", documents_table.c.owner_id)

orders_table = Table(
    "orders",
    metadata,
    Column("order_id", UUID(as_uuid=True), primary_key=True),
    Column("owner_id", UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT"), nullable=False),
    Column("status", String(length=50), nullable=False, server_default=text("'pending'")),
    Column("amount", Numeric(12, 2), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=text("NOW()")),
    Column("is_deleted", Boolean, nullable=False, server_default=text("FALSE")),
    CheckConstraint("amount >= 0", name="ck_orders_amount"),
)

Index("idx_orders_owner_id", orders_table.c.owner_id)
