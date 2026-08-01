from __future__ import annotations

import json

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.rules import AnomalyRecord


class SqlBehavioralDetectorRepository:
    def __init__(self, engine: Engine):
        self._engine = engine

    def latest_decision_id(self, user_id: str) -> int | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                text("SELECT id FROM opa_decision_log WHERE user_id = :user_id ORDER BY timestamp DESC LIMIT 1"),
                {"user_id": user_id},
            ).first()
        return None if row is None else row.id

    def anomaly_already_recorded(self, anomaly_type: str, subject: str, window_seconds: int) -> bool:
        # One code path for all 4 anomaly types, via idx_event_anomaly_subject
        # -- subject is set uniformly (user_id or attacker IP), unlike id_log
        # which is NULL for authentication. See 0014_event_anomaly_subject for
        # why this replaced an earlier id_log-based (and inconsistent) dedup.
        with self._engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT 1 FROM event_anomaly "
                    "WHERE anomaly_type = CAST(:anomaly_type AS anomaly_type) "
                    "AND subject = :subject "
                    "AND timestamp >= NOW() - (:window_seconds || ' seconds')::interval "
                    "LIMIT 1"
                ),
                {"anomaly_type": anomaly_type, "subject": subject, "window_seconds": window_seconds},
            ).first()
        return row is not None

    def write_anomaly(self, record: AnomalyRecord) -> None:
        with self._engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO event_anomaly (id_log, subject, anomaly_type, risk_score, severity, contributing_features) "
                    "VALUES (:id_log, :subject, CAST(:anomaly_type AS anomaly_type), :risk_score, "
                    "CAST(:severity AS severity_level), CAST(:contributing_features AS JSONB))"
                ),
                {
                    "id_log": record.id_log,
                    "subject": record.subject,
                    "anomaly_type": record.anomaly_type,
                    "risk_score": record.risk_score,
                    "severity": record.severity,
                    "contributing_features": json.dumps(record.contributing_features),
                },
            )
            # is_anomaly lives on the specific decision this anomaly attaches
            # to -- authentication has none (id_log is NULL, see AnomalyRecord),
            # so there is nothing to mark for that type.
            if record.id_log is not None:
                connection.execute(
                    text(
                        "UPDATE opa_decision_log SET is_anomaly = CAST('pending_classification' AS anomaly_status) "
                        "WHERE id = :id_log"
                    ),
                    {"id_log": record.id_log},
                )
