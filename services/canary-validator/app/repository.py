from __future__ import annotations

import json

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.validator import CalibrationSample, ComparisonRow, ComparisonSample, ScoreDistribution


class SqlCanaryValidatorRepository:
    def __init__(self, engine: Engine):
        self._engine = engine

    def load_calibration_samples(self, window_days: int, batch_size: int) -> list[CalibrationSample]:
        with self._engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT trace_id, feature_vector FROM ml_training_samples "
                    "WHERE created_at >= NOW() - (:window_days || ' days')::interval "
                    "ORDER BY created_at DESC "
                    "LIMIT :batch_size"
                ),
                {"window_days": window_days, "batch_size": batch_size},
            ).all()
        return [CalibrationSample(trace_id=row.trace_id, feature_vector=list(row.feature_vector)) for row in rows]

    def load_unscored_comparison_samples(
        self, candidate_version: str, window_days: int, batch_size: int
    ) -> list[ComparisonSample]:
        with self._engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT s.trace_id, s.feature_vector, s.risk_score, s.model_version "
                    "FROM ml_training_samples s "
                    "WHERE s.risk_score IS NOT NULL "
                    "  AND s.created_at >= NOW() - (:window_days || ' days')::interval "
                    "  AND NOT EXISTS ( "
                    "      SELECT 1 FROM canary_validation_log c "
                    "      WHERE c.trace_id = s.trace_id "
                    "        AND c.candidate_model_version = :candidate_version "
                    "  ) "
                    "LIMIT :batch_size"
                ),
                {"window_days": window_days, "candidate_version": candidate_version, "batch_size": batch_size},
            ).all()
        return [
            ComparisonSample(
                trace_id=row.trace_id,
                feature_vector=list(row.feature_vector),
                production_risk_score=row.risk_score,
                production_model_version=row.model_version,
            )
            for row in rows
        ]

    def write_score_distribution(self, candidate_version: str, distribution: ScoreDistribution) -> None:
        with self._engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE ml_model_registry SET score_distribution = CAST(:distribution AS JSONB) "
                    "WHERE model_version = :version"
                ),
                {"distribution": json.dumps(distribution.to_dict()), "version": candidate_version},
            )

    def insert_comparison_rows(self, rows: list[ComparisonRow]) -> int:
        if not rows:
            return 0
        with self._engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO canary_validation_log "
                    "(trace_id, production_model_version, candidate_model_version, "
                    " production_risk_score, candidate_risk_score, review_status) "
                    "VALUES (:trace_id, :production_model_version, :candidate_model_version, "
                    " :production_risk_score, :candidate_risk_score, CAST('pending' AS canary_review_status))"
                ),
                [
                    {
                        "trace_id": row.trace_id,
                        "production_model_version": row.production_model_version,
                        "candidate_model_version": row.candidate_model_version,
                        "production_risk_score": row.production_risk_score,
                        "candidate_risk_score": row.candidate_risk_score,
                    }
                    for row in rows
                ],
            )
        return len(rows)
