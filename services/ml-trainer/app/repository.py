from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.trainer import FEATURE_VECTOR_DIMENSIONS, TrainingSample, next_version_from_existing


class SqlMlTrainerRepository:
    def __init__(self, engine: Engine):
        self._engine = engine

    def resolve_excluded_user_ids(self, emails: list[str]) -> list[UUID]:
        if not emails:
            return []
        with self._engine.connect() as connection:
            rows = connection.execute(
                text("SELECT user_id FROM users WHERE email = ANY(:emails)"),
                {"emails": emails},
            ).all()
        return [row.user_id for row in rows]

    def load_training_samples(
        self,
        window_days: int,
        excluded_user_ids: list[UUID],
        max_resource_access: int | None = None,
    ) -> list[TrainingSample]:
        # ml_training_samples carries no user_id of its own (only trace_id) --
        # joining opa_decision_log is how every row's actual author is known.
        # This join was already proven 1:1 (one training sample -> exactly one
        # decision row) during the investigation that led to this exclusion
        # mechanism existing at all; see live diagnostic output in that
        # investigation's history. `<> ALL(excluded_user_ids)` on an EMPTY
        # list is vacuously true for every row in Postgres -- no special-case
        # needed for "nothing excluded".
        #
        # feature_vector[8] is 1-based SQL array indexing into the same
        # ARRAY(Float) column TrainingSample.feature_vector is built from --
        # index 8 here is Python's 0-based index 7 (distinct raw resources,
        # 5 min window), no reordering between Gateway construction and DB
        # storage. `max_resource_access IS NULL` short-circuits the filter
        # off entirely (rétrocompatible default) rather than needing a second
        # query shape.
        with self._engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT s.feature_vector, s.created_at "
                    "FROM ml_training_samples s "
                    "JOIN opa_decision_log d ON d.trace_id = s.trace_id "
                    "WHERE s.created_at >= NOW() - (:window_days || ' days')::interval "
                    "AND d.user_id <> ALL(CAST(:excluded_user_ids AS uuid[])) "
                    "AND (:max_resource_access IS NULL OR s.feature_vector[8] <= :max_resource_access)"
                ),
                {
                    "window_days": window_days,
                    "excluded_user_ids": excluded_user_ids,
                    "max_resource_access": max_resource_access,
                },
            ).all()
        return [TrainingSample(feature_vector=list(row.feature_vector), created_at=row.created_at) for row in rows]

    def register_training_run(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
        sample_count: int,
        hyperparameters: dict[str, Any],
        quality_metrics: dict[str, Any] | None,
    ) -> str:
        with self._engine.begin() as connection:
            existing_versions = connection.execute(text("SELECT model_version FROM ml_model_registry")).scalars().all()
            version = next_version_from_existing(list(existing_versions))
            connection.execute(
                text(
                    "INSERT INTO ml_model_registry "
                    "(model_version, training_window_start, training_window_end, training_samples, "
                    "hyperparameters, feature_dims, training_quality) "
                    "VALUES (:version, :window_start, :window_end, :sample_count, "
                    "CAST(:hyperparameters AS JSONB), :feature_dims, CAST(:quality_metrics AS JSONB))"
                ),
                {
                    "version": version,
                    "window_start": window_start,
                    "window_end": window_end,
                    "sample_count": sample_count,
                    "hyperparameters": json.dumps(hyperparameters),
                    "feature_dims": FEATURE_VECTOR_DIMENSIONS,
                    "quality_metrics": json.dumps(quality_metrics) if quality_metrics is not None else None,
                },
            )
        return version
