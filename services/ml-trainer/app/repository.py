from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.trainer import TrainingSample, next_version_from_existing


class SqlMlTrainerRepository:
    def __init__(self, engine: Engine):
        self._engine = engine

    def load_training_samples(self, window_days: int) -> list[TrainingSample]:
        with self._engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT feature_vector, created_at FROM ml_training_samples "
                    "WHERE created_at >= NOW() - (:window_days || ' days')::interval"
                ),
                {"window_days": window_days},
            ).all()
        return [TrainingSample(feature_vector=list(row.feature_vector), created_at=row.created_at) for row in rows]

    def register_training_run(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
        sample_count: int,
        hyperparameters: dict[str, Any],
    ) -> str:
        with self._engine.begin() as connection:
            existing_versions = connection.execute(text("SELECT model_version FROM ml_model_registry")).scalars().all()
            version = next_version_from_existing(list(existing_versions))
            connection.execute(
                text(
                    "INSERT INTO ml_model_registry "
                    "(model_version, training_window_start, training_window_end, training_samples, hyperparameters) "
                    "VALUES (:version, :window_start, :window_end, :sample_count, CAST(:hyperparameters AS JSONB))"
                ),
                {
                    "version": version,
                    "window_start": window_start,
                    "window_end": window_end,
                    "sample_count": sample_count,
                    "hyperparameters": json.dumps(hyperparameters),
                },
            )
        return version
