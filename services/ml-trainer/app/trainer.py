from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# Convention isolation-forest must follow when loading artifacts: one file per
# version, named "model_{version}.joblib", directly under models_dir.
MODEL_FILENAME_TEMPLATE = "model_{version}.joblib"

CANDIDATE_VERSION_KEY = "model:candidate_version"

# Single source of truth for this service's expected vector shape -- must
# match api-gateway's FeatureVectorService (16 dims), the DB's
# chk_feature_vector_size CHECK constraint, and isolation-forest's
# ScoreRequest validation. Referenced once here rather than repeating the
# literal, so a future change to the vector's dimensionality only needs
# updating in one place per service.
FEATURE_VECTOR_DIMENSIONS = 16

_VERSION_PATTERN = re.compile(r"^v(\d+)$")


class TrainingOutcome(str, Enum):
    TRAINED = "trained"
    SKIPPED_INSUFFICIENT_SAMPLES = "skipped_insufficient_samples"


@dataclass(slots=True)
class TrainingSample:
    feature_vector: list[float]
    created_at: datetime


@dataclass(slots=True)
class TrainingReport:
    outcome: TrainingOutcome
    version: str | None = None
    sample_count: int = 0
    window_start: datetime | None = None
    window_end: datetime | None = None
    artifact_path: Path | None = None


class MlTrainerRepository(Protocol):
    def load_training_samples(self, window_days: int) -> list[TrainingSample]: ...

    def register_training_run(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
        sample_count: int,
        hyperparameters: dict[str, Any],
    ) -> str:
        """Computes the next version (MAX over existing registry rows + 1) and
        inserts the registry row in a single transaction, so two concurrent
        training runs can never both succeed in claiming the same version --
        the primary key stays unique, but the second run raises an uncaught
        IntegrityError rather than failing gracefully. Not a real-world risk
        (this is a scheduled job, profiles: ["jobs"], not meant to run
        concurrently with itself) but the guarantee is data integrity, not a
        clean failure mode. Returns the new version."""
        ...


def next_version_from_existing(existing_versions: list[str]) -> str:
    max_n = 0
    for value in existing_versions:
        match = _VERSION_PATTERN.match(value)
        if match:
            max_n = max(max_n, int(match.group(1)))
    return f"v{max_n + 1}"


def validate_feature_vectors(samples: list[TrainingSample]) -> None:
    for sample in samples:
        if len(sample.feature_vector) != FEATURE_VECTOR_DIMENSIONS:
            raise ValueError(
                f"malformed training sample: feature_vector has {len(sample.feature_vector)} dims, "
                f"expected {FEATURE_VECTOR_DIMENSIONS} (created_at={sample.created_at})"
            )


def train_model(feature_vectors: list[list[float]], *, n_estimators: int, random_state: int) -> IsolationForest:
    data = np.asarray(feature_vectors, dtype=float)
    model = IsolationForest(n_estimators=n_estimators, contamination="auto", random_state=random_state)
    model.fit(data)
    return model


def write_artifact(model: IsolationForest, models_dir: Path, version: str) -> Path:
    models_dir.mkdir(parents=True, exist_ok=True)
    path = models_dir / MODEL_FILENAME_TEMPLATE.format(version=version)
    joblib.dump(model, path)
    return path


def run_training_job(repository: MlTrainerRepository, redis_client, settings) -> TrainingReport:
    samples = repository.load_training_samples(settings.training_window_days)

    if len(samples) < settings.min_training_samples:
        logger.info(
            "Not enough training samples (%d/%d), skipping training",
            len(samples),
            settings.min_training_samples,
        )
        return TrainingReport(outcome=TrainingOutcome.SKIPPED_INSUFFICIENT_SAMPLES, sample_count=len(samples))

    validate_feature_vectors(samples)

    # Window bounds record the actual extent of the loaded data (min/max created_at
    # of the retrieved rows), not the requested "now() - N days" boundary -- more
    # informative provenance than the request parameters, which are already implied
    # by training_window_days in hyperparameters.
    window_start = min(sample.created_at for sample in samples)
    window_end = max(sample.created_at for sample in samples)
    hyperparameters = {
        "n_estimators": settings.n_estimators,
        "contamination": "auto",
        "random_state": settings.random_state,
        "training_window_days": settings.training_window_days,
    }

    model = train_model(
        [sample.feature_vector for sample in samples],
        n_estimators=settings.n_estimators,
        random_state=settings.random_state,
    )

    version = repository.register_training_run(
        window_start=window_start,
        window_end=window_end,
        sample_count=len(samples),
        hyperparameters=hyperparameters,
    )

    # Artifact must exist on disk before the Redis candidate pointer is set --
    # otherwise a consumer could observe a version with no backing file yet.
    artifact_path = write_artifact(model, Path(settings.models_dir), version)
    redis_client.set(CANDIDATE_VERSION_KEY, version)

    logger.info(
        "Trained model %s on %d samples (window %s -> %s), artifact at %s",
        version,
        len(samples),
        window_start,
        window_end,
        artifact_path,
    )

    return TrainingReport(
        outcome=TrainingOutcome.TRAINED,
        version=version,
        sample_count=len(samples),
        window_start=window_start,
        window_end=window_end,
        artifact_path=artifact_path,
    )
