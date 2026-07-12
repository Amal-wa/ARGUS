from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from app.settings import TrainerSettings
from app.trainer import (
    CANDIDATE_VERSION_KEY,
    TrainingOutcome,
    TrainingSample,
    next_version_from_existing,
    run_training_job,
    train_model,
    validate_feature_vectors,
)


@dataclass(slots=True)
class RegisteredRun:
    version: str
    window_start: datetime
    window_end: datetime
    sample_count: int
    hyperparameters: dict[str, Any]


@dataclass(slots=True)
class FakeMlTrainerRepository:
    samples: list[TrainingSample] = field(default_factory=list)
    existing_versions: list[str] = field(default_factory=list)
    registered_runs: list[RegisteredRun] = field(default_factory=list)

    def load_training_samples(self, window_days: int) -> list[TrainingSample]:
        return self.samples

    def register_training_run(self, *, window_start, window_end, sample_count, hyperparameters) -> str:
        version = next_version_from_existing(self.existing_versions)
        self.existing_versions.append(version)
        self.registered_runs.append(
            RegisteredRun(
                version=version,
                window_start=window_start,
                window_end=window_end,
                sample_count=sample_count,
                hyperparameters=hyperparameters,
            )
        )
        return version


@dataclass(slots=True)
class FakeRedis:
    values: dict[str, str] = field(default_factory=dict)

    def set(self, key: str, value: str) -> bool:
        self.values[key] = value
        return True

    def get(self, key: str) -> str | None:
        return self.values.get(key)


def _settings(tmp_path: Path, **overrides) -> TrainerSettings:
    defaults = dict(
        models_dir=str(tmp_path),
        min_training_samples=5,
        n_estimators=10,
        random_state=42,
        training_window_days=30,
    )
    defaults.update(overrides)
    return TrainerSettings(**defaults)


def _synthetic_samples(count: int, *, dims: int = 20) -> list[TrainingSample]:
    rng = np.random.RandomState(0)
    now = datetime.now(timezone.utc)
    return [
        TrainingSample(
            feature_vector=rng.normal(size=dims).tolist(),
            created_at=now - timedelta(days=i % 30, hours=i % 24),
        )
        for i in range(count)
    ]


def test_skip_when_insufficient_samples(tmp_path):
    repository = FakeMlTrainerRepository(samples=_synthetic_samples(3))
    redis = FakeRedis()
    settings = _settings(tmp_path, min_training_samples=5)

    report = run_training_job(repository, redis, settings)

    assert report.outcome == TrainingOutcome.SKIPPED_INSUFFICIENT_SAMPLES
    assert report.sample_count == 3
    assert list(tmp_path.iterdir()) == []
    assert repository.registered_runs == []
    assert redis.values == {}


def test_trains_when_at_or_above_threshold(tmp_path):
    samples = _synthetic_samples(10)
    repository = FakeMlTrainerRepository(samples=samples)
    redis = FakeRedis()
    settings = _settings(tmp_path, min_training_samples=5)

    report = run_training_job(repository, redis, settings)

    assert report.outcome == TrainingOutcome.TRAINED
    assert report.version == "v1"
    assert report.sample_count == 10
    assert report.artifact_path == tmp_path / "model_v1.joblib"
    assert report.artifact_path.exists()

    assert len(repository.registered_runs) == 1
    run = repository.registered_runs[0]
    assert run.sample_count == 10
    assert run.window_start == min(s.created_at for s in samples)
    assert run.window_end == max(s.created_at for s in samples)

    assert redis.get(CANDIDATE_VERSION_KEY) == "v1"
    # Core safety property: training must NEVER touch the active pointer.
    assert redis.get("model:active_version") is None
    assert "model:active_version" not in redis.values


def test_version_increments_from_empty_registry():
    assert next_version_from_existing([]) == "v1"


def test_version_increments_from_existing_registry():
    assert next_version_from_existing(["v1", "v2"]) == "v3"


def test_malformed_feature_vector_raises_and_writes_nothing(tmp_path):
    samples = _synthetic_samples(10)
    samples[3] = TrainingSample(feature_vector=[0.0] * 5, created_at=datetime.now(timezone.utc))
    repository = FakeMlTrainerRepository(samples=samples)
    redis = FakeRedis()
    settings = _settings(tmp_path, min_training_samples=5)

    with pytest.raises(ValueError):
        run_training_job(repository, redis, settings)

    assert list(tmp_path.iterdir()) == []
    assert repository.registered_runs == []
    assert redis.values == {}


def test_validate_feature_vectors_accepts_correct_shape():
    validate_feature_vectors(_synthetic_samples(5))


def test_trained_model_is_reproducible_with_fixed_random_state():
    samples = _synthetic_samples(50)
    vectors = [s.feature_vector for s in samples]

    model_a = train_model(vectors, n_estimators=10, random_state=42)
    model_b = train_model(vectors, n_estimators=10, random_state=42)

    probe = np.asarray([vectors[0], vectors[1]], dtype=float)
    scores_a = model_a.score_samples(probe)
    scores_b = model_b.score_samples(probe)

    assert list(scores_a) == list(scores_b)
