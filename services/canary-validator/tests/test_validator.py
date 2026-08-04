from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

import joblib
import pytest
from sklearn.ensemble import IsolationForest

import json

from app.score_mapping import is_valid_breakpoints, percentile_calibrate
from app.settings import ValidatorSettings
from app.validator import (
    ACTIVE_SCORE_BREAKPOINTS_KEY,
    ACTIVE_VERSION_KEY,
    CANDIDATE_VERSION_KEY,
    CalibrationSample,
    ComparisonRow,
    ComparisonSample,
    ScoreDistribution,
    ValidationMode,
    compute_score_distribution,
    run_validation_job,
    score_feature_vector,
)


@dataclass(slots=True)
class RawSample:
    trace_id: UUID
    feature_vector: list[float]
    risk_score: float | None
    model_version: str | None


@dataclass(slots=True)
class FakeCanaryValidatorRepository:
    all_samples: list[RawSample] = field(default_factory=list)
    already_compared: set[tuple[UUID, str]] = field(default_factory=set)
    score_distributions: dict[str, ScoreDistribution] = field(default_factory=dict)
    inserted_rows: list[ComparisonRow] = field(default_factory=list)

    def load_calibration_samples(self, window_days: int, batch_size: int) -> list[CalibrationSample]:
        return [CalibrationSample(trace_id=s.trace_id, feature_vector=s.feature_vector) for s in self.all_samples][
            :batch_size
        ]

    def load_unscored_comparison_samples(
        self, candidate_version: str, window_days: int, batch_size: int
    ) -> list[ComparisonSample]:
        eligible = [
            s
            for s in self.all_samples
            if s.risk_score is not None and (s.trace_id, candidate_version) not in self.already_compared
        ]
        return [
            ComparisonSample(
                trace_id=s.trace_id,
                feature_vector=s.feature_vector,
                production_risk_score=s.risk_score,
                production_model_version=s.model_version,
            )
            for s in eligible[:batch_size]
        ]

    def write_score_distribution(self, candidate_version: str, distribution: ScoreDistribution) -> None:
        self.score_distributions[candidate_version] = distribution

    def insert_comparison_rows(self, rows: list[ComparisonRow]) -> int:
        for row in rows:
            self.already_compared.add((row.trace_id, row.candidate_model_version))
            self.inserted_rows.append(row)
        return len(rows)


@dataclass(slots=True)
class FakeRedis:
    values: dict[str, str] = field(default_factory=dict)

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> bool:
        self.values[key] = value
        return True


def _settings(tmp_path: Path, **overrides) -> ValidatorSettings:
    defaults = dict(models_dir=str(tmp_path), window_days=30, batch_size=5000)
    defaults.update(overrides)
    return ValidatorSettings(**defaults)


def _dump_model(tmp_path: Path, version: str) -> None:
    rng_data = random.Random(0)
    data = [[rng_data.gauss(0, 1) for _ in range(16)] for _ in range(100)]
    model = IsolationForest(n_estimators=10, random_state=42)
    model.fit(data)
    joblib.dump(model, tmp_path / f"model_{version}.joblib")


def _raw_samples(count: int, *, with_production_score: bool, model_version: str | None = "v1") -> list[RawSample]:
    rng = random.Random(2)
    samples = []
    for _ in range(count):
        samples.append(
            RawSample(
                trace_id=uuid.uuid4(),
                feature_vector=[rng.gauss(0, 1) for _ in range(16)],
                risk_score=rng.uniform(0, 1) if with_production_score else None,
                model_version=model_version if with_production_score else None,
            )
        )
    return samples


def test_no_candidate_set_is_a_noop(tmp_path):
    repository = FakeCanaryValidatorRepository()
    redis = FakeRedis()
    settings = _settings(tmp_path)

    report = run_validation_job(repository, redis, settings)

    assert report.mode == ValidationMode.NO_CANDIDATE
    assert repository.inserted_rows == []
    assert repository.score_distributions == {}


def test_mode_a_calibration_writes_distribution_and_no_comparison_rows(tmp_path):
    _dump_model(tmp_path, "v1")
    repository = FakeCanaryValidatorRepository(all_samples=_raw_samples(50, with_production_score=False))
    redis = FakeRedis(values={CANDIDATE_VERSION_KEY: "v1"})
    settings = _settings(tmp_path)

    report = run_validation_job(repository, redis, settings)

    assert report.mode == ValidationMode.CALIBRATION
    assert report.samples_scored == 50
    assert "v1" in repository.score_distributions
    distribution = repository.score_distributions["v1"]
    assert distribution.samples_scored == 50
    assert 0.0 <= distribution.min <= distribution.p50 <= distribution.p95 <= distribution.p98 <= distribution.max <= 1.0
    assert repository.inserted_rows == []
    # Core safety property: the job never touches either Redis pointer.
    assert ACTIVE_VERSION_KEY not in redis.values


def test_mode_b_comparison_inserts_one_row_per_eligible_sample(tmp_path):
    _dump_model(tmp_path, "v2")
    samples = _raw_samples(20, with_production_score=True, model_version="v1")
    repository = FakeCanaryValidatorRepository(all_samples=samples)
    redis = FakeRedis(values={CANDIDATE_VERSION_KEY: "v2", ACTIVE_VERSION_KEY: "v1"})
    settings = _settings(tmp_path)

    report = run_validation_job(repository, redis, settings)

    assert report.mode == ValidationMode.COMPARISON
    assert report.comparison_rows_inserted == 20
    assert len(repository.inserted_rows) == 20

    row = repository.inserted_rows[0]
    matching_sample = next(s for s in samples if s.trace_id == row.trace_id)
    assert row.production_risk_score == matching_sample.risk_score
    assert row.production_model_version == "v1"
    assert row.candidate_model_version == "v2"

    assert "v2" in repository.score_distributions
    # Core safety property: candidate/active pointers are read-only inputs, never rewritten.
    assert redis.values[ACTIVE_VERSION_KEY] == "v1"
    assert redis.values[CANDIDATE_VERSION_KEY] == "v2"


def test_mode_b_excludes_bootstrap_samples_with_no_production_score(tmp_path):
    _dump_model(tmp_path, "v2")
    bootstrap_samples = _raw_samples(10, with_production_score=False)
    scored_samples = _raw_samples(5, with_production_score=True, model_version="v1")
    repository = FakeCanaryValidatorRepository(all_samples=bootstrap_samples + scored_samples)
    redis = FakeRedis(values={CANDIDATE_VERSION_KEY: "v2", ACTIVE_VERSION_KEY: "v1"})
    settings = _settings(tmp_path)

    report = run_validation_job(repository, redis, settings)

    assert report.comparison_rows_inserted == 5


def test_mode_b_is_idempotent_on_second_run(tmp_path):
    _dump_model(tmp_path, "v2")
    samples = _raw_samples(15, with_production_score=True, model_version="v1")
    repository = FakeCanaryValidatorRepository(all_samples=samples)
    redis = FakeRedis(values={CANDIDATE_VERSION_KEY: "v2", ACTIVE_VERSION_KEY: "v1"})
    settings = _settings(tmp_path)

    first_report = run_validation_job(repository, redis, settings)
    second_report = run_validation_job(repository, redis, settings)

    assert first_report.comparison_rows_inserted == 15
    assert second_report.comparison_rows_inserted == 0
    assert len(repository.inserted_rows) == 15


def test_percentile_calibrate_maps_raw_score_into_breakpoints_space():
    # A narrow reference band, matching the real-world pattern documented in
    # this project (raw sigmoid scores empirically cluster ~0.55-0.66):
    # a raw score at the low end of the band maps near 0.0, at the high end
    # near 1.0, regardless of where it sits in the full [0, 1] sigmoid range.
    breakpoints = [0.55, 0.60, 0.66]

    assert percentile_calibrate(0.55, breakpoints) == pytest.approx(0.0)
    assert percentile_calibrate(0.66, breakpoints) == pytest.approx(1.0)
    assert percentile_calibrate(0.60, breakpoints) == pytest.approx(0.5)
    # Outside the reference range clamps rather than extrapolating.
    assert percentile_calibrate(0.0, breakpoints) == pytest.approx(0.0)
    assert percentile_calibrate(1.0, breakpoints) == pytest.approx(1.0)


def test_is_valid_breakpoints_rejects_non_monotonic_or_too_short():
    assert is_valid_breakpoints([0.1, 0.5, 0.9]) is True
    assert is_valid_breakpoints([0.1]) is False
    assert is_valid_breakpoints([0.9, 0.1, 0.5]) is False
    assert is_valid_breakpoints(None) is False


def test_mode_b_calibrates_candidate_score_against_production_breakpoints_when_available(tmp_path):
    # Regression test for the cross-service scale mismatch found in the
    # system-level audit: production_risk_score (ml_training_samples.risk_score)
    # is already percentile-calibrated by isolation-forest before it's ever
    # written -- candidate_risk_score must go through the same mapping, or
    # the two columns in the same canary_validation_log row are on different
    # scales despite both looking like plain [0, 1] floats.
    _dump_model(tmp_path, "v2")
    samples = _raw_samples(5, with_production_score=True, model_version="v1")
    repository = FakeCanaryValidatorRepository(all_samples=samples)
    breakpoints = [0.55, 0.60, 0.66]
    redis = FakeRedis(
        values={
            CANDIDATE_VERSION_KEY: "v2",
            ACTIVE_VERSION_KEY: "v1",
            ACTIVE_SCORE_BREAKPOINTS_KEY: json.dumps(breakpoints),
        }
    )
    settings = _settings(tmp_path)

    run_validation_job(repository, redis, settings)

    candidate_model = joblib.load(tmp_path / "model_v2.joblib")
    for row in repository.inserted_rows:
        matching_sample = next(s for s in samples if s.trace_id == row.trace_id)
        raw_score = score_feature_vector(candidate_model, matching_sample.feature_vector)
        expected = percentile_calibrate(raw_score, breakpoints)
        assert row.candidate_risk_score == pytest.approx(expected)
        # The fix only matters if calibration actually moves the value --
        # assert it's NOT just silently equal to the uncalibrated raw score
        # (which would happen if the breakpoints were ignored).
        assert row.candidate_risk_score != pytest.approx(raw_score)

    # score_distribution must still be built from RAW scores (it becomes
    # this candidate's OWN future calibration reference if promoted), not
    # from the percentile-calibrated candidate_risk_score values above.
    distribution = repository.score_distributions["v2"]
    raw_scores = [
        score_feature_vector(candidate_model, next(s for s in samples if s.trace_id == row.trace_id).feature_vector)
        for row in repository.inserted_rows
    ]
    assert distribution.max == pytest.approx(max(raw_scores))
    assert distribution.min == pytest.approx(min(raw_scores))


def test_mode_b_falls_back_to_raw_score_when_no_breakpoints_published(tmp_path):
    # No ACTIVE_SCORE_BREAKPOINTS_KEY in Redis (e.g. a promotion done before
    # this key existed, or a desync) -- must degrade to today's behavior
    # (the uncalibrated raw score) rather than crash or drop the sample.
    _dump_model(tmp_path, "v2")
    samples = _raw_samples(5, with_production_score=True, model_version="v1")
    repository = FakeCanaryValidatorRepository(all_samples=samples)
    redis = FakeRedis(values={CANDIDATE_VERSION_KEY: "v2", ACTIVE_VERSION_KEY: "v1"})
    settings = _settings(tmp_path)

    run_validation_job(repository, redis, settings)

    candidate_model = joblib.load(tmp_path / "model_v2.joblib")
    for row in repository.inserted_rows:
        matching_sample = next(s for s in samples if s.trace_id == row.trace_id)
        raw_score = score_feature_vector(candidate_model, matching_sample.feature_vector)
        assert row.candidate_risk_score == pytest.approx(raw_score)


def test_compute_score_distribution_percentiles_on_known_input():
    scores = [float(i) for i in range(1, 101)]  # 1..100

    distribution = compute_score_distribution(scores)

    assert distribution.samples_scored == 100
    assert distribution.min == 1.0
    assert distribution.max == 100.0
    assert distribution.p50 == pytest.approx(50.5, abs=0.5)
    assert distribution.p95 == pytest.approx(95.05, abs=0.5)
    assert len(distribution.percentile_breakpoints) == 101
    assert distribution.percentile_breakpoints == sorted(distribution.percentile_breakpoints)
    assert distribution.percentile_breakpoints[0] == pytest.approx(distribution.min)
    assert distribution.percentile_breakpoints[50] == pytest.approx(distribution.p50)
    assert distribution.percentile_breakpoints[98] == pytest.approx(distribution.p98)
    assert distribution.percentile_breakpoints[100] == pytest.approx(distribution.max)
    assert distribution.p98 == pytest.approx(98.02, abs=0.5)
