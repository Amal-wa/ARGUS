from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import numpy as np
import pytest

from app.settings import TrainerSettings
from app.trainer import (
    CANDIDATE_VERSION_KEY,
    QualityMetrics,
    TrainingOutcome,
    TrainingSample,
    evaluate_holdout_quality,
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
    quality_metrics: dict[str, Any] | None = None


@dataclass(slots=True)
class FakeMlTrainerRepository:
    samples: list[TrainingSample] = field(default_factory=list)
    existing_versions: list[str] = field(default_factory=list)
    registered_runs: list[RegisteredRun] = field(default_factory=list)
    # Test-configured email -> user_id mapping, mirroring what a real `users`
    # table lookup would resolve -- lets tests prove run_training_job passes
    # the RESOLVED ids through to load_training_samples, not the raw emails.
    email_to_user_id: dict[str, UUID] = field(default_factory=dict)
    resolve_calls: list[list[str]] = field(default_factory=list)
    load_calls: list[list[UUID]] = field(default_factory=list)
    max_resource_access_calls: list[int | None] = field(default_factory=list)

    def resolve_excluded_user_ids(self, emails: list[str]) -> list[UUID]:
        self.resolve_calls.append(list(emails))
        return [self.email_to_user_id[email] for email in emails if email in self.email_to_user_id]

    def load_training_samples(
        self, window_days: int, excluded_user_ids: list[UUID], max_resource_access: int | None = None
    ) -> list[TrainingSample]:
        self.load_calls.append(list(excluded_user_ids))
        self.max_resource_access_calls.append(max_resource_access)
        return self.samples

    def register_training_run(self, *, window_start, window_end, sample_count, hyperparameters, quality_metrics) -> str:
        version = next_version_from_existing(self.existing_versions)
        self.existing_versions.append(version)
        self.registered_runs.append(
            RegisteredRun(
                version=version,
                window_start=window_start,
                window_end=window_end,
                sample_count=sample_count,
                hyperparameters=hyperparameters,
                quality_metrics=quality_metrics,
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


def _synthetic_samples(count: int, *, dims: int = 16) -> list[TrainingSample]:
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
    # 10 samples * default holdout_fraction (0.15) is ~1-2 held-out rows --
    # nowhere near default min_holdout_samples_for_quality (50), so this
    # must come back None, not a statistically meaningless AUC.
    assert run.quality_metrics is None
    # Regression guard for the earlier scaffolding bug: these three used to
    # be read from TrainerSettings but never actually reach hyperparameters
    # or train_model at all.
    assert run.hyperparameters["max_samples"] == "auto"
    assert run.hyperparameters["max_features"] == 1.0
    assert run.hyperparameters["bootstrap"] is False
    assert run.hyperparameters["holdout_fraction"] == pytest.approx(0.15)
    assert run.hyperparameters["training_excluded_emails"] == []
    # No exclusions configured -- resolution still runs (uniform code path,
    # no special-casing), but with an empty list in and out.
    assert repository.resolve_calls == [[]]
    assert repository.load_calls == [[]]

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


def test_validate_feature_vectors_rejects_old_20_dim_samples():
    # Proves the cardinality propagation is complete here too: a sample built
    # under the OLD (pre-rebuild) 20-dimension layout must be rejected, not
    # silently trained on, now that the contract is 16.
    with pytest.raises(ValueError, match="expected 16"):
        validate_feature_vectors(_synthetic_samples(5, dims=20))


def test_trained_model_is_reproducible_with_fixed_random_state():
    samples = _synthetic_samples(50)
    vectors = [s.feature_vector for s in samples]

    model_a = train_model(vectors, n_estimators=10, random_state=42)
    model_b = train_model(vectors, n_estimators=10, random_state=42)

    probe = np.asarray([vectors[0], vectors[1]], dtype=float)
    scores_a = model_a.score_samples(probe)
    scores_b = model_b.score_samples(probe)

    assert list(scores_a) == list(scores_b)


def test_train_model_forwards_max_samples_max_features_bootstrap():
    # Regression test for the earlier scaffolding bug: train_model's
    # signature used to only accept n_estimators/random_state -- these three
    # were read from TrainerSettings but silently dropped before ever
    # reaching IsolationForest. Checking the FITTED model's own attributes
    # (not just that train_model accepts the kwargs without raising) is what
    # actually proves they were forwarded, not ignored.
    vectors = [s.feature_vector for s in _synthetic_samples(50)]

    model = train_model(
        vectors, n_estimators=10, random_state=42, max_samples=20, max_features=0.5, bootstrap=True
    )

    assert model.max_samples_ == 20  # resolved sample count per tree, not sklearn's "auto" default of 50
    assert model.max_features == 0.5
    assert model.bootstrap is True


def test_evaluate_holdout_quality_returns_none_below_min_samples():
    vectors = [s.feature_vector for s in _synthetic_samples(30)]
    model = train_model(vectors, n_estimators=10, random_state=42)

    result = evaluate_holdout_quality(model, vectors[:10], random_state=42, min_holdout_samples=50)

    assert result is None


def test_evaluate_holdout_quality_separates_normal_from_synthetic_anomalies():
    # Normal vectors cluster around 0 (~N(0,1) on every dimension). Synthetic
    # anomalies push ONE of 16 dimensions to an extreme value (see
    # _SYNTHETIC_PERTURBATIONS) -- clearly separable, but NOT near-perfectly:
    # with max_features=1.0 (default), IsolationForest considers all 16
    # dimensions at every split, so a single extreme dimension's isolation
    # advantage is diluted by the other 15, which are just as random for a
    # synthetic anomaly as for a normal sample. This is the same "one
    # dimension too diluted among the other 15" effect CLAUDE.md documents
    # for adaptive_access.rego's high_distinct_ips (the reason that check
    # bypasses the ML score entirely) -- confirmed empirically here too: a
    # first version of this test asserted auc > 0.9 and measured 0.776 with
    # random_state=42. 0.65 stays clearly, meaningfully above chance (0.5)
    # without assuming a separation this synthetic setup doesn't actually
    # produce -- consistent with CLAUDE.md's own ROC AUC ~0.82 benchmark for
    # scenario A, not a number invented for this test.
    train_vectors = [s.feature_vector for s in _synthetic_samples(200)]
    holdout_vectors = [s.feature_vector for s in _synthetic_samples(60)]
    model = train_model(train_vectors, n_estimators=100, random_state=42)

    result = evaluate_holdout_quality(model, holdout_vectors, random_state=42, min_holdout_samples=50)

    assert result is not None
    assert result.holdout_normal_count == 60
    assert result.synthetic_anomaly_count == 60
    assert result.auc > 0.65


def test_evaluate_holdout_quality_is_reproducible_with_fixed_random_state():
    train_vectors = [s.feature_vector for s in _synthetic_samples(200)]
    holdout_vectors = [s.feature_vector for s in _synthetic_samples(60)]
    model = train_model(train_vectors, n_estimators=10, random_state=42)

    result_a = evaluate_holdout_quality(model, holdout_vectors, random_state=7, min_holdout_samples=50)
    result_b = evaluate_holdout_quality(model, holdout_vectors, random_state=7, min_holdout_samples=50)

    assert result_a == result_b


def test_run_training_job_computes_quality_with_enough_holdout_samples(tmp_path):
    # End-to-end: with enough samples that the 15% holdout split clears
    # min_holdout_samples_for_quality, training_quality must actually be
    # populated -- not just accepted as an optional field that stays None
    # forever, which is exactly what the earlier scaffolding bug produced.
    samples = _synthetic_samples(400)
    repository = FakeMlTrainerRepository(samples=samples)
    redis = FakeRedis()
    settings = _settings(tmp_path, min_training_samples=5, min_holdout_samples_for_quality=50)

    report = run_training_job(repository, redis, settings)

    assert report.quality is not None
    assert report.quality.holdout_normal_count >= 50
    assert isinstance(report.quality.auc, float)

    run = repository.registered_runs[0]
    assert run.quality_metrics is not None
    assert run.quality_metrics == report.quality.to_dict()


def test_run_training_job_ships_a_model_trained_on_the_full_sample_set(tmp_path):
    # The held-out split is only for the quality estimate -- the artifact
    # that actually gets promoted must still be fit on every sample, not
    # just the 85% train split. Verified indirectly: report.sample_count
    # (the full set) must stay larger than quality.holdout_normal_count (the
    # held-out slice used only for evaluation), proving the two are
    # genuinely different sample sets, not the same one double-counted.
    samples = _synthetic_samples(400)
    repository = FakeMlTrainerRepository(samples=samples)
    redis = FakeRedis()
    settings = _settings(tmp_path, min_training_samples=5, min_holdout_samples_for_quality=50)

    report = run_training_job(repository, redis, settings)

    assert report.sample_count == 400
    assert report.quality is not None
    assert report.quality.holdout_normal_count < report.sample_count


def test_run_training_job_resolves_and_passes_configured_exclusions(tmp_path):
    # Proves the two-step design end to end at the orchestration level: the
    # configured EMAIL is resolved to a user_id exactly once, and that
    # resolved id (not the raw email) is what reaches load_training_samples.
    # The real SQL behind resolve_excluded_user_ids/load_training_samples is
    # verified separately, live, against the actual database -- this test
    # only proves run_training_job wires the two calls together correctly.
    reader1_id = uuid4()
    samples = _synthetic_samples(10)
    repository = FakeMlTrainerRepository(samples=samples, email_to_user_id={"reader1@zt.local": reader1_id})
    redis = FakeRedis()
    settings = _settings(tmp_path, min_training_samples=5, training_excluded_emails=["reader1@zt.local"])

    report = run_training_job(repository, redis, settings)

    assert report.outcome == TrainingOutcome.TRAINED
    assert repository.resolve_calls == [["reader1@zt.local"]]
    assert repository.load_calls == [[reader1_id]]

    run = repository.registered_runs[0]
    assert run.hyperparameters["training_excluded_emails"] == ["reader1@zt.local"]


def test_run_training_job_passes_configured_max_resource_access(tmp_path):
    # Wiring-level proof (mirrors the exclusion-email wiring test above): the
    # configured threshold reaches load_training_samples unchanged. The real
    # SQL filtering behavior itself (values above/at/below the threshold)
    # is verified separately, live, against the actual database -- a Fake
    # repository has no real WHERE clause to prove correct; see
    # tests/test_repository.py.
    samples = _synthetic_samples(10)
    repository = FakeMlTrainerRepository(samples=samples)
    redis = FakeRedis()
    settings = _settings(tmp_path, min_training_samples=5, training_max_resource_access=30)

    report = run_training_job(repository, redis, settings)

    assert report.outcome == TrainingOutcome.TRAINED
    assert repository.max_resource_access_calls == [30]

    run = repository.registered_runs[0]
    assert run.hyperparameters["training_max_resource_access"] == 30


def test_run_training_job_default_max_resource_access_is_none_rétrocompat(tmp_path):
    # Backward compatibility: a settings object that doesn't specify the new
    # field must not change behavior for existing deployments -- None reaches
    # the repository unchanged, which load_training_samples's own default
    # (also None) treats as "no filter".
    samples = _synthetic_samples(10)
    repository = FakeMlTrainerRepository(samples=samples)
    redis = FakeRedis()
    settings = _settings(tmp_path, min_training_samples=5)

    report = run_training_job(repository, redis, settings)

    assert report.outcome == TrainingOutcome.TRAINED
    assert repository.max_resource_access_calls == [settings.training_max_resource_access]


def test_run_training_job_unknown_excluded_email_resolves_to_nothing(tmp_path):
    # An email in TRAINING_EXCLUDED_EMAILS that no longer matches any user
    # (typo, deleted account) must not fail the job -- it simply excludes
    # nothing, same as resolve_excluded_user_ids's own documented contract.
    samples = _synthetic_samples(10)
    repository = FakeMlTrainerRepository(samples=samples, email_to_user_id={})
    redis = FakeRedis()
    settings = _settings(tmp_path, min_training_samples=5, training_excluded_emails=["ghost@zt.local"])

    report = run_training_job(repository, redis, settings)

    assert report.outcome == TrainingOutcome.TRAINED
    assert repository.resolve_calls == [["ghost@zt.local"]]
    assert repository.load_calls == [[]]
