from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

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

# Feature vector indices this module perturbs to build synthetic anomalies
# for evaluate_holdout_quality below -- duplicated from api-gateway's
# app/services/feature_vector.py, the single documented source of truth for
# this 16-dimension layout's order (same "must match" contract as
# FEATURE_VECTOR_DIMENSIONS above: a change to that layout means updating
# these indices too, not just retraining).
_RESOURCE_ACCESS_INDEX = 7  # distinct raw resources, 5 min window
_DENY_COUNT_INDEX = 12  # DENY count, 5 min window
_DISTINCT_IPS_INDEX = 13  # distinct IPs, 5 min window

# Values pushed past behavioral-detector's own empirically-calibrated
# thresholds for these same three dimensions (see CLAUDE.md's Behavioral
# detector section: resource_access >= 26, authorization/deny count >= 5,
# network/distinct IPs >= 2) -- generous margins past each threshold, not
# just past it, so a synthetic sample is unambiguously anomalous rather than
# borderline. Reusing these specific, already-validated thresholds (rather
# than inventing new ones) grounds the synthetic anomalies in the same real-
# traffic evidence the rest of the project already relies on.
_SYNTHETIC_PERTURBATIONS: tuple[tuple[int, float], ...] = (
    (_RESOURCE_ACCESS_INDEX, 40.0),
    (_DENY_COUNT_INDEX, 10.0),
    (_DISTINCT_IPS_INDEX, 4.0),
)


class TrainingOutcome(str, Enum):
    TRAINED = "trained"
    SKIPPED_INSUFFICIENT_SAMPLES = "skipped_insufficient_samples"


@dataclass(slots=True)
class TrainingSample:
    feature_vector: list[float]
    created_at: datetime


@dataclass(slots=True)
class QualityMetrics:
    holdout_normal_count: int
    synthetic_anomaly_count: int
    auc: float

    def to_dict(self) -> dict[str, int | float]:
        return {
            "holdout_normal_count": self.holdout_normal_count,
            "synthetic_anomaly_count": self.synthetic_anomaly_count,
            "auc": self.auc,
        }


@dataclass(slots=True)
class TrainingReport:
    outcome: TrainingOutcome
    version: str | None = None
    sample_count: int = 0
    window_start: datetime | None = None
    window_end: datetime | None = None
    artifact_path: Path | None = None
    quality: QualityMetrics | None = None


class MlTrainerRepository(Protocol):
    def resolve_excluded_user_ids(self, emails: list[str]) -> list[UUID]:
        """Resolves TrainerSettings.training_excluded_emails to user_ids ONCE
        per run (called by run_training_job before load_training_samples) --
        ml_training_samples itself carries neither user_id nor email (only
        trace_id), so this keeps the identity lookup (users.email) out of
        the training-data query entirely, rather than joining users on every
        load. Unknown emails simply resolve to nothing (not an error) -- a
        stale entry in TRAINING_EXCLUDED_EMAILS must not fail the whole job."""
        ...

    def load_training_samples(
        self, window_days: int, excluded_user_ids: list[UUID], max_resource_access: int | None = None
    ) -> list[TrainingSample]: ...

    def register_training_run(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
        sample_count: int,
        hyperparameters: dict[str, Any],
        quality_metrics: dict[str, Any] | None,
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


def train_model(
    feature_vectors: list[list[float]],
    *,
    n_estimators: int,
    random_state: int,
    max_samples: str | int | float = "auto",
    max_features: float = 1.0,
    bootstrap: bool = False,
) -> IsolationForest:
    data = np.asarray(feature_vectors, dtype=float)
    model = IsolationForest(
        n_estimators=n_estimators,
        # Left at sklearn's default rather than exposed as a real tuning
        # knob: this codebase only ever calls .score_samples() (this
        # service's evaluate_holdout_quality below, isolation-forest's
        # ModelStore.score(), canary-validator's score_feature_vector()) --
        # contamination has ZERO effect on that method's output. It only
        # shapes .predict()/.decision_function()'s binary threshold, which
        # nothing in this project calls. max_samples/max_features/bootstrap
        # below, by contrast, DO shape the trees score_samples() reads from
        # -- those are the parameters that actually matter here.
        contamination="auto",
        max_samples=max_samples,
        max_features=max_features,
        bootstrap=bootstrap,
        random_state=random_state,
    )
    model.fit(data)
    return model


def _synthesize_anomalous_vectors(normal_vectors: list[list[float]], rng: np.random.Generator) -> list[list[float]]:
    """Builds one synthetic anomalous vector per held-out normal vector, by
    perturbing a single dimension (chosen at random per sample, from
    _SYNTHETIC_PERTURBATIONS above) to a value past one of
    behavioral-detector's own attack thresholds. One dimension at a time,
    not all three at once: a real attack replay (CLAUDE.md's scenarios A/C/D)
    typically stands out on ONE signal, not every one simultaneously -- see
    CLAUDE.md's note that resource_access and network/authorization
    anomalies are "independently true" of the same traffic, not that every
    attack trips every rule together."""
    synthetic: list[list[float]] = []
    for vector in normal_vectors:
        index, value = _SYNTHETIC_PERTURBATIONS[rng.integers(0, len(_SYNTHETIC_PERTURBATIONS))]
        perturbed = list(vector)
        perturbed[index] = value
        synthetic.append(perturbed)
    return synthetic


def evaluate_holdout_quality(
    model: IsolationForest,
    holdout_normal_vectors: list[list[float]],
    *,
    random_state: int,
    min_holdout_samples: int,
) -> QualityMetrics | None:
    """Automatic, objective separation check for a freshly trained model --
    previously missing entirely: a model could be trained, calibrated by
    canary-validator, and promoted with nobody having verified it can tell
    normal traffic from anomalous traffic AT ALL, beyond an operator
    eyeballing canary_validation_log after the fact.

    Held-out normal samples (never seen during THIS eval model's training --
    see run_training_job, which fits a separate model on the train split
    before fitting the real, full-data model that actually ships) are paired
    with synthetic anomalies built from those same samples
    (_synthesize_anomalous_vectors), scored with score_samples() (unbounded,
    LOWER = more anomalous), and compared via ROC AUC -- negated so higher =
    more anomalous, matching roc_auc_score's positive-class convention. No
    sigmoid/percentile step needed first: AUC depends only on score RANKING,
    which any strictly monotonic transform (like the sigmoid in
    isolation-forest/canary-validator) leaves unchanged.

    Returns None below min_holdout_samples -- an AUC computed from a
    handful of samples is noise, not signal, and publishing it into
    ml_model_registry would look like a real measurement when it isn't one.
    """
    if len(holdout_normal_vectors) < min_holdout_samples:
        return None

    rng = np.random.default_rng(random_state)
    synthetic_vectors = _synthesize_anomalous_vectors(holdout_normal_vectors, rng)

    normal_array = np.asarray(holdout_normal_vectors, dtype=float)
    synthetic_array = np.asarray(synthetic_vectors, dtype=float)

    normal_scores = -model.score_samples(normal_array)
    synthetic_scores = -model.score_samples(synthetic_array)

    y_true = np.concatenate([np.zeros(len(normal_scores)), np.ones(len(synthetic_scores))])
    y_score = np.concatenate([normal_scores, synthetic_scores])

    return QualityMetrics(
        holdout_normal_count=len(holdout_normal_vectors),
        synthetic_anomaly_count=len(synthetic_vectors),
        auc=float(roc_auc_score(y_true, y_score)),
    )


def write_artifact(model: IsolationForest, models_dir: Path, version: str) -> Path:
    models_dir.mkdir(parents=True, exist_ok=True)
    path = models_dir / MODEL_FILENAME_TEMPLATE.format(version=version)
    joblib.dump(model, path)
    return path


def run_training_job(repository: MlTrainerRepository, redis_client, settings) -> TrainingReport:
    # Resolved once, before loading any training data -- see
    # MlTrainerRepository.resolve_excluded_user_ids's docstring for why this
    # is a separate step rather than a join inside load_training_samples.
    excluded_user_ids = repository.resolve_excluded_user_ids(settings.training_excluded_emails)
    samples = repository.load_training_samples(
        settings.training_window_days, excluded_user_ids, settings.training_max_resource_access
    )

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
        "max_samples": settings.max_samples,
        "max_features": settings.max_features,
        "bootstrap": settings.bootstrap,
        "random_state": settings.random_state,
        "training_window_days": settings.training_window_days,
        "holdout_fraction": settings.holdout_fraction,
        "training_excluded_emails": settings.training_excluded_emails,
        "training_max_resource_access": settings.training_max_resource_access,
    }

    all_vectors = [sample.feature_vector for sample in samples]

    # Evaluate on a held-out split BEFORE fitting the model that actually
    # ships -- see evaluate_holdout_quality. train_test_split's own
    # random_state keeps the split (and therefore training_quality)
    # reproducible for a given settings.random_state, the same determinism
    # guarantee train_model already provides for the model itself.
    train_vectors, holdout_vectors = train_test_split(
        all_vectors, test_size=settings.holdout_fraction, random_state=settings.random_state
    )
    eval_model = train_model(
        train_vectors,
        n_estimators=settings.n_estimators,
        random_state=settings.random_state,
        max_samples=settings.max_samples,
        max_features=settings.max_features,
        bootstrap=settings.bootstrap,
    )
    quality = evaluate_holdout_quality(
        eval_model,
        holdout_vectors,
        random_state=settings.random_state,
        min_holdout_samples=settings.min_holdout_samples_for_quality,
    )

    # The SHIPPED model is fit on every sample, not just the train split
    # above -- the held-out slice was only needed to estimate quality; there
    # is no reason to withhold real data from the model that actually goes
    # to production.
    model = train_model(
        all_vectors,
        n_estimators=settings.n_estimators,
        random_state=settings.random_state,
        max_samples=settings.max_samples,
        max_features=settings.max_features,
        bootstrap=settings.bootstrap,
    )

    version = repository.register_training_run(
        window_start=window_start,
        window_end=window_end,
        sample_count=len(samples),
        hyperparameters=hyperparameters,
        quality_metrics=quality.to_dict() if quality is not None else None,
    )

    # Artifact must exist on disk before the Redis candidate pointer is set --
    # otherwise a consumer could observe a version with no backing file yet.
    artifact_path = write_artifact(model, Path(settings.models_dir), version)
    redis_client.set(CANDIDATE_VERSION_KEY, version)

    logger.info(
        "Trained model %s on %d samples (window %s -> %s), artifact at %s, quality=%s",
        version,
        len(samples),
        window_start,
        window_end,
        artifact_path,
        quality.to_dict() if quality is not None else None,
    )

    return TrainingReport(
        outcome=TrainingOutcome.TRAINED,
        version=version,
        sample_count=len(samples),
        window_start=window_start,
        window_end=window_end,
        artifact_path=artifact_path,
        quality=quality,
    )
