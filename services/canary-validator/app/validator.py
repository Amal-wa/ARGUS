from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol
from uuid import UUID

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.score_mapping import is_valid_breakpoints, percentile_calibrate, risk_score_from_anomaly_score

logger = logging.getLogger(__name__)

CANDIDATE_VERSION_KEY = "model:candidate_version"
ACTIVE_VERSION_KEY = "model:active_version"
# Published by scripts/promote_model.py alongside ACTIVE_VERSION_KEY -- the
# active model's own calibration reference (see model_store.percentile_calibrate).
# Read here (Mode B only) to put a candidate's score in the same space
# production_risk_score is already in -- see percentile_calibrate's comment
# in score_mapping.py.
ACTIVE_SCORE_BREAKPOINTS_KEY = "model:active_score_breakpoints"

# Must match ml-trainer's MODEL_FILENAME_TEMPLATE / isolation-forest's model_path
# convention: one file per version, named "model_{version}.joblib", under models_dir.
MODEL_FILENAME_TEMPLATE = "model_{version}.joblib"


class ValidationMode(str, Enum):
    NO_CANDIDATE = "no_candidate"
    CALIBRATION = "calibration"  # Mode A: no active model yet, no baseline to compare against.
    COMPARISON = "comparison"  # Mode B: candidate scored against the live production model's samples.


@dataclass(slots=True)
class CalibrationSample:
    trace_id: UUID
    feature_vector: list[float]


@dataclass(slots=True)
class ComparisonSample:
    trace_id: UUID
    feature_vector: list[float]
    production_risk_score: float
    production_model_version: str


@dataclass(slots=True)
class ComparisonRow:
    trace_id: UUID
    production_model_version: str
    candidate_model_version: str
    production_risk_score: float
    candidate_risk_score: float


@dataclass(slots=True)
class ScoreDistribution:
    samples_scored: int
    min: float
    p50: float
    p95: float
    p98: float
    max: float
    # 101 values: np.percentile(scores, 0), np.percentile(scores, 1), ..., 100.
    # The calibration reference isolation-forest interpolates a raw score
    # against to get its percentile rank -- see model_store.percentile_calibrate.
    # Redundant with min/p50/p95/p98/max above (those are exactly breakpoints
    # at indices 0/50/95/98/100) but kept alongside them rather than derived,
    # since those fields are also used standalone for reporting/comparisons.
    percentile_breakpoints: list[float]

    def to_dict(self) -> dict[str, float | int | list[float]]:
        return {
            "samples_scored": self.samples_scored,
            "min": self.min,
            "p50": self.p50,
            "p95": self.p95,
            "p98": self.p98,
            "max": self.max,
            "percentile_breakpoints": self.percentile_breakpoints,
        }


@dataclass(slots=True)
class ValidationReport:
    mode: ValidationMode
    candidate_version: str | None = None
    samples_scored: int = 0
    comparison_rows_inserted: int = 0
    score_distribution: ScoreDistribution | None = None


class CanaryValidatorRepository(Protocol):
    def load_calibration_samples(self, window_days: int, batch_size: int) -> list[CalibrationSample]: ...

    def load_unscored_comparison_samples(
        self, candidate_version: str, window_days: int, batch_size: int
    ) -> list[ComparisonSample]:
        """Idempotent selection: excludes samples already compared against this
        candidate_version (via NOT EXISTS on canary_validation_log), and excludes
        bootstrap samples with no production risk_score."""
        ...

    def write_score_distribution(self, candidate_version: str, distribution: ScoreDistribution) -> None: ...

    def insert_comparison_rows(self, rows: list[ComparisonRow]) -> int: ...


def load_candidate_model(models_dir: Path, version: str) -> IsolationForest:
    path = models_dir / MODEL_FILENAME_TEMPLATE.format(version=version)
    if not path.exists():
        raise FileNotFoundError(f"candidate model file not found for version {version!r}: {path}")
    return joblib.load(path)


def score_feature_vector(model: IsolationForest, feature_vector: list[float]) -> float:
    anomaly_score = float(model.score_samples(np.asarray([feature_vector], dtype=float))[0])
    return risk_score_from_anomaly_score(anomaly_score)


def compute_score_distribution(scores: list[float]) -> ScoreDistribution:
    array = np.asarray(scores, dtype=float)
    # 101 evenly-spaced integer percentiles (0..100) -- coarse enough to stay
    # a small, easily-transported JSON array, fine enough that interpolation
    # error between adjacent breakpoints is negligible relative to the
    # calibration batch's own sampling noise.
    breakpoints = np.percentile(array, np.arange(0, 101)).tolist()
    return ScoreDistribution(
        samples_scored=len(scores),
        min=float(np.min(array)),
        p50=float(np.percentile(array, 50)),
        p95=float(np.percentile(array, 95)),
        p98=float(np.percentile(array, 98)),
        max=float(np.max(array)),
        percentile_breakpoints=breakpoints,
    )


def _load_active_score_breakpoints(redis_client) -> list[float] | None:
    """Tolerates absence or malformed JSON -- never raises, callers fall back
    to comparing the candidate's raw, uncalibrated score (today's behavior)
    rather than aborting the whole comparison run over a desynced Redis key."""
    raw = redis_client.get(ACTIVE_SCORE_BREAKPOINTS_KEY)
    if raw is None:
        return None
    try:
        breakpoints = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(
            "canary-validator: %s is not valid JSON; comparing candidate scores uncalibrated",
            ACTIVE_SCORE_BREAKPOINTS_KEY,
        )
        return None
    if not is_valid_breakpoints(breakpoints):
        logger.warning(
            "canary-validator: %s is not a valid monotonic breakpoints array; comparing candidate scores uncalibrated",
            ACTIVE_SCORE_BREAKPOINTS_KEY,
        )
        return None
    return breakpoints


def run_validation_job(repository: CanaryValidatorRepository, redis_client, settings) -> ValidationReport:
    candidate_version = redis_client.get(CANDIDATE_VERSION_KEY)
    if candidate_version is None:
        logger.info("No candidate model set (%s unset); nothing to validate", CANDIDATE_VERSION_KEY)
        return ValidationReport(mode=ValidationMode.NO_CANDIDATE)

    candidate_model = load_candidate_model(Path(settings.models_dir), candidate_version)
    active_version = redis_client.get(ACTIVE_VERSION_KEY)

    if active_version is None:
        return _run_calibration(repository, settings, candidate_version, candidate_model)

    return _run_comparison(repository, settings, candidate_version, candidate_model, redis_client)


def _run_calibration(
    repository: CanaryValidatorRepository, settings, candidate_version: str, candidate_model: IsolationForest
) -> ValidationReport:
    samples = repository.load_calibration_samples(settings.window_days, settings.batch_size)
    if not samples:
        logger.info("No training samples available to calibrate candidate %s", candidate_version)
        return ValidationReport(mode=ValidationMode.CALIBRATION, candidate_version=candidate_version, samples_scored=0)

    scores = [score_feature_vector(candidate_model, sample.feature_vector) for sample in samples]
    distribution = compute_score_distribution(scores)
    repository.write_score_distribution(candidate_version, distribution)

    logger.info(
        "Calibration: scored %d samples for candidate %s, distribution=%s",
        len(samples),
        candidate_version,
        distribution.to_dict(),
    )
    return ValidationReport(
        mode=ValidationMode.CALIBRATION,
        candidate_version=candidate_version,
        samples_scored=len(samples),
        score_distribution=distribution,
    )


def _run_comparison(
    repository: CanaryValidatorRepository, settings, candidate_version: str, candidate_model: IsolationForest,
    redis_client,
) -> ValidationReport:
    samples = repository.load_unscored_comparison_samples(candidate_version, settings.window_days, settings.batch_size)
    production_breakpoints = _load_active_score_breakpoints(redis_client)

    comparison_rows = []
    raw_scores = []
    for sample in samples:
        raw_score = score_feature_vector(candidate_model, sample.feature_vector)
        raw_scores.append(raw_score)
        # Stored separately from raw_score: production_risk_score (read from
        # ml_training_samples.risk_score) is already percentile-calibrated
        # against the ACTIVE model's own breakpoints, so the candidate's
        # score must go through the same mapping to be comparable in this
        # row -- otherwise the two columns share a [0, 1] range but not a
        # scale (see percentile_calibrate's comment in score_mapping.py).
        candidate_score = (
            percentile_calibrate(raw_score, production_breakpoints)
            if production_breakpoints is not None
            else raw_score
        )
        comparison_rows.append(
            ComparisonRow(
                trace_id=sample.trace_id,
                production_model_version=sample.production_model_version,
                candidate_model_version=candidate_version,
                production_risk_score=sample.production_risk_score,
                candidate_risk_score=candidate_score,
            )
        )

    inserted = repository.insert_comparison_rows(comparison_rows) if comparison_rows else 0

    # Only recompute/overwrite the distribution when there was something new to
    # score -- an idempotent re-run with nothing left to do must not clobber the
    # distribution a previous run already wrote. Deliberately built from
    # raw_scores, NOT the (possibly percentile-calibrated) candidate_risk_score
    # above -- this distribution becomes the candidate's OWN future
    # calibration reference if it's promoted (scripts/promote_model.py), and
    # that reference must be a distribution of raw scores, the same contract
    # percentile_calibrate expects everywhere else it's used.
    distribution = None
    if raw_scores:
        distribution = compute_score_distribution(raw_scores)
        repository.write_score_distribution(candidate_version, distribution)

    logger.info(
        "Comparison: inserted %d canary_validation_log rows for candidate %s",
        inserted,
        candidate_version,
    )
    return ValidationReport(
        mode=ValidationMode.COMPARISON,
        candidate_version=candidate_version,
        samples_scored=len(samples),
        comparison_rows_inserted=inserted,
        score_distribution=distribution,
    )
