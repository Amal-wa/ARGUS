from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol
from uuid import UUID

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.score_mapping import risk_score_from_anomaly_score

logger = logging.getLogger(__name__)

CANDIDATE_VERSION_KEY = "model:candidate_version"
ACTIVE_VERSION_KEY = "model:active_version"

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


def run_validation_job(repository: CanaryValidatorRepository, redis_client, settings) -> ValidationReport:
    candidate_version = redis_client.get(CANDIDATE_VERSION_KEY)
    if candidate_version is None:
        logger.info("No candidate model set (%s unset); nothing to validate", CANDIDATE_VERSION_KEY)
        return ValidationReport(mode=ValidationMode.NO_CANDIDATE)

    candidate_model = load_candidate_model(Path(settings.models_dir), candidate_version)
    active_version = redis_client.get(ACTIVE_VERSION_KEY)

    if active_version is None:
        return _run_calibration(repository, settings, candidate_version, candidate_model)

    return _run_comparison(repository, settings, candidate_version, candidate_model)


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
    repository: CanaryValidatorRepository, settings, candidate_version: str, candidate_model: IsolationForest
) -> ValidationReport:
    samples = repository.load_unscored_comparison_samples(candidate_version, settings.window_days, settings.batch_size)

    comparison_rows = []
    scores = []
    for sample in samples:
        candidate_score = score_feature_vector(candidate_model, sample.feature_vector)
        scores.append(candidate_score)
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
    # distribution a previous run already wrote.
    distribution = None
    if scores:
        distribution = compute_score_distribution(scores)
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
