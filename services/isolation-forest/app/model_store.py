from __future__ import annotations

import asyncio
import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np

logger = logging.getLogger(__name__)

REDIS_ACTIVE_VERSION_KEY = "model:active_version"
# Published by scripts/promote_model.py, from the SAME version's
# ml_model_registry.score_distribution.percentile_breakpoints -- see
# percentile_calibrate below for why the raw sigmoid needs this. JSON-encoded
# list of 101 floats (percentiles 0..100 of the calibration reference).
REDIS_ACTIVE_SCORE_BREAKPOINTS_KEY = "model:active_score_breakpoints"

# Convention ml-trainer must follow when writing new model artifacts:
# one file per version, named "model_{version}.joblib", directly under models_dir.
MODEL_FILENAME_TEMPLATE = "model_{version}.joblib"


def model_path(models_dir: Path, version: str) -> Path:
    return models_dir / MODEL_FILENAME_TEMPLATE.format(version=version)


def risk_score_from_anomaly_score(anomaly_score: float) -> float:
    """Maps IsolationForest.score_samples output (unbounded, lower = more anomalous)
    to a bounded [0, 1] risk score where higher = more anomalous.

    DEMO-PHASE CHOICE: a logistic squash of the negated anomaly score, centered at 0.
    This calibration is a placeholder to recalibrate later against real score
    distributions (e.g. a percentile-based mapping) -- the only guarantees made here
    are that the result is bounded in [0, 1], monotonically increasing as the sample
    becomes more anomalous, and deterministic.

    MUST STAY IDENTICAL to services/canary-validator/app/score_mapping.py's copy of
    this function -- canary comparisons are only meaningful if both services map
    raw scores to [0, 1] the same way. See that file's comment for why it's a
    deliberate duplication rather than a shared library.
    """
    return 1.0 / (1.0 + math.exp(anomaly_score))


def percentile_calibrate(raw_score: float, breakpoints: list[float]) -> float:
    """Maps a raw risk_score_from_anomaly_score() output to its percentile rank
    within the ACTIVE model's own calibration reference (ml_model_registry.
    score_distribution.percentile_breakpoints, published to Redis by
    scripts/promote_model.py alongside model:active_threshold).

    Why this exists: the fixed sigmoid above is bounded in [0, 1] but, on real
    traffic, clusters tightly inside whatever narrow band score_samples()
    happens to produce for this model (empirically ~0.55-0.66) -- normal and
    anomalous requests alike, leaving little real separation for a threshold
    comparison to work with.

    An earlier version of this fix used min-max normalization instead of
    percentile rank -- rejected after live testing: min-max anchors the WHOLE
    scale on two literal extreme points from a finite calibration batch, so a
    single unusually-extreme sample (which any finite batch will have some of)
    skews every other score. Percentile rank only moves that one sample's own
    rank, never the scale itself -- verified empirically (see
    calibration_demo.py in the project history) to be far more stable under
    injection of a single outlier, and to separate normal/anomalous traffic
    better on this project's real data than min-max did.

    breakpoints must be `percentile_breakpoints`: 101 monotonically
    non-decreasing values, np.percentile(reference, 0..100). np.interp
    naturally clamps to [0, 1] for a raw_score outside the observed range
    (below breakpoints[0] -> 0.0, above breakpoints[-1] -> 1.0), same
    saturate-at-the-edge behavior as the min-max version had.
    """
    ranks = np.linspace(0.0, 1.0, num=len(breakpoints))
    return float(np.interp(raw_score, breakpoints, ranks))


def _is_valid_breakpoints(breakpoints: list[float] | None) -> bool:
    return (
        breakpoints is not None
        and len(breakpoints) >= 2
        and all(a <= b for a, b in zip(breakpoints, breakpoints[1:]))
    )


@dataclass(slots=True)
class ModelStore:
    models_dir: Path
    _model: Any = field(default=None, init=False)
    _version: str | None = field(default=None, init=False)
    _score_breakpoints: list[float] | None = field(default=None, init=False)

    def current(self) -> tuple[Any, str | None]:
        return self._model, self._version

    def calibration(self) -> list[float] | None:
        return self._score_breakpoints

    def load_version(self, version: str, *, score_breakpoints: list[float] | None = None) -> None:
        path = model_path(self.models_dir, version)
        if not path.exists():
            raise FileNotFoundError(f"model file not found for version {version!r}: {path}")

        try:
            model = joblib.load(path)
        except Exception as exc:
            raise RuntimeError(f"failed to load model version {version!r} from {path}") from exc

        # Assign only after a fully successful load -- a bad new model must never
        # knock out an already-working one. Calibration travels with the model
        # version it was computed for, so it is assigned in this same place,
        # never independently -- see poll_once/main._startup, the only callers.
        self._model = model
        self._version = version
        self._score_breakpoints = score_breakpoints

    def score(self, feature_vector: list[float]) -> float:
        if self._model is None:
            raise RuntimeError("no model loaded")
        anomaly_score = float(self._model.score_samples(np.asarray([feature_vector], dtype=float))[0])
        raw_score = risk_score_from_anomaly_score(anomaly_score)
        if _is_valid_breakpoints(self._score_breakpoints):
            return percentile_calibrate(raw_score, self._score_breakpoints)
        # No (usable) calibration published for the active model -- e.g. a
        # promotion done before this feature existed, or a desynced Redis
        # write. Fail soft to the raw sigmoid rather than crash scoring.
        return raw_score


async def read_score_calibration(redis_client) -> list[float] | None:
    """Reads model:active_score_breakpoints, tolerating absence or malformed
    JSON -- never raises, callers fall back to the unscaled raw score."""
    raw = await redis_client.get(REDIS_ACTIVE_SCORE_BREAKPOINTS_KEY)
    if raw is None:
        return None
    try:
        breakpoints = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("isolation-forest: %s=%r is not valid JSON; ignoring calibration", REDIS_ACTIVE_SCORE_BREAKPOINTS_KEY, raw)
        return None
    if not _is_valid_breakpoints(breakpoints):
        logger.warning(
            "isolation-forest: %s=%r is not a valid monotonic breakpoints array; ignoring calibration",
            REDIS_ACTIVE_SCORE_BREAKPOINTS_KEY,
            raw,
        )
        return None
    return breakpoints


async def poll_once(store: ModelStore, redis_client) -> None:
    active_version = await redis_client.get(REDIS_ACTIVE_VERSION_KEY)
    if active_version is None:
        return

    _, current_version = store.current()
    if active_version == current_version:
        return

    score_breakpoints = await read_score_calibration(redis_client)
    try:
        store.load_version(active_version, score_breakpoints=score_breakpoints)
        logger.info("isolation-forest: loaded model version %s", active_version)
    except Exception:
        logger.exception(
            "isolation-forest: failed to load model version %s; continuing to serve version %s",
            active_version,
            current_version,
        )


async def poll_forever(store: ModelStore, redis_client, poll_interval_seconds: float) -> None:
    while True:
        await asyncio.sleep(poll_interval_seconds)
        await poll_once(store, redis_client)
