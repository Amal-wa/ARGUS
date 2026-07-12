from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np

logger = logging.getLogger(__name__)

REDIS_ACTIVE_VERSION_KEY = "model:active_version"

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
    """
    return 1.0 / (1.0 + math.exp(anomaly_score))


@dataclass(slots=True)
class ModelStore:
    models_dir: Path
    _model: Any = field(default=None, init=False)
    _version: str | None = field(default=None, init=False)

    def current(self) -> tuple[Any, str | None]:
        return self._model, self._version

    def load_version(self, version: str) -> None:
        path = model_path(self.models_dir, version)
        if not path.exists():
            raise FileNotFoundError(f"model file not found for version {version!r}: {path}")

        try:
            model = joblib.load(path)
        except Exception as exc:
            raise RuntimeError(f"failed to load model version {version!r} from {path}") from exc

        # Assign only after a fully successful load -- a bad new model must never
        # knock out an already-working one.
        self._model = model
        self._version = version

    def score(self, feature_vector: list[float]) -> float:
        if self._model is None:
            raise RuntimeError("no model loaded")
        anomaly_score = float(self._model.score_samples(np.asarray([feature_vector], dtype=float))[0])
        return risk_score_from_anomaly_score(anomaly_score)


async def poll_once(store: ModelStore, redis_client) -> None:
    active_version = await redis_client.get(REDIS_ACTIVE_VERSION_KEY)
    if active_version is None:
        return

    _, current_version = store.current()
    if active_version == current_version:
        return

    try:
        store.load_version(active_version)
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
