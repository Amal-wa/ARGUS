from __future__ import annotations

import math

import numpy as np

# THIS FUNCTION MUST STAY IDENTICAL TO services/isolation-forest/app/model_store.py's
# risk_score_from_anomaly_score. A canary comparison is only meaningful if the
# candidate score and the production score in ml_training_samples.risk_score were
# produced by the exact same raw-score -> [0,1] mapping -- if the two services'
# mappings ever diverge, every row in canary_validation_log becomes invalid. A
# shared library between the two services is out of scope for now; this is a
# deliberate, documented duplication instead of a silent one.


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


# THIS FUNCTION MUST STAY IDENTICAL TO services/isolation-forest/app/model_store.py's
# percentile_calibrate -- same reasoning as risk_score_from_anomaly_score above.
# Used in Mode B (comparison) to map a candidate's raw score into the SAME
# space production_risk_score is already in (ml_training_samples.risk_score
# is written by isolation-forest's ModelStore.score(), which applies this
# same percentile-rank step against the active model's own calibration
# reference before the score ever reaches the Gateway). Without this, a
# canary_validation_log row compares a percentile rank (production) against
# a raw, uncalibrated sigmoid (candidate) -- two different scales that
# happen to share a [0, 1] range but mean different things, making the
# stored comparison meaningless despite looking valid.
def percentile_calibrate(raw_score: float, breakpoints: list[float]) -> float:
    ranks = np.linspace(0.0, 1.0, num=len(breakpoints))
    return float(np.interp(raw_score, breakpoints, ranks))


def is_valid_breakpoints(breakpoints: list[float] | None) -> bool:
    return (
        breakpoints is not None
        and len(breakpoints) >= 2
        and all(a <= b for a, b in zip(breakpoints, breakpoints[1:]))
    )
