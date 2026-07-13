from __future__ import annotations

import math

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
