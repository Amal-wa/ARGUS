from __future__ import annotations

import asyncio
import json
import math
import ssl
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.core.errors import ScoringUnavailableError
from app.schemas.authorization import RiskScoreResult

# A conformant Isolation Forest instance always returns risk_score within
# these bounds (ScoreResponse.risk_score is a plain float, [0, 1] by
# construction of risk_score_from_anomaly_score/percentile_calibrate on that
# side) -- but this client is a trust boundary, not that service's own
# internal guarantee. Proven live: an impersonating/malfunctioning peer
# returning e.g. 57.0 was accepted with zero validation, propagated into
# opa_decision_log, and crashed its CHECK (risk_score BETWEEN 0 AND 1)
# constraint with an uncaught exception -- a single bad upstream value 500'd
# every authenticated request in the system, not just the one that triggered
# it (write_decision runs unconditionally after every OPA decision). See
# SECURITY.md.
MIN_RISK_SCORE = 0.0
MAX_RISK_SCORE = 1.0


@dataclass(slots=True)
class IsolationForestClient:
    base_url: str
    score_path: str
    # None for plain http:// (e.g. local debugging without the Docker
    # stack/certs) -- urlopen ignores `context` entirely for non-https URLs,
    # so this stays a safe no-op in that case rather than a special branch.
    # Same pattern as OpaClient.ssl_context; see core/tls.py.
    ssl_context: ssl.SSLContext | None = None

    async def health(self) -> bool:
        return await asyncio.to_thread(self._health_sync)

    def _health_sync(self) -> bool:
        endpoint = f"{self.base_url.rstrip('/')}/health"
        try:
            with urlopen(Request(endpoint), timeout=5, context=self.ssl_context) as response:
                if not (200 <= response.status < 300):
                    return False
                payload = json.loads(response.read().decode("utf-8"))
        except (URLError, TimeoutError, json.JSONDecodeError):
            return False
        return payload.get("status") == "ok"

    async def score(self, feature_vector: list[float]) -> RiskScoreResult:
        return await asyncio.to_thread(self._score_sync, feature_vector)

    def _score_sync(self, feature_vector: list[float]) -> RiskScoreResult:
        endpoint = f"{self.base_url.rstrip('/')}{self.score_path}"
        request = Request(
            endpoint,
            data=json.dumps({"feature_vector": feature_vector}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10, context=self.ssl_context) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ScoringUnavailableError("Isolation Forest scoring endpoint is unavailable") from exc

        risk_score = raw.get("risk_score")
        model_version = raw.get("model_version")

        # bool excluded explicitly: isinstance(True, int) is True in Python,
        # so a JSON `true`/`false` would otherwise silently pass the numeric
        # check. math.isfinite rejects NaN/Infinity/-Infinity -- not a
        # theoretical case, json.loads accepts those literal tokens by
        # default (Python's json module is permissive beyond strict JSON).
        if (
            not isinstance(risk_score, (int, float))
            or isinstance(risk_score, bool)
            or not math.isfinite(risk_score)
            or not (MIN_RISK_SCORE <= risk_score <= MAX_RISK_SCORE)
        ):
            raise ScoringUnavailableError(f"Isolation Forest returned an invalid risk_score: {risk_score!r}")
        if not isinstance(model_version, str) or not model_version:
            raise ScoringUnavailableError(f"Isolation Forest returned an invalid model_version: {model_version!r}")

        return RiskScoreResult(
            risk_score=float(risk_score),
            model_version=model_version,
        )
