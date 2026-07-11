from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.core.errors import OpaUnavailableError
from app.schemas.authorization import RiskScoreResult


@dataclass(slots=True)
class IsolationForestClient:
    base_url: str
    score_path: str

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
            with urlopen(request, timeout=10) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OpaUnavailableError("Isolation Forest scoring endpoint is unavailable") from exc

        return RiskScoreResult(
            risk_score=raw.get("risk_score"),
            model_version=raw.get("model_version"),
        )
