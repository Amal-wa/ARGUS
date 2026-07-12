from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.core.errors import OpaUnavailableError
from app.schemas.authorization import OpaDecision, OpaDecisionResult, OpaPolicyInput


@dataclass(slots=True)
class OpaClient:
    base_url: str
    decision_path: str
    timeout_seconds: float = 3.0

    async def decide(self, payload: OpaPolicyInput) -> OpaDecisionResult:
        return await asyncio.to_thread(self._decide_sync, payload)

    def _decide_sync(self, payload: OpaPolicyInput) -> OpaDecisionResult:
        endpoint = f"{self.base_url.rstrip('/')}{self.decision_path}"
        request = Request(
            endpoint,
            data=json.dumps({"input": payload.model_dump(mode="json")}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                if response.status < 200 or response.status >= 300:
                    raise OpaUnavailableError(f"OPA returned unexpected HTTP status {response.status}")
                raw = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise OpaUnavailableError(f"OPA returned HTTP error {exc.code}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise OpaUnavailableError("OPA decision endpoint is unavailable") from exc

        result = raw.get("result", raw)
        if isinstance(result, dict):
            decision_value = str(result.get("decision", "")).upper()
            policy_name = str(result.get("policy_name", "default"))
            try:
                decision = OpaDecision(decision_value)
            except ValueError as exc:
                raise OpaUnavailableError(f"OPA returned unsupported decision {decision_value!r}") from exc
            if "decision" not in result or "policy_name" not in result:
                raise OpaUnavailableError("OPA response did not contain a decision contract")
            return OpaDecisionResult(
                decision=decision,
                policy_name=policy_name,
                reason=result.get("reason"),
            )

        raise OpaUnavailableError("OPA response did not contain a decision")
