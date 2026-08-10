from __future__ import annotations

import asyncio
import json
import ssl
from dataclasses import dataclass
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.core.errors import OpaUnavailableError
from app.schemas.authorization import OpaDecision, OpaDecisionResult, OpaPolicyInput

# mTLS Gateway<->OPA: OPA runs with --authentication=tls (see
# docker-compose.yml), so it requires a client certificate signed by the
# same internal CA that signed its own server certificate. The SSLContext
# itself is built by core.tls.build_gateway_client_ssl_context -- shared
# with IsolationForestClient, since both are the same Gateway identity
# authenticating to a different internal service signed by the same CA. See
# that module for why this moved out of being OPA-specific.


@dataclass(slots=True)
class OpaClient:
    base_url: str
    decision_path: str
    timeout_seconds: float = 3.0
    # None for plain http:// (e.g. local debugging without the Docker
    # stack/certs) -- urlopen ignores `context` entirely for non-https URLs,
    # so this stays a safe no-op in that case rather than a special branch.
    ssl_context: ssl.SSLContext | None = None

    async def health(self) -> bool:
        return await asyncio.to_thread(self._health_sync)

    def _health_sync(self) -> bool:
        endpoint = f"{self.base_url.rstrip('/')}/health"
        try:
            with urlopen(Request(endpoint), timeout=self.timeout_seconds, context=self.ssl_context) as response:
                return 200 <= response.status < 300
        except (HTTPError, URLError, TimeoutError):
            return False

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
            with urlopen(request, timeout=self.timeout_seconds, context=self.ssl_context) as response:
                if response.status < 200 or response.status >= 300:
                    raise OpaUnavailableError(f"OPA returned unexpected HTTP status {response.status}")
                raw = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise OpaUnavailableError(f"OPA returned HTTP error {exc.code}") from exc
        except (URLError, TimeoutError, HTTPException, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise OpaUnavailableError("OPA decision endpoint is unavailable") from exc

        result = raw.get("result", raw)
        if isinstance(result, dict):
            # Checked before extracting defaults below: a missing "decision"
            # key is also caught later by OpaDecision("") raising ValueError,
            # but a missing "policy_name" alone would otherwise silently
            # default to "default" instead of being treated as a malformed
            # contract.
            if "decision" not in result or "policy_name" not in result:
                raise OpaUnavailableError("OPA response did not contain a decision contract")
            decision_value = str(result.get("decision", "")).upper()
            policy_name = str(result.get("policy_name", "default"))
            try:
                decision = OpaDecision(decision_value)
            except ValueError as exc:
                raise OpaUnavailableError(f"OPA returned unsupported decision {decision_value!r}") from exc
            return OpaDecisionResult(
                decision=decision,
                policy_name=policy_name,
                reason=result.get("reason"),
            )

        raise OpaUnavailableError("OPA response did not contain a decision")
