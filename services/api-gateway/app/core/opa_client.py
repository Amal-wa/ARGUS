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


def build_opa_ssl_context(*, client_cert_path: str, client_key_path: str, ca_cert_path: str) -> ssl.SSLContext:
    # mTLS Gateway<->OPA: OPA runs with --authentication=tls (see
    # docker-compose.yml), so it requires a client certificate signed by the
    # same internal CA that signed its own server certificate (both issued
    # by vault-init.sh's PKI role from one root CA). TLS 1.3 only, matching
    # OPA's own --min-tls-version 1.3 -- both sides enforce the floor
    # explicitly rather than relying on implicit negotiation.
    # load_cert_chain/load_verify_locations raise (FileNotFoundError/
    # ssl.SSLError) if a path is missing or invalid -- deliberately no
    # pre-check here, so a misconfigured deployment fails loudly at startup
    # instead of falling back to an unauthenticated connection.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=ca_cert_path)
    context.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
    return context


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
