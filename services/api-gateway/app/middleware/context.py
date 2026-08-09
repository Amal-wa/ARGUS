from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from time import perf_counter
from uuid import UUID, uuid4

from app.core.security import VerifiedJWT


@dataclass(slots=True)
class RequestContext:
    trace_id: UUID = field(default_factory=uuid4)
    started_at: float = field(default_factory=perf_counter)
    method: str = "GET"
    path: str = "/"
    ip_address: str = "127.0.0.1"
    claims: VerifiedJWT | None = None
    is_post_step_up: bool = False
    # Set by AuthorizationService.authorize() once the route pattern is
    # resolved -- MfaChallengeService.create_challenge reuses it so the
    # challenge (and later the action ticket) is scoped to the same route
    # PATTERN the retried request will resolve to, not the raw path.
    route_pattern: str | None = None

    def latency_ms(self) -> int:
        return max(0, int((perf_counter() - self.started_at) * 1000))


def resolve_client_ip(request, trusted_proxies: frozenset[str]) -> str:
    """Resolves the client IP, honouring X-Forwarded-For only when the DIRECT
    peer is in `trusted_proxies` -- a spoofed header can never make itself
    trusted, since the check is on the peer, not on anything in the header
    (RFC 7239 / standard reverse-proxy practice). Empty allowlist (the
    default) means the header is always ignored."""
    peer = getattr(getattr(request, "client", None), "host", "127.0.0.1")
    if peer not in trusted_proxies:
        return peer

    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer

    # XFF is a comma-separated chain "client, proxy1, proxy2" -- the first
    # entry is the original client.
    candidate = forwarded.split(",")[0].strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        # Malformed/injected value -- never let it become a Redis key.
        return peer
    return candidate
