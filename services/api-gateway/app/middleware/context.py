from __future__ import annotations

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

    def latency_ms(self) -> int:
        return max(0, int((perf_counter() - self.started_at) * 1000))
