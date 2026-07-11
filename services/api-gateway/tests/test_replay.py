from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from uuid import uuid4

import pytest

from app.core.redis_client import InMemoryRedis
from app.core.security import VerifiedJWT
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext
from app.middleware.replay import check_replay


@dataclass(slots=True)
class Recorder:
    items: list[object] = field(default_factory=list)

    async def write(self, payload):
        self.items.append(payload)


def _claims():
    now = 1_700_000_000
    return VerifiedJWT(
        subject=uuid4(),
        issuer="zt-api-gateway",
        audience="zt-api",
        issued_at=now,
        expires_at=now + 60,
        jti=uuid4(),
        role="user",
        risk_ctx=None,
        raw_claims={},
    )


def test_replay_detection_sets_first_use_then_detects_replay():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        claims = _claims()
        context = RequestContext(ip_address="10.0.0.4", method="GET", path="/v1/items", claims=claims)
        settings = GatewaySettings()

        first = await check_replay(context=context, settings=settings, redis_client=redis, event_logger=recorder)
        second = await check_replay(context=context, settings=settings, redis_client=redis, event_logger=recorder)

        assert first is None
        assert second == "replay"
        assert recorder.items[-1].event_type == "replay_detected"

    asyncio.run(_run())
