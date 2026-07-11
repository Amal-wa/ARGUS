from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from uuid import uuid4

import pytest

from app.core.redis_client import InMemoryRedis
from app.core.security import VerifiedJWT
from app.middleware.context import RequestContext
from app.middleware.jti_blacklist import check_jti_blacklist


@dataclass(slots=True)
class Recorder:
    items: list[object] = field(default_factory=list)

    async def write(self, payload):
        self.items.append(payload)


def _claims():
    return VerifiedJWT(
        subject=uuid4(),
        issuer="zt-api-gateway",
        audience="zt-api",
        issued_at=0,
        expires_at=9999999999,
        jti=uuid4(),
        role="user",
        risk_ctx=None,
        raw_claims={},
    )


def test_revoked_jti_writes_event():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        claims = _claims()
        await redis.set(f"revoked:jti:{claims.jti}", "1")
        context = RequestContext(ip_address="10.0.0.3", method="POST", path="/v1/token", claims=claims)

        result = await check_jti_blacklist(context=context, redis_client=redis, event_logger=recorder)

        assert result == "revoked"
        assert recorder.items[-1].event_type == "token_revoked_used"

    asyncio.run(_run())
