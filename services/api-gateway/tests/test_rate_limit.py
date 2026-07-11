from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from uuid import uuid4

import pytest

from app.core.redis_client import InMemoryRedis
from app.core.settings import GatewaySettings
from app.core.security import VerifiedJWT
from app.middleware.context import RequestContext
from app.middleware.rate_limit import enforce_ip_rate_limit, enforce_user_rate_limit


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


def _settings():
    return GatewaySettings(rate_limit_ip_limit=1, rate_limit_user_limit=1, jwk_refresh_lock_ttl_seconds=30)


def test_ip_rate_limit_writes_event():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        context = RequestContext(ip_address="10.0.0.1", method="GET", path="/v1/items")
        settings = _settings()

        first = await enforce_ip_rate_limit(context=context, settings=settings, redis_client=redis, event_logger=recorder)
        second = await enforce_ip_rate_limit(context=context, settings=settings, redis_client=redis, event_logger=recorder)

        assert first.exceeded is False
        assert second.exceeded is True
        assert recorder.items[-1].event_type == "rate_limit_ip_exceeded"

    asyncio.run(_run())


def test_user_rate_limit_writes_event():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        context = RequestContext(ip_address="10.0.0.2", method="GET", path="/v1/items", claims=_claims())
        settings = GatewaySettings(rate_limit_ip_limit=10, rate_limit_user_limit=1, jwk_refresh_lock_ttl_seconds=30)

        await enforce_user_rate_limit(context=context, settings=settings, redis_client=redis, event_logger=recorder)
        result = await enforce_user_rate_limit(context=context, settings=settings, redis_client=redis, event_logger=recorder)

        assert result.exceeded is True
        assert recorder.items[-1].event_type == "rate_limit_user_exceeded"

    asyncio.run(_run())


def test_authenticated_request_increments_ip_counter_only_once():
    async def _run():
        redis = InMemoryRedis()
        recorder = Recorder()
        context = RequestContext(ip_address="10.0.0.3", method="GET", path="/v1/items", claims=_claims())
        settings = GatewaySettings(rate_limit_ip_limit=100, rate_limit_user_limit=100, jwk_refresh_lock_ttl_seconds=30)

        await enforce_ip_rate_limit(context=context, settings=settings, redis_client=redis, event_logger=recorder)
        await enforce_user_rate_limit(context=context, settings=settings, redis_client=redis, event_logger=recorder)

        ip_counter = await redis.get(f"ratelimit:ip:{context.ip_address}")
        assert ip_counter == "1"

    asyncio.run(_run())
