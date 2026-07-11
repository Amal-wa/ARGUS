from __future__ import annotations

from dataclasses import dataclass

from app.core.events import EventPayload
from app.core.redis_client import RedisLike
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext


@dataclass(slots=True)
class RateLimitResult:
    exceeded: bool
    counter: int


async def _increment_windowed_counter(redis_client: RedisLike, key: str, window_seconds: int) -> int:
    count = await redis_client.incr(key)
    if count == 1:
        await redis_client.expire(key, window_seconds)
    return count


async def enforce_ip_rate_limit(*, context: RequestContext, settings: GatewaySettings, redis_client: RedisLike, event_logger) -> RateLimitResult:
    counter = await _increment_windowed_counter(redis_client, f"ratelimit:ip:{context.ip_address}", settings.rate_limit_window_seconds)
    if counter > settings.rate_limit_ip_limit:
        await event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=None,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=429,
                event_type="rate_limit_ip_exceeded",
                error_code="rate_limit_ip_exceeded",
                error_message="IP rate limit exceeded",
            )
        )
        return RateLimitResult(exceeded=True, counter=counter)

    return RateLimitResult(exceeded=False, counter=counter)


async def enforce_user_rate_limit(*, context: RequestContext, settings: GatewaySettings, redis_client: RedisLike, event_logger) -> RateLimitResult:
    counter = await _increment_windowed_counter(redis_client, f"ratelimit:user:{context.claims.subject}", settings.rate_limit_window_seconds)
    if counter > settings.rate_limit_user_limit:
        await event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=context.claims.subject,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=429,
                event_type="rate_limit_user_exceeded",
                error_code="rate_limit_user_exceeded",
                error_message="User rate limit exceeded",
            )
        )
        return RateLimitResult(exceeded=True, counter=counter)

    return RateLimitResult(exceeded=False, counter=counter)
