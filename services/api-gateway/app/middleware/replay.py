from __future__ import annotations

from app.core.events import EventPayload
from app.core.redis_client import RedisLike
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext


async def check_replay(*, context: RequestContext, settings: GatewaySettings, redis_client: RedisLike, event_logger):
    if context.claims is None:
        return None

    key = f"used:jti:{context.claims.jti}"
    ttl = settings.replay_ttl_seconds
    if ttl is None:
        ttl = max(1, context.claims.expires_at - int(context.claims.issued_at))

    stored = await redis_client.set(key, str(context.trace_id), nx=True, ex=ttl)
    if stored:
        return None

    await event_logger.write(
        EventPayload(
            trace_id=context.trace_id,
            user_id=context.claims.subject,
            ip_address=context.ip_address,
            http_method=context.method,
            request_path=context.path,
            latency_ms=context.latency_ms(),
            http_status=401,
            event_type="replay_detected",
            error_code="replay_detected",
            error_message="JWT replay detected",
        )
    )
    return "replay"
