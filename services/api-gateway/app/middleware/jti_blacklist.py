from __future__ import annotations

from app.core.events import EventPayload
from app.core.redis_client import RedisLike
from app.middleware.context import RequestContext


async def check_jti_blacklist(*, context: RequestContext, redis_client: RedisLike, event_logger):
    if context.claims is None:
        return None

    revoked = await redis_client.exists(f"revoked:jti:{context.claims.jti}")
    if not revoked:
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
            event_type="token_revoked_used",
            error_code="token_revoked_used",
            error_message="Revoked JWT was presented",
        )
    )
    return "revoked"
