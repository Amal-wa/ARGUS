from __future__ import annotations

from dataclasses import dataclass

from app.core.redis_client import RedisLike
from app.middleware.context import RequestContext


@dataclass(slots=True)
class FeatureVectorService:
    redis_client: RedisLike

    async def build_vector(self, context: RequestContext) -> list[float]:
        if context.claims is None:
            raise RuntimeError("feature vectors require authenticated claims")

        user_id = context.claims.subject
        read_count = await self._counter(f"requests:read:{user_id}")
        write_count = await self._counter(f"requests:write:{user_id}")
        deny_count = await self._counter(f"decisions:deny:{user_id}")
        path_count = await self._set_size(f"paths:user:{user_id}")
        ip_count = await self._set_size(f"distinct_ips:user:{user_id}")
        rate_limit_count = await self._counter(f"ratelimit:user:{user_id}")

        method_one_hot = [0.0, 0.0, 0.0, 0.0, 0.0]
        method_index = {"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}.get(context.method.upper())
        if method_index is not None:
            method_one_hot[method_index] = 1.0

        vector = [
            float(read_count),
            float(write_count),
            float(deny_count),
            float(path_count),
            float(ip_count),
            float(rate_limit_count),
            float(read_count + write_count),
            float(read_count) / max(1.0, float(read_count + write_count)),
            float(write_count) / max(1.0, float(read_count + write_count)),
            float(context.latency_ms()),
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            *method_one_hot,
        ]

        return vector[:20]

    async def record_observation(self, context: RequestContext, route_pattern: str) -> None:
        if context.claims is None:
            raise RuntimeError("feature observations require authenticated claims")

        user_id = context.claims.subject
        if context.method.upper() == "GET":
            await self._counter(f"requests:read:{user_id}", increment=True)
        else:
            await self._counter(f"requests:write:{user_id}", increment=True)

        await self._set_add(f"paths:user:{user_id}", route_pattern)
        await self._set_add(f"distinct_ips:user:{user_id}", context.ip_address)

    async def record_deny(self, context: RequestContext) -> None:
        if context.claims is None:
            raise RuntimeError("deny tracking requires authenticated claims")
        await self._counter(f"decisions:deny:{context.claims.subject}", increment=True)

    async def _counter(self, key: str, increment: bool = False) -> int:
        value = await self.redis_client.get(key)
        current = int(value) if value is not None else 0
        if increment:
            current = await self.redis_client.incr(key)
            if current == 1:
                await self.redis_client.expire(key, 300)
        return current

    async def _set_add(self, key: str, member: str) -> int:
        added = await self.redis_client.sadd(key, member)
        if added > 0:
            await self.redis_client.expire(key, 300)
        return added

    async def _set_size(self, key: str) -> int:
        return await self.redis_client.scard(key)
