from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

from app.core.redis_client import RedisLike
from app.middleware.context import RequestContext

# Sliding-window size shared by every aggregated feature below, EXCEPT
# request_count (index 5), which deliberately reuses the 1-minute
# ratelimit:user:{id} counter instead of a dedicated 5-minute one -- see the
# index map.
WINDOW_SECONDS = 300

# Single source of truth for this service's vector shape -- must match
# ml-trainer's FEATURE_VECTOR_DIMENSIONS, isolation-forest's ScoreRequest
# validation, the ml_training_samples CHECK constraint, and
# ml_model_registry.feature_dims (see scripts/promote_model.py, which refuses
# to promote a model whose registry row disagrees with this number).
FEATURE_VECTOR_DIMENSIONS = 16

# Fixed, 16-dimension feature vector layout. Position is part of the contract
# with isolation-forest / canary-validator / ml-trainer / the
# ml_training_samples CHECK constraint -- changing the order or count here
# means retraining, not just redeploying.
#
#  0-4  one-hot HTTP method [GET, POST, PUT, PATCH, DELETE]   instantaneous, current request
#  5    request_count                                          1 min,  reuses ratelimit:user:{id}
#  6    distinct route patterns                                5 min,  paths:user:{id}
#  7    distinct raw resources (path incl. identifiers)         5 min,  resources:user:{id}
#  8    mean inter-request interval (seconds)                   5 min,  intervals:user:{id} (ZSET)
#  9    std-dev of inter-request intervals (seconds)            5 min,  intervals:user:{id} (ZSET)
# 10    distinct HTTP methods used                              5 min,  methods:user:{id}
# 11    read/write ratio (read_count / total)                   5 min,  requests:read/write:{id}
# 12    DENY count                                               5 min,  decisions:deny:{id}
# 13    distinct IPs                                             5 min,  distinct_ips:user:{id}
# 14    authentication failures from this IP                    5 min,  auth_failed:ip:{ip} (IP-scoped, not
#                                                                        user-scoped -- see record_auth_failure)
# 15    request latency (ms)                                    instantaneous, current request

_METHOD_INDEX = {"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}


@dataclass(slots=True)
class FeatureVectorService:
    redis_client: RedisLike

    async def build_vector(self, context: RequestContext) -> list[float]:
        if context.claims is None:
            raise RuntimeError("feature vectors require authenticated claims")

        user_id = context.claims.subject
        ip = context.ip_address
        now = time.time()

        method_one_hot = [0.0, 0.0, 0.0, 0.0, 0.0]
        method_index = _METHOD_INDEX.get(context.method.upper())
        if method_index is not None:
            method_one_hot[method_index] = 1.0

        request_count = await self._counter(f"ratelimit:user:{user_id}")
        route_pattern_count = await self._set_size(f"paths:user:{user_id}")
        raw_resource_count = await self._set_size(f"resources:user:{user_id}")
        interval_mean, interval_stddev = await self._interval_stats(f"intervals:user:{user_id}", now)
        method_count = await self._set_size(f"methods:user:{user_id}")
        read_count = await self._counter(f"requests:read:{user_id}")
        write_count = await self._counter(f"requests:write:{user_id}")
        read_ratio = float(read_count) / max(1.0, float(read_count + write_count))
        deny_count = await self._counter(f"decisions:deny:{user_id}")
        ip_count = await self._set_size(f"distinct_ips:user:{user_id}")
        auth_failed_count = await self._counter(f"auth_failed:ip:{ip}")

        return [
            *method_one_hot,
            float(request_count),
            float(route_pattern_count),
            float(raw_resource_count),
            interval_mean,
            interval_stddev,
            float(method_count),
            read_ratio,
            float(deny_count),
            float(ip_count),
            float(auth_failed_count),
            float(context.latency_ms()),
        ]

    async def record_observation(self, context: RequestContext, route_pattern: str) -> None:
        if context.claims is None:
            raise RuntimeError("feature observations require authenticated claims")

        user_id = context.claims.subject
        method = context.method.upper()
        if method == "GET":
            await self._counter(f"requests:read:{user_id}", increment=True)
        else:
            await self._counter(f"requests:write:{user_id}", increment=True)

        await self._set_add(f"paths:user:{user_id}", route_pattern)
        # Raw resource (the real path, identifiers included) is a SEPARATE set
        # from the route-pattern one above: route patterns stay bounded (one
        # per endpoint shape, ~6 on this API), raw resources grow with
        # enumeration -- this divergence is the signal scenario A's docstring
        # (resource enumeration) depends on, and previously did not exist.
        await self._set_add(f"resources:user:{user_id}", context.path)
        await self._set_add(f"distinct_ips:user:{user_id}", context.ip_address)
        await self._set_add(f"methods:user:{user_id}", method)
        await self._record_interval_timestamp(f"intervals:user:{user_id}", str(context.trace_id), time.time())

    async def record_deny(self, context: RequestContext) -> None:
        if context.claims is None:
            raise RuntimeError("deny tracking requires authenticated claims")
        await self._counter(f"decisions:deny:{context.claims.subject}", increment=True)

    async def record_auth_failure(self, ip_address: str, attempted_email: str | None = None) -> None:
        # Anti-spoofing: scoped on IP, never on a user_id taken from an
        # unverified/not-yet-issued JWT -- at the point a login attempt fails,
        # there is no verified identity to key on, and keying on the
        # attacker-supplied email would let an attacker inflate a victim's
        # counter or evade detection by rotating identities. IP is what
        # resolve_client_ip already treats as the trustworthy signal
        # (X-Forwarded-For only honored from a trusted proxy peer). This is
        # the password-spraying signal: one IP, many accounts, one failure
        # each -- see tools/traffic-generator's scenario B.
        await self._counter(f"auth_failed:ip:{ip_address}", increment=True)
        # Separate from the counter above: a plain count can't tell "10
        # failures on 1 account" from "10 failures across 10 accounts" --
        # confirmed empirically by a live replay of scenario B, where the
        # count alone was indistinguishable from bruteforce. The attempted
        # email is only ever added as a SET MEMBER here (never a lookup key),
        # so the anti-spoofing property above is unaffected -- an attacker
        # can still only inflate a count of their OWN attempts, not a
        # victim's, and rotating identities is exactly what this set is
        # built to reveal (its size), not evade.
        if attempted_email:
            await self._set_add(f"auth_failed_accounts:ip:{ip_address}", attempted_email)

    async def _counter(self, key: str, increment: bool = False) -> int:
        value = await self.redis_client.get(key)
        current = int(value) if value is not None else 0
        if increment:
            current = await self.redis_client.incr(key)
            if current == 1:
                await self.redis_client.expire(key, WINDOW_SECONDS)
        return current

    async def _set_add(self, key: str, member: str) -> int:
        # TTL is set only when this SADD creates the key -- a set that keeps
        # discovering new members (e.g. an enumeration attack) must still
        # expire on the same 5-minute cadence as every other feature, not
        # slide forward forever. Checked BEFORE the SADD, since afterwards the
        # key always exists.
        existed = await self.redis_client.exists(key)
        added = await self.redis_client.sadd(key, member)
        if not existed:
            await self.redis_client.expire(key, WINDOW_SECONDS)
        return added

    async def _set_size(self, key: str) -> int:
        return await self.redis_client.scard(key)

    async def _record_interval_timestamp(self, key: str, member: str, timestamp: float) -> None:
        existed = await self.redis_client.exists(key)
        await self.redis_client.zadd(key, {member: timestamp})
        # Trim on every write so the ZSET cannot grow without bound for a
        # long-lived, continuously active user.
        await self.redis_client.zremrangebyscore(key, float("-inf"), timestamp - WINDOW_SECONDS)
        if not existed:
            await self.redis_client.expire(key, WINDOW_SECONDS)

    async def _interval_stats(self, key: str, now: float) -> tuple[float, float]:
        await self.redis_client.zremrangebyscore(key, float("-inf"), now - WINDOW_SECONDS)
        entries = await self.redis_client.zrange(key, 0, -1, withscores=True)
        timestamps = sorted(score for _, score in entries)
        if len(timestamps) < 2:
            # Fewer than 2 timestamps in the window means no interval is
            # computable yet. 0.0 rather than a sentinel like -1: a real
            # interval is always >= 0, so a sentinel outside that range would
            # be unambiguous but this vector has no reserved-value convention
            # elsewhere, and 0.0 ("no time has passed") is the least
            # surprising stand-in given the sequencing rule (the current
            # request's own timestamp is never in this read -- see
            # AuthorizationService.authorize, which calls build_vector before
            # record_observation).
            return 0.0, 0.0
        diffs = [later - earlier for earlier, later in zip(timestamps, timestamps[1:])]
        return statistics.fmean(diffs), statistics.pstdev(diffs)
