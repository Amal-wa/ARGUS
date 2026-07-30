from __future__ import annotations

import asyncio
import statistics
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.redis_client import InMemoryRedis
from app.core.security import VerifiedJWT
from app.middleware.context import RequestContext
from app.services.feature_vector import WINDOW_SECONDS, FeatureVectorService


def _claims(**overrides) -> VerifiedJWT:
    defaults = dict(
        subject=uuid4(),
        issuer="zt-api-gateway",
        audience="zt-api",
        issued_at=1_700_000_000,
        expires_at=1_700_000_060,
        jti=uuid4(),
        role="reader",
        risk_ctx=None,
        raw_claims={},
    )
    defaults.update(overrides)
    return VerifiedJWT(**defaults)


def test_build_vector_has_16_dimensions_and_no_constant_dimension():
    async def _run():
        redis = InMemoryRedis()
        service = FeatureVectorService(redis_client=redis)
        claims = _claims()
        vectors: list[list[float]] = []
        call_count = 0

        async def _step(*, method: str, path: str, route_pattern: str, ip: str, mark_deny: bool = False) -> None:
            nonlocal call_count
            call_count += 1
            # request_count (index 5) reuses ratelimit:user:{id}, which is
            # written by middleware/rate_limit.py BEFORE AuthorizationService
            # ever runs -- simulated here so this dimension varies the way it
            # would in the real pipeline, instead of sitting at a constant 0.
            await redis.incr(f"ratelimit:user:{claims.subject}")
            context = RequestContext(method=method, path=path, ip_address=ip, claims=claims)
            # Backdate started_at so latency_ms() varies across calls, the
            # way it would in production (JWT verify + rate-limit work
            # elapses between context creation and build_vector) instead of
            # reading ~0ms every time in this synchronous test.
            context.started_at -= call_count * 0.002
            vectors.append(await service.build_vector(context))
            await service.record_observation(context, route_pattern)
            if mark_deny:
                await service.record_deny(context)
            await asyncio.sleep(0.001)  # guarantees measurable, non-zero intervals

        await _step(method="GET", path="/documents/aaa", route_pattern="/documents/{document_id}", ip="10.0.0.1")
        await _step(method="GET", path="/documents/bbb", route_pattern="/documents/{document_id}", ip="10.0.0.1")
        await _step(method="POST", path="/orders", route_pattern="/orders", ip="10.0.0.2", mark_deny=True)
        await _step(method="PUT", path="/documents/aaa", route_pattern="/documents/{document_id}", ip="10.0.0.2")
        await _step(method="PATCH", path="/documents/bbb", route_pattern="/documents/{document_id}", ip="10.0.0.2")
        await _step(method="DELETE", path="/documents/ccc", route_pattern="/documents/{document_id}", ip="10.0.0.3")
        await service.record_auth_failure("203.0.113.5")
        await _step(method="GET", path="/orders", route_pattern="/orders", ip="203.0.113.5")

        assert all(len(v) == 16 for v in vectors)
        for index in range(16):
            column = {v[index] for v in vectors}
            assert len(column) > 1, f"dimension {index} is constant across varied inputs: {column}"

    asyncio.run(_run())


def test_scenario_a_resource_enumeration_diverges_route_pattern_from_raw_resource():
    # The signal scenario A's docstring (resource enumeration) depends on:
    # hitting distinct documents must grow raw-resource cardinality while
    # route-pattern cardinality stays pinned at 1 (same endpoint shape).
    async def _run():
        redis = InMemoryRedis()
        service = FeatureVectorService(redis_client=redis)
        claims = _claims()
        route_pattern = "/documents/{document_id}"

        for raw_path in ("/documents/aaa", "/documents/bbb", "/documents/ccc"):
            context = RequestContext(method="GET", path=raw_path, ip_address="10.0.0.1", claims=claims)
            await service.record_observation(context, route_pattern)

        probe = RequestContext(method="GET", path="/documents/ddd", ip_address="10.0.0.1", claims=claims)
        vector = await service.build_vector(probe)

        assert vector[6] == 1.0  # distinct route patterns
        assert vector[7] == 3.0  # distinct raw resources

    asyncio.run(_run())


def test_record_auth_failure_tracks_distinct_targeted_accounts():
    # The signal scenario B's docstring (password spraying) depends on: a
    # plain auth_failed:ip:{ip} counter can't tell "N failures on 1 account"
    # from "N failures across N accounts" -- confirmed empirically by a live
    # replay, where the counter alone was indistinguishable from bruteforce.
    async def _run():
        redis = InMemoryRedis()
        service = FeatureVectorService(redis_client=redis)

        for email in ("victim1@zt.local", "victim2@zt.local", "victim3@zt.local"):
            await service.record_auth_failure("203.0.113.9", attempted_email=email)

        assert await redis.get("auth_failed:ip:203.0.113.9") == "3"
        assert await redis.scard("auth_failed_accounts:ip:203.0.113.9") == 3

    asyncio.run(_run())


def test_record_auth_failure_without_email_still_increments_counter():
    # Backward-compatible: attempted_email is optional, existing callers that
    # don't pass it keep working exactly as before.
    async def _run():
        redis = InMemoryRedis()
        service = FeatureVectorService(redis_client=redis)

        await service.record_auth_failure("203.0.113.9")

        assert await redis.get("auth_failed:ip:203.0.113.9") == "1"
        assert await redis.scard("auth_failed_accounts:ip:203.0.113.9") == 0

    asyncio.run(_run())


def test_record_auth_failure_repeated_same_account_does_not_inflate_account_set():
    # The inverse shape: bruteforce (same account, repeated attempts) must NOT
    # look like spraying -- the set stays at size 1 regardless of how many
    # times the same email is retried.
    async def _run():
        redis = InMemoryRedis()
        service = FeatureVectorService(redis_client=redis)

        for _ in range(5):
            await service.record_auth_failure("203.0.113.9", attempted_email="victim1@zt.local")

        assert await redis.get("auth_failed:ip:203.0.113.9") == "5"
        assert await redis.scard("auth_failed_accounts:ip:203.0.113.9") == 1

    asyncio.run(_run())


def test_interval_mean_and_stddev_match_hand_computed_values():
    async def _run():
        redis = InMemoryRedis()
        service = FeatureVectorService(redis_client=redis)
        key = "intervals:user:test-user"

        timestamps = [1_700_000_000.0, 1_700_000_010.0, 1_700_000_025.0]
        for index, timestamp in enumerate(timestamps):
            await service._record_interval_timestamp(key, f"req-{index}", timestamp)

        mean, stddev = await service._interval_stats(key, now=1_700_000_030.0)

        diffs = [10.0, 15.0]
        assert mean == pytest.approx(statistics.fmean(diffs))
        assert stddev == pytest.approx(statistics.pstdev(diffs))

    asyncio.run(_run())


def test_interval_stats_with_fewer_than_two_timestamps_returns_documented_fallback():
    async def _run():
        redis = InMemoryRedis()
        service = FeatureVectorService(redis_client=redis)

        mean, stddev = await service._interval_stats("intervals:user:none", now=1_700_000_000.0)
        assert (mean, stddev) == (0.0, 0.0)

        await service._record_interval_timestamp("intervals:user:one", "req-0", 1_700_000_000.0)
        mean, stddev = await service._interval_stats("intervals:user:one", now=1_700_000_005.0)
        assert (mean, stddev) == (0.0, 0.0)

    asyncio.run(_run())


def test_set_ttl_is_set_only_at_creation_not_extended_by_later_members(monkeypatch):
    # Verified by monkeypatching InMemoryRedis's clock so time can be
    # advanced deterministically between two _set_add calls on the SAME key,
    # then asserting the TTL reflects only the first call's expiry -- a real
    # wall-clock sleep would make this slow and flaky instead of exact.
    async def _run():
        redis = InMemoryRedis()
        service = FeatureVectorService(redis_client=redis)
        key = "paths:user:test-user"
        current_time = {"value": datetime(2026, 1, 1, tzinfo=timezone.utc)}
        monkeypatch.setattr(InMemoryRedis, "_now", lambda self: current_time["value"])

        await service._set_add(key, "/documents")
        assert await redis.ttl(key) == WINDOW_SECONDS

        current_time["value"] += timedelta(seconds=200)
        await service._set_add(key, "/orders")  # a second, DISTINCT member

        assert await redis.ttl(key) == WINDOW_SECONDS - 200

    asyncio.run(_run())


def test_sequencing_current_requests_own_observation_is_not_visible_in_its_own_vector():
    # Mirrors AuthorizationService.authorize's call order exactly:
    # build_vector runs BEFORE record_observation for the SAME request --
    # otherwise the very first request in a window would inflate its own
    # anomaly signal. See app/services/authorization.py.
    async def _run():
        redis = InMemoryRedis()
        service = FeatureVectorService(redis_client=redis)
        claims = _claims()
        context = RequestContext(method="GET", path="/documents/aaa", ip_address="10.0.0.1", claims=claims)

        vector = await service.build_vector(context)
        await service.record_observation(context, "/documents/{document_id}")

        assert vector[6] == 0.0  # distinct route patterns: not yet recorded
        assert vector[7] == 0.0  # distinct raw resources: not yet recorded
        assert vector[13] == 0.0  # distinct IPs: not yet recorded

        # The ZSET specifically: this request's own timestamp must not have
        # entered its own interval computation.
        entries = await redis.zrange(f"intervals:user:{claims.subject}", 0, -1)
        assert len(entries) == 1  # written by record_observation, AFTER the read above

    asyncio.run(_run())
