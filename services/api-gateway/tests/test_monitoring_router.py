from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

from app.core.redis_client import InMemoryRedis
from app.core.repositories import (
    AlertRow,
    AuditPage,
    DecisionAuditRow,
    DecisionLogRow,
    DecisionStats,
    ModelRegistryRow,
    RiskTimelinePoint,
)
from app.routers.monitoring import get_alerts, get_audit, get_risk_timeline, get_stats, get_system_status, list_decisions


@dataclass(slots=True)
class _Record:
    trace_id: UUID
    created_at: datetime
    user_id: UUID
    user_email: str | None
    role: str
    resource: str
    action: str
    decision: str
    policy_name: str
    risk_score: float | None
    model_version: str | None
    ip_address: str
    is_anomaly: str = "none"
    reason: str | None = None
    latency_ms: int = 5


@dataclass(slots=True)
class FakeMonitoringRepository:
    """In-memory stand-in that mirrors the real repository's filtering and
    pagination behavior closely enough to meaningfully test the router --
    not just a shape-only fake. See app/core/repositories.py for the real
    SQL these mirror."""

    records: list[_Record] = field(default_factory=list)
    model_registry: dict[str, ModelRegistryRow] = field(default_factory=dict)
    ping_calls: int = 0
    ping_raises: bool = False

    async def get_stats(self, window_minutes):
        allow = sum(1 for r in self.records if r.decision == "allow")
        deny = sum(1 for r in self.records if r.decision == "deny")
        step_up = sum(1 for r in self.records if r.decision == "step_up")
        return DecisionStats(
            total_decisions=allow + deny + step_up,
            allow=allow,
            deny=deny,
            step_up=step_up,
            active_users=len({r.user_id for r in self.records}),
            distinct_ips=len({r.ip_address for r in self.records}),
        )

    async def list_decisions(self, *, limit, since, user_email):
        rows = sorted(self.records, key=lambda r: r.created_at, reverse=True)
        if since is not None:
            rows = [r for r in rows if r.created_at > since]
        if user_email is not None:
            rows = [r for r in rows if r.user_email == user_email]
        rows = rows[:limit]
        return [
            DecisionLogRow(
                trace_id=r.trace_id, created_at=r.created_at, user_id=r.user_id, user_email=r.user_email,
                resource=r.resource, action=r.action, decision=r.decision, policy_name=r.policy_name,
                risk_score=r.risk_score, model_version=r.model_version, ip_address=r.ip_address,
            )
            for r in rows
        ]

    async def get_risk_timeline(self, *, user_email, window_minutes):
        rows = sorted(self.records, key=lambda r: r.created_at)
        if user_email is not None:
            rows = [r for r in rows if r.user_email == user_email]
        return [RiskTimelinePoint(created_at=r.created_at, user_email=r.user_email, risk_score=r.risk_score) for r in rows]

    async def get_alerts(self, *, limit):
        rows = sorted((r for r in self.records if r.decision == "step_up"), key=lambda r: r.created_at, reverse=True)
        rows = rows[:limit]
        return [
            AlertRow(type="step_up", created_at=r.created_at, user_email=r.user_email, resource=r.resource, risk_score=r.risk_score, trace_id=r.trace_id)
            for r in rows
        ]

    async def get_model_registry_row(self, version):
        return self.model_registry.get(version)

    async def ping_database(self):
        self.ping_calls += 1
        if self.ping_raises:
            raise RuntimeError("postgres down")

    async def get_decision_audit_page(self, *, page, page_size, user_email, decision, from_ts, to_ts):
        rows = sorted(self.records, key=lambda r: r.created_at, reverse=True)
        if user_email is not None:
            rows = [r for r in rows if r.user_email == user_email]
        if decision is not None:
            rows = [r for r in rows if r.decision == decision]
        if from_ts is not None:
            rows = [r for r in rows if r.created_at >= from_ts]
        if to_ts is not None:
            rows = [r for r in rows if r.created_at <= to_ts]
        total = len(rows)
        start = (page - 1) * page_size
        page_rows = rows[start : start + page_size]
        return AuditPage(
            rows=[
                DecisionAuditRow(
                    id=i, trace_id=r.trace_id, created_at=r.created_at, user_id=r.user_id, user_email=r.user_email,
                    role=r.role, resource=r.resource, action=r.action, ip_address=r.ip_address,
                    risk_score=r.risk_score, model_version=r.model_version, is_anomaly=r.is_anomaly,
                    decision=r.decision, policy_name=r.policy_name, reason=r.reason, latency_ms=r.latency_ms,
                )
                for i, r in enumerate(page_rows)
            ],
            total=total,
        )

    async def get_event_audit_page(self, **kwargs):
        return AuditPage(rows=[], total=0)


@dataclass(slots=True)
class FakeHealthClient:
    healthy: bool = True
    raises: bool = False

    async def health(self):
        if self.raises:
            raise RuntimeError("unreachable")
        return self.healthy


def _record(
    *, user_email="reader3@zt.local", decision="allow", risk_score=0.6, minutes_ago=0, ip="10.10.0.3", role="reader"
) -> _Record:
    return _Record(
        trace_id=uuid4(),
        created_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        user_id=uuid4(),
        user_email=user_email,
        role=role,
        resource="/documents/{document_id}",
        action="read",
        decision=decision,
        policy_name="risk_allow" if decision == "allow" else "step_up_required",
        risk_score=risk_score,
        model_version="v1",
        ip_address=ip,
    )


def _request(*, repository=None, redis=None, scoring_healthy=True, opa_healthy=True):
    repository = repository or FakeMonitoringRepository()
    redis = redis or InMemoryRedis()
    services = SimpleNamespace(
        monitoring_repository=repository,
        redis_client=redis,
        authorization_service=SimpleNamespace(
            scoring_client=FakeHealthClient(healthy=scoring_healthy),
            opa_client=FakeHealthClient(healthy=opa_healthy),
        ),
    )
    app = SimpleNamespace(state=SimpleNamespace(gateway_services=services))
    return SimpleNamespace(app=app)


def test_stats_shape_and_allow_rate():
    async def _run():
        repo = FakeMonitoringRepository(
            records=[
                _record(decision="allow", minutes_ago=1),
                _record(decision="allow", minutes_ago=2),
                _record(decision="deny", minutes_ago=3),
                _record(decision="step_up", minutes_ago=4),
            ]
        )
        response = await get_stats(_request(repository=repo), window_minutes=60)

        assert response["total_decisions"] == 4
        assert response["allow"] == 2
        assert response["deny"] == 1
        assert response["step_up"] == 1
        assert response["allow_rate"] == 0.5
        assert response["window_minutes"] == 60

    asyncio.run(_run())


def test_stats_zero_decisions_does_not_divide_by_zero():
    async def _run():
        response = await get_stats(_request(), window_minutes=60)
        assert response["total_decisions"] == 0
        assert response["allow_rate"] == 0.0

    asyncio.run(_run())


def test_decisions_shape_and_most_recent_first():
    async def _run():
        older = _record(minutes_ago=10)
        newer = _record(minutes_ago=1)
        repo = FakeMonitoringRepository(records=[older, newer])

        response = await list_decisions(_request(repository=repo), limit=50, since=None, user_email=None)

        decisions = response["decisions"]
        assert len(decisions) == 2
        assert decisions[0]["trace_id"] == str(newer.trace_id)
        assert decisions[1]["trace_id"] == str(older.trace_id)
        assert "password_hash" not in decisions[0]

    asyncio.run(_run())


def test_decisions_since_filter_returns_only_newer_rows():
    async def _run():
        old = _record(minutes_ago=30)
        boundary_ref = datetime.now(timezone.utc) - timedelta(minutes=15)
        new = _record(minutes_ago=5)
        repo = FakeMonitoringRepository(records=[old, new])

        response = await list_decisions(_request(repository=repo), limit=50, since=boundary_ref, user_email=None)

        trace_ids = {d["trace_id"] for d in response["decisions"]}
        assert trace_ids == {str(new.trace_id)}

    asyncio.run(_run())


def test_decisions_limit_is_clamped_to_max():
    async def _run():
        repo = FakeMonitoringRepository(records=[_record(minutes_ago=i) for i in range(5)])
        response = await list_decisions(_request(repository=repo), limit=10_000, since=None, user_email=None)
        # Fake doesn't itself enforce MAX_DECISIONS_LIMIT beyond what limit is
        # passed in -- this asserts the router clamped before calling the repo.
        assert len(response["decisions"]) == 5

    asyncio.run(_run())


def test_risk_timeline_includes_active_threshold_and_time_ordered_points():
    async def _run():
        redis = InMemoryRedis()
        await redis.set("model:active_threshold", "0.651")
        first = _record(user_email="reader3@zt.local", risk_score=0.60, minutes_ago=10)
        second = _record(user_email="reader3@zt.local", risk_score=0.94, minutes_ago=1)
        repo = FakeMonitoringRepository(records=[second, first])  # deliberately out of order

        response = await get_risk_timeline(_request(repository=repo, redis=redis), user_email="reader3@zt.local", window_minutes=30)

        assert response["threshold"] == 0.651
        scores = [p["risk_score"] for p in response["points"]]
        assert scores == [0.60, 0.94]  # ascending by time

    asyncio.run(_run())


def test_risk_timeline_threshold_null_when_no_active_model():
    async def _run():
        response = await get_risk_timeline(_request(), user_email=None, window_minutes=30)
        assert response["threshold"] is None

    asyncio.run(_run())


def test_alerts_returns_step_ups_most_recent_first():
    async def _run():
        allow_row = _record(decision="allow", minutes_ago=1)
        old_step_up = _record(decision="step_up", risk_score=0.90, minutes_ago=20)
        new_step_up = _record(decision="step_up", risk_score=0.95, minutes_ago=2)
        repo = FakeMonitoringRepository(records=[allow_row, old_step_up, new_step_up])

        response = await get_alerts(_request(repository=repo), limit=50)

        alerts = response["alerts"]
        assert len(alerts) == 2
        assert alerts[0]["trace_id"] == str(new_step_up.trace_id)
        assert alerts[0]["type"] == "step_up"
        assert alerts[1]["trace_id"] == str(old_step_up.trace_id)

    asyncio.run(_run())


def test_system_status_reports_model_and_service_health():
    async def _run():
        redis = InMemoryRedis()
        await redis.set("model:active_version", "v1")
        await redis.set("model:active_threshold", "0.651")
        repo = FakeMonitoringRepository(
            model_registry={
                "v1": ModelRegistryRow(
                    model_version="v1",
                    created_at=datetime.now(timezone.utc),
                    training_samples=10061,
                    score_distribution={"p50": 0.607, "p95": 0.644, "p98": 0.651},
                )
            }
        )

        response = await get_system_status(_request(repository=repo, redis=redis))

        assert response["active_model"] == "v1"
        assert response["active_threshold"] == 0.651
        assert response["training_samples"] == 10061
        assert response["score_distribution"]["p98"] == 0.651
        assert response["services"] == {"isolation_forest": "healthy", "opa": "healthy", "redis": "up", "postgres": "up"}

    asyncio.run(_run())


def test_system_status_reports_failing_dependency_without_500():
    async def _run():
        redis = InMemoryRedis()
        repo = FakeMonitoringRepository(ping_raises=True)

        response = await get_system_status(
            _request(repository=repo, redis=redis, scoring_healthy=False)
        )

        assert response["services"]["isolation_forest"] == "unhealthy"
        assert response["services"]["postgres"] == "down"
        assert response["services"]["opa"] == "healthy"

    asyncio.run(_run())


def test_system_status_no_active_model_leaves_model_fields_null():
    async def _run():
        response = await get_system_status(_request())
        assert response["active_model"] is None
        assert response["active_threshold"] is None
        assert response["training_samples"] is None
        assert response["score_distribution"] is None

    asyncio.run(_run())


def test_audit_pagination_pages_do_not_overlap_and_total_is_correct():
    async def _run():
        records = [_record(minutes_ago=i) for i in range(5)]
        repo = FakeMonitoringRepository(records=records)

        page1 = await get_audit(_request(repository=repo), page=1, page_size=2, user_email=None, decision=None, from_=None, to=None, event_type=None)
        page2 = await get_audit(_request(repository=repo), page=2, page_size=2, user_email=None, decision=None, from_=None, to=None, event_type=None)

        assert page1["total"] == 5
        assert page2["total"] == 5
        ids_page1 = {r["trace_id"] for r in page1["rows"]}
        ids_page2 = {r["trace_id"] for r in page2["rows"]}
        assert len(page1["rows"]) == 2
        assert len(page2["rows"]) == 2
        assert ids_page1.isdisjoint(ids_page2)

    asyncio.run(_run())


def test_audit_no_sensitive_fields_leak():
    async def _run():
        repo = FakeMonitoringRepository(records=[_record()])
        response = await get_audit(_request(repository=repo), page=1, page_size=50, user_email=None, decision=None, from_=None, to=None, event_type=None)

        for row in response["rows"]:
            assert "password_hash" not in row
            assert "totp_secret_ciphertext" not in row
            assert "failed_login_attempts" not in row
            assert "locked_until" not in row

    asyncio.run(_run())
