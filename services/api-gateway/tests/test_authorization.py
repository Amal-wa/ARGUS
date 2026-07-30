from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI

from app.core.redis_client import InMemoryRedis
from app.core.repositories import OpaDecisionRecord, TrainingSampleRecord
from app.core.security import VerifiedJWT
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext
from app.schemas.authorization import OpaDecision, OpaDecisionResult, RiskScoreResult
from app.services.authorization import AuthorizationService
from app.services.feature_vector import FeatureVectorService


@dataclass(slots=True)
class RecordingOpaClient:
    result: OpaDecisionResult
    payloads: list[object] = field(default_factory=list)

    async def decide(self, payload):
        self.payloads.append(payload)
        return self.result


@dataclass(slots=True)
class RecordingScoringClient:
    result: RiskScoreResult
    calls: int = 0

    async def score(self, feature_vector):
        self.calls += 1
        return self.result


@dataclass(slots=True)
class RecordingRepository:
    decisions: list[OpaDecisionRecord] = field(default_factory=list)
    samples: list[TrainingSampleRecord] = field(default_factory=list)

    async def write_decision(self, record):
        self.decisions.append(record)

    async def write_training_sample(self, record):
        self.samples.append(record)


def _claims() -> VerifiedJWT:
    return VerifiedJWT(
        subject=uuid4(),
        issuer="zt-api-gateway",
        audience="zt-api",
        issued_at=1_700_000_000,
        expires_at=1_700_000_060,
        jti=uuid4(),
        role="user",
        risk_ctx=None,
        raw_claims={},
    )


def _request(app: FastAPI, path: str = "/documents/123", method: str = "GET"):
    scope = {"type": "http", "method": method, "path": path, "headers": []}
    return SimpleNamespace(app=app, scope=scope, url=SimpleNamespace(path=path))


def _service(opa_result: OpaDecisionResult, scoring_result: RiskScoreResult, redis: InMemoryRedis | None = None):
    redis = redis or InMemoryRedis()
    app = FastAPI()

    @app.get("/documents/{document_id}")
    async def read_document(document_id: str):
        return {"document_id": document_id}

    @app.get("/monitoring/stats")
    async def monitoring_stats():
        return {"total_decisions": 0}

    service = AuthorizationService(
        redis_client=redis,
        opa_client=RecordingOpaClient(opa_result),
        scoring_client=RecordingScoringClient(scoring_result),
        feature_vector_service=FeatureVectorService(redis_client=redis),
        repository=RecordingRepository(),
        settings=GatewaySettings(),
    )
    return app, service


def test_authorize_allow_persists_decision_and_training_sample():
    async def _run():
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="policy.allow"),
            RiskScoreResult(risk_score=None, model_version=None),
        )
        context = RequestContext(method="GET", path="/documents/123", claims=_claims())
        request = _request(app)

        outcome = await service.authorize(request=request, context=context)

        assert outcome.decision == OpaDecision.ALLOW
        repo = service.repository
        assert len(repo.decisions) == 1
        assert len(repo.samples) == 1
        assert service.opa_client.payloads[0].resource.route == "/documents/{document_id}"
        assert service.opa_client.payloads[0].risk_ctx.score is None
        assert service.opa_client.payloads[0].mfa.verified is False
        assert service.opa_client.payloads[0].is_post_step_up is False
        # Must match the lowercase Postgres decision_type enum (allow/deny/step_up),
        # not the uppercase OpaDecision.value ("ALLOW") -- a real-DB-only bug the
        # RecordingRepository fake can't catch on its own.
        assert repo.decisions[0].decision == "allow"

    asyncio.run(_run())


def test_authorize_deny_does_not_persist_training_sample_and_tracks_deny():
    async def _run():
        redis = InMemoryRedis()
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.DENY, policy_name="policy.deny", reason="blocked"),
            RiskScoreResult(risk_score=0.7, model_version="model-1"),
            redis=redis,
        )
        context = RequestContext(method="POST", path="/documents/123", claims=_claims())
        request = _request(app, method="POST")

        outcome = await service.authorize(request=request, context=context)

        assert outcome.decision == OpaDecision.DENY
        assert len(service.repository.decisions) == 1
        assert len(service.repository.samples) == 0
        assert await redis.get(f"decisions:deny:{context.claims.subject}") == "1"

    asyncio.run(_run())


def test_authorize_first_step_up_request_uses_pre_step_up_payload():
    async def _run():
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="policy.allow.after.stepup"),
            RiskScoreResult(risk_score=0.2, model_version="model-2"),
        )
        context = RequestContext(method="GET", path="/documents/123", claims=_claims(), is_post_step_up=False)
        request = _request(app)

        outcome = await service.authorize(request=request, context=context)

        assert outcome.decision == OpaDecision.ALLOW
        assert len(service.repository.decisions) == 1
        assert len(service.repository.samples) == 1
        assert service.opa_client.payloads[0].is_post_step_up is False
        assert service.opa_client.payloads[0].mfa.verified is False

    asyncio.run(_run())


def test_authorize_post_step_up_request_marks_mfa_verified_and_post_step_up():
    async def _run():
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="policy.allow.after.stepup"),
            RiskScoreResult(risk_score=0.2, model_version="model-2"),
        )
        context = RequestContext(method="GET", path="/documents/123", claims=_claims(), is_post_step_up=True)
        request = _request(app)

        outcome = await service.authorize(request=request, context=context)

        assert outcome.decision == OpaDecision.ALLOW
        assert len(service.repository.decisions) == 1
        assert len(service.repository.samples) == 0
        assert service.opa_client.payloads[0].is_post_step_up is True
        assert service.opa_client.payloads[0].mfa.verified is True

    asyncio.run(_run())


def test_authorize_no_active_model_leaves_threshold_null():
    async def _run():
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="bootstrap_allow"),
            RiskScoreResult(risk_score=None, model_version=None),
        )
        context = RequestContext(method="GET", path="/documents/123", claims=_claims())
        request = _request(app)

        await service.authorize(request=request, context=context)

        assert service.opa_client.payloads[0].risk_ctx.score is None
        assert service.opa_client.payloads[0].risk_ctx.threshold is None
        assert service.scoring_client.calls == 0

    asyncio.run(_run())


def test_authorize_active_threshold_is_injected_into_opa_input():
    async def _run():
        redis = InMemoryRedis()
        await redis.set("model:active_version", "v1")
        await redis.set("model:active_threshold", "0.651")
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="risk_allow"),
            RiskScoreResult(risk_score=0.6, model_version="v1"),
            redis=redis,
        )
        context = RequestContext(method="GET", path="/documents/123", claims=_claims())
        request = _request(app)

        await service.authorize(request=request, context=context)

        assert service.opa_client.payloads[0].risk_ctx.threshold == pytest.approx(0.651)

    asyncio.run(_run())


def test_authorize_missing_threshold_with_active_model_uses_fallback_and_logs_warning(caplog):
    async def _run():
        redis = InMemoryRedis()
        await redis.set("model:active_version", "v1")
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="risk_allow"),
            RiskScoreResult(risk_score=0.6, model_version="v1"),
            redis=redis,
        )
        context = RequestContext(method="GET", path="/documents/123", claims=_claims())
        request = _request(app)

        with caplog.at_level(logging.WARNING):
            await service.authorize(request=request, context=context)

        assert service.opa_client.payloads[0].risk_ctx.threshold == pytest.approx(
            service.settings.fallback_step_up_threshold
        )
        assert any("model:active_threshold" in record.message for record in caplog.records)

    asyncio.run(_run())


def test_authorize_model_version_mismatch_uses_fallback_and_logs_warning(caplog):
    async def _run():
        redis = InMemoryRedis()
        await redis.set("model:active_version", "v2")
        await redis.set("model:active_threshold", "0.651")
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="risk_allow"),
            # isolation-forest hasn't hot-swapped to v2 yet -- still scoring with v1.
            RiskScoreResult(risk_score=0.6, model_version="v1"),
            redis=redis,
        )
        context = RequestContext(method="GET", path="/documents/123", claims=_claims())
        request = _request(app)

        with caplog.at_level(logging.WARNING):
            await service.authorize(request=request, context=context)

        assert service.opa_client.payloads[0].risk_ctx.threshold == pytest.approx(
            service.settings.fallback_step_up_threshold
        )
        assert any("model_version" in record.message for record in caplog.records)

    asyncio.run(_run())


def test_authorize_unparseable_threshold_with_active_model_uses_fallback_and_logs_warning(caplog):
    async def _run():
        redis = InMemoryRedis()
        await redis.set("model:active_version", "v1")
        await redis.set("model:active_threshold", "not-a-float")
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="risk_allow"),
            RiskScoreResult(risk_score=0.6, model_version="v1"),
            redis=redis,
        )
        context = RequestContext(method="GET", path="/documents/123", claims=_claims())
        request = _request(app)

        with caplog.at_level(logging.WARNING):
            await service.authorize(request=request, context=context)

        assert service.opa_client.payloads[0].risk_ctx.threshold == pytest.approx(
            service.settings.fallback_step_up_threshold
        )
        assert any("model:active_threshold" in record.message for record in caplog.records)

    asyncio.run(_run())


def test_authorize_monitoring_route_skips_scoring_and_training_sample():
    async def _run():
        redis = InMemoryRedis()
        await redis.set("model:active_version", "v1")
        await redis.set("model:active_threshold", "0.651")
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="bootstrap_allow"),
            RiskScoreResult(risk_score=0.9, model_version="v1"),  # would be a step_up-worthy score if scored
            redis=redis,
        )
        context = RequestContext(method="GET", path="/monitoring/stats", claims=_claims())
        request = _request(app, path="/monitoring/stats")

        outcome = await service.authorize(request=request, context=context)

        assert outcome.decision == OpaDecision.ALLOW
        # The category-error fix: isolation-forest must not be called at all
        # for /monitoring/*, even though a model is active.
        assert service.scoring_client.calls == 0
        assert service.opa_client.payloads[0].risk_ctx.score is None
        assert service.opa_client.payloads[0].risk_ctx.threshold is None
        # Contamination fix: no training sample from monitoring traffic, even on ALLOW.
        assert len(service.repository.samples) == 0

    asyncio.run(_run())


def test_authorize_monitoring_route_does_not_record_observation():
    async def _run():
        redis = InMemoryRedis()
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="bootstrap_allow"),
            RiskScoreResult(),
            redis=redis,
        )
        claims = _claims()
        context = RequestContext(method="GET", path="/monitoring/stats", claims=claims)
        request = _request(app, path="/monitoring/stats")

        await service.authorize(request=request, context=context)

        # record_observation would have populated these sliding-window keys --
        # they must stay untouched so the admin's HUMAN activity elsewhere
        # isn't distorted by this machine traffic.
        assert await redis.scard(f"paths:user:{claims.subject}") == 0
        assert await redis.get(f"requests:read:{claims.subject}") is None

    asyncio.run(_run())


def test_authorize_monitoring_route_still_verifies_jwt_and_writes_decision_log():
    async def _run():
        # AuthorizationService.authorize() is only ever invoked (by
        # GatewayMiddleware) AFTER JWT verification, both rate limits, and
        # the JTI blacklist check have already passed -- this test operates
        # at the AuthorizationService level, so it asserts what IS this
        # service's responsibility: OPA is still called and opa_decision_log
        # still gets a row, for a monitoring route exactly as for any other.
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="bootstrap_allow"),
            RiskScoreResult(),
        )
        context = RequestContext(method="GET", path="/monitoring/stats", claims=_claims())
        request = _request(app, path="/monitoring/stats")

        outcome = await service.authorize(request=request, context=context)

        assert outcome.decision == OpaDecision.ALLOW
        assert len(service.opa_client.payloads) == 1
        assert len(service.repository.decisions) == 1
        assert service.repository.decisions[0].resource == "/monitoring/stats"

    asyncio.run(_run())


def test_authorize_monitoring_route_deny_still_propagates():
    async def _run():
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.DENY, policy_name="rbac_deny"),
            RiskScoreResult(),
        )
        context = RequestContext(method="GET", path="/monitoring/stats", claims=_claims())
        request = _request(app, path="/monitoring/stats")

        outcome = await service.authorize(request=request, context=context)

        assert outcome.decision == OpaDecision.DENY
        assert outcome.response_payload == {"detail": "access denied"}
        assert service.scoring_client.calls == 0
        assert len(service.repository.samples) == 0

    asyncio.run(_run())


def test_authorize_non_monitoring_route_unaffected_still_scored_and_trained():
    async def _run():
        redis = InMemoryRedis()
        await redis.set("model:active_version", "v1")
        await redis.set("model:active_threshold", "0.651")
        app, service = _service(
            OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="risk_allow"),
            RiskScoreResult(risk_score=0.6, model_version="v1"),
            redis=redis,
        )
        context = RequestContext(method="GET", path="/documents/123", claims=_claims())
        request = _request(app, path="/documents/123")

        outcome = await service.authorize(request=request, context=context)

        assert outcome.decision == OpaDecision.ALLOW
        assert service.scoring_client.calls == 1
        assert service.opa_client.payloads[0].risk_ctx.score == pytest.approx(0.6)
        assert service.opa_client.payloads[0].risk_ctx.threshold == pytest.approx(0.651)
        assert len(service.repository.samples) == 1

    asyncio.run(_run())
