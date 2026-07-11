from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI

from app.core.redis_client import InMemoryRedis
from app.core.repositories import OpaDecisionRecord, TrainingSampleRecord
from app.core.security import VerifiedJWT
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

    service = AuthorizationService(
        redis_client=redis,
        opa_client=RecordingOpaClient(opa_result),
        scoring_client=RecordingScoringClient(scoring_result),
        feature_vector_service=FeatureVectorService(redis_client=redis),
        repository=RecordingRepository(),
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
