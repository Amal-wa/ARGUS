from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import Request

from app.core.errors import OpaUnavailableError
from app.core.isolation_forest_client import IsolationForestClient
from app.core.opa_client import OpaClient
from app.core.redis_client import RedisLike
from app.core.repositories import AuthorizationRepository, OpaDecisionRecord, TrainingSampleRecord
from app.core.request_matching import request_action, resolve_route_pattern
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext
from app.schemas.authorization import OpaDecision, OpaPolicyInput, RiskScoreResult
from app.services.feature_vector import FeatureVectorService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AuthorizationOutcome:
    decision: OpaDecision
    response_payload: dict[str, object] | None = None
    risk_ctx: RiskScoreResult | None = None


@dataclass(slots=True)
class AuthorizationService:
    redis_client: RedisLike
    opa_client: OpaClient
    scoring_client: IsolationForestClient
    feature_vector_service: FeatureVectorService
    repository: AuthorizationRepository
    settings: GatewaySettings

    async def authorize(self, request: Request, context: RequestContext) -> AuthorizationOutcome:
        if context.claims is None:
            raise RuntimeError("authorization requires validated JWT claims")

        route_pattern = resolve_route_pattern(request)
        action = request_action(context.method)

        feature_vector = await self.feature_vector_service.build_vector(context)
        await self.feature_vector_service.record_observation(context, route_pattern)

        active_model_version = await self.redis_client.get("model:active_version")
        risk_ctx = RiskScoreResult()
        threshold: float | None = None
        if active_model_version is not None:
            risk_ctx = await self.scoring_client.score(feature_vector)
            raw_threshold = await self.redis_client.get("model:active_threshold")
            if raw_threshold is None:
                threshold = self.settings.fallback_step_up_threshold
                logger.warning(
                    "model:active_threshold missing while model:active_version=%s is active; "
                    "falling back to configured threshold %.3f",
                    active_model_version,
                    threshold,
                    extra={"model_version": active_model_version, "fallback_threshold": threshold},
                )
            else:
                try:
                    threshold = float(raw_threshold)
                except ValueError:
                    threshold = self.settings.fallback_step_up_threshold
                    logger.warning(
                        "model:active_threshold %r is unparseable while model:active_version=%s is active; "
                        "falling back to configured threshold %.3f",
                        raw_threshold,
                        active_model_version,
                        threshold,
                        extra={"model_version": active_model_version, "fallback_threshold": threshold},
                    )

        mfa_verified = context.is_post_step_up
        verified_marker = await self.redis_client.get(f"mfa:verified:{context.claims.subject}")
        if verified_marker is not None:
            context.is_post_step_up = True
            mfa_verified = True

        opa_input = OpaPolicyInput(
            identity={"subject": context.claims.subject, "role": context.claims.role},
            resource={"http_method": context.method, "route": route_pattern, "action": action},
            risk_ctx={
                "score": risk_ctx.risk_score,
                "model_version": risk_ctx.model_version,
                "threshold": threshold,
            },
            mfa={"verified": mfa_verified},
            is_post_step_up=context.is_post_step_up,
            feature_vector=feature_vector,
        )

        decision = await self.opa_client.decide(opa_input)
        await self.repository.write_decision(
            OpaDecisionRecord(
                trace_id=context.trace_id,
                user_id=context.claims.subject,
                jti=context.claims.jti,
                role=context.claims.role,
                resource=route_pattern,
                action=action,
                ip_address=context.ip_address,
                risk_score=risk_ctx.risk_score,
                model_version=risk_ctx.model_version,
                decision=decision.decision.value.lower(),
                policy_name=decision.policy_name,
                reason=decision.reason,
                latency_ms=context.latency_ms(),
            )
        )

        if decision.decision == OpaDecision.ALLOW:
            if not context.is_post_step_up:
                await self.repository.write_training_sample(
                    TrainingSampleRecord(
                        trace_id=context.trace_id,
                        feature_vector=feature_vector,
                        risk_score=risk_ctx.risk_score,
                        model_version=risk_ctx.model_version,
                    )
                )
            return AuthorizationOutcome(decision=decision.decision, risk_ctx=risk_ctx)

        if decision.decision == OpaDecision.DENY:
            await self.feature_vector_service.record_deny(context)
            return AuthorizationOutcome(
                decision=decision.decision,
                response_payload={"detail": "access denied"},
                risk_ctx=risk_ctx,
            )

        return AuthorizationOutcome(
            decision=decision.decision,
            response_payload={"detail": "step_up_required"},
            risk_ctx=risk_ctx,
        )
