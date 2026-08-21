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

# /monitoring/* is the Argus dashboard's supervision plane, not business
# traffic -- and scoring it against the IsolationForest is a category error,
# not a borderline case. The model is trained on HUMAN traffic (15s-30min
# inter-request intervals, /documents and /orders paths). The dashboard is a
# MACHINE: ~5 req/2s, near-zero intervals, on paths never seen in training.
# High frequency + short intervals + unseen paths is exactly the enumeration
# signature the model is supposed to catch -- it correctly flags this traffic
# as anomalous, and step-up on the dashboard's own polling then locks out the
# very console meant to observe the system. Do not "fix" this by touching the
# model or the threshold: the fix is to not score a machine against a
# human baseline at all. Authentication (JWT), both rate limits, JTI
# blacklist, and OPA authorization (admin-only RBAC) all stay fully active
# for these routes -- only *scoring* and *training-set membership* are
# exempted, not access control or traceability. See AuthorizationService.authorize.
MONITORING_PATH_PREFIX = "/monitoring"


def _is_monitoring_route(route_pattern: str) -> bool:
    return route_pattern.startswith(MONITORING_PATH_PREFIX)


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
        is_monitoring_route = _is_monitoring_route(route_pattern)
        context.route_pattern = route_pattern

        feature_vector = await self.feature_vector_service.build_vector(context)
        if not is_monitoring_route:
            # Deliberately NOT called for /monitoring/*: recording this
            # machine traffic into the admin's own read/write/path/IP
            # sliding-window counters would distort the very feature vector
            # used to score that admin's OTHER (human) activity later.
            await self.feature_vector_service.record_observation(context, route_pattern)

        risk_ctx = RiskScoreResult()
        threshold: float | None = None
        model_ever_active = False
        if not is_monitoring_route:
            active_model_version = await self.redis_client.get("model:active_version")
            if active_model_version is not None:
                risk_ctx = await self.scoring_client.score(feature_vector)
                if risk_ctx.model_version is not None and risk_ctx.model_version != active_model_version:
                    # isolation-forest hasn't hot-swapped to the just-promoted
                    # version yet (poll lag, see model_store.poll_forever) --
                    # model:active_threshold was already calibrated for the
                    # NEW version, but this score was produced by the OLD one.
                    # Comparing the two would be meaningless, so treat this
                    # exactly like a missing threshold: fall back and warn,
                    # never silently compare mismatched model/threshold pairs.
                    threshold = self.settings.fallback_step_up_threshold
                    logger.warning(
                        "isolation-forest scored with model_version=%s but Gateway expected active "
                        "model_version=%s (promotion in-flight?); falling back to configured threshold %.3f",
                        risk_ctx.model_version,
                        active_model_version,
                        threshold,
                        extra={
                            "scored_model_version": risk_ctx.model_version,
                            "active_model_version": active_model_version,
                            "fallback_threshold": threshold,
                        },
                    )
                else:
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
            else:
                # model:active_version is unset -- either no model has ever
                # been trained (true bootstrap) or one WAS active and is now
                # missing (failed promotion, Redis key loss, incident).
                # model:ever_active is the one-way flag set once by
                # scripts/promote_model.py and never cleared; only read here,
                # not on the model-active path above, so this costs nothing
                # on the normal hot path.
                model_ever_active = await self.redis_client.get("model:ever_active") is not None
        # is_monitoring_route: risk_ctx stays RiskScoreResult() (score=None)
        # and threshold stays None -- OPA's bootstrap_mode (score == null)
        # short-circuits to "allow" before the threshold comparison is ever
        # reached, so step-up structurally cannot fire on these routes. No
        # Rego change needed; see adaptive_access.rego's bootstrap_mode rule.
        risk_ctx.threshold = threshold

        # Two independent, mechanical pieces of evidence -- Python never decides
        # which one is "enough" for THIS request; that stays Rego's call
        # (mfa.rego imports adaptive_access.sensitive_action directly). See
        # CLAUDE.md / SECURITY.md for the finding this closes: a single TOTP
        # used to unlock a 5-minute blank check for every subsequent sensitive
        # action, keyed only by user_id (not even by session).
        ticket_verified = context.is_post_step_up
        if not ticket_verified:
            ticket_key = f"mfa:action_ticket:{context.claims.subject}:{context.claims.jti}:{route_pattern}:{action}"
            # Single-use: DELETE-if-exists, not GET then DELETE -- a second
            # concurrent request for the same (user, jti, route, action) must
            # never both observe the ticket as present.
            ticket_verified = bool(await self.redis_client.delete(ticket_key))
        grace_marker = await self.redis_client.get(f"mfa:verified:{context.claims.subject}:{context.claims.jti}")
        grace_verified = grace_marker is not None

        if ticket_verified or grace_verified:
            context.is_post_step_up = True

        opa_input = OpaPolicyInput(
            identity={"subject": context.claims.subject, "role": context.claims.role},
            resource={"http_method": context.method, "route": route_pattern, "action": action},
            risk_ctx={
                "score": risk_ctx.risk_score,
                "model_version": risk_ctx.model_version,
                "threshold": risk_ctx.threshold,
                "model_ever_active": model_ever_active,
            },
            mfa={"ticket_verified": ticket_verified, "grace_verified": grace_verified},
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
            # Contamination fix: /monitoring/* traffic must never enter the
            # training set, even on ALLOW -- it's machine traffic and would
            # pollute a set built from human behavior (see MONITORING_PATH_PREFIX
            # comment above).
            if not context.is_post_step_up and not is_monitoring_route:
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
