from __future__ import annotations

from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class OpaDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"


class IdentityContext(BaseModel):
    subject: UUID
    role: str


class ResourceContext(BaseModel):
    http_method: str
    route: str
    action: str


class RiskContext(BaseModel):
    score: float | None = None
    model_version: str | None = None
    threshold: float | None = None
    # True once ANY model has ever been promoted (Redis model:ever_active,
    # set once by scripts/promote_model.py and never cleared). Lets
    # adaptive_access.rego's model_unavailable rule tell "no model has ever
    # been trained" (bootstrap_mode, permissive) apart from "a model WAS
    # active and risk_ctx.score is null now anyway" (model:active_version
    # lost -- failed promotion, Redis key loss, incident -- must force
    # step_up instead of silently falling back to bootstrap-allow). See
    # AuthorizationService.authorize.
    model_ever_active: bool = False


class MfaContext(BaseModel):
    # Two raw, mechanical pieces of evidence -- deliberately not a single
    # pre-combined "verified" boolean. Whether either one counts as
    # sufficient for THIS request is Rego's call (policies/risk/mfa.rego
    # imports adaptive_access.sensitive_action to decide), not Python's --
    # see CLAUDE.md for why a pre-merged boolean here would either duplicate
    # that policy in Python or force a second OPA round-trip.
    ticket_verified: bool = False
    grace_verified: bool = False


class OpaPolicyInput(BaseModel):
    identity: IdentityContext
    resource: ResourceContext
    risk_ctx: RiskContext = Field(default_factory=RiskContext)
    mfa: MfaContext = Field(default_factory=MfaContext)
    is_post_step_up: bool = False
    feature_vector: list[float] = Field(default_factory=list)


class OpaDecisionResult(BaseModel):
    decision: OpaDecision
    policy_name: str = "default"
    reason: str | None = None


class RiskScoreResult(BaseModel):
    risk_score: float | None = None
    model_version: str | None = None
    threshold: float | None = None
