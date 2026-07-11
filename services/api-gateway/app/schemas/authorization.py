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


class OpaPolicyInput(BaseModel):
    identity: IdentityContext
    resource: ResourceContext
    risk_ctx: RiskContext = Field(default_factory=RiskContext)
    is_post_step_up: bool = False
    feature_vector: list[float] = Field(default_factory=list)


class OpaDecisionResult(BaseModel):
    decision: OpaDecision
    policy_name: str = "default"
    reason: str | None = None


class RiskScoreResult(BaseModel):
    risk_score: float | None = None
    model_version: str | None = None
