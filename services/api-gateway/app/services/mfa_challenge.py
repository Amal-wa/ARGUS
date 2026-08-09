from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from app.core.redis_client import RedisLike
from app.core.repositories import UserMfaRepository
from app.core.request_matching import request_action
from app.core.security import VerifiedJWT
from app.core.settings import GatewaySettings
from app.core.totp import verify_totp
from app.middleware.context import RequestContext
from app.schemas.authorization import RiskScoreResult
from app.services.mfa_enrollment import MfaEnrollmentService


class MfaVerificationStatus(str, Enum):
    CHALLENGE_EXPIRED = "challenge_expired"
    NOT_ENROLLED = "not_enrolled"
    LOCKED = "locked"
    LOCKED_NOW = "locked_now"
    INVALID_CODE = "invalid_code"
    TOTP_REPLAYED = "totp_replayed"
    VERIFIED = "verified"


@dataclass(slots=True)
class ChallengeContext:
    user_id: UUID
    jti: UUID
    role: str
    resource: str
    action: str
    http_method: str
    trace_id: UUID
    ip_address: str
    risk_score: float | None
    model_version: str | None
    threshold: float | None

    def to_json(self) -> str:
        return json.dumps(
            {
                "user_id": str(self.user_id),
                "jti": str(self.jti),
                "role": self.role,
                "resource": self.resource,
                "action": self.action,
                "http_method": self.http_method,
                "trace_id": str(self.trace_id),
                "ip_address": self.ip_address,
                "risk_score": self.risk_score,
                "model_version": self.model_version,
                "threshold": self.threshold,
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> "ChallengeContext":
        data = json.loads(raw)
        return cls(
            user_id=UUID(data["user_id"]),
            jti=UUID(data["jti"]),
            role=data["role"],
            resource=data["resource"],
            action=data["action"],
            http_method=data["http_method"],
            trace_id=UUID(data["trace_id"]),
            ip_address=data["ip_address"],
            risk_score=data["risk_score"],
            model_version=data["model_version"],
            threshold=data.get("threshold"),
        )


@dataclass(slots=True)
class ChallengeVerificationResult:
    status: MfaVerificationStatus
    context: ChallengeContext | None = None


@dataclass(slots=True)
class MfaChallengeService:
    redis_client: RedisLike
    repository: UserMfaRepository
    enrollment: MfaEnrollmentService
    settings: GatewaySettings

    async def create_challenge(self, context: RequestContext, risk_ctx: RiskScoreResult) -> str | None:
        if context.claims is None:
            raise RuntimeError("challenge creation requires authenticated claims")

        record = await self.repository.get(context.claims.subject)
        if record is None:
            return None

        challenge_id = str(uuid4())
        challenge_context = ChallengeContext(
            user_id=context.claims.subject,
            jti=context.claims.jti,
            role=context.claims.role,
            # The route PATTERN, not the raw path -- must match exactly what
            # AuthorizationService.authorize computes for the retried request
            # (resolve_route_pattern), since it's what the action ticket gets
            # scoped to on successful verification. Falls back to the raw
            # path only defensively; route_pattern is always set by the time
            # authorize() has produced a step_up outcome.
            resource=context.route_pattern or context.path,
            action=request_action(context.method),
            http_method=context.method,
            trace_id=context.trace_id,
            ip_address=context.ip_address,
            risk_score=risk_ctx.risk_score,
            model_version=risk_ctx.model_version,
            threshold=risk_ctx.threshold,
        )
        await self.redis_client.set(
            f"challenge:{challenge_id}",
            challenge_context.to_json(),
            ex=self.settings.mfa_challenge_ttl_seconds,
        )
        return challenge_id

    async def verify_challenge(self, *, challenge_id: str, code: str, claims: VerifiedJWT) -> ChallengeVerificationResult:
        raw = await self.redis_client.get(f"challenge:{challenge_id}")
        if raw is None:
            return ChallengeVerificationResult(status=MfaVerificationStatus.CHALLENGE_EXPIRED)

        challenge_context = ChallengeContext.from_json(raw)
        if challenge_context.user_id != claims.subject:
            return ChallengeVerificationResult(status=MfaVerificationStatus.CHALLENGE_EXPIRED)

        # Session binding: the token resolving this challenge must be the
        # SAME token whose request triggered it. Without this, a second
        # valid token for the same user_id (stolen/leaked access token,
        # concurrent session) could resolve a challenge it never triggered
        # and inherit the resulting grace window -- same CHALLENGE_EXPIRED
        # treatment as the subject mismatch above, not a new status, since
        # from the caller's perspective it's the same "this isn't yours" case.
        if challenge_context.jti != claims.jti:
            return ChallengeVerificationResult(status=MfaVerificationStatus.CHALLENGE_EXPIRED)

        record = await self.repository.get(challenge_context.user_id)
        if record is None:
            return ChallengeVerificationResult(status=MfaVerificationStatus.NOT_ENROLLED)

        now = datetime.now(timezone.utc)
        if record.locked_until is not None and record.locked_until > now:
            return ChallengeVerificationResult(status=MfaVerificationStatus.LOCKED)

        secret = await self.enrollment.get_decrypted_secret(challenge_context.user_id)
        matched_step = verify_totp(secret, code)

        if matched_step is None:
            updated = await self.repository.record_failed_attempt(
                challenge_context.user_id,
                max_attempts=self.settings.mfa_max_failed_attempts,
                lockout_duration_minutes=self.settings.mfa_lockout_duration_minutes,
            )
            if updated.locked_until is not None:
                return ChallengeVerificationResult(status=MfaVerificationStatus.LOCKED_NOW)
            return ChallengeVerificationResult(status=MfaVerificationStatus.INVALID_CODE)

        replay_key = f"totp:used:{challenge_context.user_id}:{matched_step}"
        stored = await self.redis_client.set(replay_key, "1", ex=self.settings.totp_replay_ttl_seconds, nx=True)
        if not stored:
            return ChallengeVerificationResult(status=MfaVerificationStatus.TOTP_REPLAYED)

        await self.repository.reset_on_success(challenge_context.user_id)
        await self.redis_client.delete(f"challenge:{challenge_id}")

        # Single-use ticket, scoped to exactly the (user, jti, route pattern,
        # action) that was challenged -- always sufficient on its own,
        # regardless of sensitivity (see mfa.rego). Lets the client's retry
        # of the SAME original request through without relying on the
        # broader ambient grace window below.
        await self.redis_client.set(
            f"mfa:action_ticket:{challenge_context.user_id}:{challenge_context.jti}:"
            f"{challenge_context.resource}:{challenge_context.action}",
            "1",
            ex=self.settings.sensitive_action_ticket_ttl_seconds,
        )
        # Ambient grace window, now scoped to user_id:jti (not just
        # user_id) -- closes the cross-session leak. Still sufficient on its
        # own for non-sensitive step-ups (score-driven, high_distinct_ips);
        # mfa.rego is what enforces that it is NOT sufficient alone for a
        # sensitive_action.
        await self.redis_client.set(
            f"mfa:verified:{challenge_context.user_id}:{challenge_context.jti}",
            "1",
            ex=self.settings.mfa_verified_ttl_seconds,
        )
        return ChallengeVerificationResult(status=MfaVerificationStatus.VERIFIED, context=challenge_context)
