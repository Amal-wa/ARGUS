from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.core.errors import MfaAlreadyEnrolledError
from app.core.events import EventPayload
from app.core.refresh_cookie import set_refresh_cookie
from app.schemas.authorization import OpaPolicyInput
from app.services.mfa_challenge import MfaVerificationStatus

router = APIRouter()

_OTP_ISSUER = "ZT-Gateway"


@router.post("/mfa/enroll")
async def enroll_mfa(request: Request, response: Response):
    context = request.state.gateway_context
    services = request.app.state.gateway_services

    try:
        base32_secret = await services.mfa_enrollment_service.enroll(context.claims.subject)
    except MfaAlreadyEnrolledError:
        return JSONResponse({"detail": "mfa_already_enrolled"}, status_code=409)

    # Expected caller is an `mfa_enrollment`-scoped token (the Gateway confines
    # it to this path; see GatewayMiddleware) -- but a normal, already-full
    # access token calling this defensively also works and is never refused:
    # `mfa_enrollment_service.enroll` above already raises MfaAlreadyEnrolledError
    # for the (post-fix, expected) case where that caller is already enrolled,
    # so this line is only reached for a genuinely first-time enrollment either
    # way. No user is ever locked out by this endpoint.
    pair = await services.auth_service.issue_full_pair(context.claims.subject, context.claims.role)

    # Same rule as POST /auth/login: the refresh token issued here is a full
    # session credential exactly like a normal login's, so it gets the same
    # httpOnly-cookie treatment, not a JSON body field -- `response` is
    # FastAPI's injected mutable Response, whose headers are merged into the
    # final response even though this handler returns a plain dict below.
    set_refresh_cookie(response, pair.refresh_token, request)

    account = str(context.claims.subject)
    otpauth_uri = (
        f"otpauth://totp/{quote(_OTP_ISSUER)}:{quote(account)}"
        f"?secret={base32_secret}&issuer={quote(_OTP_ISSUER)}&digits=6&period=30"
    )
    return {
        "secret": base32_secret,
        "otpauth_uri": otpauth_uri,
        "access_token": pair.access_token,
        "token_type": "bearer",
        "expires_in": pair.expires_in,
    }


@router.post("/mfa/challenge/verify")
async def verify_mfa_challenge(request: Request):
    body = await request.json()
    challenge_id = body.get("challenge_id")
    code = body.get("code")

    context = request.state.gateway_context
    services = request.app.state.gateway_services

    result = await services.mfa_challenge_service.verify_challenge(
        challenge_id=challenge_id, code=code, claims=context.claims
    )

    if result.status == MfaVerificationStatus.CHALLENGE_EXPIRED:
        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=context.claims.subject,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=401,
                event_type="challenge_expired",
                error_code="challenge_expired",
                error_message="MFA challenge missing, expired, or user mismatch",
            )
        )
        return JSONResponse({"detail": "challenge_expired"}, status_code=401)

    if result.status == MfaVerificationStatus.NOT_ENROLLED:
        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=context.claims.subject,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=403,
                event_type="mfa_failed",
                error_code="mfa_not_enrolled",
                error_message="MFA challenge verify attempted with no user_mfa row",
            )
        )
        return JSONResponse({"detail": "mfa_not_configured"}, status_code=403)

    if result.status in (MfaVerificationStatus.LOCKED, MfaVerificationStatus.LOCKED_NOW):
        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=context.claims.subject,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=429,
                event_type="mfa_locked",
                error_code="mfa_locked",
                error_message="MFA attempts locked out",
            )
        )
        return JSONResponse({"detail": "mfa_locked"}, status_code=429)

    if result.status == MfaVerificationStatus.INVALID_CODE:
        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=context.claims.subject,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=401,
                event_type="mfa_failed",
                error_code="mfa_failed",
                error_message="Invalid TOTP code",
            )
        )
        return JSONResponse({"detail": "invalid_code"}, status_code=401)

    if result.status == MfaVerificationStatus.TOTP_REPLAYED:
        await services.event_logger.write(
            EventPayload(
                trace_id=context.trace_id,
                user_id=context.claims.subject,
                ip_address=context.ip_address,
                http_method=context.method,
                request_path=context.path,
                latency_ms=context.latency_ms(),
                http_status=403,
                event_type="totp_replay_detected",
                error_code="totp_replay_detected",
                error_message="TOTP code already used",
            )
        )
        return JSONResponse({"detail": "totp_replayed"}, status_code=403)

    # VERIFIED: re-evaluate OPA using the original, stored risk_ctx -- no
    # recomputation -- purely to answer "would the originally-challenged
    # request now be allowed", so the caller knows whether retrying it is
    # worthwhile. This does NOT persist to opa_decision_log: that row
    # belongs to an actual resource access, and none has happened yet here
    # -- verifying a challenge isn't itself a request against
    # challenge_context.resource. The single-use ticket set by
    # verify_challenge above is what makes the caller's actual retry (the
    # real GET/POST/etc. against that resource) succeed and get logged
    # exactly once, by AuthorizationService.authorize itself. Persisting a
    # second, speculative decision here duplicated that one -- both showed
    # decision=allow/policy_name=mfa_verified_allow with different trace_ids,
    # since this code path and the retried request's authorize() call are
    # two independent writers of what's supposed to be a one-row-per-access
    # log (caught live: opening the dashboard's Audit log, resolving the
    # step-up, and watching /monitoring/audit's own retry produced two rows
    # instead of one -- confirmed via uvicorn's access log showing only the
    # single real GET).
    challenge_context = result.context
    opa_input = OpaPolicyInput(
        identity={"subject": challenge_context.user_id, "role": challenge_context.role},
        resource={
            "http_method": challenge_context.http_method,
            "route": challenge_context.resource,
            "action": challenge_context.action,
        },
        risk_ctx={
            "score": challenge_context.risk_score,
            "model_version": challenge_context.model_version,
            "threshold": challenge_context.threshold,
        },
        # We know verification just succeeded in this same call --
        # ticket_verified=True is always sufficient regardless of
        # sensitivity (see mfa.rego), so no need to re-derive from Redis.
        mfa={"ticket_verified": True, "grace_verified": False},
        is_post_step_up=True,
    )
    decision = await services.authorization_service.opa_client.decide(opa_input)

    if decision.decision.name == "ALLOW":
        return {"decision": "allow"}
    return JSONResponse({"decision": "deny"}, status_code=403)
