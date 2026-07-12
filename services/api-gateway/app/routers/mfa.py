from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.errors import MfaAlreadyEnrolledError
from app.core.events import EventPayload
from app.core.repositories import OpaDecisionRecord
from app.schemas.authorization import OpaPolicyInput
from app.services.mfa_challenge import MfaVerificationStatus

router = APIRouter()

_OTP_ISSUER = "ZT-Gateway"


@router.post("/mfa/enroll")
async def enroll_mfa(request: Request):
    context = request.state.gateway_context
    services = request.app.state.gateway_services

    try:
        base32_secret = await services.mfa_enrollment_service.enroll(context.claims.subject)
    except MfaAlreadyEnrolledError:
        return JSONResponse({"detail": "mfa_already_enrolled"}, status_code=409)

    account = str(context.claims.subject)
    otpauth_uri = (
        f"otpauth://totp/{quote(_OTP_ISSUER)}:{quote(account)}"
        f"?secret={base32_secret}&issuer={quote(_OTP_ISSUER)}&digits=6&period=30"
    )
    return {"secret": base32_secret, "otpauth_uri": otpauth_uri}


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

    # VERIFIED: re-evaluate OPA using the original, stored risk_ctx -- no recomputation.
    challenge_context = result.context
    opa_input = OpaPolicyInput(
        identity={"subject": challenge_context.user_id, "role": challenge_context.role},
        resource={
            "http_method": challenge_context.http_method,
            "route": challenge_context.resource,
            "action": challenge_context.action,
        },
        risk_ctx={"score": challenge_context.risk_score, "model_version": challenge_context.model_version},
        mfa={"verified": True},
        is_post_step_up=True,
    )
    decision = await services.authorization_service.opa_client.decide(opa_input)
    await services.authorization_service.repository.write_decision(
        OpaDecisionRecord(
            trace_id=challenge_context.trace_id,
            user_id=challenge_context.user_id,
            jti=challenge_context.jti,
            role=challenge_context.role,
            resource=challenge_context.resource,
            action=challenge_context.action,
            ip_address=challenge_context.ip_address,
            risk_score=challenge_context.risk_score,
            model_version=challenge_context.model_version,
            decision=decision.decision.value.lower(),
            policy_name=decision.policy_name,
            reason=decision.reason,
            latency_ms=context.latency_ms(),
        )
    )

    if decision.decision.name == "ALLOW":
        return {"decision": "allow"}
    return JSONResponse({"decision": "deny"}, status_code=403)
