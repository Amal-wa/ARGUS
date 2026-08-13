from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace
from uuid import uuid4

from fastapi import Response

from app.core.errors import MfaAlreadyEnrolledError
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext
from app.routers.mfa import enroll_mfa, verify_mfa_challenge
from app.schemas.authorization import OpaDecision, OpaDecisionResult
from app.services.mfa_challenge import ChallengeContext, ChallengeVerificationResult, MfaVerificationStatus


@dataclass(slots=True)
class FakeMfaEnrollmentService:
    already_enrolled: bool = False
    enrolled_user_ids: list = field(default_factory=list)

    async def enroll(self, user_id):
        if self.already_enrolled:
            raise MfaAlreadyEnrolledError(f"{user_id} already enrolled")
        self.enrolled_user_ids.append(user_id)
        return "BASE32SECRETXXXX"


@dataclass(slots=True)
class FakeAuthService:
    calls: list = field(default_factory=list)

    async def issue_full_pair(self, user_id, role):
        self.calls.append((user_id, role))
        return SimpleNamespace(
            access_token=f"access-for-{user_id}", refresh_token=f"refresh-for-{user_id}", expires_in=900
        )


def _request(mfa_enrollment_service, auth_service, *, subject=None, role="reader"):
    services = SimpleNamespace(
        mfa_enrollment_service=mfa_enrollment_service, auth_service=auth_service, settings=GatewaySettings()
    )
    app = SimpleNamespace(state=SimpleNamespace(gateway_services=services))
    context = RequestContext(claims=SimpleNamespace(subject=subject or uuid4(), role=role))
    return SimpleNamespace(app=app, state=SimpleNamespace(gateway_context=context))


def test_enroll_success_issues_full_pair_and_sets_refresh_cookie():
    async def _run():
        mfa_service = FakeMfaEnrollmentService()
        auth_service = FakeAuthService()
        user_id = uuid4()
        request = _request(mfa_service, auth_service, subject=user_id, role="reader")
        response = Response()

        body = await enroll_mfa(request, response)

        assert body["secret"] == "BASE32SECRETXXXX"
        assert "otpauth_uri" in body
        assert body["access_token"] == f"access-for-{user_id}"
        assert "refresh_token" not in body
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == 900
        assert auth_service.calls == [(user_id, "reader")]
        assert mfa_service.enrolled_user_ids == [user_id]

        set_cookie = response.headers.get("set-cookie")
        assert set_cookie is not None
        assert f"refresh_token=refresh-for-{user_id}" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "Path=/auth" in set_cookie

    asyncio.run(_run())


def test_enroll_already_enrolled_returns_409_and_does_not_issue_pair():
    async def _run():
        mfa_service = FakeMfaEnrollmentService(already_enrolled=True)
        auth_service = FakeAuthService()
        request = _request(mfa_service, auth_service)

        response = await enroll_mfa(request, Response())

        assert response.status_code == 409
        assert auth_service.calls == []

    asyncio.run(_run())


@dataclass(slots=True)
class FakeMfaChallengeService:
    result: ChallengeVerificationResult

    async def verify_challenge(self, *, challenge_id, code, claims):
        return self.result


@dataclass(slots=True)
class RecordingOpaClient:
    result: OpaDecisionResult
    payloads: list = field(default_factory=list)

    async def decide(self, payload):
        self.payloads.append(payload)
        return self.result


@dataclass(slots=True)
class ExplodingRepository:
    """Fails the test the moment anything calls write_decision -- this
    endpoint verifies a challenge, it doesn't itself record an access
    attempt against opa_decision_log. That row belongs solely to the
    caller's own retry of the originally-challenged request, once it
    actually happens, via AuthorizationService.authorize."""

    async def write_decision(self, record):
        raise AssertionError("verify_mfa_challenge must not write to opa_decision_log itself")


class _FakeEventLogger:
    async def write(self, payload):
        pass


class _VerifyRequest:
    def __init__(self, app, context, challenge_id, code):
        self.app = app
        self.state = SimpleNamespace(gateway_context=context)
        self._body = {"challenge_id": challenge_id, "code": code}

    async def json(self):
        return self._body


def _verify_request(mfa_challenge_service, opa_client, *, challenge_id="chal-1", code="123456"):
    authorization_service = SimpleNamespace(opa_client=opa_client, repository=ExplodingRepository())
    services = SimpleNamespace(
        mfa_challenge_service=mfa_challenge_service,
        authorization_service=authorization_service,
        event_logger=_FakeEventLogger(),
    )
    app = SimpleNamespace(state=SimpleNamespace(gateway_services=services))
    context = RequestContext(claims=SimpleNamespace(subject=uuid4(), role="reader"))
    return _VerifyRequest(app, context, challenge_id, code)


def test_verify_success_does_not_double_log_the_speculative_decision():
    # Regression test: this endpoint used to call opa_client.decide() AND
    # independently write_decision() for the ORIGINAL challenged request,
    # even though that request hasn't actually been retried yet -- the
    # caller's real retry (once it happens) goes through
    # AuthorizationService.authorize, which logs its own row for the same
    # (trace_id, resource) via ticket_verified/grace_verified. Both writers
    # produced a decision=allow/policy_name=mfa_verified_allow row with
    # different trace_ids for what looked like one access -- confirmed live
    # via the dashboard's Audit log: resolving one step-up logged two allow
    # rows, even though the Gateway's own access log showed only the single
    # real retried GET. ExplodingRepository below fails loudly if this
    # endpoint ever touches write_decision again.
    async def _run():
        challenge_context = ChallengeContext(
            user_id=uuid4(),
            jti=uuid4(),
            role="reader",
            resource="/monitoring/audit",
            action="read",
            http_method="GET",
            trace_id=uuid4(),
            ip_address="127.0.0.1",
            risk_score=None,
            model_version=None,
            threshold=None,
        )
        mfa_service = FakeMfaChallengeService(
            ChallengeVerificationResult(status=MfaVerificationStatus.VERIFIED, context=challenge_context)
        )
        opa_client = RecordingOpaClient(OpaDecisionResult(decision=OpaDecision.ALLOW, policy_name="mfa_verified_allow"))
        request = _verify_request(mfa_service, opa_client)

        body = await verify_mfa_challenge(request)

        assert body == {"decision": "allow"}
        # opa_client.decide was still called (the endpoint's actual job:
        # answer "would this now be allowed") -- only the persistence to
        # opa_decision_log was removed.
        assert len(opa_client.payloads) == 1

    asyncio.run(_run())
