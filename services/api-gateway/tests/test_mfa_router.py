from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace
from uuid import uuid4

from fastapi import Response

from app.core.errors import MfaAlreadyEnrolledError
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext
from app.routers.mfa import enroll_mfa


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
