from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from app.core.redis_client import InMemoryRedis
from app.core.security import VerifiedJWT
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext
from app.routers.auth import CSRF_HEADER_NAME, CSRF_HEADER_VALUE, router as auth_router
from app.services.auth import LoginResult, LoginStatus, RefreshResult, RefreshStatus
from app.services.feature_vector import FeatureVectorService
from app.services.token_service import hash_refresh_token
from test_auth_service import FakeRefreshTokenRepository, FakeUserRepository, _service, _user


@dataclass(slots=True)
class Recorder:
    items: list = field(default_factory=list)

    async def write(self, payload):
        self.items.append(payload)


@dataclass(slots=True)
class FakeAuthService:
    """Router-level unit tests fake AuthService entirely -- they're testing
    cookie/header wiring, not AuthService's own logic (that's
    test_auth_service.py's job). The end-to-end reuse-detection test below
    uses the REAL AuthService instead, to prove the two layers still compose
    correctly."""

    login_result: LoginResult | None = None
    refresh_results: list[RefreshResult] = field(default_factory=list)
    login_calls: list[tuple[str, str]] = field(default_factory=list)
    refresh_calls: list[str] = field(default_factory=list)
    logout_calls: list[str] = field(default_factory=list)

    async def login(self, email, password):
        self.login_calls.append((email, password))
        return self.login_result

    async def refresh(self, refresh_token):
        self.refresh_calls.append(refresh_token)
        return self.refresh_results.pop(0)

    async def logout(self, refresh_token):
        self.logout_calls.append(refresh_token)


def _build_app(
    auth_service, settings: GatewaySettings | None = None, *, ip_address: str = "127.0.0.1", redis=None
) -> FastAPI:
    app = FastAPI()

    # Stand-in for GatewayMiddleware's context injection -- the router reads
    # request.state.gateway_context on its event-logging branches. The full
    # middleware (JWT verify, rate limits, etc.) is irrelevant to these
    # router-only tests, which is why it isn't mounted here.
    @app.middleware("http")
    async def _inject_context(request: Request, call_next):
        request.state.gateway_context = SimpleNamespace(
            trace_id=uuid4(),
            ip_address=ip_address,
            method=request.method,
            path=request.url.path,
            latency_ms=lambda: 0,
        )
        return await call_next(request)

    # SimpleNamespace, not the real GatewayServices dataclass -- deliberate
    # for these router-only tests (see comment above): constructing a real
    # one would drag in JWTVerifier/Vault/OPA/DB wiring this file has no
    # business touching. Known tradeoff: a fake that doesn't require every
    # real field diverges silently as GatewayServices grows (a typo'd or
    # missing attribute here only fails at the call site, not loudly at
    # construction like the real dataclass would). Acceptable while the
    # surface stays this small; if this fake grows much further, switch to a
    # real GatewayServices with the unused fields stubbed.
    app.state.gateway_services = SimpleNamespace(
        auth_service=auth_service,
        event_logger=Recorder(),
        settings=settings or GatewaySettings(),
        feature_vector_service=FeatureVectorService(redis_client=redis if redis is not None else InMemoryRedis()),
    )
    app.include_router(auth_router)
    return app


def test_login_success_sets_httponly_cookie_and_body_has_no_refresh_token():
    auth_service = FakeAuthService(
        login_result=LoginResult(status=LoginStatus.SUCCESS, access_token="access-1", refresh_token="refresh-1", expires_in=900)
    )
    client = TestClient(_build_app(auth_service))

    response = client.post("/auth/login", json={"email": "a@zt.local", "password": "x"})

    assert response.status_code == 200
    body = response.json()
    assert body == {"access_token": "access-1", "token_type": "bearer", "expires_in": 900}
    assert "refresh_token" not in body

    set_cookie = response.headers.get("set-cookie")
    assert set_cookie is not None
    assert "refresh_token=refresh-1" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Path=/auth" in set_cookie
    # Dev defaults (GatewaySettings() with no env overrides).
    assert "Secure" not in set_cookie
    assert "samesite=lax" in set_cookie.lower()


def test_login_success_cookie_honors_secure_and_samesite_settings():
    auth_service = FakeAuthService(
        login_result=LoginResult(status=LoginStatus.SUCCESS, access_token="access-1", refresh_token="refresh-1", expires_in=900)
    )
    prod_settings = GatewaySettings(refresh_cookie_secure=True, refresh_cookie_samesite="none")
    client = TestClient(_build_app(auth_service, settings=prod_settings))

    response = client.post("/auth/login", json={"email": "a@zt.local", "password": "x"})

    set_cookie = response.headers.get("set-cookie")
    assert "Secure" in set_cookie
    assert "samesite=none" in set_cookie.lower()


def test_login_mfa_enrollment_required_has_no_cookie():
    auth_service = FakeAuthService(
        login_result=LoginResult(status=LoginStatus.MFA_ENROLLMENT_REQUIRED, enrollment_token="enroll-1")
    )
    client = TestClient(_build_app(auth_service))

    response = client.post("/auth/login", json={"email": "a@zt.local", "password": "x"})

    assert response.status_code == 200
    assert response.json()["mfa_enrollment_required"] is True
    assert response.headers.get("set-cookie") is None


def test_refresh_reads_cookie_rotates_and_sets_new_cookie():
    auth_service = FakeAuthService(
        refresh_results=[RefreshResult(status=RefreshStatus.SUCCESS, access_token="access-2", refresh_token="refresh-2", expires_in=900)]
    )
    client = TestClient(_build_app(auth_service))
    client.cookies.set("refresh_token", "refresh-1")

    response = client.post("/auth/refresh", headers={CSRF_HEADER_NAME: CSRF_HEADER_VALUE})

    assert response.status_code == 200
    assert response.json() == {"access_token": "access-2", "token_type": "bearer", "expires_in": 900}
    assert auth_service.refresh_calls == ["refresh-1"]
    set_cookie = response.headers.get("set-cookie")
    assert "refresh_token=refresh-2" in set_cookie


def test_refresh_without_csrf_header_is_rejected_and_never_calls_auth_service():
    auth_service = FakeAuthService()
    client = TestClient(_build_app(auth_service))
    client.cookies.set("refresh_token", "refresh-1")

    response = client.post("/auth/refresh")  # no CSRF header

    assert response.status_code == 403
    assert auth_service.refresh_calls == []


def test_refresh_with_wrong_csrf_header_value_is_rejected():
    auth_service = FakeAuthService()
    client = TestClient(_build_app(auth_service))
    client.cookies.set("refresh_token", "refresh-1")

    response = client.post("/auth/refresh", headers={CSRF_HEADER_NAME: "not-the-dashboard"})

    assert response.status_code == 403
    assert auth_service.refresh_calls == []


def test_refresh_with_no_cookie_at_all_returns_401_without_calling_auth_service():
    auth_service = FakeAuthService()
    client = TestClient(_build_app(auth_service))

    response = client.post("/auth/refresh", headers={CSRF_HEADER_NAME: CSRF_HEADER_VALUE})

    assert response.status_code == 401
    assert auth_service.refresh_calls == []


def test_refresh_invalid_token_returns_401_and_clears_cookie():
    auth_service = FakeAuthService(refresh_results=[RefreshResult(status=RefreshStatus.INVALID)])
    client = TestClient(_build_app(auth_service))
    client.cookies.set("refresh_token", "expired-or-unknown")

    response = client.post("/auth/refresh", headers={CSRF_HEADER_NAME: CSRF_HEADER_VALUE})

    assert response.status_code == 401
    set_cookie = response.headers.get("set-cookie")
    assert set_cookie is not None
    assert "refresh_token=" in set_cookie
    # Starlette's delete_cookie clears the value and zeroes Max-Age.
    assert "Max-Age=0" in set_cookie


def test_refresh_reuse_detected_returns_401_and_clears_cookie():
    auth_service = FakeAuthService(
        refresh_results=[RefreshResult(status=RefreshStatus.REUSE_DETECTED, user_id=uuid4(), family_id=uuid4())]
    )
    client = TestClient(_build_app(auth_service))
    client.cookies.set("refresh_token", "stolen-and-replayed")

    response = client.post("/auth/refresh", headers={CSRF_HEADER_NAME: CSRF_HEADER_VALUE})

    assert response.status_code == 401
    set_cookie = response.headers.get("set-cookie")
    assert set_cookie is not None
    assert "Max-Age=0" in set_cookie


def test_logout_revokes_server_side_and_clears_cookie():
    auth_service = FakeAuthService()
    client = TestClient(_build_app(auth_service))
    client.cookies.set("refresh_token", "refresh-1")

    response = client.post("/auth/logout", headers={CSRF_HEADER_NAME: CSRF_HEADER_VALUE})

    assert response.status_code == 200
    assert auth_service.logout_calls == ["refresh-1"]
    set_cookie = response.headers.get("set-cookie")
    assert set_cookie is not None
    assert "Max-Age=0" in set_cookie


def test_logout_without_csrf_header_is_rejected_and_never_revokes():
    auth_service = FakeAuthService()
    client = TestClient(_build_app(auth_service))
    client.cookies.set("refresh_token", "refresh-1")

    response = client.post("/auth/logout")  # no CSRF header

    assert response.status_code == 403
    assert auth_service.logout_calls == []


def test_logout_with_no_cookie_still_clears_cookie_and_does_not_call_auth_service():
    auth_service = FakeAuthService()
    client = TestClient(_build_app(auth_service))

    response = client.post("/auth/logout", headers={CSRF_HEADER_NAME: CSRF_HEADER_VALUE})

    assert response.status_code == 200
    assert auth_service.logout_calls == []
    assert response.headers.get("set-cookie") is not None


def test_reuse_detection_end_to_end_through_the_cookie_path():
    """The security property that matters most here: rotating the refresh
    token on every /auth/refresh, and revoking the whole family the instant a
    consumed token is replayed, is EXISTING behaviour (AuthService.refresh) --
    this proves it still works now that the token travels as a cookie instead
    of a JSON body field. Uses the REAL AuthService (wired to the same fakes
    test_auth_service.py uses), not FakeAuthService, so both layers -- router
    cookie handling and service-level reuse detection -- are exercised
    together."""
    user = _user()
    user_repo = FakeUserRepository(records_by_email={user.email: user})
    refresh_repo = FakeRefreshTokenRepository()
    real_auth_service = _service(user_repository=user_repo, refresh_token_repository=refresh_repo)

    family_id = uuid4()
    original_token = "original-refresh-token"
    asyncio.run(
        refresh_repo.create(
            hash_refresh_token(original_token), family_id, user.user_id, datetime.now(timezone.utc) + timedelta(days=7)
        )
    )

    client = TestClient(_build_app(real_auth_service))
    client.cookies.set("refresh_token", original_token)

    first = client.post("/auth/refresh", headers={CSRF_HEADER_NAME: CSRF_HEADER_VALUE})
    assert first.status_code == 200
    rotated_token = first.headers["set-cookie"].split("refresh_token=", 1)[1].split(";", 1)[0]
    assert rotated_token != original_token

    # Replay the ORIGINAL, now-consumed cookie -- e.g. a stolen copy used
    # after the legitimate client already rotated past it.
    client.cookies.set("refresh_token", original_token)
    second = client.post("/auth/refresh", headers={CSRF_HEADER_NAME: CSRF_HEADER_VALUE})

    assert second.status_code == 401
    assert "Max-Age=0" in second.headers["set-cookie"]
    for record in refresh_repo.records.values():
        if record.family_id == family_id:
            assert record.revoked is True

    # The token from the FIRST (legitimate) refresh must be dead too --
    # reuse detection revokes the entire family, not just the replayed token.
    client.cookies.set("refresh_token", rotated_token)
    third = client.post("/auth/refresh", headers={CSRF_HEADER_NAME: CSRF_HEADER_VALUE})
    assert third.status_code == 401


# auth_failed:ip:{ip} -- feature #11 in the rebuilt feature vector (see
# app/services/feature_vector.py). These tests cover both the write side
# (this router) and, at the bottom, the read side (build_vector), since a
# perfectly-incremented counter that build_vector never reads would leave
# both halves green while the actual signal never reaches OPA.


def test_invalid_credentials_increments_auth_failed_ip_counter():
    auth_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.INVALID_CREDENTIALS))
    redis = InMemoryRedis()
    client = TestClient(_build_app(auth_service, ip_address="203.0.113.9", redis=redis))

    response = client.post("/auth/login", json={"email": "a@zt.local", "password": "wrong"})

    assert response.status_code == 401
    assert asyncio.run(redis.get("auth_failed:ip:203.0.113.9")) == "1"


def test_auth_failed_ip_counter_accumulates_across_distinct_accounts_same_ip():
    # The password-spraying shape: one attacker IP, many different target
    # accounts, one failed attempt each -- see tools/traffic-generator's
    # scenario B, which already documents auth_failed:ip:{ip} as the
    # detection signal for exactly this pattern.
    redis = InMemoryRedis()
    for email in ("victim1@zt.local", "victim2@zt.local", "victim3@zt.local"):
        auth_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.INVALID_CREDENTIALS))
        client = TestClient(_build_app(auth_service, ip_address="203.0.113.9", redis=redis))
        response = client.post("/auth/login", json={"email": email, "password": "common-password"})
        assert response.status_code == 401

    assert asyncio.run(redis.get("auth_failed:ip:203.0.113.9")) == "3"


def test_invalid_credentials_records_attempted_email_for_spraying_detection():
    # A live replay of scenario B showed the plain counter above can't tell
    # spraying (many accounts) from bruteforce (one account, retried) -- this
    # is the fix: distinct accounts land in a separate Redis set, and the
    # attempted email is persisted in the events row too (the counter's TTL
    # expires long before an after-the-fact investigation would look).
    events = Recorder()
    redis = InMemoryRedis()
    for email in ("victim1@zt.local", "victim2@zt.local", "victim3@zt.local"):
        auth_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.INVALID_CREDENTIALS))
        app = _build_app(auth_service, ip_address="203.0.113.9", redis=redis)
        app.state.gateway_services.event_logger = events
        client = TestClient(app)
        response = client.post("/auth/login", json={"email": email, "password": "common-password"})
        assert response.status_code == 401

    assert asyncio.run(redis.scard("auth_failed_accounts:ip:203.0.113.9")) == 3
    assert [item.attempted_email for item in events.items] == [
        "victim1@zt.local",
        "victim2@zt.local",
        "victim3@zt.local",
    ]


def test_account_locked_also_counts_as_auth_failure_from_ip():
    auth_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.ACCOUNT_LOCKED))
    redis = InMemoryRedis()
    client = TestClient(_build_app(auth_service, ip_address="203.0.113.9", redis=redis))

    response = client.post("/auth/login", json={"email": "a@zt.local", "password": "wrong"})

    # 401, not 429 -- see test_account_locked_response_is_byte_identical_to_invalid_credentials
    # below for why this must be indistinguishable from a plain wrong password.
    assert response.status_code == 401
    assert asyncio.run(redis.get("auth_failed:ip:203.0.113.9")) == "1"


def test_account_locked_also_records_attempted_email():
    events = Recorder()
    auth_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.ACCOUNT_LOCKED))
    redis = InMemoryRedis()
    app = _build_app(auth_service, ip_address="203.0.113.9", redis=redis)
    app.state.gateway_services.event_logger = events
    client = TestClient(app)

    response = client.post("/auth/login", json={"email": "a@zt.local", "password": "wrong"})

    assert response.status_code == 401
    # The wire response no longer distinguishes locked from invalid, but the
    # audit trail written server-side still must -- an authenticated analyst
    # reading /monitoring/audit needs the real reason, even though the
    # unauthenticated caller never sees it.
    assert events.items[0].attempted_email == "a@zt.local"
    assert events.items[0].error_code == "account_locked"


def test_account_locked_response_is_byte_identical_to_invalid_credentials():
    """The actual regression test for the account-existence oracle: an
    unauthenticated caller must not be able to tell "wrong password" apart
    from "this real account is locked" -- only a real account can ever lock
    (see AuthService.login), so any distinguishable status/body here would
    let a caller enumerate registered emails by deliberately tripping the
    lockout threshold. Compares the two responses directly rather than just
    asserting each independently, so this fails loudly if either branch's
    response ever drifts from the other again."""
    locked_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.ACCOUNT_LOCKED))
    invalid_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.INVALID_CREDENTIALS))
    locked_client = TestClient(_build_app(locked_service, ip_address="203.0.113.10"))
    invalid_client = TestClient(_build_app(invalid_service, ip_address="203.0.113.11"))

    locked_response = locked_client.post("/auth/login", json={"email": "a@zt.local", "password": "wrong"})
    invalid_response = invalid_client.post("/auth/login", json={"email": "a@zt.local", "password": "wrong"})

    assert locked_response.status_code == invalid_response.status_code == 401
    assert locked_response.json() == invalid_response.json() == {"detail": "invalid credentials"}


def test_successful_login_does_not_touch_auth_failed_ip_counter():
    auth_service = FakeAuthService(
        login_result=LoginResult(status=LoginStatus.SUCCESS, access_token="a", refresh_token="r", expires_in=900)
    )
    redis = InMemoryRedis()
    client = TestClient(_build_app(auth_service, ip_address="203.0.113.9", redis=redis))

    client.post("/auth/login", json={"email": "a@zt.local", "password": "correct"})

    assert asyncio.run(redis.get("auth_failed:ip:203.0.113.9")) is None


def test_auth_failed_ip_counter_is_isolated_per_ip():
    # The property that justifies scoping on IP at all: every test above
    # uses a single IP, so a bug that keyed this counter globally (e.g.
    # "auth_failed" with no IP suffix) would pass every one of them while
    # silently merging distinct attackers -- or distinct innocent users
    # behind the same NAT -- into one counter.
    redis = InMemoryRedis()
    auth_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.INVALID_CREDENTIALS))
    client = TestClient(_build_app(auth_service, ip_address="203.0.113.9", redis=redis))

    client.post("/auth/login", json={"email": "victim@zt.local", "password": "wrong"})

    assert asyncio.run(redis.get("auth_failed:ip:203.0.113.9")) == "1"
    assert asyncio.run(redis.get("auth_failed:ip:203.0.113.10")) is None


def test_auth_failed_ip_counter_carries_a_ttl():
    # Without a TTL this becomes "failures ever", not "failures recently" --
    # exactly the sliding-vs-fixed-window bug Part B of the feature-vector
    # rebuild fixed for the Redis SETs. The counter path (_counter) already
    # sets TTL on creation; this asserts that guarantee actually holds for
    # this specific key.
    redis = InMemoryRedis()
    auth_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.INVALID_CREDENTIALS))
    client = TestClient(_build_app(auth_service, ip_address="203.0.113.9", redis=redis))

    client.post("/auth/login", json={"email": "a@zt.local", "password": "wrong"})

    ttl = asyncio.run(redis.ttl("auth_failed:ip:203.0.113.9"))
    assert 0 < ttl <= 300


def test_auth_failed_ip_counter_is_read_by_build_vector_at_correct_index():
    # Composition check: the router-side write (above) and the scoring-side
    # read (FeatureVectorService.build_vector) must agree on both the key
    # name and the vector position (index 14 -- see feature_vector.py's
    # module-level index map).
    redis = InMemoryRedis()
    auth_service = FakeAuthService(login_result=LoginResult(status=LoginStatus.INVALID_CREDENTIALS))
    client = TestClient(_build_app(auth_service, ip_address="203.0.113.9", redis=redis))
    for _ in range(3):
        client.post("/auth/login", json={"email": "victim@zt.local", "password": "wrong"})

    claims = VerifiedJWT(
        subject=uuid4(),
        issuer="zt-api-gateway",
        audience="zt-api",
        issued_at=1_700_000_000,
        expires_at=1_700_000_060,
        jti=uuid4(),
        role="reader",
        risk_ctx=None,
        raw_claims={},
    )
    context = RequestContext(method="GET", path="/documents", ip_address="203.0.113.9", claims=claims)

    vector = asyncio.run(FeatureVectorService(redis_client=redis).build_vector(context))

    assert len(vector) == 16
    assert vector[14] == 3.0
