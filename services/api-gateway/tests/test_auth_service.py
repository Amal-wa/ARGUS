from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from argon2 import PasswordHasher

from app.core.repositories import RefreshTokenRecord, UserRecord
from app.core.settings import GatewaySettings
from app.services.auth import AuthService, LoginStatus, RefreshStatus
from app.services.token_service import hash_refresh_token

_password_hasher = PasswordHasher()


@dataclass(slots=True)
class FakeUserRepository:
    records_by_email: dict[str, UserRecord] = field(default_factory=dict)

    async def get_by_email(self, email):
        return self.records_by_email.get(email)

    async def get_by_id(self, user_id):
        for record in self.records_by_email.values():
            if record.user_id == user_id:
                return record
        return None

    async def record_failed_login(self, user_id, *, max_attempts, lockout_minutes):
        record = next(r for r in self.records_by_email.values() if r.user_id == user_id)
        incremented = record.failed_login_attempts + 1
        if incremented >= max_attempts:
            record.failed_login_attempts = 0
            record.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        else:
            record.failed_login_attempts = incremented
        return record

    async def reset_login_attempts(self, user_id):
        record = next(r for r in self.records_by_email.values() if r.user_id == user_id)
        record.failed_login_attempts = 0
        record.locked_until = None


@dataclass(slots=True)
class FakeRefreshTokenRepository:
    records: dict[str, RefreshTokenRecord] = field(default_factory=dict)
    created: list[RefreshTokenRecord] = field(default_factory=list)

    async def create(self, token_hash, family_id, user_id, expires_at):
        record = RefreshTokenRecord(
            token_hash=token_hash,
            family_id=family_id,
            user_id=user_id,
            issued_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            used_at=None,
            revoked=False,
        )
        self.records[token_hash] = record
        self.created.append(record)

    async def get(self, token_hash):
        return self.records.get(token_hash)

    async def consume(self, token_hash):
        record = self.records.get(token_hash)
        if record is None:
            return False
        now = datetime.now(timezone.utc)
        if record.used_at is not None or record.revoked or record.expires_at <= now:
            return False
        record.used_at = now
        return True

    async def revoke_family(self, family_id):
        for record in self.records.values():
            if record.family_id == family_id:
                record.revoked = True


@dataclass(slots=True)
class FakeTokenService:
    issued_access_tokens: list[tuple[UUID, str]] = field(default_factory=list)
    issued_enrollment_tokens: list[tuple[UUID, str]] = field(default_factory=list)

    async def issue_access_token(self, *, user_id, role):
        self.issued_access_tokens.append((user_id, role))
        return f"access-token-for-{user_id}"

    async def issue_enrollment_token(self, *, user_id, role):
        self.issued_enrollment_tokens.append((user_id, role))
        return f"enrollment-token-for-{user_id}"

    def issue_refresh_token(self):
        token = f"refresh-token-{uuid4()}"
        token_hash = hash_refresh_token(token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        return token, token_hash, expires_at


@dataclass(slots=True)
class FakeUserMfaRepository:
    """Defaults to "everyone enrolled" so pre-existing SUCCESS-path tests are
    unaffected; pass enrolled=False to exercise the MFA-enrollment gate."""

    enrolled: bool = True

    async def get(self, user_id):
        return object() if self.enrolled else None


def _user(email="reader@zt.local", password="correct-horse-battery-staple", **overrides) -> UserRecord:
    defaults = dict(
        user_id=uuid4(),
        email=email,
        password_hash=_password_hasher.hash(password),
        role="reader",
        is_active=True,
        failed_login_attempts=0,
        locked_until=None,
    )
    defaults.update(overrides)
    return UserRecord(**defaults)


def _settings(**overrides) -> GatewaySettings:
    defaults = dict(login_max_failed_attempts=5, login_lockout_duration_minutes=15)
    defaults.update(overrides)
    return GatewaySettings(**defaults)


def _service(
    user_repository=None, refresh_token_repository=None, token_service=None, settings=None, user_mfa_repository=None
):
    return AuthService(
        user_repository=user_repository or FakeUserRepository(),
        refresh_token_repository=refresh_token_repository or FakeRefreshTokenRepository(),
        token_service=token_service or FakeTokenService(),
        settings=settings or _settings(),
        user_mfa_repository=user_mfa_repository or FakeUserMfaRepository(enrolled=True),
    )


def test_login_success_returns_tokens_and_resets_attempts():
    async def _run():
        user = _user(failed_login_attempts=2)
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        refresh_repo = FakeRefreshTokenRepository()
        service = _service(user_repository=user_repo, refresh_token_repository=refresh_repo)

        result = await service.login(user.email, "correct-horse-battery-staple")

        assert result.status == LoginStatus.SUCCESS
        assert result.access_token is not None
        assert result.refresh_token is not None
        assert result.expires_in == _settings().access_token_ttl_minutes * 60
        assert user.failed_login_attempts == 0
        assert len(refresh_repo.created) == 1

    asyncio.run(_run())


def test_login_wrong_password_records_failed_attempt():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        service = _service(user_repository=user_repo)

        result = await service.login(user.email, "wrong-password")

        assert result.status == LoginStatus.INVALID_CREDENTIALS
        assert user.failed_login_attempts == 1

    asyncio.run(_run())


def test_login_unknown_email_returns_generic_invalid_credentials():
    async def _run():
        service = _service()

        result = await service.login("nobody@zt.local", "whatever")

        assert result.status == LoginStatus.INVALID_CREDENTIALS

    asyncio.run(_run())


def test_login_inactive_user_returns_generic_invalid_credentials():
    async def _run():
        user = _user(is_active=False)
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        service = _service(user_repository=user_repo)

        result = await service.login(user.email, "correct-horse-battery-staple")

        assert result.status == LoginStatus.INVALID_CREDENTIALS

    asyncio.run(_run())


def test_login_locked_account_still_returns_account_locked_status_internally():
    async def _run():
        user = _user(locked_until=datetime.now(timezone.utc) + timedelta(minutes=5))
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        service = _service(user_repository=user_repo)

        result = await service.login(user.email, "wrong-password-does-not-matter")

        assert result.status == LoginStatus.ACCOUNT_LOCKED
        assert user.failed_login_attempts == 0  # untouched -- locked check short-circuits
        # LoginStatus.ACCOUNT_LOCKED is still returned to the CALLER of
        # AuthService.login (kept for internal audit-log accuracy -- see
        # routers/auth.py, which now maps it to the exact same external
        # response as INVALID_CREDENTIALS). This test only asserts the
        # service layer's own contract, not the HTTP response shape.

    asyncio.run(_run())


def test_login_locked_account_denies_even_with_correct_password():
    # Regression test for the account-existence oracle this fix closes: the
    # real Argon2id check now always runs (see AuthService.login), but its
    # result must still be ignored while locked -- a locked account must
    # deny access regardless of whether the password was actually correct.
    async def _run():
        user = _user(locked_until=datetime.now(timezone.utc) + timedelta(minutes=5))
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        service = _service(user_repository=user_repo)

        result = await service.login(user.email, "correct-horse-battery-staple")

        assert result.status == LoginStatus.ACCOUNT_LOCKED
        assert user.failed_login_attempts == 0

    asyncio.run(_run())


def test_login_fifth_failure_locks_account():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        service = _service(user_repository=user_repo, settings=_settings(login_max_failed_attempts=5))

        results = []
        for _ in range(5):
            results.append(await service.login(user.email, "wrong-password"))

        assert results[0].status == LoginStatus.INVALID_CREDENTIALS
        assert results[3].status == LoginStatus.INVALID_CREDENTIALS
        assert results[4].status == LoginStatus.ACCOUNT_LOCKED
        assert user.failed_login_attempts == 0
        assert user.locked_until is not None

    asyncio.run(_run())


def test_login_unenrolled_user_returns_enrollment_token_not_full_pair():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        refresh_repo = FakeRefreshTokenRepository()
        token_service = FakeTokenService()
        service = _service(
            user_repository=user_repo,
            refresh_token_repository=refresh_repo,
            token_service=token_service,
            user_mfa_repository=FakeUserMfaRepository(enrolled=False),
        )

        result = await service.login(user.email, "correct-horse-battery-staple")

        assert result.status == LoginStatus.MFA_ENROLLMENT_REQUIRED
        assert result.enrollment_token == f"enrollment-token-for-{user.user_id}"
        assert result.access_token is None
        assert result.refresh_token is None
        assert len(token_service.issued_enrollment_tokens) == 1
        assert len(token_service.issued_access_tokens) == 0
        assert len(refresh_repo.created) == 0

    asyncio.run(_run())


def test_login_enrolled_user_returns_full_pair_not_enrollment_token():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        service = _service(user_repository=user_repo, user_mfa_repository=FakeUserMfaRepository(enrolled=True))

        result = await service.login(user.email, "correct-horse-battery-staple")

        assert result.status == LoginStatus.SUCCESS
        assert result.access_token is not None
        assert result.refresh_token is not None
        assert result.enrollment_token is None

    asyncio.run(_run())


def test_issue_full_pair_used_by_login_and_directly_produce_identical_shape():
    async def _run():
        user = _user()
        refresh_repo = FakeRefreshTokenRepository()
        service = _service(refresh_token_repository=refresh_repo)

        direct = await service.issue_full_pair(user.user_id, user.role)

        assert direct.status == LoginStatus.SUCCESS
        assert direct.access_token is not None
        assert direct.refresh_token is not None
        assert len(refresh_repo.created) == 1
        assert refresh_repo.created[0].user_id == user.user_id

    asyncio.run(_run())


def test_refresh_happy_path_issues_new_pair_with_same_family_id():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        refresh_repo = FakeRefreshTokenRepository()
        service = _service(user_repository=user_repo, refresh_token_repository=refresh_repo)

        family_id = uuid4()
        token = "original-refresh-token"
        await refresh_repo.create(
            hash_refresh_token(token), family_id, user.user_id, datetime.now(timezone.utc) + timedelta(days=7)
        )

        result = await service.refresh(token)

        assert result.status == RefreshStatus.SUCCESS
        assert result.access_token is not None
        assert result.refresh_token is not None
        new_record = refresh_repo.created[-1]
        assert new_record.family_id == family_id

    asyncio.run(_run())


def test_refresh_expired_token_is_invalid():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        refresh_repo = FakeRefreshTokenRepository()
        service = _service(user_repository=user_repo, refresh_token_repository=refresh_repo)

        token = "expired-refresh-token"
        await refresh_repo.create(
            hash_refresh_token(token), uuid4(), user.user_id, datetime.now(timezone.utc) - timedelta(seconds=1)
        )

        result = await service.refresh(token)

        assert result.status == RefreshStatus.INVALID

    asyncio.run(_run())


def test_refresh_revoked_token_is_invalid():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        refresh_repo = FakeRefreshTokenRepository()
        service = _service(user_repository=user_repo, refresh_token_repository=refresh_repo)

        family_id = uuid4()
        token = "revoked-refresh-token"
        await refresh_repo.create(
            hash_refresh_token(token), family_id, user.user_id, datetime.now(timezone.utc) + timedelta(days=7)
        )
        await refresh_repo.revoke_family(family_id)

        result = await service.refresh(token)

        assert result.status == RefreshStatus.INVALID

    asyncio.run(_run())


def test_refresh_reuse_of_consumed_token_revokes_entire_family():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        refresh_repo = FakeRefreshTokenRepository()
        service = _service(user_repository=user_repo, refresh_token_repository=refresh_repo)

        family_id = uuid4()
        token = "original-refresh-token"
        token_hash = hash_refresh_token(token)
        await refresh_repo.create(token_hash, family_id, user.user_id, datetime.now(timezone.utc) + timedelta(days=7))

        first = await service.refresh(token)
        assert first.status == RefreshStatus.SUCCESS

        second = await service.refresh(token)

        assert second.status == RefreshStatus.REUSE_DETECTED
        # Every token of that family -- including the newly-issued one from the
        # first (legitimate) refresh -- must now be revoked.
        for record in refresh_repo.records.values():
            if record.family_id == family_id:
                assert record.revoked is True

    asyncio.run(_run())


def test_logout_revokes_the_presented_tokens_whole_family():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        refresh_repo = FakeRefreshTokenRepository()
        service = _service(user_repository=user_repo, refresh_token_repository=refresh_repo)

        family_id = uuid4()
        token = "logout-token"
        await refresh_repo.create(
            hash_refresh_token(token), family_id, user.user_id, datetime.now(timezone.utc) + timedelta(days=7)
        )

        await service.logout(token)

        for record in refresh_repo.records.values():
            if record.family_id == family_id:
                assert record.revoked is True

    asyncio.run(_run())


def test_logout_with_unknown_token_is_a_no_op():
    async def _run():
        refresh_repo = FakeRefreshTokenRepository()
        service = _service(refresh_token_repository=refresh_repo)

        await service.logout("never-issued-token")  # must not raise

        assert refresh_repo.records == {}

    asyncio.run(_run())


def test_refresh_concurrent_calls_with_same_token_only_one_succeeds():
    async def _run():
        user = _user()
        user_repo = FakeUserRepository(records_by_email={user.email: user})
        refresh_repo = FakeRefreshTokenRepository()
        service = _service(user_repository=user_repo, refresh_token_repository=refresh_repo)

        token = "contested-refresh-token"
        await refresh_repo.create(
            hash_refresh_token(token), uuid4(), user.user_id, datetime.now(timezone.utc) + timedelta(days=7)
        )

        results = await asyncio.gather(*[service.refresh(token) for _ in range(10)])

        successes = [r for r in results if r.status == RefreshStatus.SUCCESS]
        assert len(successes) == 1

    asyncio.run(_run())
