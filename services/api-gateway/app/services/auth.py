from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.core.repositories import RefreshTokenRepository, UserRepository
from app.core.settings import GatewaySettings
from app.services.token_service import TokenService, hash_refresh_token

_password_hasher = PasswordHasher()

# Verified (and discarded) whenever the user doesn't exist / isn't active, so that
# login latency is the same whether or not the email is registered -- otherwise
# the timing difference (skip vs. run Argon2id) leaks account existence.
_DUMMY_PASSWORD_HASH = _password_hasher.hash("dummy-password-never-matches-anything")


def _verify_password_constant_time(password_hash: str, password: str) -> bool:
    try:
        _password_hasher.verify(password_hash, password)
        return True
    except Exception:
        return False


class LoginStatus(str, Enum):
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"


class RefreshStatus(str, Enum):
    SUCCESS = "success"
    INVALID = "invalid"
    REUSE_DETECTED = "reuse_detected"


@dataclass(slots=True)
class LoginResult:
    status: LoginStatus
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None


@dataclass(slots=True)
class RefreshResult:
    status: RefreshStatus
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    user_id: UUID | None = None
    family_id: UUID | None = None


@dataclass(slots=True)
class AuthService:
    user_repository: UserRepository
    refresh_token_repository: RefreshTokenRepository
    token_service: TokenService
    settings: GatewaySettings

    async def login(self, email: str, password: str) -> LoginResult:
        user = await self.user_repository.get_by_email(email)
        now = datetime.now(timezone.utc)

        if user is None or not user.is_active:
            # Do the same expensive Argon2id work as the real path so response
            # timing doesn't reveal whether this email is registered.
            _verify_password_constant_time(_DUMMY_PASSWORD_HASH, password)
            return LoginResult(status=LoginStatus.INVALID_CREDENTIALS)

        if user.locked_until is not None and user.locked_until > now:
            return LoginResult(status=LoginStatus.ACCOUNT_LOCKED)

        if not _verify_password_constant_time(user.password_hash, password):
            updated = await self.user_repository.record_failed_login(
                user.user_id,
                max_attempts=self.settings.login_max_failed_attempts,
                lockout_minutes=self.settings.login_lockout_duration_minutes,
            )
            if updated.locked_until is not None:
                return LoginResult(status=LoginStatus.ACCOUNT_LOCKED)
            return LoginResult(status=LoginStatus.INVALID_CREDENTIALS)

        await self.user_repository.reset_login_attempts(user.user_id)

        family_id = uuid4()
        access_token = await self.token_service.issue_access_token(user_id=user.user_id, role=user.role)
        refresh_token, refresh_token_hash, refresh_expires_at = self.token_service.issue_refresh_token()
        await self.refresh_token_repository.create(refresh_token_hash, family_id, user.user_id, refresh_expires_at)

        return LoginResult(
            status=LoginStatus.SUCCESS,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.settings.access_token_ttl_minutes * 60,
        )

    async def refresh(self, refresh_token: str) -> RefreshResult:
        token_hash = hash_refresh_token(refresh_token)
        record = await self.refresh_token_repository.get(token_hash)
        if record is None:
            return RefreshResult(status=RefreshStatus.INVALID)

        now = datetime.now(timezone.utc)

        if record.used_at is not None:
            # Reuse of an already-consumed refresh token: the token was almost
            # certainly stolen, and we cannot tell the thief from the legitimate
            # user -- so the entire family is revoked and both must re-authenticate.
            await self.refresh_token_repository.revoke_family(record.family_id)
            return RefreshResult(status=RefreshStatus.REUSE_DETECTED, user_id=record.user_id, family_id=record.family_id)

        if record.revoked or record.expires_at <= now:
            return RefreshResult(status=RefreshStatus.INVALID)

        consumed = await self.refresh_token_repository.consume(token_hash)
        if not consumed:
            # Lost a race against another refresh call using the same token.
            return RefreshResult(status=RefreshStatus.INVALID)

        user = await self.user_repository.get_by_id(record.user_id)
        if user is None or not user.is_active:
            return RefreshResult(status=RefreshStatus.INVALID)

        access_token = await self.token_service.issue_access_token(user_id=user.user_id, role=user.role)
        new_refresh_token, new_refresh_token_hash, new_expires_at = self.token_service.issue_refresh_token()
        await self.refresh_token_repository.create(new_refresh_token_hash, record.family_id, user.user_id, new_expires_at)

        return RefreshResult(
            status=RefreshStatus.SUCCESS,
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=self.settings.access_token_ttl_minutes * 60,
        )
