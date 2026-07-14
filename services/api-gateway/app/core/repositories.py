from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import case, func, insert, select, update

from app.models.tables import (
    ml_training_samples_table,
    opa_decision_log_table,
    refresh_tokens_table,
    user_mfa_table,
    users_table,
)


@dataclass(slots=True)
class OpaDecisionRecord:
    trace_id: UUID
    user_id: UUID
    jti: UUID
    role: str
    resource: str
    action: str
    ip_address: str
    risk_score: float | None
    model_version: str | None
    decision: str
    policy_name: str
    reason: str | None
    latency_ms: int
    is_anomaly: str = "none"


@dataclass(slots=True)
class TrainingSampleRecord:
    trace_id: UUID
    feature_vector: list[float]
    risk_score: float | None
    model_version: str | None


class AuthorizationRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def write_decision(self, record: OpaDecisionRecord) -> None:
        async with self._session_factory() as session:
            await session.execute(
                insert(opa_decision_log_table).values(
                    trace_id=record.trace_id,
                    user_id=record.user_id,
                    jti=record.jti,
                    role=record.role,
                    resource=record.resource,
                    action=record.action,
                    ip_address=record.ip_address,
                    risk_score=record.risk_score,
                    model_version=record.model_version,
                    is_anomaly=record.is_anomaly,
                    decision=record.decision,
                    policy_name=record.policy_name,
                    reason=record.reason,
                    latency_ms=record.latency_ms,
                )
            )
            await session.commit()

    async def write_training_sample(self, record: TrainingSampleRecord) -> None:
        async with self._session_factory() as session:
            await session.execute(
                insert(ml_training_samples_table).values(
                    trace_id=record.trace_id,
                    feature_vector=record.feature_vector,
                    risk_score=record.risk_score,
                    model_version=record.model_version,
                )
            )
            await session.commit()


@dataclass(slots=True)
class UserMfaRecord:
    user_id: UUID
    totp_secret_ciphertext: str
    failed_attempts: int
    locked_until: datetime | None


def _row_to_user_mfa_record(row) -> UserMfaRecord:
    return UserMfaRecord(
        user_id=row.user_id,
        totp_secret_ciphertext=row.totp_secret_ciphertext,
        failed_attempts=row.failed_attempts,
        locked_until=row.locked_until,
    )


class UserMfaRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def get(self, user_id: UUID) -> UserMfaRecord | None:
        stmt = select(
            user_mfa_table.c.user_id,
            user_mfa_table.c.totp_secret_ciphertext,
            user_mfa_table.c.failed_attempts,
            user_mfa_table.c.locked_until,
        ).where(user_mfa_table.c.user_id == user_id)
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
        return None if row is None else _row_to_user_mfa_record(row)

    async def create(self, user_id: UUID, totp_secret_ciphertext: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                insert(user_mfa_table).values(
                    user_id=user_id,
                    totp_secret_ciphertext=totp_secret_ciphertext,
                    failed_attempts=0,
                    locked_until=None,
                )
            )
            await session.commit()

    async def record_failed_attempt(
        self, user_id: UUID, *, max_attempts: int, lockout_duration_minutes: int
    ) -> UserMfaRecord:
        incremented = user_mfa_table.c.failed_attempts + 1
        reached_limit = incremented >= max_attempts
        stmt = (
            update(user_mfa_table)
            .where(user_mfa_table.c.user_id == user_id)
            .values(
                failed_attempts=case((reached_limit, 0), else_=incremented),
                locked_until=case(
                    (reached_limit, func.now() + func.make_interval(0, 0, 0, 0, 0, lockout_duration_minutes)),
                    else_=user_mfa_table.c.locked_until,
                ),
                updated_at=func.now(),
            )
            .returning(
                user_mfa_table.c.user_id,
                user_mfa_table.c.totp_secret_ciphertext,
                user_mfa_table.c.failed_attempts,
                user_mfa_table.c.locked_until,
            )
        )
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one()
            await session.commit()
        return _row_to_user_mfa_record(row)

    async def reset_on_success(self, user_id: UUID) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(user_mfa_table)
                .where(user_mfa_table.c.user_id == user_id)
                .values(failed_attempts=0, locked_until=None, updated_at=func.now())
            )
            await session.commit()


@dataclass(slots=True)
class UserRecord:
    user_id: UUID
    email: str
    password_hash: str
    role: str
    is_active: bool
    failed_login_attempts: int
    locked_until: datetime | None


def _row_to_user_record(row) -> UserRecord:
    return UserRecord(
        user_id=row.user_id,
        email=row.email,
        password_hash=row.password_hash,
        role=row.role,
        is_active=row.is_active,
        failed_login_attempts=row.failed_login_attempts,
        locked_until=row.locked_until,
    )


_USER_COLUMNS = (
    users_table.c.user_id,
    users_table.c.email,
    users_table.c.password_hash,
    users_table.c.role,
    users_table.c.is_active,
    users_table.c.failed_login_attempts,
    users_table.c.locked_until,
)


class UserRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def get_by_email(self, email: str) -> UserRecord | None:
        stmt = select(*_USER_COLUMNS).where(users_table.c.email == email)
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
        return None if row is None else _row_to_user_record(row)

    async def get_by_id(self, user_id: UUID) -> UserRecord | None:
        stmt = select(*_USER_COLUMNS).where(users_table.c.user_id == user_id)
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
        return None if row is None else _row_to_user_record(row)

    async def record_failed_login(
        self, user_id: UUID, *, max_attempts: int, lockout_minutes: int
    ) -> UserRecord:
        incremented = users_table.c.failed_login_attempts + 1
        reached_limit = incremented >= max_attempts
        stmt = (
            update(users_table)
            .where(users_table.c.user_id == user_id)
            .values(
                failed_login_attempts=case((reached_limit, 0), else_=incremented),
                locked_until=case(
                    (reached_limit, func.now() + func.make_interval(0, 0, 0, 0, 0, lockout_minutes)),
                    else_=users_table.c.locked_until,
                ),
                updated_at=func.now(),
            )
            .returning(*_USER_COLUMNS)
        )
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one()
            await session.commit()
        return _row_to_user_record(row)

    async def reset_login_attempts(self, user_id: UUID) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(users_table)
                .where(users_table.c.user_id == user_id)
                .values(failed_login_attempts=0, locked_until=None, last_login=func.now(), updated_at=func.now())
            )
            await session.commit()


@dataclass(slots=True)
class RefreshTokenRecord:
    token_hash: str
    family_id: UUID
    user_id: UUID
    issued_at: datetime
    expires_at: datetime
    used_at: datetime | None
    revoked: bool


def _row_to_refresh_token_record(row) -> RefreshTokenRecord:
    return RefreshTokenRecord(
        token_hash=row.token_hash,
        family_id=row.family_id,
        user_id=row.user_id,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        used_at=row.used_at,
        revoked=row.revoked,
    )


class RefreshTokenRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def create(self, token_hash: str, family_id: UUID, user_id: UUID, expires_at: datetime) -> None:
        async with self._session_factory() as session:
            await session.execute(
                insert(refresh_tokens_table).values(
                    token_hash=token_hash,
                    family_id=family_id,
                    user_id=user_id,
                    expires_at=expires_at,
                )
            )
            await session.commit()

    async def get(self, token_hash: str) -> RefreshTokenRecord | None:
        stmt = select(refresh_tokens_table).where(refresh_tokens_table.c.token_hash == token_hash)
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
        return None if row is None else _row_to_refresh_token_record(row)

    async def consume(self, token_hash: str) -> bool:
        # Atomic: only the caller whose UPDATE actually matched a still-unused,
        # non-revoked, non-expired row gets a RETURNING row back. Two concurrent
        # refreshes with the same token can never both succeed.
        stmt = (
            update(refresh_tokens_table)
            .where(
                refresh_tokens_table.c.token_hash == token_hash,
                refresh_tokens_table.c.used_at.is_(None),
                refresh_tokens_table.c.revoked.is_(False),
                refresh_tokens_table.c.expires_at > func.now(),
            )
            .values(used_at=func.now())
            .returning(refresh_tokens_table.c.token_hash)
        )
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
            await session.commit()
        return row is not None

    async def revoke_family(self, family_id: UUID) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(refresh_tokens_table)
                .where(refresh_tokens_table.c.family_id == family_id)
                .values(revoked=True)
            )
            await session.commit()
