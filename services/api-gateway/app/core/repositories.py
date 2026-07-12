from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import case, func, insert, select, update

from app.models.tables import ml_training_samples_table, opa_decision_log_table, user_mfa_table


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
