from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy import case, func, insert, select, text, update

from app.models.tables import (
    documents_table,
    event_anomaly_table,
    events_table,
    ml_model_registry_table,
    ml_training_samples_table,
    opa_decision_log_table,
    orders_table,
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

    async def list_all(self, *, limit: int = 50, offset: int = 0) -> list[UserRecord]:
        stmt = select(*_USER_COLUMNS).order_by(users_table.c.email).limit(limit).offset(offset)
        async with self._session_factory() as session:
            rows = (await session.execute(stmt)).all()
        return [_row_to_user_record(row) for row in rows]

    async def create_user(self, email: str, password_hash: str, role: str) -> UserRecord:
        user_id = uuid4()
        async with self._session_factory() as session:
            await session.execute(
                insert(users_table).values(
                    user_id=user_id,
                    email=email,
                    password_hash=password_hash,
                    role=role,
                )
            )
            await session.commit()
        return await self.get_by_id(user_id)

    async def update_user(
        self, user_id: UUID, *, email: str | None = None, role: str | None = None, is_active: bool | None = None
    ) -> UserRecord | None:
        values = {"updated_at": func.now()}
        if email is not None:
            values["email"] = email
        if role is not None:
            values["role"] = role
        if is_active is not None:
            values["is_active"] = is_active

        async with self._session_factory() as session:
            await session.execute(update(users_table).where(users_table.c.user_id == user_id).values(**values))
            await session.commit()
        return await self.get_by_id(user_id)

    async def soft_delete(self, user_id: UUID) -> bool:
        # Never a hard DELETE -- accounts the traffic generator (or real users)
        # are actively using must never disappear out from under them.
        async with self._session_factory() as session:
            result = await session.execute(
                update(users_table)
                .where(users_table.c.user_id == user_id)
                .values(is_active=False, updated_at=func.now())
            )
            await session.commit()
        return result.rowcount > 0


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


@dataclass(slots=True)
class DocumentRecord:
    document_id: UUID
    owner_id: UUID
    title: str
    content: str | None
    created_at: datetime
    updated_at: datetime
    is_deleted: bool


def _row_to_document_record(row) -> DocumentRecord:
    return DocumentRecord(
        document_id=row.document_id,
        owner_id=row.owner_id,
        title=row.title,
        content=row.content,
        created_at=row.created_at,
        updated_at=row.updated_at,
        is_deleted=row.is_deleted,
    )


class DocumentRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def list_all(self, *, limit: int = 50, offset: int = 0) -> list[DocumentRecord]:
        stmt = (
            select(documents_table)
            .where(documents_table.c.is_deleted.is_(False))
            .order_by(documents_table.c.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        async with self._session_factory() as session:
            rows = (await session.execute(stmt)).all()
        return [_row_to_document_record(row) for row in rows]

    async def get(self, document_id: UUID) -> DocumentRecord | None:
        stmt = select(documents_table).where(
            documents_table.c.document_id == document_id,
            documents_table.c.is_deleted.is_(False),
        )
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
        return None if row is None else _row_to_document_record(row)

    async def create(self, owner_id: UUID, title: str, content: str | None) -> DocumentRecord:
        document_id = uuid4()
        async with self._session_factory() as session:
            await session.execute(
                insert(documents_table).values(
                    document_id=document_id,
                    owner_id=owner_id,
                    title=title,
                    content=content,
                )
            )
            await session.commit()
        return await self.get(document_id)

    async def update(
        self, document_id: UUID, *, title: str | None = None, content: str | None = None
    ) -> DocumentRecord | None:
        values = {"updated_at": func.now()}
        if title is not None:
            values["title"] = title
        if content is not None:
            values["content"] = content

        async with self._session_factory() as session:
            await session.execute(
                update(documents_table)
                .where(documents_table.c.document_id == document_id, documents_table.c.is_deleted.is_(False))
                .values(**values)
            )
            await session.commit()
        return await self.get(document_id)

    async def soft_delete(self, document_id: UUID) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(
                update(documents_table)
                .where(documents_table.c.document_id == document_id, documents_table.c.is_deleted.is_(False))
                .values(is_deleted=True, updated_at=func.now())
            )
            await session.commit()
        return result.rowcount > 0


@dataclass(slots=True)
class OrderRecord:
    order_id: UUID
    owner_id: UUID
    status: str
    amount: Decimal
    created_at: datetime
    updated_at: datetime
    is_deleted: bool


def _row_to_order_record(row) -> OrderRecord:
    return OrderRecord(
        order_id=row.order_id,
        owner_id=row.owner_id,
        status=row.status,
        amount=row.amount,
        created_at=row.created_at,
        updated_at=row.updated_at,
        is_deleted=row.is_deleted,
    )


class OrderRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def list_all(self, *, limit: int = 50, offset: int = 0) -> list[OrderRecord]:
        stmt = (
            select(orders_table)
            .where(orders_table.c.is_deleted.is_(False))
            .order_by(orders_table.c.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        async with self._session_factory() as session:
            rows = (await session.execute(stmt)).all()
        return [_row_to_order_record(row) for row in rows]

    async def get(self, order_id: UUID) -> OrderRecord | None:
        stmt = select(orders_table).where(
            orders_table.c.order_id == order_id,
            orders_table.c.is_deleted.is_(False),
        )
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
        return None if row is None else _row_to_order_record(row)

    async def create(self, owner_id: UUID, status: str, amount: Decimal) -> OrderRecord:
        order_id = uuid4()
        async with self._session_factory() as session:
            await session.execute(
                insert(orders_table).values(
                    order_id=order_id,
                    owner_id=owner_id,
                    status=status,
                    amount=amount,
                )
            )
            await session.commit()
        return await self.get(order_id)

    async def update(
        self, order_id: UUID, *, status: str | None = None, amount: Decimal | None = None
    ) -> OrderRecord | None:
        values = {"updated_at": func.now()}
        if status is not None:
            values["status"] = status
        if amount is not None:
            values["amount"] = amount

        async with self._session_factory() as session:
            await session.execute(
                update(orders_table)
                .where(orders_table.c.order_id == order_id, orders_table.c.is_deleted.is_(False))
                .values(**values)
            )
            await session.commit()
        return await self.get(order_id)

    async def soft_delete(self, order_id: UUID) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(
                update(orders_table)
                .where(orders_table.c.order_id == order_id, orders_table.c.is_deleted.is_(False))
                .values(is_deleted=True, updated_at=func.now())
            )
            await session.commit()
        return result.rowcount > 0


# --- Monitoring (read-only, admin dashboard) -------------------------------
#
# GET-only queries backing app/routers/monitoring.py. opa_decision_log is the
# append-only decision audit trail (see CLAUDE.md) -- nothing here writes to
# it. Every query is bounded (LIMIT/pagination); the table grows without
# bound, and an unbounded SELECT here would be a real footgun.

# Internal safety cap for /monitoring/risk-timeline -- the endpoint is
# windowed by time, not by row count, so this bounds worst case (a very wide
# window on a very busy system) without being an exposed, tunable knob.
MAX_RISK_TIMELINE_POINTS = 2000


@dataclass(slots=True)
class DecisionStats:
    total_decisions: int
    allow: int
    deny: int
    step_up: int
    active_users: int
    distinct_ips: int


@dataclass(slots=True)
class DecisionLogRow:
    trace_id: UUID
    created_at: datetime
    user_id: UUID
    user_email: str | None
    resource: str
    action: str
    decision: str
    policy_name: str
    risk_score: float | None
    model_version: str | None
    ip_address: str


@dataclass(slots=True)
class RiskTimelinePoint:
    created_at: datetime
    user_email: str | None
    risk_score: float | None


@dataclass(slots=True)
class AlertRow:
    type: str  # "step_up" | "anomaly"
    created_at: datetime
    user_email: str | None
    resource: str | None
    risk_score: float | None
    trace_id: UUID | None


@dataclass(slots=True)
class ModelRegistryRow:
    model_version: str
    created_at: datetime
    training_samples: int
    score_distribution: dict | None


@dataclass(slots=True)
class DecisionAuditRow:
    id: int
    trace_id: UUID
    created_at: datetime
    user_id: UUID
    user_email: str | None
    role: str
    resource: str
    action: str
    ip_address: str
    risk_score: float | None
    model_version: str | None
    is_anomaly: str
    decision: str
    policy_name: str
    reason: str | None
    latency_ms: int


@dataclass(slots=True)
class EventAuditRow:
    id: int
    trace_id: UUID
    created_at: datetime
    user_id: UUID | None
    ip_address: str
    http_method: str
    request_path: str
    latency_ms: int
    http_status: int
    error_code: str | None
    error_message: str | None
    event_type: str


@dataclass(slots=True)
class AuditPage:
    rows: list
    total: int


def _window_since(window_minutes: int):
    # func.make_interval mirrors the lockout-window pattern already used in
    # UserMfaRepository/UserRepository -- avoids a raw string-interpolated
    # interval while still pushing the arithmetic to Postgres.
    return func.now() - func.make_interval(0, 0, 0, 0, 0, window_minutes)


class MonitoringRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def get_stats(self, window_minutes: int) -> DecisionStats:
        since = _window_since(window_minutes)
        by_decision_stmt = (
            select(opa_decision_log_table.c.decision, func.count())
            .where(opa_decision_log_table.c.timestamp >= since)
            .group_by(opa_decision_log_table.c.decision)
        )
        aggregate_stmt = select(
            func.count(func.distinct(opa_decision_log_table.c.user_id)),
            func.count(func.distinct(opa_decision_log_table.c.ip_address)),
        ).where(opa_decision_log_table.c.timestamp >= since)

        async with self._session_factory() as session:
            by_decision = (await session.execute(by_decision_stmt)).all()
            active_users, distinct_ips = (await session.execute(aggregate_stmt)).one()

        counts = {decision: count for decision, count in by_decision}
        allow = counts.get("allow", 0)
        deny = counts.get("deny", 0)
        step_up = counts.get("step_up", 0)
        return DecisionStats(
            total_decisions=allow + deny + step_up,
            allow=allow,
            deny=deny,
            step_up=step_up,
            active_users=active_users,
            distinct_ips=distinct_ips,
        )

    async def list_decisions(
        self, *, limit: int, since: datetime | None, user_email: str | None
    ) -> list[DecisionLogRow]:
        join = opa_decision_log_table.outerjoin(users_table, opa_decision_log_table.c.user_id == users_table.c.user_id)
        stmt = (
            select(
                opa_decision_log_table.c.trace_id,
                opa_decision_log_table.c.timestamp,
                opa_decision_log_table.c.user_id,
                users_table.c.email,
                opa_decision_log_table.c.resource,
                opa_decision_log_table.c.action,
                opa_decision_log_table.c.decision,
                opa_decision_log_table.c.policy_name,
                opa_decision_log_table.c.risk_score,
                opa_decision_log_table.c.model_version,
                opa_decision_log_table.c.ip_address,
            )
            .select_from(join)
            .order_by(opa_decision_log_table.c.timestamp.desc())
            .limit(limit)
        )
        if since is not None:
            stmt = stmt.where(opa_decision_log_table.c.timestamp > since)
        if user_email is not None:
            stmt = stmt.where(users_table.c.email == user_email)

        async with self._session_factory() as session:
            rows = (await session.execute(stmt)).all()

        return [
            DecisionLogRow(
                trace_id=row.trace_id,
                created_at=row.timestamp,
                user_id=row.user_id,
                user_email=row.email,
                resource=row.resource,
                action=row.action,
                decision=row.decision,
                policy_name=row.policy_name,
                risk_score=row.risk_score,
                model_version=row.model_version,
                ip_address=str(row.ip_address),
            )
            for row in rows
        ]

    async def get_risk_timeline(self, *, user_email: str | None, window_minutes: int) -> list[RiskTimelinePoint]:
        join = opa_decision_log_table.outerjoin(users_table, opa_decision_log_table.c.user_id == users_table.c.user_id)
        stmt = (
            select(opa_decision_log_table.c.timestamp, users_table.c.email, opa_decision_log_table.c.risk_score)
            .select_from(join)
            .where(opa_decision_log_table.c.timestamp >= _window_since(window_minutes))
            .order_by(opa_decision_log_table.c.timestamp.asc())
            .limit(MAX_RISK_TIMELINE_POINTS)
        )
        if user_email is not None:
            stmt = stmt.where(users_table.c.email == user_email)

        async with self._session_factory() as session:
            rows = (await session.execute(stmt)).all()

        return [RiskTimelinePoint(created_at=row.timestamp, user_email=row.email, risk_score=row.risk_score) for row in rows]

    async def get_alerts(self, *, limit: int, window_minutes: int) -> list[AlertRow]:
        # Bounded by time, not just count: opa_decision_log is the permanent
        # audit trail (never pruned -- see CLAUDE.md), so an unwindowed "last
        # N step_ups" would keep surfacing arbitrarily old rows as if they
        # were current (this is exactly what happened with historical
        # step_ups from before the /monitoring/* scoring exemption). The
        # window matches /monitoring/stats's default so the two panels never
        # visibly disagree about "now".
        since = _window_since(window_minutes)

        step_up_join = opa_decision_log_table.outerjoin(
            users_table, opa_decision_log_table.c.user_id == users_table.c.user_id
        )
        step_up_stmt = (
            select(
                opa_decision_log_table.c.trace_id,
                opa_decision_log_table.c.timestamp,
                users_table.c.email,
                opa_decision_log_table.c.resource,
                opa_decision_log_table.c.risk_score,
            )
            .select_from(step_up_join)
            .where(opa_decision_log_table.c.decision == "step_up", opa_decision_log_table.c.timestamp >= since)
            .order_by(opa_decision_log_table.c.timestamp.desc())
            .limit(limit)
        )

        anomaly_join = event_anomaly_table.join(
            opa_decision_log_table, event_anomaly_table.c.id_log == opa_decision_log_table.c.id
        ).outerjoin(users_table, opa_decision_log_table.c.user_id == users_table.c.user_id)
        anomaly_stmt = (
            select(
                opa_decision_log_table.c.trace_id,
                event_anomaly_table.c.timestamp,
                users_table.c.email,
                opa_decision_log_table.c.resource,
                event_anomaly_table.c.risk_score,
            )
            .select_from(anomaly_join)
            .where(event_anomaly_table.c.timestamp >= since)
            .order_by(event_anomaly_table.c.timestamp.desc())
            .limit(limit)
        )

        async with self._session_factory() as session:
            step_up_rows = (await session.execute(step_up_stmt)).all()
            anomaly_rows = (await session.execute(anomaly_stmt)).all()

        alerts = [
            AlertRow(
                type="step_up", created_at=row.timestamp, user_email=row.email, resource=row.resource,
                risk_score=row.risk_score, trace_id=row.trace_id,
            )
            for row in step_up_rows
        ] + [
            AlertRow(
                type="anomaly", created_at=row.timestamp, user_email=row.email, resource=row.resource,
                risk_score=row.risk_score, trace_id=row.trace_id,
            )
            for row in anomaly_rows
        ]
        alerts.sort(key=lambda alert: alert.created_at, reverse=True)
        return alerts[:limit]

    async def get_model_registry_row(self, version: str) -> ModelRegistryRow | None:
        stmt = select(
            ml_model_registry_table.c.model_version,
            ml_model_registry_table.c.created_at,
            ml_model_registry_table.c.training_samples,
            ml_model_registry_table.c.score_distribution,
        ).where(ml_model_registry_table.c.model_version == version)
        async with self._session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
        if row is None:
            return None
        return ModelRegistryRow(
            model_version=row.model_version,
            created_at=row.created_at,
            training_samples=row.training_samples,
            score_distribution=row.score_distribution,
        )

    async def ping_database(self) -> None:
        async with self._session_factory() as session:
            await session.execute(text("SELECT 1"))

    async def get_decision_audit_page(
        self,
        *,
        page: int,
        page_size: int,
        user_email: str | None,
        decision: str | None,
        from_ts: datetime | None,
        to_ts: datetime | None,
    ) -> AuditPage:
        join = opa_decision_log_table.outerjoin(users_table, opa_decision_log_table.c.user_id == users_table.c.user_id)

        conditions = []
        if user_email is not None:
            conditions.append(users_table.c.email == user_email)
        if decision is not None:
            conditions.append(opa_decision_log_table.c.decision == decision)
        if from_ts is not None:
            conditions.append(opa_decision_log_table.c.timestamp >= from_ts)
        if to_ts is not None:
            conditions.append(opa_decision_log_table.c.timestamp <= to_ts)

        count_stmt = select(func.count()).select_from(join)
        rows_stmt = select(
            opa_decision_log_table.c.id,
            opa_decision_log_table.c.trace_id,
            opa_decision_log_table.c.timestamp,
            opa_decision_log_table.c.user_id,
            users_table.c.email,
            opa_decision_log_table.c.role,
            opa_decision_log_table.c.resource,
            opa_decision_log_table.c.action,
            opa_decision_log_table.c.ip_address,
            opa_decision_log_table.c.risk_score,
            opa_decision_log_table.c.model_version,
            opa_decision_log_table.c.is_anomaly,
            opa_decision_log_table.c.decision,
            opa_decision_log_table.c.policy_name,
            opa_decision_log_table.c.reason,
            opa_decision_log_table.c.latency_ms,
        ).select_from(join)
        for condition in conditions:
            count_stmt = count_stmt.where(condition)
            rows_stmt = rows_stmt.where(condition)
        rows_stmt = (
            rows_stmt.order_by(opa_decision_log_table.c.timestamp.desc())
            .limit(page_size)
            .offset((page - 1) * page_size)
        )

        async with self._session_factory() as session:
            total = (await session.execute(count_stmt)).scalar_one()
            rows = (await session.execute(rows_stmt)).all()

        return AuditPage(
            rows=[
                DecisionAuditRow(
                    id=row.id, trace_id=row.trace_id, created_at=row.timestamp, user_id=row.user_id,
                    user_email=row.email, role=row.role, resource=row.resource, action=row.action,
                    ip_address=str(row.ip_address), risk_score=row.risk_score, model_version=row.model_version,
                    is_anomaly=row.is_anomaly, decision=row.decision, policy_name=row.policy_name,
                    reason=row.reason, latency_ms=row.latency_ms,
                )
                for row in rows
            ],
            total=total,
        )

    async def get_event_audit_page(
        self,
        *,
        page: int,
        page_size: int,
        user_email: str | None,
        event_type: str | None,
        from_ts: datetime | None,
        to_ts: datetime | None,
    ) -> AuditPage:
        join = events_table.outerjoin(users_table, events_table.c.user_id == users_table.c.user_id)

        conditions = []
        if user_email is not None:
            conditions.append(users_table.c.email == user_email)
        if event_type is not None:
            conditions.append(events_table.c.event_type == event_type)
        if from_ts is not None:
            conditions.append(events_table.c.timestamp >= from_ts)
        if to_ts is not None:
            conditions.append(events_table.c.timestamp <= to_ts)

        count_stmt = select(func.count()).select_from(join)
        rows_stmt = select(
            events_table.c.id,
            events_table.c.trace_id,
            events_table.c.timestamp,
            events_table.c.user_id,
            events_table.c.ip_address,
            events_table.c.http_method,
            events_table.c.request_path,
            events_table.c.latency_ms,
            events_table.c.http_status,
            events_table.c.error_code,
            events_table.c.error_message,
            events_table.c.event_type,
        ).select_from(join)
        for condition in conditions:
            count_stmt = count_stmt.where(condition)
            rows_stmt = rows_stmt.where(condition)
        rows_stmt = (
            rows_stmt.order_by(events_table.c.timestamp.desc()).limit(page_size).offset((page - 1) * page_size)
        )

        async with self._session_factory() as session:
            total = (await session.execute(count_stmt)).scalar_one()
            rows = (await session.execute(rows_stmt)).all()

        return AuditPage(
            rows=[
                EventAuditRow(
                    id=row.id, trace_id=row.trace_id, created_at=row.timestamp, user_id=row.user_id,
                    ip_address=str(row.ip_address), http_method=row.http_method, request_path=row.request_path,
                    latency_ms=row.latency_ms, http_status=row.http_status, error_code=row.error_code,
                    error_message=row.error_message, event_type=row.event_type,
                )
                for row in rows
            ],
            total=total,
        )
