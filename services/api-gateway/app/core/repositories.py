from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import insert

from app.models.tables import ml_training_samples_table, opa_decision_log_table


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
