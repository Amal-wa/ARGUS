from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.models.tables import events_table


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EventPayload:
    trace_id: UUID
    user_id: UUID | None
    ip_address: str
    http_method: str
    request_path: str
    latency_ms: int
    http_status: int
    event_type: str
    error_code: str | None = None
    error_message: str | None = None
    attempted_email: str | None = None


class SqlAlchemyEventLogger:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    async def write(self, payload: EventPayload) -> None:
        async with self._session_factory() as session:
            try:
                await session.execute(
                    insert(events_table).values(
                        trace_id=payload.trace_id,
                        user_id=payload.user_id,
                        ip_address=payload.ip_address,
                        http_method=payload.http_method,
                        request_path=payload.request_path,
                        latency_ms=payload.latency_ms,
                        http_status=payload.http_status,
                        error_code=payload.error_code,
                        error_message=payload.error_message,
                        event_type=payload.event_type,
                        attempted_email=payload.attempted_email,
                    )
                )
                await session.commit()
            except Exception:
                await session.rollback()
                logger.exception(
                    "Failed to persist gateway event",
                    extra={
                        "trace_id": str(payload.trace_id),
                        "event_type": payload.event_type,
                        "http_status": payload.http_status,
                    },
                )
                raise


class NoopEventLogger:
    async def write(self, payload: EventPayload) -> None:
        return None


def build_sqlalchemy_event_logger(session_factory: async_sessionmaker[AsyncSession]) -> SqlAlchemyEventLogger:
    return SqlAlchemyEventLogger(session_factory)
