from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@dataclass(slots=True)
class DatabaseResources:
    engine: object
    session_factory: async_sessionmaker[AsyncSession]


def build_async_session_factory(database_url: str):
    resources = _build_database_resources(database_url)
    return resources.engine, resources.session_factory


@lru_cache(maxsize=1)
def _build_database_resources(database_url: str) -> DatabaseResources:
    engine = create_async_engine(database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return DatabaseResources(engine=engine, session_factory=session_factory)
