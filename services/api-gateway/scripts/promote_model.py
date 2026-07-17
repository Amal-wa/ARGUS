"""Promote a model version to production.

Manual, deliberate act -- run explicitly:
    poetry run python scripts/promote_model.py <version>
or, against the docker-compose stack:
    docker compose run --rm api-gateway poetry run python scripts/promote_model.py <version>

Sets two Redis keys together:
    model:active_version    <version>
    model:active_threshold  <p98 of that version's score_distribution>

The threshold is the step-up threshold consumed by policies/risk/adaptive_access.rego
(via the Gateway's OPA input) -- the 2% most behaviorally atypical requests, calibrated
per-model, trigger step_up. It is derived from ml_model_registry.score_distribution,
which canary-validator computes and writes when it calibrates a candidate. If that
column is still NULL for <version>, this script aborts and changes nothing: promoting
a model before it has been calibrated would leave OPA with a score but no threshold to
compare it against.

These two keys must always change together -- do not set model:active_version by hand.
Promoting through anything other than this script risks exactly the desync (an active
model with a stale or missing threshold) that AuthorizationService's fallback path
exists to survive, not to be relied on routinely.
"""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import select

from app.core.database import build_async_session_factory
from app.core.redis_client import RedisLike, create_redis_client
from app.core.settings import GatewaySettings
from app.models.tables import ml_model_registry_table

ACTIVE_VERSION_KEY = "model:active_version"
ACTIVE_THRESHOLD_KEY = "model:active_threshold"


class PromotionError(Exception):
    pass


class ModelRegistryRepository(Protocol):
    async def get_score_distribution(self, version: str) -> dict[str, float] | None:
        """Returns None if the version is unknown OR uncalibrated (no distribution yet)."""
        ...


@dataclass(slots=True)
class SqlAlchemyModelRegistryRepository:
    session_factory: object

    async def get_score_distribution(self, version: str) -> dict[str, float] | None:
        stmt = select(ml_model_registry_table.c.score_distribution).where(
            ml_model_registry_table.c.model_version == version
        )
        async with self.session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
        return None if row is None else row[0]


@dataclass(slots=True)
class PromotionResult:
    version: str
    threshold: float
    previous_version: str | None
    previous_threshold: str | None


async def promote_model(
    repository: ModelRegistryRepository, redis_client: RedisLike, version: str
) -> PromotionResult:
    score_distribution = await repository.get_score_distribution(version)
    if not score_distribution or "p98" not in score_distribution:
        raise PromotionError(
            f"model {version!r} has no score_distribution yet -- "
            f"run canary-validator first to calibrate {version!r}"
        )

    threshold = float(score_distribution["p98"])
    previous_version = await redis_client.get(ACTIVE_VERSION_KEY)
    previous_threshold = await redis_client.get(ACTIVE_THRESHOLD_KEY)

    await redis_client.set(ACTIVE_VERSION_KEY, version)
    await redis_client.set(ACTIVE_THRESHOLD_KEY, str(threshold))

    return PromotionResult(
        version=version,
        threshold=threshold,
        previous_version=previous_version,
        previous_threshold=previous_threshold,
    )


async def main(version: str) -> None:
    settings = GatewaySettings()
    engine, session_factory = build_async_session_factory(settings.database_url)
    redis_client = create_redis_client(settings.redis_url)
    repository = SqlAlchemyModelRegistryRepository(session_factory)

    try:
        result = await promote_model(repository, redis_client, version)
    except PromotionError as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        await engine.dispose()

    print(f"model:active_version:   {result.previous_version!r} -> {result.version!r}")
    print(f"model:active_threshold: {result.previous_threshold!r} -> {result.threshold!r}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: promote_model.py <version>")
    asyncio.run(main(sys.argv[1]))
