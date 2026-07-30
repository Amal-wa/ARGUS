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

model:candidate_version vs model:active_version -- the single source of truth for
"pending" vs "live": candidate_version names a model canary-validator is (or was)
comparing against production; active_version names the model actually serving traffic.
A version cannot be meaningfully both, so once <version> is promoted, if
model:candidate_version still holds that SAME version, it is cleared (there is nothing
left to compare -- the candidate won). If it holds a DIFFERENT version, it is left
alone: that is a genuinely separate, still-pending candidate, and clearing it would
lose real state.
"""
from __future__ import annotations

import asyncio
import json
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
from app.services.feature_vector import FEATURE_VECTOR_DIMENSIONS

ACTIVE_VERSION_KEY = "model:active_version"
ACTIVE_THRESHOLD_KEY = "model:active_threshold"
# Published alongside the two keys above so isolation-forest can map its raw
# sigmoid output to a percentile rank against THIS version's own calibration
# reference -- see services/isolation-forest/app/model_store.py:
# percentile_calibrate. JSON-encoded list of 101 floats. Same "these keys
# must always change together" contract as active_version/threshold.
ACTIVE_SCORE_BREAKPOINTS_KEY = "model:active_score_breakpoints"
CANDIDATE_VERSION_KEY = "model:candidate_version"


def _percentile_rank(raw_value: float, breakpoints: list[float]) -> float:
    """Same interpolation as isolation-forest's percentile_calibrate, without
    a numpy dependency here -- api-gateway doesn't otherwise need numpy, and
    this is the only place in this script that needs the math. Must produce
    the same result percentile_calibrate would for consistency between the
    threshold computed here and the scores it will be compared against."""
    ranks = [i / (len(breakpoints) - 1) for i in range(len(breakpoints))]
    if raw_value <= breakpoints[0]:
        return 0.0
    if raw_value >= breakpoints[-1]:
        return 1.0
    for i in range(1, len(breakpoints)):
        if raw_value <= breakpoints[i]:
            lo, hi = breakpoints[i - 1], breakpoints[i]
            fraction = 0.0 if hi == lo else (raw_value - lo) / (hi - lo)
            return ranks[i - 1] + fraction * (ranks[i] - ranks[i - 1])
    return 1.0  # unreachable given the bounds checks above


class PromotionError(Exception):
    pass


class ModelRegistryRepository(Protocol):
    async def get_score_distribution(self, version: str) -> dict[str, float] | None:
        """Returns None if the version is unknown OR uncalibrated (no distribution yet)."""
        ...

    async def get_feature_dims(self, version: str) -> int | None:
        """Returns None if the version is unknown."""
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

    async def get_feature_dims(self, version: str) -> int | None:
        stmt = select(ml_model_registry_table.c.feature_dims).where(
            ml_model_registry_table.c.model_version == version
        )
        async with self.session_factory() as session:
            row = (await session.execute(stmt)).one_or_none()
        return None if row is None else row[0]


@dataclass(slots=True)
class PromotionResult:
    version: str
    threshold: float
    score_breakpoints: list[float]
    previous_version: str | None
    previous_threshold: str | None
    cleared_candidate: bool


async def promote_model(
    repository: ModelRegistryRepository, redis_client: RedisLike, version: str
) -> PromotionResult:
    score_distribution = await repository.get_score_distribution(version)
    if not score_distribution or "p98" not in score_distribution:
        raise PromotionError(
            f"model {version!r} has no score_distribution yet -- "
            f"run canary-validator first to calibrate {version!r}"
        )

    feature_dims = await repository.get_feature_dims(version)
    if feature_dims != FEATURE_VECTOR_DIMENSIONS:
        raise PromotionError(
            f"model {version!r} was trained on a {feature_dims}-dimension feature vector, "
            f"but the Gateway currently builds {FEATURE_VECTOR_DIMENSIONS}-dimension vectors -- "
            f"promoting it would make isolation-forest crash on every /score call"
        )

    # canary-validator's ScoreDistribution.to_dict() always writes
    # percentile_breakpoints alongside p98 as one JSON blob (see
    # write_score_distribution) -- "p98" present above already guarantees it is too.
    score_breakpoints = score_distribution.get("percentile_breakpoints")
    if (
        not score_breakpoints
        or len(score_breakpoints) < 2
        or any(a > b for a, b in zip(score_breakpoints, score_breakpoints[1:]))
    ):
        raise PromotionError(
            f"model {version!r} has no usable percentile_breakpoints in its score_distribution -- "
            f"re-run canary-validator to calibrate {version!r} (was it calibrated before this feature existed?)"
        )
    if score_breakpoints[0] == score_breakpoints[-1]:
        raise PromotionError(
            f"model {version!r} has a degenerate score_distribution (every percentile collapses to "
            f"{score_breakpoints[0]!r}) -- cannot calibrate a meaningful threshold from it"
        )

    raw_p98 = float(score_distribution["p98"])
    # Same percentile-rank space isolation-forest will map its live raw scores
    # into (percentile_calibrate) -- the threshold must live in whatever space
    # the score it's compared against lives in.
    threshold = _percentile_rank(raw_p98, score_breakpoints)

    previous_version = await redis_client.get(ACTIVE_VERSION_KEY)
    previous_threshold = await redis_client.get(ACTIVE_THRESHOLD_KEY)

    await redis_client.set(ACTIVE_VERSION_KEY, version)
    await redis_client.set(ACTIVE_THRESHOLD_KEY, str(threshold))
    await redis_client.set(ACTIVE_SCORE_BREAKPOINTS_KEY, json.dumps(score_breakpoints))

    # See the module docstring: candidate_version means "pending", active_version
    # means "live" -- once THIS version is live, it can't still be pending. Only
    # clear it if it's the version we just promoted; a different candidate is
    # real, separate state and must survive promotion of an unrelated version.
    candidate_version = await redis_client.get(CANDIDATE_VERSION_KEY)
    cleared_candidate = candidate_version == version
    if cleared_candidate:
        await redis_client.delete(CANDIDATE_VERSION_KEY)

    return PromotionResult(
        version=version,
        threshold=threshold,
        score_breakpoints=score_breakpoints,
        previous_version=previous_version,
        previous_threshold=previous_threshold,
        cleared_candidate=cleared_candidate,
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

    print(f"model:active_version:    {result.previous_version!r} -> {result.version!r}")
    print(f"model:active_threshold:  {result.previous_threshold!r} -> {result.threshold!r}")
    print(f"model:active_score_breakpoints: -> 101 values, range [{result.score_breakpoints[0]!r}, {result.score_breakpoints[-1]!r}]")
    if result.cleared_candidate:
        print(f"model:candidate_version: {result.version!r} -> None (cleared: promoted version was still marked as candidate)")
    else:
        print("model:candidate_version: unchanged (not the version just promoted)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: promote_model.py <version>")
    asyncio.run(main(sys.argv[1]))
