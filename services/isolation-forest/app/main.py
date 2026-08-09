from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field

from app.model_store import REDIS_ACTIVE_VERSION_KEY, ModelStore, poll_forever, read_score_calibration
from app.settings import ScoringSettings

# Without this, every logger.exception() call in this module and model_store.py
# (startup/poll load failures, the poll-tick error handling in poll_forever)
# is silently swallowed -- uvicorn configures its own "uvicorn"/"uvicorn.error"
# loggers but attaches no handler to this app's logger hierarchy on its own.
# Confirmed live: a poll tick failed repeatedly for 16 minutes during a real
# Redis outage with zero output in `docker logs`. Same pattern as
# behavioral-detector/app/main.py.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# Single source of truth for this service's expected vector shape -- must
# match api-gateway's FeatureVectorService, the DB's chk_feature_vector_size
# CHECK constraint, and ml-trainer's FEATURE_VECTOR_DIMENSIONS. Referenced
# once here rather than repeating the literal in both Field bounds below.
FEATURE_VECTOR_DIMENSIONS = 16

# How many missed poll intervals before /health calls the loop stale rather
# than just "between ticks". A live 16-minute Redis outage is what surfaced
# the need for this: /health used to report model_loaded=true forever off
# whatever was last successfully loaded, indistinguishable from a genuinely
# healthy service, while poll_forever's task had (before that fix) died
# silently. This heartbeat check is the second half of that fix -- it makes
# a stalled loop observable even if some future code path bypasses
# poll_forever's own try/except.
HEARTBEAT_STALE_MULTIPLIER = 3


class ScoreRequest(BaseModel):
    feature_vector: Annotated[
        list[float], Field(min_length=FEATURE_VECTOR_DIMENSIONS, max_length=FEATURE_VECTOR_DIMENSIONS)
    ]


class ScoreResponse(BaseModel):
    risk_score: float
    model_version: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_version: str | None


def _create_redis_client(redis_url: str):
    from redis.asyncio import Redis

    return Redis.from_url(redis_url, decode_responses=True)


def build_app(
    settings: ScoringSettings | None = None,
    *,
    redis_client=None,
    model_store: ModelStore | None = None,
) -> FastAPI:
    settings = settings or ScoringSettings()
    app = FastAPI(title="Isolation Forest Scoring Service")

    store = model_store or ModelStore(models_dir=Path(settings.models_dir))
    redis_client = redis_client or _create_redis_client(settings.redis_url)

    app.state.model_store = store
    app.state.redis_client = redis_client
    app.state.settings = settings

    @app.on_event("startup")
    async def _startup() -> None:
        try:
            active_version = await redis_client.get(REDIS_ACTIVE_VERSION_KEY)
        except Exception:
            logger.exception("isolation-forest: failed to read %s at startup; starting unloaded (bootstrap)", REDIS_ACTIVE_VERSION_KEY)
            active_version = None

        if active_version is not None:
            score_breakpoints = await read_score_calibration(redis_client)
            try:
                store.load_version(active_version, score_breakpoints=score_breakpoints)
                logger.info("isolation-forest: loaded model version %s at startup", active_version)
            except Exception:
                logger.exception(
                    "isolation-forest: failed to load model version %s at startup; starting unloaded (bootstrap)",
                    active_version,
                )

        app.state.poll_task = asyncio.create_task(
            poll_forever(store, redis_client, settings.model_poll_interval_seconds)
        )

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        task = getattr(app.state, "poll_task", None)
        if task is not None:
            task.cancel()

    @app.get("/health")
    async def health(response: Response) -> HealthResponse:
        _, version = store.current()
        last_poll = store.last_poll_at()
        # last_poll is None before the poll loop's first tick has had a
        # chance to run (within one poll_interval_seconds of startup) --
        # treated as healthy on purpose, same "bootstrap is not unhealthy"
        # philosophy as model_loaded=False before any model has been
        # promoted. Only an ACTUALLY stale heartbeat (the loop ran at least
        # once, then stopped) is reported as unhealthy.
        stale = last_poll is not None and (
            time.monotonic() - last_poll > HEARTBEAT_STALE_MULTIPLIER * settings.model_poll_interval_seconds
        )
        if stale:
            # The existing Docker healthcheck (docker-compose.yml) already
            # just checks that this URL doesn't raise -- any non-2xx fails it
            # on its own, no compose change needed to make a stalled poll
            # loop actually surface as `unhealthy`.
            response.status_code = 503
        return HealthResponse(status="stale" if stale else "ok", model_loaded=version is not None, model_version=version)

    @app.post("/score")
    async def score(request: ScoreRequest) -> ScoreResponse:
        model, version = store.current()
        if model is None:
            raise HTTPException(status_code=503, detail="no model loaded")
        risk_score = store.score(request.feature_vector)
        return ScoreResponse(risk_score=risk_score, model_version=version)

    return app


app = build_app()
