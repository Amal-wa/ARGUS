from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(slots=True)
class ScoringSettings:
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    models_dir: str = os.getenv("MODELS_DIR", "/models")
    model_poll_interval_seconds: float = float(os.getenv("MODEL_POLL_INTERVAL_SECONDS", "30"))
