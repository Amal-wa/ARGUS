from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(slots=True)
class ValidatorSettings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql://postgres:admin@postgres:5432/zt_db")
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    models_dir: str = os.getenv("MODELS_DIR", "/models")
    window_days: int = int(os.getenv("CANARY_WINDOW_DAYS", "30"))
    batch_size: int = int(os.getenv("CANARY_BATCH_SIZE", "5000"))
