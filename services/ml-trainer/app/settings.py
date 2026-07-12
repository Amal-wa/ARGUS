from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(slots=True)
class TrainerSettings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql://postgres:admin@postgres:5432/zt_db")
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    models_dir: str = os.getenv("MODELS_DIR", "/models")
    training_window_days: int = int(os.getenv("TRAINING_WINDOW_DAYS", "30"))
    min_training_samples: int = int(os.getenv("MIN_TRAINING_SAMPLES", "1000"))
    n_estimators: int = int(os.getenv("MODEL_N_ESTIMATORS", "100"))
    random_state: int = int(os.getenv("MODEL_RANDOM_STATE", "42"))
