from __future__ import annotations

import logging
import sys

from redis import Redis
from sqlalchemy import create_engine

from app.repository import SqlMlTrainerRepository
from app.settings import TrainerSettings
from app.trainer import TrainingOutcome, run_training_job

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def main() -> int:
    settings = TrainerSettings()
    engine = create_engine(settings.database_url)
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    repository = SqlMlTrainerRepository(engine)

    try:
        report = run_training_job(repository, redis_client, settings)
    except Exception:
        logger.exception("ml-trainer: training job failed")
        return 1

    if report.outcome == TrainingOutcome.SKIPPED_INSUFFICIENT_SAMPLES:
        logger.info(
            "ml-trainer: no-op, insufficient samples (%d/%d)",
            report.sample_count,
            settings.min_training_samples,
        )
    else:
        logger.info(
            "ml-trainer: trained %s on %d samples, window %s -> %s, artifact %s, quality=%s",
            report.version,
            report.sample_count,
            report.window_start,
            report.window_end,
            report.artifact_path,
            report.quality.to_dict() if report.quality is not None else None,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
