from __future__ import annotations

import logging
import sys

from redis import Redis
from sqlalchemy import create_engine

from app.repository import SqlCanaryValidatorRepository
from app.settings import ValidatorSettings
from app.validator import ValidationMode, run_validation_job

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def main() -> int:
    settings = ValidatorSettings()
    engine = create_engine(settings.database_url)
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    repository = SqlCanaryValidatorRepository(engine)

    try:
        report = run_validation_job(repository, redis_client, settings)
    except Exception:
        logger.exception("canary-validator: validation job failed")
        return 1

    if report.mode == ValidationMode.NO_CANDIDATE:
        logger.info("canary-validator: no-op, no candidate model set")
    elif report.mode == ValidationMode.CALIBRATION:
        logger.info(
            "canary-validator: calibration mode, candidate %s, scored %d samples, distribution=%s",
            report.candidate_version,
            report.samples_scored,
            report.score_distribution.to_dict() if report.score_distribution else None,
        )
    else:
        logger.info(
            "canary-validator: comparison mode, candidate %s, %d samples considered, %d canary_validation_log rows inserted",
            report.candidate_version,
            report.samples_scored,
            report.comparison_rows_inserted,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
