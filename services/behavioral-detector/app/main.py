from __future__ import annotations

import logging
import time

from redis import Redis
from sqlalchemy import create_engine

from app.repository import SqlBehavioralDetectorRepository
from app.rules import run_detection_scan
from app.settings import DetectorSettings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def scan_once(repository, redis_client, settings: DetectorSettings) -> None:
    report = run_detection_scan(repository, redis_client, settings)
    logger.info(
        "behavioral-detector: scan complete, %d candidate(s), %d written, %d deduplicated",
        report.anomalies_found,
        report.anomalies_written,
        report.anomalies_deduplicated,
    )


def main() -> None:
    settings = DetectorSettings()
    engine = create_engine(settings.database_url)
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    repository = SqlBehavioralDetectorRepository(engine)

    logger.info("behavioral-detector: starting, scanning every %ds", settings.scan_interval_seconds)
    while True:
        try:
            scan_once(repository, redis_client, settings)
        except Exception:
            # Long-running service, not a one-shot job (unlike
            # canary-validator/ml-trainer) -- a transient DB/Redis hiccup on
            # one tick must not kill the whole container. Same philosophy as
            # isolation-forest's poll_once: log and keep serving/scanning.
            logger.exception("behavioral-detector: scan failed, will retry next tick")
        time.sleep(settings.scan_interval_seconds)


if __name__ == "__main__":
    main()
