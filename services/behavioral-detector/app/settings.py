from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(slots=True)
class DetectorSettings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql://postgres:admin@postgres:5432/zt_db")
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379")
    scan_interval_seconds: int = int(os.getenv("SCAN_INTERVAL_SECONDS", "60"))
    # Same 300s sliding window as every Redis-backed feature in
    # api-gateway/app/services/feature_vector.py -- the keys this job scans
    # share that TTL discipline, so the dedup window below must match it
    # (an anomaly re-alerted after its OWN underlying window has already
    # expired and reset would be a fresh occurrence, not a duplicate).
    window_seconds: int = int(os.getenv("DETECTOR_WINDOW_SECONDS", "300"))
    # Touched once per loop iteration (main.py) regardless of scan
    # success/failure -- a long-running service with no HTTP server (unlike
    # isolation-forest's GET /health), so this file's mtime is the only
    # liveness signal Docker's HEALTHCHECK has to detect a hung/deadlocked
    # process.
    heartbeat_file: str = os.getenv("HEARTBEAT_FILE", "/tmp/behavioral-detector-heartbeat")

    # Thresholds. resource_access and network/authentication are empirically
    # calibrated against real project data (see project history: the
    # session-hijack and resource-enumeration audits) -- authorization is a
    # reasonable default, not calibrated the same way (see rules.py).
    resource_access_threshold: int = int(os.getenv("RESOURCE_ACCESS_THRESHOLD", "26"))
    authentication_threshold: int = int(os.getenv("AUTHENTICATION_THRESHOLD", "2"))
    network_threshold: int = int(os.getenv("NETWORK_THRESHOLD", "2"))
    authorization_threshold: int = int(os.getenv("AUTHORIZATION_THRESHOLD", "5"))

    def __post_init__(self) -> None:
        # Fail fast at startup rather than crash every tick forever: each
        # threshold is a divisor in rules._risk_score_for (value / threshold),
        # so a misconfigured 0 (e.g. a typo'd env var) would raise
        # ZeroDivisionError on the very first matching key, on every single
        # scan, indefinitely -- caught only as a generic "scan failed" log.
        for name in (
            "resource_access_threshold",
            "authentication_threshold",
            "network_threshold",
            "authorization_threshold",
        ):
            value = getattr(self, name)
            if value < 1:
                raise ValueError(f"{name} must be >= 1, got {value!r} (it is used as a divisor)")
