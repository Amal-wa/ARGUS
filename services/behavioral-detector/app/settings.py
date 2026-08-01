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

    # Thresholds. resource_access and network/authentication are empirically
    # calibrated against real project data (see project history: the
    # session-hijack and resource-enumeration audits) -- authorization is a
    # reasonable default, not calibrated the same way (see rules.py).
    resource_access_threshold: int = int(os.getenv("RESOURCE_ACCESS_THRESHOLD", "26"))
    authentication_threshold: int = int(os.getenv("AUTHENTICATION_THRESHOLD", "2"))
    network_threshold: int = int(os.getenv("NETWORK_THRESHOLD", "2"))
    authorization_threshold: int = int(os.getenv("AUTHORIZATION_THRESHOLD", "5"))
