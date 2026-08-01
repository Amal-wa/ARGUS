from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

# The 4 Redis structures this job reads are ALL written by
# api-gateway/app/services/feature_vector.py, on the SAME 300s sliding window
# (DetectorSettings.window_seconds must match). This job never writes to
# Redis and never touches the feature vector itself -- it only reads
# structures that already exist for a different purpose (the ML feature
# vector / the Rego high_distinct_ips rule) and applies a threshold OPA/the
# ML score does not.
RESOURCE_ACCESS_PATTERN = "resources:user:*"
AUTHENTICATION_PATTERN = "auth_failed_accounts:ip:*"
NETWORK_PATTERN = "distinct_ips:user:*"
AUTHORIZATION_PATTERN = "decisions:deny:*"


@dataclass(slots=True)
class AnomalyRecord:
    anomaly_type: str  # matches the DB enum: resource_access | authentication | network | authorization
    severity: str  # matches the DB enum: low | medium | high | critical
    risk_score: float
    contributing_features: dict[str, object]
    # id_log is NULL only for authentication: password spraying is pre-auth,
    # so there is structurally no opa_decision_log row to reference (see
    # 0013_event_anomaly_id_log_nullable) -- it is an AUDIT reference (which
    # request was this?), nothing more.
    id_log: int | None
    # subject is the STABLE identity anomaly_already_recorded() dedups on --
    # user_id for the 3 types that have one, the attacker IP for
    # authentication. Deliberately its own field, not derived from id_log:
    # a still-active user keeps producing new decisions between scan ticks,
    # so the latest id_log changes every 60s even though it's the same
    # ongoing anomaly -- deduplicating on id_log defeats deduplication
    # entirely (caught live: 4 near-identical rows for one continuous
    # attack). subject is set for all 4 anomaly types alike, so
    # deduplication doesn't need a second, inconsistent code path for
    # authentication the way reusing id_log would have (see
    # 0014_event_anomaly_subject).
    subject: str


@dataclass(slots=True)
class ScanReport:
    anomalies_found: int = 0
    anomalies_written: int = 0
    anomalies_deduplicated: int = 0


class RedisLike(Protocol):
    def scan_iter(self, match: str): ...
    def scard(self, key: str) -> int: ...
    def get(self, key: str) -> str | None: ...


class BehavioralDetectorRepository(Protocol):
    def latest_decision_id(self, user_id: str) -> int | None:
        """Most recent opa_decision_log.id for this user -- the decision the
        anomaly attaches to for audit purposes. None if no decision exists
        yet (defensive; should not happen given the Redis key and the
        decision share the same request path)."""
        ...

    def anomaly_already_recorded(self, anomaly_type: str, subject: str, window_seconds: int) -> bool:
        """True if an anomaly of this type for this subject was already
        written within window_seconds -- prevents re-alerting every scan tick
        (60s) for the same still-ongoing anomaly (5 min TTL window => up to 5
        near-identical rows without this check)."""
        ...

    def write_anomaly(self, record: AnomalyRecord) -> None: ...


def _risk_score_for(value: float, threshold: float) -> float:
    # Deliberately NOT the ML risk_score -- this is the rule's own confidence,
    # independent of the (already documented as too diluted) model score.
    # The single source of truth for both risk_score and severity (see
    # _severity_for, which buckets THIS value rather than recomputing its own
    # ratio) -- CVSS/AWS GuardDuty pattern: one continuous score, severity is
    # a bucketed view of it, never a second independent calculation. Saturates
    # at 6x threshold, same point severity reaches "critical" -- past that,
    # like CVSS capping at 10.0, no further distinction is made on purpose.
    return min(1.0, (value / threshold) / 6)


def _severity_for(risk_score: float) -> str:
    if risk_score < 0.25:
        return "low"
    if risk_score < 0.5:
        return "medium"
    if risk_score < 1.0:
        return "high"
    return "critical"


def scan_resource_access(redis_client: RedisLike, repository: BehavioralDetectorRepository, threshold: int) -> list[AnomalyRecord]:
    records = []
    for key in redis_client.scan_iter(match=RESOURCE_ACCESS_PATTERN):
        count = redis_client.scard(key)
        if count < threshold:
            continue
        user_id = key.removeprefix("resources:user:")
        id_log = repository.latest_decision_id(user_id)
        if id_log is None:
            continue
        risk_score = _risk_score_for(count, threshold)
        records.append(
            AnomalyRecord(
                anomaly_type="resource_access",
                severity=_severity_for(risk_score),
                risk_score=risk_score,
                contributing_features={"distinct_raw_resources_5min": count, "threshold": threshold},
                id_log=id_log,
                subject=user_id,
            )
        )
    return records


def scan_network(redis_client: RedisLike, repository: BehavioralDetectorRepository, threshold: int) -> list[AnomalyRecord]:
    records = []
    for key in redis_client.scan_iter(match=NETWORK_PATTERN):
        count = redis_client.scard(key)
        if count < threshold:
            continue
        user_id = key.removeprefix("distinct_ips:user:")
        id_log = repository.latest_decision_id(user_id)
        if id_log is None:
            continue
        risk_score = _risk_score_for(count, threshold)
        records.append(
            AnomalyRecord(
                anomaly_type="network",
                severity=_severity_for(risk_score),
                risk_score=risk_score,
                contributing_features={"distinct_ips_5min": count, "threshold": threshold},
                id_log=id_log,
                subject=user_id,
            )
        )
    return records


def scan_authorization(redis_client: RedisLike, repository: BehavioralDetectorRepository, threshold: int) -> list[AnomalyRecord]:
    records = []
    for key in redis_client.scan_iter(match=AUTHORIZATION_PATTERN):
        raw = redis_client.get(key)
        count = int(raw) if raw is not None else 0
        if count < threshold:
            continue
        user_id = key.removeprefix("decisions:deny:")
        id_log = repository.latest_decision_id(user_id)
        if id_log is None:
            continue
        risk_score = _risk_score_for(count, threshold)
        records.append(
            AnomalyRecord(
                anomaly_type="authorization",
                severity=_severity_for(risk_score),
                risk_score=risk_score,
                contributing_features={"deny_count_5min": count, "threshold": threshold},
                id_log=id_log,
                subject=user_id,
            )
        )
    return records


def scan_authentication(redis_client: RedisLike, threshold: int) -> list[AnomalyRecord]:
    records = []
    for key in redis_client.scan_iter(match=AUTHENTICATION_PATTERN):
        count = redis_client.scard(key)
        if count < threshold:
            continue
        attacker_ip = key.removeprefix("auth_failed_accounts:ip:")
        risk_score = _risk_score_for(count, threshold)
        records.append(
            AnomalyRecord(
                anomaly_type="authentication",
                severity=_severity_for(risk_score),
                risk_score=risk_score,
                contributing_features={
                    "distinct_accounts_targeted": count,
                    "threshold": threshold,
                    "attacker_ip": attacker_ip,
                },
                id_log=None,
                subject=attacker_ip,
            )
        )
    return records


def run_detection_scan(repository: BehavioralDetectorRepository, redis_client: RedisLike, settings) -> ScanReport:
    report = ScanReport()

    candidates = (
        scan_resource_access(redis_client, repository, settings.resource_access_threshold)
        + scan_authentication(redis_client, settings.authentication_threshold)
        + scan_network(redis_client, repository, settings.network_threshold)
        + scan_authorization(redis_client, repository, settings.authorization_threshold)
    )
    report.anomalies_found = len(candidates)

    for record in candidates:
        if repository.anomaly_already_recorded(record.anomaly_type, record.subject, settings.window_seconds):
            report.anomalies_deduplicated += 1
            continue
        repository.write_anomaly(record)
        report.anomalies_written += 1

    return report
