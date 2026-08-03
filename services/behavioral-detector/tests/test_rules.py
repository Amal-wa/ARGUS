from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from app.rules import (
    AnomalyRecord,
    RESOURCE_ACCESS_PATTERN,
    ScanReport,
    run_detection_scan,
    scan_authentication,
    scan_authorization,
    scan_network,
    scan_resource_access,
)
from app.settings import DetectorSettings


@dataclass(slots=True)
class FakeRedis:
    strings: dict[str, str] = field(default_factory=dict)
    sets: dict[str, set[str]] = field(default_factory=dict)
    # Patterns that raise instead of scanning -- simulates a transient Redis
    # failure (or any other exception) hitting a single rule's SCAN call.
    broken_patterns: frozenset[str] = frozenset()

    def scan_iter(self, match: str):
        if match in self.broken_patterns:
            raise ConnectionError("simulated Redis failure")
        prefix = match.rstrip("*")
        for key in list(self.strings) + list(self.sets):
            if key.startswith(prefix):
                yield key

    def scard(self, key: str) -> int:
        return len(self.sets.get(key, set()))

    def get(self, key: str) -> str | None:
        return self.strings.get(key)


@dataclass(slots=True)
class FakeRepository:
    decision_ids: dict[str, int] = field(default_factory=dict)
    already_recorded: set[tuple[str, str]] = field(default_factory=set)
    written: list[AnomalyRecord] = field(default_factory=list)

    def latest_decision_id(self, user_id: str) -> int | None:
        return self.decision_ids.get(user_id)

    def anomaly_already_recorded(self, anomaly_type: str, subject: str, window_seconds: int) -> bool:
        return (anomaly_type, subject) in self.already_recorded

    def write_anomaly(self, record: AnomalyRecord) -> None:
        self.written.append(record)
        self.already_recorded.add((record.anomaly_type, record.subject))


def _settings(**overrides) -> DetectorSettings:
    defaults = dict(
        resource_access_threshold=26,
        authentication_threshold=2,
        network_threshold=2,
        authorization_threshold=5,
        window_seconds=300,
    )
    defaults.update(overrides)
    return DetectorSettings(**defaults)


# --- resource_access ---


def test_scan_resource_access_flags_at_or_above_threshold():
    redis = FakeRedis(sets={"resources:user:u1": {f"/documents/{i}" for i in range(26)}})
    repository = FakeRepository(decision_ids={"u1": 42})

    records = scan_resource_access(redis, repository, threshold=26)

    assert len(records) == 1
    assert records[0].anomaly_type == "resource_access"
    assert records[0].id_log == 42
    assert records[0].subject == "u1"
    assert records[0].contributing_features == {"distinct_raw_resources_5min": 26, "threshold": 26}


def test_scan_resource_access_ignores_below_threshold():
    redis = FakeRedis(sets={"resources:user:u1": {f"/documents/{i}" for i in range(25)}})
    repository = FakeRepository(decision_ids={"u1": 42})

    records = scan_resource_access(redis, repository, threshold=26)

    assert records == []


def test_scan_resource_access_skips_when_no_decision_exists():
    # Defensive: shouldn't happen given the key and the decision share a
    # request path, but must not crash if it somehow does.
    redis = FakeRedis(sets={"resources:user:u1": {f"/documents/{i}" for i in range(30)}})
    repository = FakeRepository(decision_ids={})

    records = scan_resource_access(redis, repository, threshold=26)

    assert records == []


# --- network ---


def test_scan_network_flags_at_threshold():
    redis = FakeRedis(sets={"distinct_ips:user:u1": {"10.10.0.1", "203.0.113.9"}})
    repository = FakeRepository(decision_ids={"u1": 7})

    records = scan_network(redis, repository, threshold=2)

    assert len(records) == 1
    assert records[0].anomaly_type == "network"
    assert records[0].contributing_features == {"distinct_ips_5min": 2, "threshold": 2}


def test_scan_network_ignores_single_ip():
    redis = FakeRedis(sets={"distinct_ips:user:u1": {"10.10.0.1"}})
    repository = FakeRepository(decision_ids={"u1": 7})

    assert scan_network(redis, repository, threshold=2) == []


# --- authorization ---


def test_scan_authorization_flags_at_threshold():
    redis = FakeRedis(strings={"decisions:deny:u1": "5"})
    repository = FakeRepository(decision_ids={"u1": 99})

    records = scan_authorization(redis, repository, threshold=5)

    assert len(records) == 1
    assert records[0].anomaly_type == "authorization"
    assert records[0].contributing_features == {"deny_count_5min": 5, "threshold": 5}


def test_scan_authorization_ignores_below_threshold():
    redis = FakeRedis(strings={"decisions:deny:u1": "4"})
    repository = FakeRepository(decision_ids={"u1": 99})

    assert scan_authorization(redis, repository, threshold=5) == []


# --- authentication (no id_log) ---


def test_scan_authentication_flags_at_threshold_with_no_id_log():
    redis = FakeRedis(sets={"auth_failed_accounts:ip:198.51.100.7": {"reader1@zt.local", "reader2@zt.local"}})

    records = scan_authentication(redis, threshold=2)

    assert len(records) == 1
    assert records[0].anomaly_type == "authentication"
    assert records[0].id_log is None
    assert records[0].subject == "198.51.100.7"
    assert records[0].contributing_features == {
        "distinct_accounts_targeted_5min": 2,
        "threshold": 2,
        "attacker_ip": "198.51.100.7",
    }


def test_scan_authentication_ignores_single_account():
    redis = FakeRedis(sets={"auth_failed_accounts:ip:198.51.100.7": {"reader1@zt.local"}})

    assert scan_authentication(redis, threshold=2) == []


# --- severity / risk_score ---


def _network_record_at_ratio(threshold: int, ratio: float) -> AnomalyRecord:
    count = round(threshold * ratio)
    redis = FakeRedis(sets={"distinct_ips:user:u1": {str(i) for i in range(count)}})
    repository = FakeRepository(decision_ids={"u1": 1})
    return scan_network(redis, repository, threshold=threshold)[0]


def test_severity_is_a_bucketed_view_of_risk_score_not_a_separate_calculation():
    # CVSS / AWS GuardDuty pattern: ONE continuous score, severity is a
    # threshold-partition of that SAME score -- not computed independently
    # (an earlier version had risk_score saturate at 2x threshold while
    # severity kept distinguishing up to 6x, so risk_score gave zero
    # information in that whole range even though severity still varied).
    at_threshold = _network_record_at_ratio(threshold=2, ratio=1)  # just above the floor
    medium = _network_record_at_ratio(threshold=2, ratio=1.5)  # risk_score lands exactly on 0.25
    high = _network_record_at_ratio(threshold=2, ratio=3)  # risk_score lands exactly on 0.5
    critical = _network_record_at_ratio(threshold=2, ratio=6)  # risk_score lands exactly on 1.0
    far_above = _network_record_at_ratio(threshold=2, ratio=10)  # still capped at 1.0, like CVSS at 10.0

    assert at_threshold.risk_score == pytest.approx(1 / 6)
    assert at_threshold.severity == "low"

    assert medium.risk_score == pytest.approx(0.25)
    assert medium.severity == "medium"

    assert high.risk_score == pytest.approx(0.5)
    assert high.severity == "high"

    assert critical.risk_score == pytest.approx(1.0)
    assert critical.severity == "critical"

    # Saturates on purpose past 6x -- no further distinction, same as CVSS
    # capping at 10.0 rather than trying to rank "very critical" vs "extremely
    # critical".
    assert far_above.risk_score == pytest.approx(1.0)
    assert far_above.severity == "critical"


# --- orchestration: run_detection_scan ---


def test_run_detection_scan_writes_all_four_types_when_all_trigger():
    redis = FakeRedis(
        sets={
            "resources:user:u1": {f"/d/{i}" for i in range(30)},
            "auth_failed_accounts:ip:198.51.100.7": {"a@zt.local", "b@zt.local"},
            "distinct_ips:user:u2": {"10.10.0.1", "203.0.113.9"},
        },
        strings={"decisions:deny:u3": "10"},
    )
    repository = FakeRepository(decision_ids={"u1": 1, "u2": 2, "u3": 3})
    settings = _settings()

    report = run_detection_scan(repository, redis, settings)

    assert report.anomalies_found == 4
    assert report.anomalies_written == 4
    assert report.anomalies_deduplicated == 0
    assert {r.anomaly_type for r in repository.written} == {
        "resource_access",
        "authentication",
        "network",
        "authorization",
    }


def test_run_detection_scan_deduplicates_already_recorded_anomaly():
    redis = FakeRedis(sets={"distinct_ips:user:u1": {"10.10.0.1", "203.0.113.9"}})
    repository = FakeRepository(decision_ids={"u1": 1}, already_recorded={("network", "u1")})
    settings = _settings()

    report = run_detection_scan(repository, redis, settings)

    assert report.anomalies_found == 1
    assert report.anomalies_written == 0
    assert report.anomalies_deduplicated == 1
    assert repository.written == []


def test_run_detection_scan_deduplicates_across_ticks_even_as_id_log_changes():
    # Regression test for a bug caught live: a still-active user produces a
    # NEW opa_decision_log row between scan ticks, so latest_decision_id
    # returns a different id_log every 60s even though it's the same ongoing
    # anomaly. Deduplicating on id_log itself (instead of the stable user_id)
    # let 4 near-identical rows through for one continuous attack replay.
    redis = FakeRedis(sets={"resources:user:u1": {f"/d/{i}" for i in range(30)}})
    repository = FakeRepository(decision_ids={"u1": 100})
    settings = _settings()

    first = run_detection_scan(repository, redis, settings)

    # Simulate the next scan tick: the user made more requests in between, so
    # the "latest decision" is now a different id_log -- but it's still u1.
    repository.decision_ids["u1"] = 999
    second = run_detection_scan(repository, redis, settings)

    assert first.anomalies_written == 1
    assert second.anomalies_written == 0
    assert second.anomalies_deduplicated == 1
    assert len(repository.written) == 1


def test_run_detection_scan_is_noop_on_empty_redis():
    report = run_detection_scan(FakeRepository(), FakeRedis(), _settings())

    assert report == ScanReport(anomalies_found=0, anomalies_written=0, anomalies_deduplicated=0)


def test_run_detection_scan_isolates_a_failing_rule_from_the_others():
    # Regression test: the 4 scan_* calls used to be chained in a single
    # Python expression, so an exception raised by ANY one of them (a
    # transient Redis error, a corrupted value, a misconfigured threshold)
    # silently cancelled the other 3 for that entire tick. Here
    # resource_access's SCAN blows up but network must still be detected and
    # written.
    redis = FakeRedis(
        sets={"distinct_ips:user:u2": {"10.10.0.1", "203.0.113.9"}},
        broken_patterns=frozenset({RESOURCE_ACCESS_PATTERN}),
    )
    repository = FakeRepository(decision_ids={"u2": 2})
    settings = _settings()

    report = run_detection_scan(repository, redis, settings)

    assert report.anomalies_found == 1
    assert report.anomalies_written == 1
    assert {r.anomaly_type for r in repository.written} == {"network"}
