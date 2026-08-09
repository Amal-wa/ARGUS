from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from pathlib import Path

import json

import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from app.model_store import ModelStore, percentile_calibrate, poll_forever, poll_once, risk_score_from_anomaly_score


def _train_and_dump(models_dir: Path, version: str) -> None:
    rng = np.random.RandomState(42)
    normal_data = rng.normal(loc=0.0, scale=1.0, size=(200, 16))
    model = IsolationForest(n_estimators=50, random_state=42)
    model.fit(normal_data)
    joblib.dump(model, models_dir / f"model_{version}.joblib")


def test_current_is_none_before_any_load(tmp_path):
    store = ModelStore(models_dir=tmp_path)
    assert store.current() == (None, None)


def test_load_version_and_score(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)

    store.load_version("v1")

    model, version = store.current()
    assert model is not None
    assert version == "v1"


def test_score_is_bounded_and_monotonic_for_anomalies(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")

    normal_vector = [0.0] * 16
    anomalous_vector = [50.0] * 16

    normal_score = store.score(normal_vector)
    anomalous_score = store.score(anomalous_vector)

    assert 0.0 <= normal_score <= 1.0
    assert 0.0 <= anomalous_score <= 1.0
    assert anomalous_score > normal_score


def test_load_missing_version_raises_and_keeps_existing_model(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    loaded_model, loaded_version = store.current()

    with pytest.raises(FileNotFoundError):
        store.load_version("v2-does-not-exist")

    model, version = store.current()
    assert model is loaded_model
    assert version == loaded_version == "v1"


def test_load_corrupt_file_raises_and_keeps_existing_model(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    loaded_model, _ = store.current()

    (tmp_path / "model_v2.joblib").write_bytes(b"not a real joblib file")

    with pytest.raises(RuntimeError):
        store.load_version("v2")

    model, version = store.current()
    assert model is loaded_model
    assert version == "v1"


def test_score_without_loaded_model_raises(tmp_path):
    store = ModelStore(models_dir=tmp_path)

    with pytest.raises(RuntimeError):
        store.score([0.0] * 16)


def test_percentile_calibrate_interpolates_against_breakpoints():
    breakpoints = [0.59, 0.60, 0.61, 0.63, 0.66]  # percentiles 0/25/50/75/100
    assert percentile_calibrate(0.59, breakpoints) == pytest.approx(0.0)
    assert percentile_calibrate(0.61, breakpoints) == pytest.approx(0.5)
    assert percentile_calibrate(0.66, breakpoints) == pytest.approx(1.0)
    # Halfway between the 50th and 75th breakpoints -> halfway between their ranks.
    assert percentile_calibrate(0.62, breakpoints) == pytest.approx(0.625)


def test_percentile_calibrate_clamps_outside_calibration_range():
    # Live traffic can fall slightly outside what the calibration batch observed.
    breakpoints = [0.59, 0.60, 0.61, 0.63, 0.66]
    assert percentile_calibrate(0.50, breakpoints) == 0.0
    assert percentile_calibrate(0.90, breakpoints) == 1.0


def test_load_version_without_calibration_leaves_score_unscaled(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")

    assert store.calibration() is None
    normal_vector = [0.0] * 16
    model, _ = store.current()
    expected_raw = risk_score_from_anomaly_score(
        float(model.score_samples(np.asarray([normal_vector], dtype=float))[0])
    )
    assert store.score(normal_vector) == pytest.approx(expected_raw)


def test_score_applies_calibration_when_present(tmp_path):
    _train_and_dump(tmp_path, "v1")
    uncalibrated = ModelStore(models_dir=tmp_path)
    uncalibrated.load_version("v1")
    normal_vector = [0.0] * 16
    raw_score = uncalibrated.score(normal_vector)

    # Calibrate so raw_score sits exactly at the top breakpoint -- the
    # calibrated output must land at 1.0.
    breakpoints = list(np.linspace(raw_score - 0.1, raw_score, num=101))
    calibrated = ModelStore(models_dir=tmp_path)
    calibrated.load_version("v1", score_breakpoints=breakpoints)

    assert calibrated.score(normal_vector) == pytest.approx(1.0)


def test_load_version_with_degenerate_calibration_falls_back_to_raw(tmp_path):
    _train_and_dump(tmp_path, "v1")
    uncalibrated = ModelStore(models_dir=tmp_path)
    uncalibrated.load_version("v1")
    normal_vector = [0.0] * 16
    raw_score = uncalibrated.score(normal_vector)

    degenerate = ModelStore(models_dir=tmp_path)
    degenerate.load_version("v1", score_breakpoints=[0.6])  # single point, not a usable range

    assert degenerate.score(normal_vector) == pytest.approx(raw_score)


@dataclass(slots=True)
class FakeRedis:
    values: dict[str, str] = field(default_factory=dict)

    async def get(self, key):
        return self.values.get(key)


def test_poll_once_reloads_on_version_change(tmp_path):
    _train_and_dump(tmp_path, "v1")
    _train_and_dump(tmp_path, "v2")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    redis = FakeRedis({"model:active_version": "v2"})

    asyncio.run(poll_once(store, redis))

    _, version = store.current()
    assert version == "v2"


def test_poll_once_is_noop_when_version_unchanged(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    original_model, _ = store.current()
    redis = FakeRedis({"model:active_version": "v1"})

    asyncio.run(poll_once(store, redis))

    model, version = store.current()
    assert model is original_model
    assert version == "v1"


def test_poll_once_is_noop_when_no_active_version_set(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    redis = FakeRedis({})

    asyncio.run(poll_once(store, redis))

    _, version = store.current()
    assert version == "v1"


def test_poll_once_keeps_serving_old_model_on_failed_reload(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    redis = FakeRedis({"model:active_version": "v-missing"})

    asyncio.run(poll_once(store, redis))

    _, version = store.current()
    assert version == "v1"


def test_poll_once_reads_calibration_keys_on_version_change(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    breakpoints = list(np.linspace(0.59, 0.66, num=101))
    redis = FakeRedis(
        {
            "model:active_version": "v1",
            "model:active_score_breakpoints": json.dumps(breakpoints),
        }
    )

    asyncio.run(poll_once(store, redis))

    assert store.calibration() == pytest.approx(breakpoints)


def test_poll_once_leaves_calibration_none_when_keys_absent(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    redis = FakeRedis({"model:active_version": "v1"})

    asyncio.run(poll_once(store, redis))

    assert store.calibration() is None


def test_poll_once_ignores_malformed_json_calibration_key(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    redis = FakeRedis(
        {
            "model:active_version": "v1",
            "model:active_score_breakpoints": "not-json",
        }
    )

    asyncio.run(poll_once(store, redis))

    assert store.calibration() is None


def test_poll_once_ignores_non_monotonic_calibration_key(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    redis = FakeRedis(
        {
            "model:active_version": "v1",
            "model:active_score_breakpoints": json.dumps([0.6, 0.5, 0.7]),  # not sorted
        }
    )

    asyncio.run(poll_once(store, redis))

    assert store.calibration() is None


@dataclass(slots=True)
class FlakyThenHealthyRedis:
    """Simulates a Redis connection that drops for the first `fail_calls` .get()
    calls (e.g. a container restart mid-poll), then recovers -- the scenario
    that silently killed poll_forever's background task in production before
    poll_once's exceptions were caught at the poll_forever level."""

    values: dict[str, str] = field(default_factory=dict)
    fail_calls: int = 0
    calls: int = field(default=0, init=False)

    async def get(self, key):
        self.calls += 1
        if self.calls <= self.fail_calls:
            raise ConnectionError("simulated Redis outage")
        return self.values.get(key)


def test_poll_forever_survives_a_redis_error_and_reloads_on_a_later_tick(tmp_path):
    _train_and_dump(tmp_path, "v1")
    _train_and_dump(tmp_path, "v2")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    # First poll tick's redis_client.get() raises (simulated outage); the
    # active version is already in place by the time the second tick runs.
    redis = FlakyThenHealthyRedis({"model:active_version": "v2"}, fail_calls=1)

    async def _run():
        task = asyncio.create_task(poll_forever(store, redis, poll_interval_seconds=0.01))
        await asyncio.sleep(0.05)  # several ticks: the failing one + at least one healthy one
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(_run())

    _, version = store.current()
    assert version == "v2"  # picked up despite the first tick's Redis error
    assert redis.calls >= 2  # the loop kept ticking after the failure, it didn't die
    # The heartbeat is the actual liveness signal /health's staleness check
    # reads -- it must advance THROUGH the failing tick too, not just on
    # successful ones, or a stalled-but-not-dead loop would look stale.
    assert store.last_poll_at() is not None


def test_record_poll_attempt_advances_even_through_a_failed_tick(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    redis = FlakyThenHealthyRedis({"model:active_version": "v1"}, fail_calls=1)

    async def _run():
        task = asyncio.create_task(poll_forever(store, redis, poll_interval_seconds=0.01))
        await asyncio.sleep(0.03)  # at least the one failing tick
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    before = store.last_poll_at()
    asyncio.run(_run())

    assert before is None
    assert store.last_poll_at() is not None
