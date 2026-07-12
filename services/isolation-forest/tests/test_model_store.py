from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from app.model_store import ModelStore, poll_once


def _train_and_dump(models_dir: Path, version: str) -> None:
    rng = np.random.RandomState(42)
    normal_data = rng.normal(loc=0.0, scale=1.0, size=(200, 20))
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

    normal_vector = [0.0] * 20
    anomalous_vector = [50.0] * 20

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
        store.score([0.0] * 20)


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
