from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest

from app.main import build_app
from app.model_store import ModelStore
from app.settings import ScoringSettings


@dataclass(slots=True)
class FakeRedis:
    values: dict[str, str] = field(default_factory=dict)

    async def get(self, key):
        return self.values.get(key)


def _train_and_dump(models_dir: Path, version: str) -> None:
    rng = np.random.RandomState(0)
    normal_data = rng.normal(size=(200, 16))
    model = IsolationForest(n_estimators=50, random_state=0)
    model.fit(normal_data)
    joblib.dump(model, models_dir / f"model_{version}.joblib")


def _build(tmp_path, *, preloaded_version: str | None = None):
    store = ModelStore(models_dir=tmp_path)
    if preloaded_version is not None:
        store.load_version(preloaded_version)
    settings = ScoringSettings(models_dir=str(tmp_path))
    return build_app(settings=settings, redis_client=FakeRedis(), model_store=store)


def test_score_endpoint_with_loaded_model_returns_valid_shape(tmp_path):
    _train_and_dump(tmp_path, "v1")
    app = _build(tmp_path, preloaded_version="v1")

    with TestClient(app) as client:
        response = client.post("/score", json={"feature_vector": [0.0] * 16})

    assert response.status_code == 200
    body = response.json()
    assert 0.0 <= body["risk_score"] <= 1.0
    assert body["model_version"] == "v1"


def test_score_endpoint_wrong_length_returns_422(tmp_path):
    app = _build(tmp_path)

    with TestClient(app) as client:
        response = client.post("/score", json={"feature_vector": [0.0] * 5})

    assert response.status_code == 422


def test_score_endpoint_old_20_dim_vector_now_rejected(tmp_path):
    # Proves the cardinality propagation is complete on this service: a
    # vector built under the OLD (pre-rebuild) 20-dimension layout must be
    # rejected, not silently accepted/mis-scored, now that the contract is 16.
    _train_and_dump(tmp_path, "v1")
    app = _build(tmp_path, preloaded_version="v1")

    with TestClient(app) as client:
        response = client.post("/score", json={"feature_vector": [0.0] * 20})

    assert response.status_code == 422


def test_score_endpoint_no_model_returns_503(tmp_path):
    app = _build(tmp_path)

    with TestClient(app) as client:
        response = client.post("/score", json={"feature_vector": [0.0] * 16})

    assert response.status_code == 503
    assert response.json()["detail"] == "no model loaded"


def test_health_reports_model_loaded_true(tmp_path):
    _train_and_dump(tmp_path, "v1")
    app = _build(tmp_path, preloaded_version="v1")

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "model_loaded": True, "model_version": "v1"}


def test_health_reports_model_loaded_false(tmp_path):
    app = _build(tmp_path)

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "model_loaded": False, "model_version": None}


def test_health_ok_before_first_poll_tick(tmp_path):
    # Neither of the two tests above ever calls record_poll_attempt() -- this
    # pins that as deliberate, not an oversight: a service that hasn't had a
    # chance to poll yet (last_poll_at() is None) must read as healthy, same
    # "bootstrap is not unhealthy" philosophy as model_loaded=False.
    _train_and_dump(tmp_path, "v1")
    app = _build(tmp_path, preloaded_version="v1")

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_reports_stale_when_heartbeat_is_old(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    # A tiny poll interval so the staleness threshold (3x it) is reachable
    # with a real, short sleep instead of reaching into private state.
    settings = ScoringSettings(models_dir=str(tmp_path), model_poll_interval_seconds=0.01)
    app = build_app(settings=settings, redis_client=FakeRedis(), model_store=store)

    store.record_poll_attempt()
    time.sleep(0.05)  # > 3 * 0.01s threshold

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "stale"
    assert body["model_loaded"] is True  # still reports what WAS loaded, just flags it stale


def test_health_not_yet_stale_within_threshold(tmp_path):
    _train_and_dump(tmp_path, "v1")
    store = ModelStore(models_dir=tmp_path)
    store.load_version("v1")
    settings = ScoringSettings(models_dir=str(tmp_path), model_poll_interval_seconds=30.0)
    app = build_app(settings=settings, redis_client=FakeRedis(), model_store=store)

    store.record_poll_attempt()  # just now -- nowhere near the 90s threshold

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
