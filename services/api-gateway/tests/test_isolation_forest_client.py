from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import pytest

from app.core.errors import ScoringUnavailableError
from app.core.isolation_forest_client import IsolationForestClient

# No dedicated test file existed for this client before -- found during a
# live audit of the Gateway<->Isolation Forest<->OPA cycle. The client used
# to forward risk_score/model_version straight from the HTTP response with
# zero validation; proven live that an out-of-range score (57.0) crashed
# opa_decision_log's CHECK constraint with an uncaught exception, 500'ing
# every authenticated request in the system, not just the one that
# triggered it. See SECURITY.md.


@dataclass
class FakeHTTPResponse:
    status: int
    body: str

    def read(self):
        return self.body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _client() -> IsolationForestClient:
    return IsolationForestClient(base_url="http://isolation-forest:8001", score_path="/score")


def _respond(monkeypatch, body: dict):
    def fake_urlopen(request, timeout=None, context=None):
        return FakeHTTPResponse(200, json.dumps(body))

    monkeypatch.setattr("app.core.isolation_forest_client.urlopen", fake_urlopen)


def _respond_raw(monkeypatch, raw_body: str):
    def fake_urlopen(request, timeout=None, context=None):
        return FakeHTTPResponse(200, raw_body)

    monkeypatch.setattr("app.core.isolation_forest_client.urlopen", fake_urlopen)


def test_valid_response_passes_through(monkeypatch):
    _respond(monkeypatch, {"risk_score": 0.42, "model_version": "v4"})

    result = asyncio.run(_client().score([0.0] * 16))

    assert result.risk_score == 0.42
    assert result.model_version == "v4"


def test_risk_score_of_zero_is_valid_boundary(monkeypatch):
    _respond(monkeypatch, {"risk_score": 0.0, "model_version": "v4"})

    result = asyncio.run(_client().score([0.0] * 16))

    assert result.risk_score == 0.0


def test_risk_score_of_one_is_valid_boundary(monkeypatch):
    _respond(monkeypatch, {"risk_score": 1.0, "model_version": "v4"})

    result = asyncio.run(_client().score([0.0] * 16))

    assert result.risk_score == 1.0


def test_risk_score_missing_raises(monkeypatch):
    _respond(monkeypatch, {"model_version": "v4"})

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))


def test_risk_score_above_one_raises(monkeypatch):
    _respond(monkeypatch, {"risk_score": 57.0, "model_version": "v4"})

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))


def test_risk_score_negative_raises(monkeypatch):
    _respond(monkeypatch, {"risk_score": -3.0, "model_version": "v4"})

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))


def test_risk_score_nan_raises(monkeypatch):
    # json.loads accepts the literal `NaN` token by default (Python's json
    # module is permissive beyond strict JSON) -- not a theoretical input.
    _respond_raw(monkeypatch, '{"risk_score": NaN, "model_version": "v4"}')

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))


def test_risk_score_infinity_raises(monkeypatch):
    _respond_raw(monkeypatch, '{"risk_score": Infinity, "model_version": "v4"}')

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))


def test_risk_score_string_type_raises(monkeypatch):
    _respond(monkeypatch, {"risk_score": "0.42", "model_version": "v4"})

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))


def test_risk_score_boolean_type_raises(monkeypatch):
    # isinstance(True, int) is True in Python -- a naive isinstance(x, (int,
    # float)) check alone would silently accept a JSON boolean here.
    _respond(monkeypatch, {"risk_score": True, "model_version": "v4"})

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))


def test_model_version_missing_raises(monkeypatch):
    _respond(monkeypatch, {"risk_score": 0.42})

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))


def test_model_version_empty_string_raises(monkeypatch):
    _respond(monkeypatch, {"risk_score": 0.42, "model_version": ""})

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))


def test_model_version_non_string_raises(monkeypatch):
    _respond(monkeypatch, {"risk_score": 0.42, "model_version": 4})

    with pytest.raises(ScoringUnavailableError):
        asyncio.run(_client().score([0.0] * 16))
