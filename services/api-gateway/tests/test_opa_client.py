from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError

import pytest

from app.core.errors import OpaUnavailableError
from app.core.opa_client import OpaClient
from app.core.request_matching import request_action
from app.schemas.authorization import OpaPolicyInput


def test_request_action_mapping():
    assert request_action("GET") == "read"
    assert request_action("POST") == "create"
    assert request_action("PUT") == "update"
    assert request_action("PATCH") == "update"
    assert request_action("DELETE") == "delete"


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


def test_opa_client_raises_unavailable_on_malformed_response(monkeypatch):
    client = OpaClient(base_url="http://opa:8181", decision_path="/v1/data/authz/decision", timeout_seconds=0.1)
    payload = OpaPolicyInput.model_validate(
        {
            "identity": {"subject": "11111111-1111-1111-1111-111111111111", "role": "reader"},
            "resource": {"http_method": "GET", "route": "/documents/{id}", "action": "read"},
            "risk_ctx": {"score": None, "model_version": None},
            "is_post_step_up": False,
            "feature_vector": [],
        }
    )

    def fake_urlopen(request, timeout):
        return FakeHTTPResponse(200, json.dumps({"result": {"decision": "UNKNOWN"}}))

    monkeypatch.setattr("app.core.opa_client.urlopen", fake_urlopen)

    with pytest.raises(OpaUnavailableError):
        client._decide_sync(payload)


def test_opa_client_raises_unavailable_on_string_result(monkeypatch):
    client = OpaClient(base_url="http://opa:8181", decision_path="/v1/data/authz/decision", timeout_seconds=0.1)
    payload = OpaPolicyInput.model_validate(
        {
            "identity": {"subject": "11111111-1111-1111-1111-111111111111", "role": "reader"},
            "resource": {"http_method": "GET", "route": "/documents/{id}", "action": "read"},
            "risk_ctx": {"score": None, "model_version": None},
            "is_post_step_up": False,
            "feature_vector": [],
        }
    )

    def fake_urlopen(request, timeout):
        return FakeHTTPResponse(200, json.dumps({"result": "deny"}))

    monkeypatch.setattr("app.core.opa_client.urlopen", fake_urlopen)

    with pytest.raises(OpaUnavailableError):
        client._decide_sync(payload)


def test_opa_client_raises_unavailable_on_connection_failure(monkeypatch):
    client = OpaClient(base_url="http://opa:8181", decision_path="/v1/data/authz/decision", timeout_seconds=0.1)
    payload = OpaPolicyInput.model_validate(
        {
            "identity": {"subject": "11111111-1111-1111-1111-111111111111", "role": "reader"},
            "resource": {"http_method": "GET", "route": "/documents/{id}", "action": "read"},
            "risk_ctx": {"score": None, "model_version": None},
            "is_post_step_up": False,
            "feature_vector": [],
        }
    )

    def fake_urlopen(request, timeout):
        raise URLError("connection refused")

    monkeypatch.setattr("app.core.opa_client.urlopen", fake_urlopen)

    with pytest.raises(OpaUnavailableError):
        client._decide_sync(payload)
