from __future__ import annotations

import base64
import json
from dataclasses import dataclass

import pytest

from app.core.vault import VaultTransitClient


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


def _client() -> VaultTransitClient:
    return VaultTransitClient(vault_addr="http://vault:8200", vault_token="test-token", key_name="gateway-jwt")


def test_encrypt_sends_base64_plaintext_and_returns_ciphertext_verbatim(monkeypatch):
    client = _client()
    captured_request = {}

    def fake_urlopen(request, timeout):
        captured_request["request"] = request
        return FakeHTTPResponse(200, json.dumps({"data": {"ciphertext": "vault:v1:abcdef"}}))

    monkeypatch.setattr("app.core.vault.urlopen", fake_urlopen)

    ciphertext = client._encrypt_sync("totp-encryption", b"hello world")

    assert ciphertext == "vault:v1:abcdef"

    request = captured_request["request"]
    assert request.full_url == "http://vault:8200/v1/transit/encrypt/totp-encryption"
    assert request.headers["X-vault-token"] == "test-token"
    sent_body = json.loads(request.data.decode("utf-8"))
    assert base64.b64decode(sent_body["plaintext"]) == b"hello world"


def test_decrypt_sends_ciphertext_and_returns_decoded_bytes(monkeypatch):
    client = _client()
    captured_request = {}
    expected_plaintext = b"hello world"
    encoded_plaintext = base64.b64encode(expected_plaintext).decode("ascii")

    def fake_urlopen(request, timeout):
        captured_request["request"] = request
        return FakeHTTPResponse(200, json.dumps({"data": {"plaintext": encoded_plaintext}}))

    monkeypatch.setattr("app.core.vault.urlopen", fake_urlopen)

    plaintext = client._decrypt_sync("totp-encryption", "vault:v1:abcdef")

    assert plaintext == expected_plaintext

    request = captured_request["request"]
    assert request.full_url == "http://vault:8200/v1/transit/decrypt/totp-encryption"
    sent_body = json.loads(request.data.decode("utf-8"))
    assert sent_body["ciphertext"] == "vault:v1:abcdef"


def test_encrypt_raises_runtime_error_on_malformed_response(monkeypatch):
    client = _client()

    def fake_urlopen(request, timeout):
        return FakeHTTPResponse(200, json.dumps({"data": {}}))

    monkeypatch.setattr("app.core.vault.urlopen", fake_urlopen)

    with pytest.raises(RuntimeError):
        client._encrypt_sync("totp-encryption", b"hello world")


def test_decrypt_raises_runtime_error_on_malformed_response(monkeypatch):
    client = _client()

    def fake_urlopen(request, timeout):
        return FakeHTTPResponse(200, json.dumps({"data": {}}))

    monkeypatch.setattr("app.core.vault.urlopen", fake_urlopen)

    with pytest.raises(RuntimeError):
        client._decrypt_sync("totp-encryption", "vault:v1:abcdef")


def test_decrypt_raises_runtime_error_on_invalid_base64(monkeypatch):
    client = _client()

    def fake_urlopen(request, timeout):
        return FakeHTTPResponse(200, json.dumps({"data": {"plaintext": "not-valid-base64!!"}}))

    monkeypatch.setattr("app.core.vault.urlopen", fake_urlopen)

    with pytest.raises(RuntimeError):
        client._decrypt_sync("totp-encryption", "vault:v1:abcdef")
