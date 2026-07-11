from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(slots=True)
class VaultTransitClient:
    vault_addr: str
    vault_token: str
    key_name: str

    async def fetch_public_key(self) -> Ed25519PublicKey:
        return await asyncio.to_thread(self._fetch_public_key_sync)

    def _fetch_public_key_sync(self) -> Ed25519PublicKey:
        endpoint = f"{self.vault_addr.rstrip('/')}/v1/transit/keys/{self.key_name}"
        request = Request(endpoint, headers={"X-Vault-Token": self.vault_token})
        try:
            with urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except URLError as exc:  # pragma: no cover - network failure path.
            raise RuntimeError("Unable to fetch Vault public key") from exc

        try:
            data = payload["data"]
            latest_version = str(data["latest_version"])
            public_key_value = data["keys"][latest_version]["public_key"]
        except (KeyError, TypeError) as exc:
            raise RuntimeError("Vault response did not include a usable public key") from exc

        try:
            raw_bytes = base64.b64decode(public_key_value)
        except Exception as exc:
            raise RuntimeError("Vault public key payload is not valid base64") from exc

        try:
            public_key = Ed25519PublicKey.from_public_bytes(raw_bytes)
        except ValueError as exc:
            raise RuntimeError("Vault public key is not a valid Ed25519 key") from exc

        return public_key

    async def encrypt(self, key_name: str, plaintext: bytes) -> str:
        return await asyncio.to_thread(self._encrypt_sync, key_name, plaintext)

    def _encrypt_sync(self, key_name: str, plaintext: bytes) -> str:
        endpoint = f"{self.vault_addr.rstrip('/')}/v1/transit/encrypt/{key_name}"
        body = json.dumps({"plaintext": base64.b64encode(plaintext).decode("ascii")}).encode("utf-8")
        request = Request(
            endpoint,
            data=body,
            headers={"X-Vault-Token": self.vault_token, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except URLError as exc:  # pragma: no cover - network failure path.
            raise RuntimeError("Unable to encrypt via Vault Transit") from exc

        try:
            ciphertext = payload["data"]["ciphertext"]
        except (KeyError, TypeError) as exc:
            raise RuntimeError("Vault response did not include a usable ciphertext") from exc

        if not isinstance(ciphertext, str) or not ciphertext:
            raise RuntimeError("Vault response did not include a usable ciphertext")

        return ciphertext

    async def decrypt(self, key_name: str, ciphertext: str) -> bytes:
        return await asyncio.to_thread(self._decrypt_sync, key_name, ciphertext)

    def _decrypt_sync(self, key_name: str, ciphertext: str) -> bytes:
        endpoint = f"{self.vault_addr.rstrip('/')}/v1/transit/decrypt/{key_name}"
        body = json.dumps({"ciphertext": ciphertext}).encode("utf-8")
        request = Request(
            endpoint,
            data=body,
            headers={"X-Vault-Token": self.vault_token, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except URLError as exc:  # pragma: no cover - network failure path.
            raise RuntimeError("Unable to decrypt via Vault Transit") from exc

        try:
            plaintext_b64 = payload["data"]["plaintext"]
        except (KeyError, TypeError) as exc:
            raise RuntimeError("Vault response did not include usable plaintext") from exc

        try:
            return base64.b64decode(plaintext_b64)
        except Exception as exc:
            raise RuntimeError("Vault plaintext payload is not valid base64") from exc
