from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger(__name__)


class AuthenticationError(RuntimeError):
    pass


class PersonaClient:
    """Authenticated HTTP client for one persona: real login via
    POST /auth/login, holds the access token, refreshes via POST /auth/refresh
    on expiry/401. No hand-forged JWTs anywhere. Sends its persona's IP via
    X-Forwarded-For on every request (see README for why TRUSTED_PROXIES must
    include the gateway's view of this generator)."""

    def __init__(self, base_url: str, email: str, password: str, ip: str):
        self.email = email
        self.password = password
        self.ip = ip
        self._client = httpx.AsyncClient(base_url=base_url, timeout=10.0)
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self.stats = {"requests": 0, "status_counts": {}, "denies": 0, "refreshes": 0}

    async def close(self) -> None:
        await self._client.aclose()

    async def login(self) -> None:
        response = await self._client.post(
            "/auth/login",
            json={"email": self.email, "password": self.password},
            headers={"X-Forwarded-For": self.ip},
        )
        if response.status_code != 200:
            raise AuthenticationError(f"login failed for {self.email}: {response.status_code} {response.text}")
        body = response.json()

        if body.get("mfa_enrollment_required"):
            # Mandatory MFA (see AuthService.login): an account with no
            # user_mfa row gets a narrow enrollment token instead of a full
            # pair. Seeded personas are pre-enrolled by scripts/seed_users.py
            # / scripts/seed_business_data.py, so this should not normally
            # fire -- it's a defensive fallback, not the expected path.
            # POST /mfa/enroll takes no code/proof and mints a fresh secret;
            # this generator has no use for that secret (it never completes a
            # step-up challenge), so it's discarded once the full pair is in
            # hand.
            enroll_response = await self._client.post(
                "/mfa/enroll", headers={"Authorization": f"Bearer {body['enrollment_token']}"}
            )
            if enroll_response.status_code != 200:
                raise AuthenticationError(
                    f"mfa auto-enrollment failed for {self.email}: {enroll_response.status_code} {enroll_response.text}"
                )
            body = enroll_response.json()
            logger.warning("%s: was not pre-enrolled in MFA, auto-enrolled now", self.email)

        self._access_token = body["access_token"]
        self._refresh_token = body["refresh_token"]

    async def _refresh(self) -> bool:
        if self._refresh_token is None:
            return False
        response = await self._client.post(
            "/auth/refresh",
            json={"refresh_token": self._refresh_token},
            headers={"X-Forwarded-For": self.ip},
        )
        if response.status_code != 200:
            logger.warning("%s: refresh failed (%s), re-logging in", self.email, response.status_code)
            return False
        body = response.json()
        self._access_token = body["access_token"]
        self._refresh_token = body["refresh_token"]
        self.stats["refreshes"] += 1
        return True

    async def request(
        self, method: str, path: str, *, json: dict | None = None, ip_override: str | None = None, _retried: bool = False
    ) -> httpx.Response:
        """ip_override lets attack scenarios (e.g. session hijack) send from a
        different XFF than this persona's own, without touching its identity."""
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "X-Forwarded-For": ip_override or self.ip,
        }
        response = await self._client.request(method, path, json=json, headers=headers)

        self.stats["requests"] += 1
        self.stats["status_counts"][response.status_code] = self.stats["status_counts"].get(response.status_code, 0) + 1

        if response.status_code == 401 and not _retried:
            if not await self._refresh():
                await self.login()
            return await self.request(method, path, json=json, ip_override=ip_override, _retried=True)

        if response.status_code == 429:
            logger.info("%s: rate limited, backing off 5s", self.email)
            await asyncio.sleep(5.0)

        if response.status_code == 403:
            self.stats["denies"] += 1

        return response
