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
    include the gateway's view of this generator).

    The refresh token is never held or read directly: /auth/login,
    /mfa/enroll, and /auth/refresh all set it as an httpOnly cookie (see
    app/routers/auth.py), and httpx.AsyncClient's default cookie jar persists
    and resends it automatically across requests on this same client instance
    -- exactly the behaviour a real browser gives the dashboard. That's also
    why /auth/refresh needs the X-Requested-With CSRF header below: the
    Gateway requires it on every cookie-authenticated call to that endpoint,
    generator included."""

    def __init__(self, base_url: str, email: str, password: str, ip: str):
        self.email = email
        self.password = password
        self.ip = ip
        self._client = httpx.AsyncClient(base_url=base_url, timeout=10.0)
        self._access_token: str | None = None
        self.stats = {"requests": 0, "status_counts": {}, "denies": 0, "refreshes": 0, "step_ups": 0}

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

    async def _refresh(self) -> bool:
        response = await self._client.post(
            "/auth/refresh",
            headers={"X-Forwarded-For": self.ip, "X-Requested-With": "argus-dashboard"},
        )
        if response.status_code != 200:
            logger.warning("%s: refresh failed (%s), re-logging in", self.email, response.status_code)
            return False
        body = response.json()
        self._access_token = body["access_token"]
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
            # A risk-based step-up 401 is NOT an expired/rejected token --
            # see the dashboard's AuthContext.tsx for the same distinction
            # ("this is exactly the bug from the first incident"). Unlike
            # the dashboard, this generator's personas do hit scored business
            # routes, so step_up_required is genuinely reachable once a model
            # is promoted (see AuthorizationService.authorize). Refreshing
            # here would burn the single-use refresh token for nothing --
            # a new access token doesn't satisfy a step-up challenge, which
            # needs a TOTP code this generator doesn't have -- and retrying
            # would just re-401 silently, forever, on the same request.
            try:
                detail = response.json().get("detail")
            except ValueError:
                detail = None
            if detail == "step_up_required":
                self.stats["step_ups"] += 1
                return response
            if not await self._refresh():
                await self.login()
            return await self.request(method, path, json=json, ip_override=ip_override, _retried=True)

        if response.status_code == 429:
            logger.info("%s: rate limited, backing off 5s", self.email)
            await asyncio.sleep(5.0)

        if response.status_code == 403:
            self.stats["denies"] += 1

        return response
