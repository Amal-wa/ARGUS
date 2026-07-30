from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

import httpx
import numpy as np

from .client import PersonaClient
from .personas import Persona

logger = logging.getLogger(__name__)

# Fixed, order-stable index per scenario. build_scenario_rngs() spawns all
# four child streams in ONE call, keyed by this mapping -- so scenario A
# always gets child stream 0 no matter which scenario a given run actually
# launches (only one runs per --scenario invocation today, but this is what
# makes that guarantee hold even if that changes). Never derive a scenario's
# index from "the next spawn() as it starts" -- that would make A's stream
# depend on whether B happened to spawn first.
SCENARIO_SEED_INDEX = {"A": 0, "B": 1, "C": 2, "D": 3}


def build_scenario_rngs(global_seed: int) -> dict[str, np.random.Generator]:
    """One independent numpy Generator per attack scenario, derived from the
    CLI's global --seed via SeedSequence.spawn(). Same seed -> same attack,
    every time (document shuffle order in A, hijack IP in C, action sequence
    in D). Each scenario's stream is an independent child sequence, spawned
    once up front -- it never reuses or perturbs another scenario's stream,
    and it never touches the normal-traffic path's `random.Random` instances
    (personas.py / behaviors.py) at all, so launching an attack cannot change
    the background traffic's sequence.
    """
    root = np.random.SeedSequence(global_seed)
    children = root.spawn(len(SCENARIO_SEED_INDEX))
    return {name: np.random.default_rng(children[index]) for name, index in SCENARIO_SEED_INDEX.items()}


# Attack pacing is deliberately tighter (lower-variance) than the normal
# path's exponential inter-arrival times (see behaviors._sample_interval) --
# a perfectly FIXED interval would itself be the automation tell the model
# keys on, instead of the actual enumeration/hijack/escalation behavior it's
# supposed to demonstrate. Gamma(shape=6) has coefficient of variation
# 1/sqrt(6) =~ 0.41, versus 1.0 for the exponential normal traffic uses:
# noticeably more regular (scripted-automation-like) while still never
# producing two identical consecutive draws. shape=6 sits mid-range of a
# reasonable 4-8 band -- high enough for a clearly tighter spread, not so
# high it collapses toward a constant. mean = shape * scale, so scale is
# solved from the configured requests_per_minute to keep the mean throughput
# exactly on target regardless of shape.
_ATTACK_INTERVAL_GAMMA_SHAPE = 6.0


def _sample_attack_interval(rng: np.random.Generator, requests_per_minute: float) -> float:
    mean = 60.0 / requests_per_minute
    scale = mean / _ATTACK_INTERVAL_GAMMA_SHAPE
    return float(rng.gamma(_ATTACK_INTERVAL_GAMMA_SHAPE, scale))


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_start(name: str, **details) -> None:
    logger.warning("[ATTACK START %s] %s %s", _ts(), name, details)


def _log_stop(name: str, **details) -> None:
    logger.warning("[ATTACK STOP  %s] %s %s", _ts(), name, details)


async def scenario_a_resource_enumeration(
    actor: PersonaClient,
    all_document_ids: list[str],
    rng: np.random.Generator,
    *,
    duration_seconds: float,
    requests_per_minute: float,
) -> None:
    """Compromised account: resource enumeration.

    A valid, already-authenticated persona (valid token, valid role, RBAC
    allows `read`) suddenly walks hundreds of distinct documents it has never
    touched, at a sustained pace kept just under the IP rate limit. Nothing in
    RBAC/OPA rejects a single one of these requests -- only the BEHAVIOR
    (distinct-paths spike, requests/minute spike, near-zero interval, novel
    resources) is aberrant. This is the scenario that justifies the whole
    project: valid credentials pass every classic access control; only
    behavioral analysis catches it.
    """
    _log_start("A-resource-enumeration", actor=actor.email, ip=actor.ip, requests_per_minute=requests_per_minute)
    shuffled = list(all_document_ids)
    rng.shuffle(shuffled)

    deadline = time.monotonic() + duration_seconds
    count = 0
    for document_id in shuffled:
        if time.monotonic() >= deadline:
            break
        await actor.request("GET", f"/documents/{document_id}")
        count += 1
        await asyncio.sleep(_sample_attack_interval(rng, requests_per_minute))

    _log_stop("A-resource-enumeration", actor=actor.email, documents_touched=count)


async def scenario_b_password_spraying(
    base_url: str, attacker_ip: str, candidate_emails: list[str], *, common_password: str, delay_seconds: float
) -> None:
    """Password spraying: ONE ip, ONE common password, MANY different accounts
    -- one attempt per account (no lockout triggered), spaced out (no IP rate
    limit triggered). Detectable via auth_failed:ip:{ip} accumulating across
    distinct accounts, not via any single-account signal."""
    _log_start("B-password-spraying", attacker_ip=attacker_ip, accounts=len(candidate_emails))

    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        for email in candidate_emails:
            await client.post(
                "/auth/login",
                json={"email": email, "password": common_password},
                headers={"X-Forwarded-For": attacker_ip},
            )
            await asyncio.sleep(delay_seconds)

    _log_stop("B-password-spraying", attacker_ip=attacker_ip, accounts=len(candidate_emails))


async def scenario_c_session_hijack(
    actor: PersonaClient,
    all_document_ids: list[str],
    rng: np.random.Generator,
    *,
    duration_seconds: float,
    requests_per_minute: float,
) -> None:
    """Session hijack / context switch: an existing persona's (already-valid)
    credentials are suddenly used from a brand-new IP never seen for that
    user, while the REQUEST PATTERN otherwise looks ordinary (same favorite-ish
    resource access, moderate pace). Detectable via distinct-IPs-per-user
    jumping, not via anything about the requests themselves."""
    # endpoint=True: inclusive high, matching random.randint(1, 254)'s semantics.
    hijack_ip = f"203.0.113.{int(rng.integers(1, 254, endpoint=True))}"  # TEST-NET-3, never a real persona IP
    _log_start("C-session-hijack", actor=actor.email, real_ip=actor.ip, hijack_ip=hijack_ip)

    deadline = time.monotonic() + duration_seconds
    pool = all_document_ids or [None]
    count = 0
    while time.monotonic() < deadline:
        document_id = rng.choice(pool)
        if document_id:
            await actor.request("GET", f"/documents/{document_id}", ip_override=hijack_ip)
            count += 1
        await asyncio.sleep(_sample_attack_interval(rng, requests_per_minute))

    _log_stop("C-session-hijack", actor=actor.email, hijack_ip=hijack_ip, requests=count)


async def scenario_d_privilege_escalation(
    actor: PersonaClient,
    all_document_ids: list[str],
    rng: np.random.Generator,
    *,
    duration_seconds: float,
    requests_per_minute: float,
) -> None:
    """Privilege escalation attempts: a reader persona hammers write routes
    and /users. OPA denies every single one -- the attack fails outright --
    but the PATTERN of repeated denials (decisions:deny:{user_id} spiking) is
    the signal."""
    _log_start("D-privilege-escalation", actor=actor.email, role="reader (expected)")

    deadline = time.monotonic() + duration_seconds
    pool = all_document_ids or [None]
    attempts = ("create_document", "update_document", "delete_document", "list_users")
    count = 0
    denies = 0
    while time.monotonic() < deadline:
        attempt = rng.choice(attempts)
        if attempt == "create_document":
            response = await actor.request("POST", "/documents", json={"title": "escalation attempt"})
        elif attempt == "update_document":
            document_id = rng.choice(pool)
            response = await actor.request("PUT", f"/documents/{document_id}", json={"content": "x"}) if document_id else None
        elif attempt == "delete_document":
            document_id = rng.choice(pool)
            response = await actor.request("DELETE", f"/documents/{document_id}") if document_id else None
        else:
            response = await actor.request("GET", "/users")

        count += 1
        if response is not None and response.status_code == 403:
            denies += 1
        await asyncio.sleep(_sample_attack_interval(rng, requests_per_minute))

    _log_stop("D-privilege-escalation", actor=actor.email, attempts=count, denies=denies)
