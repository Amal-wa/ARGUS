from __future__ import annotations

import asyncio
import logging
import random

import numpy as np

from .client import PersonaClient
from .personas import Persona

logger = logging.getLogger(__name__)

# Rare-deny probabilities for normal traffic. Keep these low: if denies were
# common in the training window, the model would learn "deny" as normal and
# scenario D (privilege escalation attempts, signaled by a burst of denies)
# would become undetectable.
READER_STRAY_WRITE_PROBABILITY = 0.02
NON_ADMIN_USERS_PEEK_PROBABILITY = 0.01


async def run_persona_normal(persona: Persona, client: PersonaClient, rng: random.Random, stop_event: asyncio.Event) -> None:
    await client.login()
    logger.info("%s (%s) logged in, ip=%s, mean_interval=%.1fs", persona.email, persona.role, persona.ip, persona.mean_interval_seconds)

    session_opened_documents: set[str] = set()

    while not stop_event.is_set():
        interval = _sample_interval(persona.mean_interval_seconds)
        if await _sleep_or_stop(interval, stop_event):
            break

        await _do_action(persona, client, rng, session_opened_documents)

        if rng.random() < persona.burst_probability:
            burst_length = rng.randint(*persona.burst_length_range)
            for _ in range(burst_length):
                if await _sleep_or_stop(rng.uniform(2, 8), stop_event):
                    return
                await _do_action(persona, client, rng, session_opened_documents)
            # Long idle pause after a burst -- real users pause after a flurry of activity.
            if await _sleep_or_stop(persona.mean_interval_seconds * 3, stop_event):
                return


def _sample_interval(mean_interval_seconds: float) -> float:
    # Exponential, not uniform -- this is what human inter-arrival times look
    # like. A uniform delay would itself be an artificial regularity.
    return max(1.0, float(np.random.exponential(mean_interval_seconds)))


async def _sleep_or_stop(seconds: float, stop_event: asyncio.Event) -> bool:
    """Sleeps up to `seconds`, waking early (returning True) if stopped."""
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
        return True
    except asyncio.TimeoutError:
        return False


def _pick_document_id(persona: Persona, rng: random.Random) -> str | None:
    pool = persona.favorite_document_ids if persona.favorite_document_ids else persona.all_document_ids
    if persona.favorite_document_ids and persona.all_document_ids and rng.random() < 0.75:
        pool = persona.favorite_document_ids
    elif persona.all_document_ids:
        pool = persona.all_document_ids
    return rng.choice(pool) if pool else None


async def _do_action(persona: Persona, client: PersonaClient, rng: random.Random, session_opened_documents: set[str]) -> None:
    try:
        if persona.role == "reader":
            await _reader_action(persona, client, rng)
        elif persona.role == "editor":
            await _editor_action(persona, client, rng, session_opened_documents)
        else:
            await _admin_action(persona, client, rng, session_opened_documents)
    except Exception:
        logger.exception("%s: action failed", persona.email)


async def _reader_action(persona: Persona, client: PersonaClient, rng: random.Random) -> None:
    if rng.random() < READER_STRAY_WRITE_PROBABILITY:
        # Rare, legitimate 403: a reader occasionally tries to edit something.
        document_id = _pick_document_id(persona, rng)
        if document_id:
            await client.request("PUT", f"/documents/{document_id}", json={"content": "oops"})
        return

    if rng.random() < 0.15:
        await client.request("GET", "/documents")
        return

    document_id = _pick_document_id(persona, rng)
    if document_id:
        await client.request("GET", f"/documents/{document_id}")


async def _editor_action(persona: Persona, client: PersonaClient, rng: random.Random, session_opened_documents: set[str]) -> None:
    roll = rng.random()

    if roll < persona.write_ratio and session_opened_documents:
        document_id = rng.choice(list(session_opened_documents))
        await client.request("PUT", f"/documents/{document_id}", json={"content": "updated by generator"})
        return

    if roll < persona.write_ratio + 0.05:
        response = await client.request("POST", "/documents", json={"title": "Generator document", "content": "hello"})
        if response.status_code == 201:
            body = response.json()
            session_opened_documents.add(body["document_id"])
        return

    if rng.random() < NON_ADMIN_USERS_PEEK_PROBABILITY:
        await client.request("GET", "/users")
        return

    document_id = _pick_document_id(persona, rng)
    if document_id:
        response = await client.request("GET", f"/documents/{document_id}")
        # "Nobody edits a document they never opened": a real GET must precede
        # any PUT of the same resource in this session.
        if response.status_code == 200:
            session_opened_documents.add(document_id)


async def _admin_action(persona: Persona, client: PersonaClient, rng: random.Random, session_opened_documents: set[str]) -> None:
    roll = rng.random()

    if roll < persona.write_ratio and session_opened_documents:
        document_id = rng.choice(list(session_opened_documents))
        await client.request("PUT", f"/documents/{document_id}", json={"content": "updated by generator (admin)"})
        return

    if roll < persona.write_ratio + 0.02 and persona.all_document_ids:
        # Rare delete -- admins occasionally clean things up.
        document_id = rng.choice(persona.all_document_ids)
        await client.request("DELETE", f"/documents/{document_id}")
        return

    if rng.random() < 0.1:
        await client.request("GET", "/users")
        return

    document_id = _pick_document_id(persona, rng)
    if document_id:
        response = await client.request("GET", f"/documents/{document_id}")
        if response.status_code == 200:
            session_opened_documents.add(document_id)
