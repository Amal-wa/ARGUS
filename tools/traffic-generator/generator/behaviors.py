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
    logger.info("%s (%s) logged in, ip=%s, mean_interval=%.1fs, document_ratio=%.2f", persona.email, persona.role, persona.ip, persona.mean_interval_seconds, persona.document_ratio)

    session_opened_documents: set[str] = set()
    session_opened_orders: set[str] = set()

    while not stop_event.is_set():
        interval = _sample_interval(persona.mean_interval_seconds)
        if await _sleep_or_stop(interval, stop_event):
            break

        await _do_action(persona, client, rng, session_opened_documents, session_opened_orders)

        if rng.random() < persona.burst_probability:
            burst_length = rng.randint(*persona.burst_length_range)
            for _ in range(burst_length):
                if await _sleep_or_stop(rng.uniform(2, 8), stop_event):
                    return
                await _do_action(persona, client, rng, session_opened_documents, session_opened_orders)
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


def _pick_from_pool(favorites: list[str], full_pool: list[str], rng: random.Random) -> str | None:
    pool = favorites if favorites else full_pool
    if favorites and full_pool and rng.random() < 0.75:
        pool = favorites
    elif full_pool:
        pool = full_pool
    return rng.choice(pool) if pool else None


def _pick_document_id(persona: Persona, rng: random.Random) -> str | None:
    return _pick_from_pool(persona.favorite_document_ids, persona.all_document_ids, rng)


def _pick_order_id(persona: Persona, rng: random.Random) -> str | None:
    return _pick_from_pool(persona.favorite_order_ids, persona.all_order_ids, rng)


def _uses_documents(persona: Persona, rng: random.Random) -> bool:
    return rng.random() < persona.document_ratio


def _random_order_amount(rng: random.Random) -> float:
    return round(rng.uniform(5, 500), 2)


async def _do_action(
    persona: Persona,
    client: PersonaClient,
    rng: random.Random,
    session_opened_documents: set[str],
    session_opened_orders: set[str],
) -> None:
    try:
        if persona.role == "reader":
            await _reader_action(persona, client, rng)
        elif persona.role == "editor":
            await _editor_action(persona, client, rng, session_opened_documents, session_opened_orders)
        else:
            await _admin_action(persona, client, rng, session_opened_documents, session_opened_orders)
    except Exception:
        logger.exception("%s: action failed", persona.email)


async def _reader_action(persona: Persona, client: PersonaClient, rng: random.Random) -> None:
    use_documents = _uses_documents(persona, rng)

    if rng.random() < READER_STRAY_WRITE_PROBABILITY:
        # Rare, legitimate 403: a reader occasionally tries to edit something.
        if use_documents:
            document_id = _pick_document_id(persona, rng)
            if document_id:
                await client.request("PUT", f"/documents/{document_id}", json={"content": "oops"})
        else:
            order_id = _pick_order_id(persona, rng)
            if order_id:
                await client.request("PUT", f"/orders/{order_id}", json={"status": "oops"})
        return

    if rng.random() < 0.15:
        await client.request("GET", "/documents" if use_documents else "/orders")
        return

    if use_documents:
        document_id = _pick_document_id(persona, rng)
        if document_id:
            await client.request("GET", f"/documents/{document_id}")
    else:
        order_id = _pick_order_id(persona, rng)
        if order_id:
            await client.request("GET", f"/orders/{order_id}")


async def _editor_action(
    persona: Persona, client: PersonaClient, rng: random.Random, session_opened_documents: set[str], session_opened_orders: set[str]
) -> None:
    roll = rng.random()
    use_documents = _uses_documents(persona, rng)

    if use_documents:
        if roll < persona.write_ratio and session_opened_documents:
            document_id = rng.choice(list(session_opened_documents))
            await client.request("PUT", f"/documents/{document_id}", json={"content": "updated by generator"})
            return

        if roll < persona.write_ratio + 0.05:
            response = await client.request("POST", "/documents", json={"title": "Generator document", "content": "hello"})
            if response.status_code == 201:
                session_opened_documents.add(response.json()["document_id"])
            return
    else:
        if roll < persona.write_ratio and session_opened_orders:
            order_id = rng.choice(list(session_opened_orders))
            await client.request("PUT", f"/orders/{order_id}", json={"status": "paid"})
            return

        if roll < persona.write_ratio + 0.05:
            response = await client.request("POST", "/orders", json={"status": "pending", "amount": _random_order_amount(rng)})
            if response.status_code == 201:
                session_opened_orders.add(response.json()["order_id"])
            return

    if rng.random() < NON_ADMIN_USERS_PEEK_PROBABILITY:
        await client.request("GET", "/users")
        return

    # "Nobody edits a resource they never opened": a real GET must precede any
    # PUT of the same resource in this session.
    if use_documents:
        document_id = _pick_document_id(persona, rng)
        if document_id:
            response = await client.request("GET", f"/documents/{document_id}")
            if response.status_code == 200:
                session_opened_documents.add(document_id)
    else:
        order_id = _pick_order_id(persona, rng)
        if order_id:
            response = await client.request("GET", f"/orders/{order_id}")
            if response.status_code == 200:
                session_opened_orders.add(order_id)


async def _admin_action(
    persona: Persona, client: PersonaClient, rng: random.Random, session_opened_documents: set[str], session_opened_orders: set[str]
) -> None:
    roll = rng.random()
    use_documents = _uses_documents(persona, rng)

    if use_documents:
        if roll < persona.write_ratio and session_opened_documents:
            document_id = rng.choice(list(session_opened_documents))
            await client.request("PUT", f"/documents/{document_id}", json={"content": "updated by generator (admin)"})
            return

        if roll < persona.write_ratio + 0.02 and persona.all_document_ids:
            # Rare delete -- admins occasionally clean things up.
            document_id = rng.choice(persona.all_document_ids)
            await client.request("DELETE", f"/documents/{document_id}")
            return
    else:
        if roll < persona.write_ratio and session_opened_orders:
            order_id = rng.choice(list(session_opened_orders))
            await client.request("PUT", f"/orders/{order_id}", json={"status": "shipped"})
            return

        if roll < persona.write_ratio + 0.02 and persona.all_order_ids:
            order_id = rng.choice(persona.all_order_ids)
            await client.request("DELETE", f"/orders/{order_id}")
            return

    if rng.random() < 0.1:
        await client.request("GET", "/users")
        return

    if use_documents:
        document_id = _pick_document_id(persona, rng)
        if document_id:
            response = await client.request("GET", f"/documents/{document_id}")
            if response.status_code == 200:
                session_opened_documents.add(document_id)
    else:
        order_id = _pick_order_id(persona, rng)
        if order_id:
            response = await client.request("GET", f"/orders/{order_id}")
            if response.status_code == 200:
                session_opened_orders.add(order_id)
