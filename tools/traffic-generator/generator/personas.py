from __future__ import annotations

import random
from dataclasses import dataclass, field

SEED_USER_PASSWORD_DEFAULT = "ChangeMe123!"

# Must match scripts/seed_business_data.py's USER_POOL_SPEC exactly -- these are
# the accounts that must already exist (run that script first if they don't).
READER_COUNT = 15
EDITOR_COUNT = 8
ADMIN_COUNT = 2


@dataclass(slots=True)
class Persona:
    index: int
    email: str
    role: str
    password: str
    ip: str
    # Sampled once at startup and kept for the persona's whole life -- this
    # spread across the population IS what makes "normal" a distribution
    # rather than a single point.
    mean_interval_seconds: float
    burst_probability: float
    burst_length_range: tuple[int, int]
    write_ratio: float
    # Populated after the resource pool is fetched from the API at startup.
    favorite_document_ids: list[str] = field(default_factory=list)
    favorite_order_ids: list[str] = field(default_factory=list)
    all_document_ids: list[str] = field(default_factory=list)
    all_order_ids: list[str] = field(default_factory=list)


def persona_ip(index: int) -> str:
    """Stable, deterministic, unique IP per persona (10.10.{block}.{host})."""
    return f"10.10.{index // 254}.{index % 254 + 1}"


def build_personas(seed: int, password: str = SEED_USER_PASSWORD_DEFAULT) -> list[Persona]:
    rng = random.Random(seed)
    personas: list[Persona] = []
    index = 0

    for i in range(1, READER_COUNT + 1):
        personas.append(_make_persona(index, f"reader{i}@zt.local", "reader", password, rng))
        index += 1
    for i in range(1, EDITOR_COUNT + 1):
        personas.append(_make_persona(index, f"editor{i}@zt.local", "editor", password, rng))
        index += 1
    for i in range(1, ADMIN_COUNT + 1):
        personas.append(_make_persona(index, f"admin{i}@zt.local", "admin", password, rng))
        index += 1

    return personas


def _make_persona(index: int, email: str, role: str, password: str, rng: random.Random) -> Persona:
    # Wide lognormal spread: median ~e^5.0 =~ 148s, but the tails reach from
    # ~20s (a "greedy" persona) to well over 10 minutes (an occasional one).
    mean_interval = rng.lognormvariate(mu=5.0, sigma=1.2)
    mean_interval = max(15.0, min(mean_interval, 1800.0))

    burst_probability = rng.uniform(0.05, 0.3)

    write_ratio = 0.0
    if role == "editor":
        write_ratio = rng.uniform(0.10, 0.30)
    elif role == "admin":
        write_ratio = rng.uniform(0.05, 0.20)

    return Persona(
        index=index,
        email=email,
        role=role,
        password=password,
        ip=persona_ip(index),
        mean_interval_seconds=mean_interval,
        burst_probability=burst_probability,
        burst_length_range=(2, 6),
        write_ratio=write_ratio,
    )


def assign_resource_pool(
    personas: list[Persona], document_ids: list[str], order_ids: list[str], seed: int
) -> None:
    """Gives every persona the full resource pool (for the rare "not a
    favorite" access) plus a small, sticky subset of favorites -- real users
    revisit the same handful of things most of the time."""
    rng = random.Random(seed + 1)
    for persona in personas:
        persona.all_document_ids = document_ids
        persona.all_order_ids = order_ids
        doc_count = min(rng.randint(5, 20), len(document_ids))
        persona.favorite_document_ids = rng.sample(document_ids, doc_count) if document_ids else []
        order_count = min(rng.randint(5, 20), len(order_ids))
        persona.favorite_order_ids = rng.sample(order_ids, order_count) if order_ids else []
