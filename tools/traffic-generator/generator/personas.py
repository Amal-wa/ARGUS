from __future__ import annotations

import random
from dataclasses import dataclass, field

SEED_USER_PASSWORD_DEFAULT = "ChangeMe123!"

# Must match scripts/seed_business_data.py's USER_POOL_SPEC exactly -- these are
# the accounts that must already exist (run that script first if they don't).
READER_COUNT = 15
EDITOR_COUNT = 8
ADMIN_COUNT = 2

# Usage-profile ranges for the two ratio parameters that carry the concept
# drift. Baseline is the range Phase 1 (calibration / v1 training) was
# collected under -- unchanged from before profiles existed. "Drifted"
# models a real process shift, NOT an attack: the editorial team moved from
# a consultation-heavy workload to a production-heavy one (more writes), and
# order handling grew as a share of activity (relatively fewer documents
# touched, more orders). Deliberately NOT touched by either profile:
# mean_interval_seconds and burst_probability (both still drawn from their
# one, profile-independent distribution in _make_persona) -- a drift that
# also raised request rate or path diversity would reproduce scenario A's
# resource-enumeration signature and defeat the point of testing drift
# separately from an attack.
WRITE_RATIO_RANGE_BASELINE = (0.10, 0.30)
WRITE_RATIO_RANGE_DRIFTED = (0.30, 0.50)
DOCUMENT_RATIO_RANGE_BASELINE = (0.50, 0.85)
DOCUMENT_RATIO_RANGE_DRIFTED = (0.30, 0.60)

# Admin write_ratio (0.05, 0.20) is deliberately absent from here and stays a
# fixed literal in _make_persona: the drift story is specifically the
# EDITORIAL team's workload shift, not an org-wide one.
PROFILES = {
    "baseline": {"write_ratio": WRITE_RATIO_RANGE_BASELINE, "document_ratio": DOCUMENT_RATIO_RANGE_BASELINE},
    "drifted": {"write_ratio": WRITE_RATIO_RANGE_DRIFTED, "document_ratio": DOCUMENT_RATIO_RANGE_DRIFTED},
}

# Applied to mean_interval_seconds below -- the only place role affects request
# VOLUME (role already affects the read/write MIX via write_ratio). Editors are
# legitimately more active than readers in real usage (they write, not just
# read); this factor is what actually encodes that, not the raw lognormal draw,
# which is otherwise identical across roles. Modest on purpose: this is a
# population-level tendency across 8 editors vs 15 readers, not a per-persona
# guarantee -- with this few editors, per-seed sample noise can still occasionally
# put the editor mean below the reader mean for a given seed (confirmed by
# simulation), same way real small teams don't perfectly track a population average.
ROLE_ACTIVITY_FACTOR = {"reader": 1.0, "editor": 0.75, "admin": 1.0}


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
    # Fraction of this persona's actions that target documents rather than
    # orders. Per-persona (not global) so the heterogeneity of the ratio
    # itself is part of the signal, same reasoning as mean_interval_seconds.
    document_ratio: float
    # Populated after the resource pool is fetched from the API at startup.
    favorite_document_ids: list[str] = field(default_factory=list)
    favorite_order_ids: list[str] = field(default_factory=list)
    all_document_ids: list[str] = field(default_factory=list)
    all_order_ids: list[str] = field(default_factory=list)


def persona_ip(index: int) -> str:
    """Stable, deterministic, unique IP per persona (10.10.{block}.{host})."""
    return f"10.10.{index // 254}.{index % 254 + 1}"


def build_personas(seed: int, password: str = SEED_USER_PASSWORD_DEFAULT, profile: str = "baseline") -> list[Persona]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose one of {sorted(PROFILES)}")
    ranges = PROFILES[profile]

    rng = random.Random(seed)
    personas: list[Persona] = []
    index = 0

    for i in range(1, READER_COUNT + 1):
        personas.append(_make_persona(index, f"reader{i}@zt.local", "reader", password, rng, ranges))
        index += 1
    for i in range(1, EDITOR_COUNT + 1):
        personas.append(_make_persona(index, f"editor{i}@zt.local", "editor", password, rng, ranges))
        index += 1
    for i in range(1, ADMIN_COUNT + 1):
        personas.append(_make_persona(index, f"admin{i}@zt.local", "admin", password, rng, ranges))
        index += 1

    return personas


def _make_persona(index: int, email: str, role: str, password: str, rng: random.Random, ranges: dict[str, tuple[float, float]]) -> Persona:
    # Tightened lognormal spread: median ~e^5.0 ~= 148s. sigma=0.35 (was 1.2)
    # and the clamp below (was 15-1800s, a 120x span) bound the per-persona
    # spread to a realistic range instead of letting a handful of personas
    # land near either extreme and dominate/vanish on a long run -- see the
    # asymmetry investigation this replaces (one persona at 1613 samples vs a
    # median of 128 on a real 4h/seed=42 run, confirmed by simulation to trace
    # to this draw, not to scheduling or burst logic). sigma/mu changes are
    # pure post-hoc scalars on the same underlying gauss() draw (CPython's
    # random.gauss caches every OTHER Box-Muller pair regardless of mu/sigma),
    # so this does not change how many random() calls this consumes -- every
    # later draw for this and subsequent personas (burst_probability,
    # write_ratio, document_ratio, IP/resource assignment) stays bit-identical
    # for a given seed. Unaffected by profile -- see PROFILES comment above.
    mean_interval = rng.lognormvariate(mu=5.0, sigma=0.35)
    # Role-based activity factor -- see ROLE_ACTIVITY_FACTOR above. A pure
    # deterministic scalar multiply, consumes no additional random() calls.
    mean_interval *= ROLE_ACTIVITY_FACTOR[role]
    mean_interval = max(75.0, min(mean_interval, 300.0))

    # Narrowed from (0.05, 0.3) -- a 6x spread that multiplied on top of the
    # interval spread above, compounding it rather than adding an independent
    # effect (every triggered burst is itself gated behind how often a
    # persona's own loop runs, which the interval already controls). Still a
    # real per-persona draw (still `uniform`, one random() call, same
    # determinism guarantee as before), just a tighter range.
    burst_probability = rng.uniform(0.08, 0.15)

    # random.Random.uniform(a, b) is exactly `a + (b-a) * self.random()` --
    # ONE call to the underlying generator regardless of (a, b). So swapping
    # in the drifted bounds here changes only the VALUE drawn for write_ratio
    # itself; it does not change how many draws are consumed, which is what
    # keeps every persona's identity/ip/mean_interval_seconds/
    # burst_probability -- and every later persona's entire generation --
    # bit-identical between profiles for the same seed. Admin's range is a
    # fixed literal, not profile-dependent (see PROFILES comment above).
    write_ratio = 0.0
    if role == "editor":
        write_ratio = rng.uniform(*ranges["write_ratio"])
    elif role == "admin":
        write_ratio = rng.uniform(0.05, 0.20)

    # Same single-draw argument as write_ratio above applies here.
    document_ratio = rng.uniform(*ranges["document_ratio"])

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
        document_ratio=document_ratio,
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
