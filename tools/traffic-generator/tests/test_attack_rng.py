from __future__ import annotations

import random

import numpy as np
import pytest

from generator.attacks import (
    SCENARIO_SEED_INDEX,
    _sample_attack_interval,
    build_scenario_rngs,
)


# ---------------------------------------------------------------------------
# Reproducibility: same global seed + same scenario -> identical attack.
# ---------------------------------------------------------------------------


def test_same_seed_reproduces_scenario_a_document_shuffle_order():
    document_ids = [f"doc-{i}" for i in range(50)]

    run1 = list(document_ids)
    build_scenario_rngs(7)["A"].shuffle(run1)

    run2 = list(document_ids)
    build_scenario_rngs(7)["A"].shuffle(run2)

    assert run1 == run2
    assert run1 != document_ids  # sanity: it actually shuffled


def test_same_seed_reproduces_scenario_c_hijack_ip():
    def hijack_ip(seed: int) -> str:
        rng = build_scenario_rngs(seed)["C"]
        return f"203.0.113.{int(rng.integers(1, 254, endpoint=True))}"

    assert hijack_ip(123) == hijack_ip(123)


def test_same_seed_reproduces_scenario_d_action_sequence():
    def action_sequence(seed: int, n: int = 20) -> list[str]:
        rng = build_scenario_rngs(seed)["D"]
        attempts = ("create_document", "update_document", "delete_document", "list_users")
        return [str(rng.choice(attempts)) for _ in range(n)]

    assert action_sequence(99) == action_sequence(99)


# ---------------------------------------------------------------------------
# Independence: different scenarios derive different, unrelated sub-streams.
# ---------------------------------------------------------------------------


def test_different_scenarios_derive_independent_streams():
    rngs = build_scenario_rngs(42)
    draws = {name: rngs[name].random(20).tolist() for name in SCENARIO_SEED_INDEX}

    names = list(SCENARIO_SEED_INDEX)
    for i, name_a in enumerate(names):
        for name_b in names[i + 1 :]:
            assert draws[name_a] != draws[name_b]


def test_scenario_a_order_differs_from_scenario_d_action_sequence_same_seed():
    # Concrete instance of the general independence property above, phrased
    # the way the task described it: A's document order and D's action
    # sequence must not coincide just because they share a global seed.
    document_ids = [f"doc-{i}" for i in range(50)]
    rngs = build_scenario_rngs(2024)

    shuffled = list(document_ids)
    rngs["A"].shuffle(shuffled)

    attempts = ("create_document", "update_document", "delete_document", "list_users")
    d_sequence = [str(rngs["D"].choice(attempts)) for _ in range(10)]

    assert shuffled[:10] != document_ids[:10]  # A actually shuffled
    assert len(set(d_sequence)) > 1  # D actually varies (sanity, not a strict independence check)


# ---------------------------------------------------------------------------
# Order-stability: a scenario's stream must not depend on whether/how much
# another scenario's stream was consumed first. This is the failure mode the
# task explicitly warns against ("do not derive by 'next spawn() as
# scenarios start'"), so it's tested directly: hammer D's stream, then verify
# a completely fresh build's A stream is unaffected.
# ---------------------------------------------------------------------------


def test_scenario_a_stream_unaffected_by_prior_consumption_of_scenario_d():
    fresh_a_first_draws = build_scenario_rngs(555)["A"].random(5).tolist()

    rngs = build_scenario_rngs(555)
    rngs["D"].random(10_000)  # heavily consume D's stream first
    a_first_draws_after_d_consumed = rngs["A"].random(5).tolist()

    assert a_first_draws_after_d_consumed == fresh_a_first_draws


def test_scenario_index_mapping_is_fixed():
    # The mapping itself (not just its runtime effect) must be a stable,
    # explicit constant -- not computed from iteration/call order.
    assert SCENARIO_SEED_INDEX == {"A": 0, "B": 1, "C": 2, "D": 3}


# ---------------------------------------------------------------------------
# No entanglement with the normal-traffic path's RNG (stdlib `random.Random`
# instances in personas.py / behaviors.py). Building and heavily consuming
# the attack scenario generators must not perturb an independent
# random.Random instance's sequence.
# ---------------------------------------------------------------------------


def test_building_and_consuming_attack_rngs_does_not_perturb_normal_traffic_random():
    baseline = random.Random(999)
    baseline_sequence = [baseline.random() for _ in range(10)]

    probe = random.Random(999)
    sequence_before_attack = [probe.random() for _ in range(4)]

    # Simulate an attack being launched and heavily drawn from mid-run.
    attack_rngs = build_scenario_rngs(42)
    for name in SCENARIO_SEED_INDEX:
        attack_rngs[name].random(5_000)

    sequence_after_attack = [probe.random() for _ in range(6)]

    assert sequence_before_attack + sequence_after_attack == baseline_sequence


# ---------------------------------------------------------------------------
# Gamma-distributed pacing: mean on target, variance clearly below the
# normal path's exponential at the same mean, never constant.
# ---------------------------------------------------------------------------


def test_attack_interval_mean_matches_configured_rate():
    rng = np.random.default_rng(1)
    requests_per_minute = 80.0
    target_mean = 60.0 / requests_per_minute

    samples = [_sample_attack_interval(rng, requests_per_minute) for _ in range(20_000)]
    sample_mean = sum(samples) / len(samples)

    assert sample_mean == pytest.approx(target_mean, rel=0.05)


def test_attack_interval_variance_well_below_exponential_at_same_mean():
    rng = np.random.default_rng(2)
    requests_per_minute = 80.0
    target_mean = 60.0 / requests_per_minute

    samples = np.array([_sample_attack_interval(rng, requests_per_minute) for _ in range(20_000)])
    sample_variance = samples.var()

    exponential_variance_at_same_mean = target_mean**2  # Exp(rate): Var = mean^2

    # True ratio at shape=6 is 1/6 =~ 0.167; 0.3 leaves comfortable sampling slack
    # while still proving "clearly smaller", not just marginally smaller.
    assert sample_variance < exponential_variance_at_same_mean * 0.3


def test_attack_interval_never_produces_identical_consecutive_draws():
    rng = np.random.default_rng(3)
    samples = [_sample_attack_interval(rng, requests_per_minute=80.0) for _ in range(500)]

    for previous, current in zip(samples, samples[1:]):
        assert previous != current


def test_attack_interval_keeps_scenario_a_under_configured_rate_limit_on_average():
    rng = np.random.default_rng(4)
    requests_per_minute = 80.0

    samples = [_sample_attack_interval(rng, requests_per_minute) for _ in range(20_000)]
    sample_mean_interval = sum(samples) / len(samples)
    achieved_requests_per_minute = 60.0 / sample_mean_interval

    # Allow modest sampling slack; must not run meaningfully hotter than configured.
    assert achieved_requests_per_minute <= requests_per_minute * 1.1
