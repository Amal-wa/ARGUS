from __future__ import annotations

from generator.personas import (
    DOCUMENT_RATIO_RANGE_BASELINE,
    DOCUMENT_RATIO_RANGE_DRIFTED,
    WRITE_RATIO_RANGE_BASELINE,
    WRITE_RATIO_RANGE_DRIFTED,
    build_personas,
)


def test_profiles_keep_identity_ip_and_timing_parameters_identical():
    baseline = build_personas(seed=123, profile="baseline")
    drifted = build_personas(seed=123, profile="drifted")

    assert len(baseline) == len(drifted)
    for base_persona, drift_persona in zip(baseline, drifted):
        assert base_persona.index == drift_persona.index
        assert base_persona.email == drift_persona.email
        assert base_persona.role == drift_persona.role
        assert base_persona.ip == drift_persona.ip
        assert base_persona.mean_interval_seconds == drift_persona.mean_interval_seconds
        assert base_persona.burst_probability == drift_persona.burst_probability
        assert base_persona.burst_length_range == drift_persona.burst_length_range


def test_profiles_only_move_write_ratio_and_document_ratio():
    baseline = build_personas(seed=123, profile="baseline")
    drifted = build_personas(seed=123, profile="drifted")

    for base_persona, drift_persona in zip(baseline, drifted):
        lo, hi = DOCUMENT_RATIO_RANGE_BASELINE
        assert lo <= base_persona.document_ratio <= hi
        lo, hi = DOCUMENT_RATIO_RANGE_DRIFTED
        assert lo <= drift_persona.document_ratio <= hi

        if base_persona.role == "editor":
            lo, hi = WRITE_RATIO_RANGE_BASELINE
            assert lo <= base_persona.write_ratio <= hi
            lo, hi = WRITE_RATIO_RANGE_DRIFTED
            assert lo <= drift_persona.write_ratio <= hi
        elif base_persona.role == "admin":
            # Admin's range is a fixed literal, not profile-dependent --
            # the drift story is editorial-only.
            assert base_persona.write_ratio == drift_persona.write_ratio
        else:
            assert base_persona.write_ratio == drift_persona.write_ratio == 0.0


def test_unknown_profile_rejected():
    import pytest

    with pytest.raises(ValueError):
        build_personas(seed=1, profile="nonexistent")
