from __future__ import annotations

import pytest

from app.settings import DetectorSettings


def _kwargs(**overrides) -> dict:
    defaults = dict(
        resource_access_threshold=26,
        authentication_threshold=2,
        network_threshold=2,
        authorization_threshold=5,
    )
    defaults.update(overrides)
    return defaults


def test_detector_settings_accepts_positive_thresholds():
    settings = DetectorSettings(**_kwargs())

    assert settings.resource_access_threshold == 26


@pytest.mark.parametrize(
    "field_name",
    [
        "resource_access_threshold",
        "authentication_threshold",
        "network_threshold",
        "authorization_threshold",
    ],
)
@pytest.mark.parametrize("bad_value", [0, -1])
def test_detector_settings_rejects_non_positive_threshold(field_name, bad_value):
    # Regression test: each threshold is a divisor in rules._risk_score_for
    # (value / threshold). A misconfigured 0 used to raise ZeroDivisionError
    # on the first matching key, on every single scan tick forever, caught
    # only by main.py's generic "scan failed" log -- silently disabling
    # detection instead of failing loudly at startup.
    with pytest.raises(ValueError):
        DetectorSettings(**_kwargs(**{field_name: bad_value}))
