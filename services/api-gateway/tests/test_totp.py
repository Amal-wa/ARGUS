from __future__ import annotations

from app.core.totp import (
    TOTP_PERIOD_SECONDS,
    compute_totp,
    current_time_step,
    generate_totp_secret,
    verify_totp,
)

RFC6238_SECRET = b"12345678901234567890"


def test_rfc6238_vector_time_step_1():
    # RFC 6238 Appendix B: at T=59s (time_step=1), the 8-digit HOTP is 94287082.
    # Our 6-digit truncation is the same value mod 10**6, i.e. its last 6 digits.
    assert compute_totp(RFC6238_SECRET, 1) == "287082"


def test_rfc6238_vector_time_step_37037036():
    # RFC 6238 Appendix B: at T=1111111109s (time_step=37037036), the 8-digit HOTP is 07081804.
    assert compute_totp(RFC6238_SECRET, 37037036) == "081804"


def test_compute_and_verify_round_trip():
    secret = generate_totp_secret()
    step = current_time_step(1_700_000_000)
    code = compute_totp(secret, step)

    assert verify_totp(secret, code, now=1_700_000_000) == step


def test_verify_accepts_previous_and_next_step_within_window():
    secret = generate_totp_secret()
    now = 1_700_000_000
    step = current_time_step(now)

    previous_code = compute_totp(secret, step - 1)
    next_code = compute_totp(secret, step + 1)

    assert verify_totp(secret, previous_code, now=now, window=1) == step - 1
    assert verify_totp(secret, next_code, now=now, window=1) == step + 1


def test_verify_rejects_code_two_steps_away():
    secret = generate_totp_secret()
    now = 1_700_000_000
    step = current_time_step(now)

    far_code = compute_totp(secret, step + 2)

    assert verify_totp(secret, far_code, now=now, window=1) is None


def test_verify_returns_matched_time_step_from_previous_step():
    secret = generate_totp_secret()
    now = 1_700_000_000
    step_n_minus_1 = current_time_step(now)
    now_at_step_n = now + TOTP_PERIOD_SECONDS

    code_for_step_n_minus_1 = compute_totp(secret, step_n_minus_1)

    assert verify_totp(secret, code_for_step_n_minus_1, now=now_at_step_n, window=1) == step_n_minus_1


def test_verify_rejects_wrong_code():
    secret = generate_totp_secret()
    now = 1_700_000_000
    step = current_time_step(now)
    real_code = compute_totp(secret, step)
    # Guaranteed not to match the real code, unlike a hardcoded guess.
    wrong_code = "".join("9" if c != "9" else "8" for c in real_code)

    assert verify_totp(secret, wrong_code, now=now) is None


def test_generate_totp_secret_is_20_bytes_and_random():
    first = generate_totp_secret()
    second = generate_totp_secret()

    assert len(first) == 20
    assert len(second) == 20
    assert first != second
