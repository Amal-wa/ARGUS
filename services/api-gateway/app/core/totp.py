from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30


def generate_totp_secret() -> bytes:
    return secrets.token_bytes(20)


def secret_to_base32(secret: bytes) -> str:
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def current_time_step(now: int | None = None) -> int:
    if now is None:
        now = int(time.time())
    return now // TOTP_PERIOD_SECONDS


def compute_totp(secret: bytes, time_step: int) -> str:
    counter = struct.pack(">Q", time_step)
    digest = hmac.new(secret, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = digest[offset : offset + 4]
    code_int = (struct.unpack(">I", truncated)[0] & 0x7FFFFFFF) % (10**TOTP_DIGITS)
    return str(code_int).zfill(TOTP_DIGITS)


def verify_totp(secret: bytes, code: str, *, now: int | None = None, window: int = 1) -> int | None:
    current_step = current_time_step(now)
    for offset in range(-window, window + 1):
        candidate_step = current_step + offset
        candidate_code = compute_totp(secret, candidate_step)
        if hmac.compare_digest(candidate_code, code):
            return candidate_step
    return None
