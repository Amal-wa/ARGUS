"""Shared helper for scripts/seed_users.py and scripts/seed_business_data.py:
mandatory MFA (see AuthService.login) means every seeded account needs a real
enrollment, or it would be stuck at the enrollment gate the first time the
traffic generator (or a developer) logs in.

Enrolling directly against the repository/Vault client (not over HTTP) mirrors
MfaEnrollmentService itself, and records each user's plaintext base32 TOTP
secret into a shared, git-ignored JSON file
(tools/traffic-generator/persona_secrets.json) so the traffic generator can
compute valid TOTP codes for its own personas. This is a demo/seed-time
convenience, not a production pattern -- nowhere else in the system are TOTP
secrets ever written to disk in plaintext.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import UUID

from app.core.errors import MfaAlreadyEnrolledError
from app.core.totp import secret_to_base32
from app.services.mfa_enrollment import MfaEnrollmentService


def secrets_file_path() -> Path:
    override = os.getenv("SEED_MFA_SECRETS_PATH")
    if override:
        return Path(override)
    # Host-run fallback (no SEED_MFA_SECRETS_PATH set, e.g. `poetry run python
    # scripts/seed_business_data.py` from services/api-gateway directly):
    # repo_root/tools/traffic-generator/persona_secrets.json.
    return Path(__file__).resolve().parents[3] / "tools" / "traffic-generator" / "persona_secrets.json"


def load_secrets(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_secrets(path: Path, secrets: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(secrets, indent=2, sort_keys=True) + "\n")


async def ensure_mfa_enrolled(
    enrollment_service: MfaEnrollmentService, user_id: UUID, email: str, secrets: dict[str, str]
) -> bool:
    """Ensures `user_id` is MFA-enrolled and `secrets[email]` holds its base32
    TOTP secret, mutating `secrets` in place. Idempotent: if already enrolled
    from a prior run, recovers the base32 secret via Vault decrypt rather than
    re-enrolling (MfaEnrollmentService.enroll would just raise) -- this also
    self-heals a lost/deleted persona_secrets.json without re-running the DB
    seed. Returns True if a brand-new enrollment happened."""
    try:
        base32_secret = await enrollment_service.enroll(user_id)
        is_new = True
    except MfaAlreadyEnrolledError:
        raw_secret = await enrollment_service.get_decrypted_secret(user_id)
        base32_secret = secret_to_base32(raw_secret)
        is_new = False

    secrets[email] = base32_secret
    return is_new
