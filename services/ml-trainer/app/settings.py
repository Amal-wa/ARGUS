from __future__ import annotations

from dataclasses import dataclass, field
import os


def _parse_excluded_emails(raw: str) -> list[str]:
    return [email.strip() for email in raw.split(",") if email.strip()]


def _parse_optional_int(raw: str) -> int | None:
    stripped = raw.strip()
    return int(stripped) if stripped else None


def _parse_max_samples(raw: str) -> str | int | float:
    """IsolationForest's max_samples accepts "auto", an absolute sample
    count (int), or a fraction of the training set (float) -- env vars are
    always strings, so this is the one place that decides which of the
    three MODEL_MAX_SAMPLES actually meant. "." is the only signal
    available to tell "0.5" (a fraction) from "500" (a count) apart."""
    if raw == "auto":
        return "auto"
    return float(raw) if "." in raw else int(raw)


@dataclass(slots=True)
class TrainerSettings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql://postgres:admin@postgres:5432/zt_db")
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    models_dir: str = os.getenv("MODELS_DIR", "/models")
    training_window_days: int = int(os.getenv("TRAINING_WINDOW_DAYS", "30"))
    min_training_samples: int = int(os.getenv("MIN_TRAINING_SAMPLES", "1000"))
    # Accounts to exclude from training entirely -- e.g. this project's own
    # live-verification/demo scripts, which authenticate as real seeded
    # accounts and therefore write real ml_training_samples rows just like
    # genuine traffic. Confirmed live: reader1@zt.local alone (reused across
    # dozens of live_verify_*.py runs over 6+ days, not one legitimate
    # session) produced resource_access values up to 386 -- with it excluded,
    # the same dimension's real max drops to 25, matching the empirical
    # threshold documented in CLAUDE.md's Behavioral detector section.
    # Default empty; the actual exclusion list for this deployment is set in
    # docker-compose.yml (TRAINING_EXCLUDED_EMAILS), same pattern as
    # CANARY_BATCH_SIZE -- a conservative default here, the real value
    # visible and auditable at the compose level, not buried as a Python
    # literal.
    training_excluded_emails: list[str] = field(
        default_factory=lambda: _parse_excluded_emails(os.getenv("TRAINING_EXCLUDED_EMAILS", ""))
    )
    # Excludes samples by BEHAVIOR (feature_vector[7], 0-based -- distinct raw
    # resources, 5 min window) rather than by identity, complementing
    # training_excluded_emails above (identity-based) rather than replacing
    # it: an account not on TRAINING_EXCLUDED_EMAILS can still have a single
    # enumeration burst worth excluding, and an excluded email can still have
    # unrelated non-enumeration rows -- the two filters serve different cases
    # and are applied together (both AND conditions in the same query). 30 is
    # calibrated on live data: real normal traffic (with reader1@zt.local and
    # the reader8@zt.local scenario-A actor already set aside) tops out at
    # 11; the reader8 attack burst itself produced 178 samples at 31-207 in a
    # single 2m20s window. Default None disables the filter entirely
    # (rétrocompatible) -- set TRAINING_MAX_RESOURCE_ACCESS="" to opt out
    # explicitly even though the env var has a non-empty default below.
    training_max_resource_access: int | None = field(
        default_factory=lambda: _parse_optional_int(os.getenv("TRAINING_MAX_RESOURCE_ACCESS", "30"))
    )
    n_estimators: int = int(os.getenv("MODEL_N_ESTIMATORS", "100"))
    random_state: int = int(os.getenv("MODEL_RANDOM_STATE", "42"))
    # Previously only n_estimators/random_state were tunable -- contamination
    # was hardcoded to "auto" in trainer.py despite having ZERO effect on
    # this codebase's actual scoring path (ModelStore.score() only ever
    # calls .score_samples(), which contamination does not influence at all;
    # it only shapes .predict()/.decision_function(), which nothing here
    # calls -- see trainer.py's comment on contamination for the full
    # explanation). max_samples/max_features/bootstrap, by contrast, DO
    # shape the trees score_samples() reads from, and were previously stuck
    # at sklearn's defaults with no way to change them short of editing code.
    max_samples: str | int | float = field(default_factory=lambda: _parse_max_samples(os.getenv("MODEL_MAX_SAMPLES", "auto")))
    max_features: float = float(os.getenv("MODEL_MAX_FEATURES", "1.0"))
    bootstrap: bool = os.getenv("MODEL_BOOTSTRAP", "false").strip().lower() == "true"
    # Fraction of loaded training samples held out (never trained on) to
    # compute training_quality's AUC -- see trainer.py::evaluate_holdout_quality.
    # The FINAL shipped model is still fit on the full sample set afterward;
    # this split only exists for the evaluation step.
    holdout_fraction: float = float(os.getenv("MODEL_HOLDOUT_FRACTION", "0.15"))
    # Below this many held-out samples, an AUC estimate is too noisy to be
    # worth recording -- run_training_job leaves training_quality NULL
    # rather than publish a number with no real statistical weight behind it.
    min_holdout_samples_for_quality: int = int(os.getenv("MIN_HOLDOUT_SAMPLES_FOR_QUALITY", "50"))
