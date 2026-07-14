from __future__ import annotations

from dataclasses import dataclass
import os


def _required_int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return int(value)


@dataclass(slots=True)
class GatewaySettings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:admin@postgres:5432/zt_db")
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    vault_addr: str = os.getenv("VAULT_ADDR", "http://vault:8200")
    vault_token: str = os.getenv("VAULT_TOKEN", "dev-root-token")
    vault_transit_key_name: str = os.getenv("VAULT_TRANSIT_KEY_NAME", "gateway-jwt")
    vault_totp_key_name: str = os.getenv("VAULT_TOTP_KEY_NAME", "totp-encryption")
    opa_url: str = os.getenv("OPA_URL", "http://opa:8181")
    opa_decision_path: str = os.getenv("OPA_DECISION_PATH", "/v1/data/authz/decision")
    isolation_forest_url: str = os.getenv("ISOLATION_FOREST_URL", "http://isolation-forest:8001")
    isolation_forest_score_path: str = os.getenv("ISOLATION_FOREST_SCORE_PATH", "/score")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "zt-api-gateway")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "zt-api")
    rate_limit_ip_limit: int = _required_int_env("RATE_LIMIT_IP_LIMIT", 100)
    rate_limit_user_limit: int = _required_int_env("RATE_LIMIT_USER_LIMIT", 200)
    rate_limit_window_seconds: int = 60
    jwk_refresh_lock_ttl_seconds: int = _required_int_env("JWK_REFRESH_LOCK_TTL_SECONDS", 30)
    replay_ttl_seconds: int | None = None
    mfa_max_failed_attempts: int = _required_int_env("MFA_MAX_FAILED_ATTEMPTS", 5)
    mfa_lockout_duration_minutes: int = _required_int_env("MFA_LOCKOUT_DURATION_MINUTES", 15)
    mfa_challenge_ttl_seconds: int = _required_int_env("MFA_CHALLENGE_TTL_SECONDS", 120)
    totp_replay_ttl_seconds: int = _required_int_env("TOTP_REPLAY_TTL_SECONDS", 90)
    mfa_verified_ttl_seconds: int = _required_int_env("MFA_VERIFIED_TTL_SECONDS", 300)
    access_token_ttl_minutes: int = _required_int_env("ACCESS_TOKEN_TTL_MINUTES", 15)
    refresh_token_ttl_days: int = _required_int_env("REFRESH_TOKEN_TTL_DAYS", 7)
    login_max_failed_attempts: int = _required_int_env("LOGIN_MAX_FAILED_ATTEMPTS", 5)
    login_lockout_duration_minutes: int = _required_int_env("LOGIN_LOCKOUT_DURATION_MINUTES", 15)
