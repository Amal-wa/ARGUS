from __future__ import annotations

from dataclasses import dataclass
import os


def _required_int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return int(value)


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(slots=True)
class GatewaySettings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:admin@postgres:5432/zt_db")
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    vault_addr: str = os.getenv("VAULT_ADDR", "http://vault:8200")
    vault_token: str = os.getenv("VAULT_TOKEN", "dev-root-token")
    vault_transit_key_name: str = os.getenv("VAULT_TRANSIT_KEY_NAME", "gateway-jwt")
    vault_totp_key_name: str = os.getenv("VAULT_TOTP_KEY_NAME", "totp-encryption")
    opa_url: str = os.getenv("OPA_URL", "https://opa:8181")
    opa_decision_path: str = os.getenv("OPA_DECISION_PATH", "/v1/data/authz/decision")
    # mTLS Gateway<->OPA (see CLAUDE.md's OPA bundle section): the Gateway's
    # own client cert/key and the internal CA used to verify OPA's server
    # cert, all issued by vault-init.sh's PKI role into the mtls-certs
    # volume. Only read/used when opa_url is https:// -- see
    # core/opa_client.build_opa_ssl_context and its call site in main.py.
    opa_client_cert_path: str = os.getenv("OPA_CLIENT_CERT_PATH", "/certs/gateway-client.pem")
    opa_client_key_path: str = os.getenv("OPA_CLIENT_KEY_PATH", "/certs/gateway-client-key.pem")
    opa_ca_cert_path: str = os.getenv("OPA_CA_CERT_PATH", "/certs/ca.pem")
    isolation_forest_url: str = os.getenv("ISOLATION_FOREST_URL", "http://isolation-forest:8001")
    isolation_forest_score_path: str = os.getenv("ISOLATION_FOREST_SCORE_PATH", "/score")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "zt-api-gateway")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "zt-api")
    rate_limit_ip_limit: int = _required_int_env("RATE_LIMIT_IP_LIMIT", 100)
    rate_limit_user_limit: int = _required_int_env("RATE_LIMIT_USER_LIMIT", 200)
    rate_limit_window_seconds: int = 60
    jwk_refresh_lock_ttl_seconds: int = _required_int_env("JWK_REFRESH_LOCK_TTL_SECONDS", 30)
    mfa_max_failed_attempts: int = _required_int_env("MFA_MAX_FAILED_ATTEMPTS", 5)
    mfa_lockout_duration_minutes: int = _required_int_env("MFA_LOCKOUT_DURATION_MINUTES", 15)
    mfa_challenge_ttl_seconds: int = _required_int_env("MFA_CHALLENGE_TTL_SECONDS", 120)
    totp_replay_ttl_seconds: int = _required_int_env("TOTP_REPLAY_TTL_SECONDS", 90)
    mfa_verified_ttl_seconds: int = _required_int_env("MFA_VERIFIED_TTL_SECONDS", 300)
    # Single-use action ticket (see mfa_challenge.py) scoped to the exact
    # (user, jti, route pattern, action) that was challenged -- deliberately
    # much shorter than mfa_verified_ttl_seconds, since it only needs to
    # survive the client's immediate retry of the just-challenged request,
    # not a whole session's worth of follow-up actions.
    sensitive_action_ticket_ttl_seconds: int = _required_int_env("SENSITIVE_ACTION_TICKET_TTL_SECONDS", 60)
    access_token_ttl_minutes: int = _required_int_env("ACCESS_TOKEN_TTL_MINUTES", 15)
    enrollment_token_ttl_minutes: int = _required_int_env("ENROLLMENT_TOKEN_TTL_MINUTES", 5)
    refresh_token_ttl_days: int = _required_int_env("REFRESH_TOKEN_TTL_DAYS", 7)
    login_max_failed_attempts: int = _required_int_env("LOGIN_MAX_FAILED_ATTEMPTS", 5)
    login_lockout_duration_minutes: int = _required_int_env("LOGIN_LOCKOUT_DURATION_MINUTES", 15)
    trusted_proxies: frozenset[str] = frozenset(
        p.strip() for p in os.getenv("TRUSTED_PROXIES", "").split(",") if p.strip()
    )
    fallback_step_up_threshold: float = float(os.getenv("FALLBACK_STEP_UP_THRESHOLD", "0.65"))
    # Same discipline as trusted_proxies: empty by default (no browser origin
    # trusted until explicitly configured), never a wildcard -- see
    # CORSMiddleware wiring in main.py for why "*" is refused even as an
    # option here.
    cors_allowed_origins: frozenset[str] = frozenset(
        o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()
    )
    # Attributes for the httpOnly refresh-token cookie (see app/routers/auth.py).
    # httpOnly itself is NOT configurable -- it's hardcoded True at the
    # set_cookie call site, non-negotiable. These two ARE, because they
    # legitimately differ between dev and prod without any code change:
    #   - dev (default): plain HTTP on localhost, dashboard (5173) and gateway
    #     (8000) are cross-ORIGIN but same-SITE (SameSite ignores port), so
    #     SameSite=Lax works and Secure must be False (no TLS on localhost).
    #   - prod: dashboard and gateway sit on two distinct domains, which is
    #     cross-SITE -- that requires SameSite=None, and browsers refuse
    #     SameSite=None without Secure, which in turn requires HTTPS.
    # Going to production is therefore a config change (set both env vars),
    # never a code change.
    refresh_cookie_secure: bool = _bool_env("REFRESH_COOKIE_SECURE", False)
    refresh_cookie_samesite: str = os.getenv("REFRESH_COOKIE_SAMESITE", "lax")
