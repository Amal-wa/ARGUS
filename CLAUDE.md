# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Zero-Trust API access control platform ("ZT_project"). A FastAPI gateway authenticates every request, builds a
behavioral feature vector, gets a risk score from an ML anomaly-detection service, and asks an OPA (Open Policy
Agent) policy bundle for an ALLOW / DENY / STEP_UP decision — logging every decision for later ML training and
canary model comparisons.

Only two components currently have real implementations: **`services/api-gateway`** (Python/FastAPI) and the
**`policies/`** OPA/Rego bundle. Everything else in `services/` (`isolation-forest`, `canary-validator`,
`behavioral-detector`, `ml-trainer`, `react-dashboard`) is scaffolding only — Dockerfiles/pyproject/package.json
exist but are currently empty, and `docker-compose.yml` already wires them in for when they're built out. Don't
assume code exists there; check first.

## Architecture

### Request flow (services/api-gateway)

Every HTTP request passes through a single Starlette middleware, `GatewayMiddleware`
(`app/middleware/gateway.py`), which runs this pipeline in order:

1. **IP rate limit** (`middleware/rate_limit.py`) — sliding window in Redis, checked before auth.
2. **JWT verification** (`core/security.py`, `JWTVerifier`) — tokens are Ed25519 (`EdDSA`)-signed; the public key
   is fetched from Vault's Transit engine (`core/vault.py`) and cached, with a Redis lock
   (`jwk:refresh:lock`) to coordinate key refresh on signature failure across gateway instances. Verifies
   `iss`/`aud`/`iat`/`exp` and requires `sub`, `jti`, `role` claims.
3. **User rate limit** (once claims are known).
4. **JTI blacklist check** (`middleware/jti_blacklist.py`) — Redis key `revoked:jti:{jti}`.
5. **Replay check** (`middleware/replay.py`) — first-use-wins on `used:jti:{jti}` via `SET NX EX`.
6. **Authorization** (`services/authorization.py`, `AuthorizationService.authorize`):
   - Resolves the matched route pattern via `core/request_matching.py` (walks `request.app.router.routes`,
     picks the `Match.FULL` route) and maps HTTP method → action (`GET`→read, `POST`→create, `PUT/PATCH`→update,
     `DELETE`→delete).
   - Builds a 20-float **feature vector** per user from Redis counters (`services/feature_vector.py`): read/write
     counts, deny count, distinct paths/IPs, rate-limit hits, ratios, latency, one-hot HTTP method — vector is
     padded/truncated to exactly 20 floats (enforced by a DB `CHECK (cardinality(feature_vector) = 20)`).
   - Calls **Isolation Forest** (`core/isolation_forest_client.py`) for a risk score, but only if
     `model:active_version` is set in Redis — otherwise risk_ctx stays `{score: null}` (**bootstrap mode**, before
     any ML model has been trained).
   - Calls **OPA** (`core/opa_client.py`, `POST {OPA_URL}/v1/data/authz/decision`) with an `OpaPolicyInput`
     (identity, resource, risk_ctx, `is_post_step_up`, feature_vector).
   - Persists every decision to `opa_decision_log`, and — only on ALLOW *and not post-step-up* — writes an
     `ml_training_samples` row (avoids feeding step-up-tainted samples back into training).
   - `ALLOW` → request proceeds to the route handler; `DENY` → 403; `STEP_UP` → 401 with
     `{"detail": "step_up_required"}`.

Requests without a bearer token skip steps 2–6 and pass straight to `call_next` (unauthenticated routes, e.g. login).

### OPA policy bundle (policies/)

Mounted read-only into the `opa` container at `/policy` (see `docker/docker-compose.yml`). Packages:

- `authz.rbac` (`policies/authz/rbac.rego`) — pure role/action RBAC (`reader`/`editor`/`admin`).
- `authz.adaptive_access` (`policies/risk/adaptive_access.rego`) — turns `risk_ctx.score` into `allow`/`step_up`.
  Threshold is `>= 0.8` → step_up. `bootstrap_mode` is true **only** when `risk_ctx.score == null` explicitly (a
  missing `risk_ctx` entirely is treated as a contract violation, not bootstrap — see comment in that file).
- `authz.mfa` (`policies/risk/mfa.rego`) — trusts `input.mfa.verified`; OPA never verifies TOTP itself, the
  Gateway does that and reports the result.
- `authz.decision` (`policies/authz/decision.rego`) — combines the three into a final `{decision, policy_name}`,
  defaulting to `deny`/`malformed_input_deny`. Decision precedence: RBAC deny wins first; then bootstrap-allow;
  then risk-allow; then MFA-verified-allow; then step-up-required.

Policy input/output contract notes live in `tests/policies/README.md` — read it before changing the risk/MFA
contract (e.g. it explains why `odd_hour` is a model feature, not a Rego input).

### Data layer

Schema is defined **twice** and must be kept in sync manually:
- `db/init/*.sql` — numbered init scripts Postgres runs on first container start (roles, `events`,
  `opa_decision_log`, `event_anomaly`, `ml_training_samples`, `canary_validation_log`).
- `services/api-gateway/app/models/tables.py` — SQLAlchemy Core `Table` definitions (used by Alembic env.py as
  `target_metadata`, and by `core/repositories.py` for inserts).

`opa_decision_log` is the append-only decision audit trail; `event_anomaly` references it by `id_log`
(`ON DELETE RESTRICT`); `ml_training_samples` holds the 20-feature vectors consumed by the (not-yet-implemented)
`ml-trainer` service; `canary_validation_log` is for comparing a candidate model's risk score against the
production model's on live traffic before promoting it.

### Docker Compose topology (docker/docker-compose.yml)

Three bridge networks: `dmz_net` (internet-facing: api-gateway, isolation-forest, canary-validator,
react-dashboard), `internal_net` (postgres, redis, vault, opa, and every backend service), `monitoring_net`
(react-dashboard only, for now). `api-gateway` is the only service in both `dmz_net` and directly reachable by
clients; ML services are only ever called *by* the gateway, never exposed to `dmz_net` traffic directly. A shared
`models-volume` is mounted into `isolation-forest`, `canary-validator`, and `ml-trainer` for the trained model
artifacts. `api-gateway` starts with `alembic stamp head && uvicorn --reload` — migrations are stamped, not run,
on container start (the DB schema comes from `db/init/*.sql`, not from Alembic migrations, in local dev).

Isolation Forest deliberately has **no** `REDIS_URL` — the gateway builds the complete feature vector (including
Redis-derived counters) before calling it, so it only ever receives a plain number vector and only writes to
Postgres. `behavioral-detector` and `ml-trainer` are unexposed background jobs (no `ports`/`expose`), triggered on
a schedule, reading `events`/`opa_decision_log` and writing `event_anomaly` / training a new model version.

## Commands

All commands below assume `cd services/api-gateway` (the only service with real code/tests today).

```bash
# Install deps (Poetry)
poetry install

# Run the full test suite
poetry run pytest

# Run a single test file / test
poetry run pytest tests/test_authorization.py
poetry run pytest tests/test_authorization.py::test_authorize_allow_persists_decision_and_training_sample

# Alembic migrations (schema source of truth is app/models/tables.py)
poetry run alembic revision --autogenerate -m "..."
poetry run alembic upgrade head
```

Tests do **not** use `pytest-asyncio`: async test bodies are wrapped in a local `_run()` coroutine and driven with
plain `asyncio.run(_run())`. External dependencies (OPA, Isolation Forest, Redis, the repository) are faked with
small `@dataclass` recorders in each test file rather than mocked — follow that pattern for new tests. `InMemoryRedis`
(`app/core/redis_client.py`) is the fallback/test double for real Redis and is also what `main.py` falls back to if
the real Redis connection fails at startup.

```bash
# Bring up the full stack (Postgres, Redis, Vault, OPA, api-gateway, and the ML/dashboard stubs)
docker compose -f docker/docker-compose.yml up
```

Local ports: api-gateway `8000`, Postgres `5433→5432`, Redis `6379`, Vault `8200`, react-dashboard `5173`.
Isolation Forest (`8001`) and canary-validator (`8002`) are only `expose`d internally, not published to the host.

There is no configured linter/formatter (no ruff/black/eslint config found) and no OPA policy test suite
(`tests/policies/*.json` are fixture inputs/documentation, not `opa test` cases) — don't assume either exists.

## Working conventions

- Env var names and defaults for the gateway are centralized in `app/core/settings.py`
  (`GatewaySettings`) — add new config there, sourced from `os.getenv`, rather than reading env vars ad hoc
  elsewhere.
- The gateway talks to Vault, OPA, and Isolation Forest over plain `urllib` wrapped in `asyncio.to_thread`, not an
  async HTTP client — match that style for new outbound calls in `app/core/`.
- `risk_ctx.score == null` (bootstrap mode) is a deliberate, distinct state from a missing `risk_ctx` — don't
  collapse the two when touching the adaptive-access policy or the `AuthorizationService` risk-scoring branch.
- `docker-compose.yml` has inline French comments explaining recent fixes (e.g. the OPA healthcheck protocol, why
  `dmz_net` was added to the ML services) — read them before "fixing" something that looks inconsistent, it may be
  intentional and already explained.
