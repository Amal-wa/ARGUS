# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Zero-Trust API access control platform ("ZT_project"). A FastAPI gateway authenticates every request, builds a
behavioral feature vector, gets a risk score from an ML anomaly-detection service, and asks an OPA (Open Policy
Agent) policy bundle for an ALLOW / DENY / STEP_UP decision — logging every decision for later ML training and
canary model comparisons.

Six components currently have real implementations: **`services/api-gateway`** (Python/FastAPI), the
**`policies/`** OPA/Rego bundle, **`services/isolation-forest`** (FastAPI + scikit-learn scoring service),
**`services/canary-validator`** (compares a candidate model's risk score against the production model's on live
traffic before promotion — see the Model promotion section below), **`services/ml-trainer`** (trains a new
Isolation Forest version from `ml_training_samples` and registers it in `ml_model_registry`), and
**`services/dashboard`** (Argus, React+Vite+TypeScript — the admin-only security dashboard for the
`/monitoring/*` endpoints; see `services/dashboard/README.md`). `services/react-dashboard/` is a leftover empty
placeholder from before `services/dashboard` existed — not wired into `docker-compose.yml` (the `dashboard`
service points at `services/dashboard`) and not to be confused with it. **`services/behavioral-detector`** is the
one remaining component that really is empty scaffolding (no files at all beyond the directory) —
`docker-compose.yml` already wires it in for when it's built out. Don't assume code exists there; check first.

## Architecture

### Request flow (services/api-gateway)

`app/main.py` wires `CORSMiddleware` (FastAPI/Starlette built-in) **after** `GatewayMiddleware` —
`app.add_middleware(GatewayMiddleware)` then `app.add_middleware(CORSMiddleware, ...)`. Starlette wraps
middlewares in reverse add-order, so the last one added is outermost and sees every request first: CORS runs
*before* `GatewayMiddleware`, not after. This is required, not stylistic — a CORS preflight is an `OPTIONS`
request with no `Authorization` header, and if `GatewayMiddleware` ran first it would 401 the preflight before
CORS ever got to answer it (the browser then reports an opaque CORS failure, not the real 401). With
`CORSMiddleware` outermost, it intercepts and answers every preflight directly; `GatewayMiddleware`'s JWT check
never runs for those requests. For normal (non-preflight) requests it just adds
`Access-Control-Allow-Origin`/`-Credentials` to whatever response comes back — 200, 401, 403, all of them — once
the request's `Origin` matches an allowed origin.

Allowed origins are `settings.cors_allowed_origins` (`CORS_ALLOWED_ORIGINS` env, comma-separated, **empty by
default** — same fail-closed discipline as `trusted_proxies`/`TRUSTED_PROXIES`). Never `allow_origins=["*"]`:
combined with the `allow_credentials=True` this API needs (so the dashboard's `Authorization` header survives
the CORS check), a wildcard origin is a well-known anti-pattern — any site a logged-in admin's browser visits
could otherwise call this API with their credentials. `docker-compose.yml` sets
`CORS_ALLOWED_ORIGINS=http://localhost:5173` for `api-gateway` — the Argus dashboard's origin (`services/dashboard`),
and the only one trusted out of the box.

Every HTTP request that gets past CORS then passes through a single Starlette middleware, `GatewayMiddleware`
(`app/middleware/gateway.py`), which runs this pipeline in order:

1. **IP rate limit** (`middleware/rate_limit.py`) — sliding window in Redis, checked before auth. The client IP
   itself is resolved by `resolve_client_ip` (`middleware/context.py`): `X-Forwarded-For` is honored **only**
   when the direct peer (`request.client.host`) is in `settings.trusted_proxies` (`TRUSTED_PROXIES` env, empty by
   default — the header is otherwise always ignored). The allowlist check is on the peer, never on anything in
   the header itself, so a spoofed header can't make itself trusted. Standard reverse-proxy practice (RFC 7239).
   Uvicorn is started with **`--no-proxy-headers`** (both in `docker-compose.yml`'s command and the Dockerfile's
   default `CMD`) — uvicorn's own built-in `X-Forwarded-For` handling is enabled and trusts `127.0.0.1` *by
   default*, and runs ahead of our app, silently rewriting `scope["client"]` before `resolve_client_ip` ever sees
   the request (verified live: a loopback request with a spoofed header was honored until this flag was added).
   Do not remove `--no-proxy-headers` — that would reopen exactly the spoofing bypass `TRUSTED_PROXIES` exists
   to close.
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
   - Builds a 16-float **feature vector** per user/IP from Redis counters, sets, and one ZSET
     (`services/feature_vector.py`, whose module-level comment is the authoritative index → concept map): one-hot
     HTTP method (5), request count (1 min, reuses `ratelimit:user:{id}` rather than a second counter), distinct
     route patterns and distinct raw resources (5 min, two *separate* sets — route patterns stay bounded per
     endpoint shape while raw resources grow with enumeration, which is the signal resource-enumeration detection
     depends on), inter-request interval mean/std-dev (5 min, `intervals:user:{id}` ZSET), distinct HTTP methods
     used, read/write ratio (one ratio, not both counts), DENY count, distinct IPs, authentication failures
     (`auth_failed:ip:{ip}` — IP-scoped, not user-scoped, since a failed-auth counter keyed on an unverified/
     not-yet-issued identity is spoofable; written from `routers/auth.py` on login failure), and request latency.
     Distinct IPs is also read **directly** by `policies/risk/adaptive_access.rego`'s `high_distinct_ips` rule
     (see the OPA bundle section), independent of the ML score — added after a live replay showed the score alone
     never reacted strongly enough to this one feature. Authentication failures has a companion signal beyond the
     plain counter: `record_auth_failure` also `SADD`s the attempted email into `auth_failed_accounts:ip:{ip}`
     (same 5-minute TTL discipline), and `events.attempted_email` (`0012_events_attempted_email` migration)
     persists it beyond that window — added because a live password-spraying replay showed the counter alone,
     and even the permanent `events` audit trail before this column existed, could not tell "N failures on 1
     account" from "N failures across N accounts", the actual signature that distinguishes spraying from
     bruteforce. Neither of these two companion signals is consumed by the ML feature vector itself (both are
     for direct behavioral rules / after-the-fact investigation) — the 16-dimension cardinality and its `CHECK`
     constraint are unaffected.
     Cardinality is fixed by construction (11 numeric + 5 one-hot), enforced by a DB
     `CHECK (cardinality(feature_vector) = 16)`. Every Redis-backed feature (counters, sets, the ZSET) shares the
     same 300s sliding window and the same TTL discipline: expiry is set only when a key is first created in the
     window, never refreshed on subsequent writes — a set/ZSET that keeps discovering new members must still expire
     on schedule, not slide forward forever. `build_vector` always runs *before* `record_observation` for the same
     request (see `AuthorizationService.authorize`), so a request's own activity is never visible in its own vector.
     This vector was rebuilt in 2026-07 from an earlier, partially-implemented 20-dimension layout (`ml_model_registry`
     version `v1` was trained on that old layout and predates this revision — it is not comparable to any later
     version and is kept only for training provenance). Three originally-designed concepts were deliberately
     dropped rather than carried forward: path-segment count, query-parameter count, and URL length (near-zero
     variance on this API — every route is one or two segments plus a fixed-width UUID, which dilutes an Isolation
     Forest more than it helps); `write_ratio` alongside `read_ratio` (perfectly collinear, `read_ratio +
     write_ratio == 1`); and per-resource request counts (would need one Redis counter per (user, resource) pair,
     already partially captured by distinct-raw-resources + request-count).
   - Calls **Isolation Forest** (`core/isolation_forest_client.py`) for a risk score, but only if
     `model:active_version` is set in Redis — otherwise risk_ctx stays `{score: null}` (**bootstrap mode**, before
     any ML model has been trained). When a model *is* active, the Gateway also reads `model:active_threshold`
     (the active model's calibrated p98 — see the OPA bundle section below) and injects it as `risk_ctx.threshold`.
     If `model:active_version` is set but `model:active_threshold` is missing or unparseable (a desync — a model
     promoted without calibration, or promoted by hand instead of via `scripts/promote_model.py`), the Gateway
     falls back to `settings.fallback_step_up_threshold` (`FALLBACK_STEP_UP_THRESHOLD`, default `0.65`) and logs a
     warning — it never silently disables step-up by leaving the threshold unset. The Gateway also cross-checks
     `risk_ctx.model_version` (the version isolation-forest actually scored with, returned in its `/score`
     response) against this same `active_model_version` it just read: isolation-forest hot-swaps models on its own
     ~30s poll cycle (see the isolation-forest section below), so there is a real window right after a promotion
     where the Gateway's threshold has already updated but isolation-forest is still serving the OLD model. On a
     mismatch the Gateway treats it exactly like a missing threshold (fallback + warning) rather than comparing a
     score and threshold calibrated for two different models — a bug found and fixed in 2026-07 (`IF-2` in that
     week's audit) after a live traffic-generator replay of a promotion made the desync window concretely visible.
   - Isolation-forest does not return the raw sigmoid score directly: `model_store.percentile_calibrate` maps it to
     its **percentile rank** against the active model's own calibration reference (`model:active_score_breakpoints`,
     101 values — see Model promotion below) before it ever reaches the Gateway. This replaced an earlier min-max
     rescale, itself a fix for the original *un*-rescaled sigmoid, which clustered essentially all real traffic
     (normal and anomalous alike) into a ~0.55-0.66 band with almost no usable separation. Min-max was rejected
     after a live A/B comparison (`calibration_demo.py`, see project history) showed it anchors the *entire* scale
     on two literal extreme points from a finite calibration batch — a single unusually-extreme sample skews every
     other score, and this was reproduced live (a resource-enumeration replay scored *lower* under min-max after
     recalibration than before it, the opposite of the intended effect). Percentile rank only moves as far as that
     one sample's own rank, never the whole scale — confirmed more robust on the same real data, and confirmed live
     (ROC AUC ≈ 0.82 for scenario A on the corrected methodology — see project history for the full sensitivity
     analysis, including why a single scenario/persona replay does not generalize past that measurement).
   - Calls **OPA** (`core/opa_client.py`, `POST {OPA_URL}/v1/data/authz/decision`) with an `OpaPolicyInput`
     (identity, resource, risk_ctx, `mfa`, `is_post_step_up`, feature_vector) wrapped as `{"input": ...}` —
     OPA's REST API requires the `input` envelope; without it OPA evaluates against an undefined `input` and
     RBAC silently denies.
   - Persists every decision to `opa_decision_log`, and — only on ALLOW *and not post-step-up* — writes an
     `ml_training_samples` row (avoids feeding step-up-tainted samples back into training).
   - `ALLOW` → request proceeds to the route handler; `DENY` → 403; `STEP_UP` → 401 with
     `{"detail": "step_up_required"}`.

Requests without a bearer token skip steps 2–6 and pass straight to `call_next` (unauthenticated routes, e.g. login).

### Session tokens: access token in memory, refresh token in an httpOnly cookie

The access token (15 min TTL) is a Bearer token: returned in the `/auth/login`/`/auth/refresh` JSON body, held only
in the dashboard's React state (never persisted), and sent as `Authorization: Bearer ...` on every authenticated
request — this is what `GatewayMiddleware` step 2 verifies.

The refresh token (7 day TTL, rotating, single-use — see `AuthService.refresh`) is different: it is **never** in a
JSON response body. `POST /auth/login` and `POST /auth/refresh` (`app/routers/auth.py`) set it as an `httpOnly`
cookie (`refresh_token`, `Path=/auth`) instead, so injected/XSS JS cannot read it at all — a strictly stronger
posture than `sessionStorage`, and the reason a page reload can silently restore the session (the browser re-sends
the cookie on its own) instead of logging the operator out.

Cookie attributes: `HttpOnly` is hardcoded (never configurable). `Secure`/`SameSite` come from
`settings.refresh_cookie_secure`/`refresh_cookie_samesite` (`REFRESH_COOKIE_SECURE`/`REFRESH_COOKIE_SAMESITE`,
defaulting to `false`/`lax` for local dev over plain HTTP). **Production requires only a config change, never a
code change**: `REFRESH_COOKIE_SECURE=true` + `REFRESH_COOKIE_SAMESITE=none`, because a real deployment puts the
dashboard and gateway on two distinct domains (cross-site, not just cross-origin), and browsers refuse
`SameSite=None` without `Secure` — the two settings change together.

Making the cookie `httpOnly` removes XSS exfiltration but reintroduces CSRF (the browser attaches the cookie to
*any* request to the gateway's origin, including one triggered by a third-party page). The defence is a required
custom header, not a token: `POST /auth/refresh` and `POST /auth/logout` 403 unless
`X-Requested-With: argus-dashboard` is present (`CSRF_HEADER_NAME`/`CSRF_HEADER_VALUE` in `routers/auth.py`). This
is sufficient *because* `CORS_ALLOWED_ORIGINS` is a strict allowlist (see above): a cross-origin `fetch`/`XHR`
setting a non-safelisted header forces a CORS preflight, which the allowlist rejects for any untrusted origin — so
an attacker's page can never get the header onto the wire for this origin. The header requirement and the CORS
allowlist are a matched pair; don't remove/loosen one without reconsidering the other. `CORSMiddleware`'s
`allow_headers` must include `X-Requested-With` or the preflight for these two routes fails before it's sent.

`POST /auth/refresh` reads the token from the cookie (not a request body), rotates it, and sets a new cookie on
success; on any failure (expired/revoked/reused) it **clears** the cookie in the response rather than leaving a
dead token in the browser to be replayed forever. `POST /auth/logout` revokes the presented token's whole family
server-side (`AuthService.logout`, the same `revoke_family` path reuse-detection uses) *and* clears the cookie —
clearing only the client-side state would leave a valid refresh token alive.

### OPA policy bundle (policies/)

Mounted read-only into the `opa` container at `/policy` (see `docker/docker-compose.yml`). Packages:

- `authz.rbac` (`policies/authz/rbac.rego`) — pure role/action RBAC (`reader`/`editor`/`admin`).
- `authz.adaptive_access` (`policies/risk/adaptive_access.rego`) — turns `risk_ctx.score` into `allow`/`step_up`.
  The threshold is **not hardcoded**: it's `risk_ctx.threshold`, injected by the Gateway from Redis'
  `model:active_threshold` (the active model's p98, calibrated on real traffic — "the 2% most behaviorally atypical
  requests trigger step-up"). `score >= threshold` → step_up, `score < threshold` → allow; if a score is present
  but `threshold == null` (should never happen — the Gateway always substitutes its fallback threshold first, see
  above), `risk_decision` is left **undefined** on purpose, which falls through to `authz`'s fail-closed default
  (deny) rather than silently allowing. `bootstrap_mode` is true **only** when `risk_ctx.score == null` explicitly
  (a missing `risk_ctx` entirely is treated as a contract violation, not bootstrap — see comment in that file).
  A second, independent rule (`high_distinct_ips`) forces `risk_decision := "step_up"` whenever
  `input.feature_vector[13]` (distinct IPs for this user in the 5-minute window — one of the 16 features, also
  described below) is `>= 2`, regardless of the score. Unlike the score threshold, this **is** a hardcoded
  constant — a deliberate exception to "never hardcode it in Rego", added after a live replay of the
  traffic-generator's session-hijack scenario (C) showed the ML score alone never crossed its threshold even
  though the feature correctly jumped from 1 to 2 (the single dimension is too diluted among the other 15 to move
  an Isolation Forest score by itself). `2` was picked empirically: every real sample gathered in this project
  with that feature `>= 2` came from that one attack replay, none from any other real traffic, at the time this
  was added. Takes precedence over the score-driven `allow` rules (both `allow` rules explicitly guard `not
  high_distinct_ips`); shares the same `"step_up"` value as the score-driven rule when both happen to fire, which
  Rego permits (only *different* values for the same complete rule conflict).
- `authz.mfa` (`policies/risk/mfa.rego`) — trusts `input.mfa.verified`; OPA never verifies TOTP itself, the
  Gateway does that and reports the result.
- `authz` (`policies/authz/decision.rego`) — combines the three into a final `{decision, policy_name}`,
  defaulting to `deny`/`malformed_input_deny`. Decision precedence: RBAC deny wins first; then bootstrap-allow;
  then risk-allow; then MFA-verified-allow; then step-up-required. Package is `authz` (not `authz.decision`) —
  the rule inside it is also named `decision`, so a package named `authz.decision` would make OPA's
  `/v1/data/authz/decision` endpoint return a double-nested `{"decision": {"decision": ..., "policy_name": ...}}`
  instead of the flat object `OpaClient` expects.

Policy input/output contract notes live in `tests/policies/README.md` — read it before changing the risk/MFA
contract (e.g. it explains why `odd_hour` is a model feature, not a Rego input).

### Data layer

**Alembic (`services/api-gateway/alembic/versions/`) is the single source of truth for the database schema.** It's
the only mechanism that creates/alters tables at runtime — the gateway's start command runs `alembic upgrade head`
before `uvicorn`. `services/api-gateway/app/models/tables.py` holds the SQLAlchemy Core `Table` definitions that
Alembic's `env.py` uses as `target_metadata` for autogenerate, and that `core/repositories.py` uses for inserts.

`db/init/*.sql` is **not** mounted into the `postgres` service (no `docker-entrypoint-initdb.d` volume in
`docker/docker-compose.yml`) and is never executed. These files are a frozen historical snapshot of the original
6-table schema (migration `0001`) kept only as human-readable reference — they can drift from the live schema and
don't need updating when new migrations land. Don't add new files there and don't treat them as authoritative; to
see the current schema, read the migrations in `alembic/versions/` (in order) or `app/models/tables.py`.

`opa_decision_log` is the append-only decision audit trail; `event_anomaly` references it by `id_log`
(`ON DELETE RESTRICT`); `ml_training_samples` holds the 16-feature vectors consumed by the `ml-trainer` service;
`canary_validation_log` is for comparing a candidate model's risk score against the production model's on live
traffic before promoting it. `events` is the gateway-level request/error audit trail (`app/core/events.py`,
`EventPayload`) — distinct from `opa_decision_log`, which only covers authenticated, authorized routes; `events`
also covers pre-auth failures (e.g. `event_type='auth_failed'` on `/auth/login`) that never reach
`AuthorizationService` at all. Its `attempted_email` column (`0012_events_attempted_email`) is audit-only — the
email a caller supplied on a failed login, independent of validity, never used as an authz/rate-limit key (see
the feature-vector section above for why this was added).

### Docker Compose topology (docker/docker-compose.yml)

Three bridge networks: `dmz_net` (internet-facing: api-gateway, isolation-forest, canary-validator),
`internal_net` (postgres, redis, vault, opa, and every backend service), `monitoring_net` (`dashboard` only).
`api-gateway` is the only service in both `dmz_net` and directly reachable by clients; ML services are only ever
called *by* the gateway, never exposed to `dmz_net` traffic directly. `dashboard` (the Argus security dashboard,
`services/dashboard/`, React+Vite+TS) is deliberately on `monitoring_net` **only** — it's a browser SPA that talks
to the Gateway's `/monitoring/*` and `/auth/*` endpoints from the *browser* via the published `8000` port, not
container-to-container, so it needs no Docker-network reachability to the Gateway at all; the network membership
just reflects that it's not on the request path for real traffic. A shared
`models-volume` is mounted into `isolation-forest`, `canary-validator`, and `ml-trainer` for the trained model
artifacts. `api-gateway` starts with `alembic upgrade head && uvicorn --reload` — migrations run for real on
container start, applying `alembic/versions/` in order against whatever schema state Postgres already has.

Isolation Forest (`services/isolation-forest`) has a `REDIS_URL`, but only to poll `model:active_version` every
`MODEL_POLL_INTERVAL_SECONDS` (default 30s) and hot-swap in the corresponding `{MODELS_DIR}/model_{version}.joblib`
— see `app/model_store.py`. It never touches feature keys and never writes to Redis or Postgres; the Gateway still
builds the complete feature vector itself (Redis-derived counters included) before calling `POST /score`, which
only ever receives a plain number vector back. `GET /health` reports `model_loaded: false` while no model is
loaded (a documented bootstrap state, not unhealthy) so the Gateway's `depends_on: service_healthy` is satisfied
even before any model has been trained; `POST /score` with no model loaded returns 503 (never a fake score).
`behavioral-detector` and `ml-trainer` are unexposed background jobs (no `ports`/`expose`), triggered on
a schedule, reading `events`/`opa_decision_log` and writing `event_anomaly` / training a new model version.

### Model promotion (`services/api-gateway/scripts/promote_model.py`)

Promoting a model to production is a deliberate manual act, run against the docker-compose stack with
`docker compose run --rm api-gateway poetry run python scripts/promote_model.py <version>` (or locally with
`cd services/api-gateway && poetry run python scripts/promote_model.py <version>`). It sets **three** Redis keys
together: `model:active_version`, `model:active_threshold`, and `model:active_score_breakpoints` (a JSON-encoded
list of 101 floats — `np.percentile(reference, 0..100)` of the calibration batch). The threshold is **not** the
raw p98 value copied verbatim — it's that p98 passed through the same percentile-rank interpolation isolation-forest
applies to every live score (`_percentile_rank` in `promote_model.py`, kept consistent with
`model_store.percentile_calibrate` by construction), so the threshold and the scores it's compared against always
live in the same space. In practice this makes the threshold converge close to `0.98` regardless of the model
version, since percentile rank is (by definition) invariant to which raw values happen to sit at that percentile —
if you see a wildly different number here, that's a signal something is wrong with the calibration data, not
normal variation. Both `percentile_breakpoints` and `p98` come from `ml_model_registry.score_distribution` — the
column canary-validator populates. If that column is still `NULL` for the given version, or has no usable
`percentile_breakpoints` (e.g. calibrated before this feature existed), or the breakpoints are degenerate (every
percentile collapsing to the same value), the script aborts and changes nothing rather than promoting off missing
or meaningless calibration data. These three keys must always change together — always promote through this
script, never `SET model:active_version` by hand, or the Gateway's fail-closed fallback threshold (see above)
becomes the normal path instead of a rare desync safety net.

## Commands

Commands in this section assume `cd services/api-gateway` unless noted otherwise.

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

`services/isolation-forest` has its own independent Poetry project (`cd services/isolation-forest`) —
`poetry install` / `poetry run pytest` there. Unlike the gateway, its tests use a real (tiny, synthetic-data)
`sklearn.ensemble.IsolationForest` trained and `joblib.dump`ed into a `tmp_path` per test, not a mock — see
`tests/test_model_store.py`. `tests/test_score_endpoint.py` drives the FastAPI app with `TestClient` (`httpx` is a
dev dependency only for this).

```bash
# Bring up the full stack (Postgres, Redis, Vault, OPA, api-gateway, and the ML/dashboard stubs)
docker compose -f docker/docker-compose.yml up
```

Local ports: api-gateway `8000`, Postgres `5433→5432`, Redis `6379`, Vault `8200`, dashboard `5173`.
Isolation Forest (`8001`) and canary-validator (`8002`) are only `expose`d internally, not published to the host.

There is no configured linter/formatter (no ruff/black/eslint config found). `tests/policies/*.json` are fixture
inputs/documentation, not `opa test` cases — but `policies/` does have a real Rego test suite, run from the repo
root with `opa test policies/ -v` (`policies/authz/rbac_test.rego`, `policies/risk/adaptive_access_test.rego`).

## Working conventions

- Env var names and defaults for the gateway are centralized in `app/core/settings.py`
  (`GatewaySettings`) — add new config there, sourced from `os.getenv`, rather than reading env vars ad hoc
  elsewhere.
- The gateway talks to Vault, OPA, and Isolation Forest over plain `urllib` wrapped in `asyncio.to_thread`, not an
  async HTTP client — match that style for new outbound calls in `app/core/`.
- `risk_ctx.score == null` (bootstrap mode) is a deliberate, distinct state from a missing `risk_ctx` — don't
  collapse the two when touching the adaptive-access policy or the `AuthorizationService` risk-scoring branch.
- The step-up threshold is **live model state**, calculated per-model and stored in Redis alongside
  `model:active_version` (as `model:active_threshold`, plus `model:active_score_breakpoints` for the percentile
  calibration both the threshold and every live score are expressed in) — never hardcode the *score* threshold in
  Rego, and never write `model:active_version` without also writing the other two (use `scripts/promote_model.py`,
  not a manual `SET`). `adaptive_access.rego`'s `high_distinct_ips` rule is a deliberate, documented exception to
  this (a fixed `>= 2` constant, not model-derived) — see the OPA bundle section for why that one is different.
- Prefer a direct Rego rule on an existing Redis-backed feature (see `high_distinct_ips`) over routing a signal
  through the ML score when the score has been shown to dilute it too much — confirmed this project's actual
  failure mode for at least one attack scenario (session hijack), not a hypothetical concern. Verify with a real
  traffic-generator replay before and after, the same way that finding was made.
- `docker-compose.yml` has inline French comments explaining recent fixes (e.g. the OPA healthcheck protocol, why
  `dmz_net` was added to the ML services) — read them before "fixing" something that looks inconsistent, it may be
  intentional and already explained.
