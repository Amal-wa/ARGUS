# Zero Trust traffic generator

A standalone Python tool that produces the data the ML pipeline needs. It is
**not** part of the Zero Trust architecture: it lives outside `services/`, is
not containerized, is not in `docker-compose.yml`, and must not appear in the
architecture diagram. It runs from the host against `http://localhost:8000`.

## Why this exists

The whole system was complete and had 6 rows in `ml_training_samples`,
because nothing called the API. `IsolationForest` learns "normal" from that
table, and the feature vector is built from **real-time Redis sliding
windows** (requests/minute, inter-request interval, distinct paths, distinct
IPs, denies, auth failures...). A script that fires requests as fast as
possible would make every one of those features constant or maxed out
permanently, and the model would learn "burst at max rate" as normal --
at which point a real enumeration attack would look statistically identical
to the learned normal and would not be detected. **There is no shortcut: this
generator runs in real time, at human pace, for days.**

## The one rule that matters: phase 1 vs phase 2

- **Phase 1 (`--mode normal`)**: normal traffic only. This is what populates
  `ml_training_samples` for training. Run it for days.
- **Phase 2 (`--mode attack --scenario X`)**: normal traffic continues in the
  background, plus one injected attack scenario, so the contrast is visible
  in the logs afterward.
- **Never run an attack scenario during the phase-1 training window.** If an
  attack's requests land in `ml_training_samples`, the model learns the
  attack as normal and will never flag it. Train first, only then attack.

## Prerequisites

1. The docker-compose stack is up (`docker compose -f docker/docker-compose.yml up -d`).
2. `scripts/seed_business_data.py` has been run against the gateway (creates
   the 25 persona accounts + 400 documents + 400 orders this tool drives, and
   -- since MFA is mandatory (see `services/api-gateway/app/services/auth.py`)
   -- enrolls all of them in MFA, writing their TOTP secrets to the
   git-ignored `persona_secrets.json` in this directory). `PersonaClient`
   copes if an account somehow isn't pre-enrolled (auto-enrolls on first
   login), but the documented path is: seed first, generator second.
3. **`TRUSTED_PROXIES` must include the gateway's view of this generator's
   peer IP**, or `X-Forwarded-For` is (correctly, securely) ignored and every
   persona collapses onto one IP -- silently producing a worthless dataset.
   The generator's startup check catches and refuses to proceed on this, but
   to fix it up front: find the peer IP with

   ```bash
   curl -s -X POST http://localhost:8000/auth/login -H "Content-Type: application/json" -d "{}"
   docker exec redis redis-cli --scan --pattern "ratelimit:ip:*"
   ```

   then set that IP as `TRUSTED_PROXIES` in `docker/docker-compose.yml` and
   recreate the `api-gateway` container. On this project's default Docker
   Desktop setup that IP is the compose project's `dmz_net` bridge gateway
   (already set to `172.18.0.1` in the committed compose file) -- re-verify if
   your Docker networking differs or the network is ever recreated.

## Install

```bash
cd tools/traffic-generator
poetry install
```

## Run

```bash
# Phase 1: normal traffic, real time, run for days (Ctrl-C to stop cleanly)
poetry run python -m generator.main --mode normal

# Short trial run (5 minutes) -- ALWAYS do this before the multi-day run
poetry run python -m generator.main --mode normal --duration 300

# Phase 2: normal traffic + one injected attack scenario
poetry run python -m generator.main --mode attack --scenario A --duration 300
```

Flags: `--duration` (seconds; omit to run until Ctrl-C), `--seed` (default
42, reproducible persona sampling), `--base-url` (default
`http://localhost:8000`), `--redis-url` (default `redis://localhost:6379/0`,
used only for the startup XFF check), `--password` (default
`ChangeMe123!`, must match `SEED_USER_PASSWORD` used when seeding).

On Ctrl-C (or when `--duration` elapses): clean shutdown, a summary is
printed (total requests, status-code counts, denies, token refreshes,
per-persona breakdown).

## What each mode does

**`--mode normal`**: builds 25 personas from the seeded accounts
(`reader1..15`, `editor1..8`, `admin1..2@zt.local`). Each persona gets, once,
at startup, from a seeded RNG: a unique IP (sent via `X-Forwarded-For`), a
mean inter-action interval sampled from a wide lognormal (some personas act
every ~20s, others every ~10+ min -- this spread across the population *is*
the "normal" distribution), a burst probability, and a small sticky set of
"favorite" resources (~70-80% of accesses; the rest come from the full pool).
Each persona is an independent `asyncio` task, running forever: wait an
exponential interval, do a role-weighted action (reader mostly reads;
editor/admin occasionally write, always GET-before-PUT the same resource in
a session), sometimes chain a short burst of 2-6 quick follow-ups, then pause
longer. All log in via `POST /auth/login` for real and refresh via
`POST /auth/refresh` on 401 -- no hand-forged JWTs anywhere.

**`--mode attack --scenario X`**: phase-1 personas keep running in the
background; one of the four scenarios below is additionally injected.

## Attack scenarios (phase 2 only)

- **A -- resource enumeration (the flagship scenario)**: an existing,
  already-authenticated, legitimate persona (valid token, valid role, RBAC
  allows `read`) suddenly walks hundreds of distinct documents it has never
  touched, at a pace kept just under the IP rate limit. Nothing in RBAC/OPA
  rejects a single one of these requests -- the token is valid, the role is
  allowed. Only the *behavior* (distinct-paths spike, requests/minute spike,
  near-zero interval, novel resources) is aberrant. This is the scenario that
  justifies the whole project: valid credentials pass every classic access
  control; only behavioral analysis catches it.
- **B -- password spraying**: one IP, one common password, many different
  accounts, one attempt each (no lockout triggered; low rate, no IP rate
  limit triggered). Detectable via `auth_failed:ip:{ip}` accumulating across
  distinct accounts.
- **C -- session hijack / context switch**: an existing persona's valid
  credentials are suddenly used from a brand-new IP never seen for that user,
  while the request pattern otherwise looks ordinary. Detectable via
  distinct-IPs-per-user jumping.
- **D -- privilege escalation attempts**: a reader persona hammers write
  routes and `/users`. OPA denies every one -- the attack fails outright --
  but the *pattern* of repeated denials (`decisions:deny:{user_id}` spiking)
  is the signal.

Each scenario logs a clear `[ATTACK START ...]` / `[ATTACK STOP ...]` line
with a UTC timestamp, so it can be correlated against `opa_decision_log`
afterward.

## Known, deliberate limitation: no time-of-day seasonality

The 20-dim feature vector contains no absolute-time feature -- the model
structurally cannot see the hour of day. Modelling day/night traffic shape in
the generator would therefore be effort invisible to detection, so it isn't
done. If an absolute-time feature is ever added to the vector, this would be
the natural place to add seasonality to match it.

## Verifying a trial run

After a `--duration 300` (5 min) run, before starting the real multi-day run,
check all of the following (`psql` against `localhost:5433/zt_db`, or
`docker exec postgres psql -U postgres -d zt_db -c "..."`):

```sql
-- 1) Rows are landing
SELECT count(*) FROM ml_training_samples;

-- 2) Many DISTINCT IPs, not one (the make-or-break check for X-Forwarded-For)
SELECT ip_address, count(*) FROM opa_decision_log GROUP BY ip_address ORDER BY 2 DESC;

-- 3) Inter-request intervals are varied, not all near-zero
SELECT trace_id, created_at FROM ml_training_samples ORDER BY created_at;
-- (diff consecutive created_at per user; see the verification notes for the
-- exact query used)

-- 4) DENY rows exist but are rare (a few %, not the majority)
SELECT decision, count(*) FROM opa_decision_log GROUP BY decision;
```

Extend to a 20-minute run once to confirm token refresh survives past the
15-minute access-token TTL without a flood of 401s, and that there's no 429
storm (personas pacing themselves under the rate limit).

Only after all of these pass: start the real, multi-day phase-1 run.
