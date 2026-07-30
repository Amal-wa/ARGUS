# ARGUS. — Pwn & Patch security dashboard

A React + Vite + TypeScript single-page app for the Zero-Trust API Gateway's
`/monitoring/*` admin endpoints. Not part of the Python monorepo services --
lives here as an independent frontend project, and (per the architecture)
talks **only** to the Gateway's published port, never to Postgres/Redis/OPA/
Isolation Forest directly.

## Prerequisites

- The docker-compose stack is up, a model is promoted (`model:active_version`
  set), and `scripts/seed_business_data.py` / `scripts/seed_users.py` have
  been run -- the dashboard needs an **already MFA-enrolled admin** to log
  in (mandatory MFA: see `services/api-gateway/app/services/auth.py`). The
  seed scripts enroll every seeded user, including `admin1@zt.local` /
  `admin2@zt.local`.
- Admin login to use for the demo: `admin1@zt.local` / `ChangeMe123!`
  (or whatever `SEED_USER_PASSWORD` was set to when seeding).

## Run (dev server, local)

```bash
cd services/dashboard
npm install
npm run dev
```

Opens on `http://localhost:5173`. Copy `.env.example` to `.env` to override
`VITE_GATEWAY_URL` (defaults to `http://localhost:8000`, the Gateway's
published port).

## Run (via docker-compose)

```bash
docker compose -f docker/docker-compose.yml up -d dashboard
```

Same URL, `http://localhost:5173`. The container only needs `monitoring_net`
(not `dmz_net`/`internal_net`) -- the actual `/monitoring/*` and `/auth/*`
calls are made by the **browser**, not the container, against the Gateway's
host-published port. The container's only job is to serve the Vite dev
server / JS bundle.

## Build

```bash
npm run build   # tsc --noEmit && vite build -> dist/
npm run preview # serve the production build locally
```

## Test

```bash
npm run test   # vitest run
```

Currently covers `AuthContext`: single-flight refresh under concurrent 401s,
and the 401 `detail` branching (see Design notes below).

## Phase 1 / Phase 2 (matches the traffic generator's own README)

- **Phase 1**: start the dashboard while `tools/traffic-generator` runs in
  `--mode normal` in another terminal. Stat cards, the feed, and the risk
  timeline (all users) should show steady, low (~0.55-0.65) risk scores and
  an allow rate near 100%.
- **Phase 2 (Scenario A demo)**: once the enumeration attack starts
  (`--mode attack --scenario A --target-email reader3@zt.local`), select
  `reader3@zt.local` in the risk-timeline dropdown to isolate its
  trajectory. Watch the line cross the dashed red threshold line (~0.651)
  and turn red; the Alerts panel should start receiving `step_up` entries
  for that user, pulsing on arrival, while the rest of the population stays
  flat and cyan.

## Design notes

- **Auth**: the access token lives in React state (`AuthContext`), never in
  `localStorage`/`sessionStorage` -- a page refresh logs you out by design.
  `authFetch` reads the *reason* on a 401 rather than assuming every 401
  means "access token expired":
  - no `detail` / an ordinary rejection (`"invalid token"`, `"token
    revoked"`, ...) -> refresh once, retry once (the normal path).
  - `detail: "step_up_required"` or `"mfa_enrollment_required"` -> do
    **not** refresh; show a clear message and return to the login screen.
    These are guards against regression, not reachable features: the
    dashboard only ever calls `/auth/*` (no OPA) and `/monitoring/*`
    (exempt from ML scoring -- see `AuthorizationService.authorize`'s
    `MONITORING_PATH_PREFIX` branch on the Gateway), so a risk-based
    step-up is structurally unreachable from this client today. The
    branch exists because the first production incident was exactly this
    misread: a `step_up_required` 401 treated as expiry, triggering a
    refresh (and, under the dashboard's ~5 concurrent pollers, a refresh
    *storm* -- see the single-flight fix below). If a scored route is
    ever added to the dashboard, this is what stops that from silently
    coming back. Deliberately not a TOTP entry flow.
  - **Single-flight refresh**: concurrent 401s across the ~5 pollers share
    one in-flight `POST /auth/refresh` call (a ref-held promise) instead of
    each presenting the single-use, rotating refresh token independently --
    the Gateway correctly treats a reused refresh token as theft and
    revokes the whole token family, which is what caused the original
    cascade-logout incident.
- **Real-time**: 2s polling (`usePolling` / `useDecisionFeed`), paused via
  the Page Visibility API when the tab isn't focused. `/monitoring/decisions`
  is polled incrementally with `?since=<last-seen timestamp>` so each tick
  only fetches new rows. `/monitoring/alerts` and `/monitoring/stats` share
  the same `window_minutes` (60, passed explicitly in `Dashboard.tsx`) so
  the two panels can't visibly disagree about "now" -- alerts is bounded by
  time, not just by row count, since `opa_decision_log` is a permanent,
  never-pruned audit trail. A WebSocket push channel would remove the
  polling delay/overhead entirely -- reasonable future evolution once the
  data volume or latency requirements justify it; not needed at this
  cadence.
- **Component tree**: `App` → `AuthProvider` → (`LoginScreen` |
  `Dashboard`). `Dashboard` owns all the polling hooks and composes
  `Header`, `StatCards`, `RiskTimeline`, `AlertsPanel`, `DecisionFeed`,
  `SystemStatusPanel`, and (on demand) `AuditView`.
- **Chart library**: Recharts. The risk timeline is the one chart in the
  app; a heavier charting library wasn't justified.
- Every panel degrades independently: a failing endpoint shows a small
  "degraded" badge on just that card, never a blank/crashed page.

## Typography

Two faces:

- **Display** (`--font-display`): **Oswald**, weights 600/700 -- the
  `ARGUS.` wordmark (header and, much larger, the login screen), stat-card
  numbers, panel titles, and key System Status figures (model version,
  threshold, training sample count). Self-hosted (`src/assets/fonts/*.woff2`,
  loaded via `@font-face` in `index.css`), not a Google Fonts `<link>` --
  this is what makes it load reliably inside the docker container
  regardless of outbound network access at demo time. Only the Latin subset
  is bundled (the UI is English/French only).
- **Body** (`--font-body`): the system font stack (`system-ui`, `-apple-system`,
  `Segoe UI`, `Roboto`) -- table content, feed rows, labels, form fields.
  No extra font to load or bundle for body copy; kept deliberately simple.
