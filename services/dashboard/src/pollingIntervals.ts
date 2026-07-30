// Poll intervals are calibrated to how fast each dataset actually changes --
// NOT a single uniform "safe" number. At the old uniform 2s, the dashboard's
// 5 pollers alone drew ~150 req/min from one browser session, tripping the
// Gateway's IP rate limit (RATE_LIMIT_IP_LIMIT, default 100/min -- see
// CLAUDE.md's Gateway request-flow section and app/core/settings.py). Do NOT
// "helpfully" set these back to a uniform value.
//
// - decisions: the live feed. This is the one thing that must feel
//   real-time, so it keeps the fast interval.
// - risk-timeline: the demo centrepiece -- needs to feel responsive as
//   scores climb, but its 30-minute window doesn't need 2s granularity.
// - stats / alerts: both aggregate over a 60-minute window. Refreshing
//   30x/minute changes nothing visible.
// - system-status: the active model/threshold only change on a deliberate
//   manual promotion (scripts/promote_model.py) -- roughly weekly at most.
export const DECISIONS_POLL_MS = 2_000;
export const RISK_TIMELINE_POLL_MS = 5_000;
export const STATS_POLL_MS = 10_000;
export const ALERTS_POLL_MS = 10_000;
export const SYSTEM_STATUS_POLL_MS = 30_000;

// Small per-poller stagger applied only to the FIRST fetch on mount, so five
// pollers with different periods don't still happen to line up into a
// synchronized burst (e.g. the 10s and 30s pollers both landing on the same
// tick). Purely for smoothing request timing across the window, not a
// correctness requirement -- each poller free-runs on its own interval after
// this initial offset.
export const DECISIONS_INITIAL_DELAY_MS = 0;
export const RISK_TIMELINE_INITIAL_DELAY_MS = 400;
export const STATS_INITIAL_DELAY_MS = 800;
export const ALERTS_INITIAL_DELAY_MS = 1_200;
export const SYSTEM_STATUS_INITIAL_DELAY_MS = 1_600;
