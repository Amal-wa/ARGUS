import { useEffect, useRef, useState } from "react";

export type PollOutcome = "success" | "rate_limited" | "error";

// Ceiling for the 429 backoff below -- doubles from the configured interval
// up to this, so a sustained rate-limit condition settles at one request
// every 60s instead of retrying at the interval that got it rate-limited in
// the first place.
const MAX_BACKOFF_MS = 60_000;

/**
 * Shared scheduling loop behind usePolling and useDecisionFeed: runs `run`
 * every `intervalMs` (paused while the tab is hidden, catching up on
 * visibility regain), but backs off exponentially -- capped at
 * MAX_BACKOFF_MS -- whenever `run` reports "rate_limited", resetting to the
 * configured interval on the next success. This is what stops a poller from
 * hammering the Gateway at the same rate that just got it 429'd.
 *
 * `run` reports its own outcome rather than throwing, so callers keep
 * ownership of their data/error state (usePolling sets `data`/`error`,
 * useDecisionFeed prepends rows) while this hook owns only the scheduling
 * and the rate-limited flag.
 */
export function usePollingSchedule(
  run: () => Promise<PollOutcome>,
  intervalMs: number,
  deps: unknown[] = [],
  initialDelayMs = 0
): { rateLimited: boolean } {
  const [rateLimited, setRateLimited] = useState(false);

  const runRef = useRef(run);
  runRef.current = run;

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let delay = intervalMs;

    const tick = () => {
      if (cancelled) return;
      if (document.hidden) {
        timer = setTimeout(tick, delay);
        return;
      }
      void runRef.current().then((outcome) => {
        if (cancelled) return;
        if (outcome === "rate_limited") {
          setRateLimited(true);
          delay = Math.min(delay * 2, MAX_BACKOFF_MS);
        } else {
          setRateLimited(false);
          delay = intervalMs;
        }
        timer = setTimeout(tick, delay);
      });
    };

    const kickoff = setTimeout(tick, initialDelayMs);

    // Catch up immediately when the tab regains focus, rather than waiting
    // out whatever's left of the current (possibly backed-off) delay.
    const onVisibility = () => {
      if (document.hidden) return;
      if (timer) clearTimeout(timer);
      tick();
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      cancelled = true;
      clearTimeout(kickoff);
      if (timer) clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, initialDelayMs, ...deps]);

  return { rateLimited };
}
