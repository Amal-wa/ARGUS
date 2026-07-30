import { useCallback, useRef, useState } from "react";
import { ApiError } from "../api/client";
import { usePollingSchedule } from "./usePollingSchedule";
import type { PollOutcome } from "./usePollingSchedule";

export interface PollingResult<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** True while this poller is backed off after a 429 -- distinct from
   * `error`, which means the backend itself is unhealthy. See
   * usePollingSchedule for the backoff behavior. */
  rateLimited: boolean;
}

/**
 * Polls `fetcher` on a schedule (see usePollingSchedule for interval/backoff/
 * visibility-pause behavior). Real-time via polling, not a WebSocket -- the
 * data cadence here (a few requests/sec at demo scale) doesn't need a
 * persistent connection; a WebSocket push channel is a reasonable future
 * evolution if that changes.
 *
 * `deps` lets a caller restart the fetch loop when a query parameter (e.g.
 * the selected user) changes, the same way useEffect deps work.
 * `initialDelayMs` staggers this poller's first fetch relative to others
 * mounted at the same time (see pollingIntervals.ts).
 */
export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = [],
  initialDelayMs = 0
): PollingResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const run = useCallback(async (): Promise<PollOutcome> => {
    try {
      const result = await fetcherRef.current();
      setData(result);
      setError(null);
      return "success";
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        // Not a generic failure -- do not touch `error`/`data`. The last
        // good data stays on screen while the schedule backs off.
        return "rate_limited";
      }
      setError(err instanceof Error ? err.message : "request failed");
      return "error";
    } finally {
      setLoading(false);
    }
  }, []);

  const { rateLimited } = usePollingSchedule(run, intervalMs, deps, initialDelayMs);

  return { data, error, loading, rateLimited };
}
