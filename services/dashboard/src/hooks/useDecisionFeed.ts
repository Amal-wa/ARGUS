import { useCallback, useRef, useState } from "react";
import { ApiError } from "../api/client";
import { getDecisions } from "../api/monitoring";
import type { DecisionRow } from "../types";
import { useAuth } from "../context/AuthContext";
import { DECISIONS_INITIAL_DELAY_MS, DECISIONS_POLL_MS } from "../pollingIntervals";
import { usePollingSchedule } from "./usePollingSchedule";
import type { PollOutcome } from "./usePollingSchedule";

const MAX_FEED_ROWS = 50;

/**
 * The live decision feed: uses `since` (the newest `created_at` seen so far)
 * so each poll only fetches NEW rows, then prepends them -- never refetches
 * the whole list. New rows are added to the front, the feed is capped at
 * MAX_FEED_ROWS.
 */
export function useDecisionFeed() {
  const { authFetch } = useAuth();
  const [rows, setRows] = useState<DecisionRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  const sinceRef = useRef<string | null>(null);
  const authFetchRef = useRef(authFetch);
  authFetchRef.current = authFetch;

  const run = useCallback(async (): Promise<PollOutcome> => {
    try {
      const response = await getDecisions(authFetchRef.current, {
        limit: MAX_FEED_ROWS,
        since: sinceRef.current ?? undefined,
      });
      if (response.decisions.length > 0) {
        sinceRef.current = response.decisions[0].created_at; // API returns most-recent-first
        setRows((prev) => [...response.decisions, ...prev].slice(0, MAX_FEED_ROWS));
      }
      setError(null);
      return "success";
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        return "rate_limited";
      }
      setError(err instanceof Error ? err.message : "request failed");
      return "error";
    }
  }, []);

  const { rateLimited } = usePollingSchedule(run, DECISIONS_POLL_MS, [], DECISIONS_INITIAL_DELAY_MS);

  return { rows, error, rateLimited };
}
