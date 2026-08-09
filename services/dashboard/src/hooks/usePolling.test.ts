import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { usePolling } from "./usePolling";
import {
  ALERTS_POLL_MS,
  DECISIONS_POLL_MS,
  RISK_TIMELINE_POLL_MS,
  STATS_POLL_MS,
  SYSTEM_STATUS_POLL_MS,
} from "../pollingIntervals";

describe("pollingIntervals", () => {
  it("gives each panel its own interval instead of one uniform value", () => {
    // The bug this fixes: all 5 panels polling at the same 2s rate summed to
    // ~150 req/min from one browser session, above the Gateway's IP rate
    // limit. Distinct intervals are the fix -- assert they stay distinct
    // rather than someone "helpfully" setting them all back to one value.
    const intervals = [DECISIONS_POLL_MS, RISK_TIMELINE_POLL_MS, STATS_POLL_MS, ALERTS_POLL_MS, SYSTEM_STATUS_POLL_MS];
    expect(new Set(intervals).size).toBeGreaterThan(1);
    // The live feed must stay the fastest -- it's the one panel that has to
    // feel real-time.
    expect(DECISIONS_POLL_MS).toBeLessThan(RISK_TIMELINE_POLL_MS);
    expect(RISK_TIMELINE_POLL_MS).toBeLessThan(STATS_POLL_MS);
    expect(STATS_POLL_MS).toBeLessThan(SYSTEM_STATUS_POLL_MS);
  });
});

describe("usePolling", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("two pollers with different intervalMs fetch at different rates", async () => {
    vi.useFakeTimers();
    const fastFetcher = vi.fn().mockResolvedValue("fast");
    const slowFetcher = vi.fn().mockResolvedValue("slow");

    renderHook(() => usePolling(fastFetcher, 1000));
    renderHook(() => usePolling(slowFetcher, 5000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0); // initial (unstaggered) fetch for both
    });
    expect(fastFetcher).toHaveBeenCalledTimes(1);
    expect(slowFetcher).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4000);
    });
    // fast (1s interval) has ticked several more times; slow (5s interval) has not ticked again yet.
    expect(fastFetcher.mock.calls.length).toBeGreaterThanOrEqual(4);
    expect(slowFetcher).toHaveBeenCalledTimes(1);
  });

  it("delays the first fetch by initialDelayMs (stagger)", async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn().mockResolvedValue("ok");

    renderHook(() => usePolling(fetcher, 1000, [], 500));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(499);
    });
    expect(fetcher).not.toHaveBeenCalled();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("a 429 backs off instead of retrying at the configured interval, and resets on the next success", async () => {
    vi.useFakeTimers();
    let call = 0;
    const fetcher = vi.fn().mockImplementation(() => {
      call += 1;
      if (call === 1) {
        return Promise.reject(new ApiError(429, "rate limit exceeded"));
      }
      return Promise.resolve({ ok: true });
    });

    const { result } = renderHook(() => usePolling(fetcher, 1000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0); // first tick -> 429
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(result.current.rateLimited).toBe(true);
    // A 429 is not a generic failure -- it must not populate `error`.
    expect(result.current.error).toBeNull();

    // The next retry must NOT happen at the base interval (1000ms) --
    // backoff doubles it to 2000ms.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(fetcher).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000); // total 2000ms since the 429
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(result.current.rateLimited).toBe(false);

    // Interval is back to normal (1000ms) after the successful response.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it("a visibility regain during the initial delay does not cause a duplicate fetch", async () => {
    // Reproduces a real bug: a tab loaded in the background (document.hidden)
    // that regains focus before initialDelayMs elapses used to fire both the
    // visibility-triggered tick() AND the original kickoff timer moments
    // later, since onVisibility only ever cancelled the recurring `timer`,
    // never the separate initial `kickoff` timer.
    vi.useFakeTimers();
    const fetcher = vi.fn().mockResolvedValue("ok");
    Object.defineProperty(document, "hidden", { value: true, configurable: true });

    try {
      renderHook(() => usePolling(fetcher, 1000, [], 500));

      await act(async () => {
        await vi.advanceTimersByTimeAsync(200); // partway through initialDelayMs
        Object.defineProperty(document, "hidden", { value: false, configurable: true });
        document.dispatchEvent(new Event("visibilitychange"));
      });

      // Let the rest of the original 500ms initial delay elapse too -- this
      // is exactly where the uncancelled kickoff timer used to fire again.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(400);
      });

      expect(fetcher).toHaveBeenCalledTimes(1);
    } finally {
      Object.defineProperty(document, "hidden", { value: false, configurable: true });
    }
  });

  it("a non-429 error is surfaced as `error`, not `rateLimited`, and does not back off", async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn().mockRejectedValue(new Error("boom"));

    const { result } = renderHook(() => usePolling(fetcher, 1000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.error).toBe("boom");
    expect(result.current.rateLimited).toBe(false);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
