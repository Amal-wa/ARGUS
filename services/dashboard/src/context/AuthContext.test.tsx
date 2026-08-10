import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider, useAuth } from "./AuthContext";

function headerValue(init: RequestInit | undefined, name: string): string | undefined {
  const headers = init?.headers as Record<string, string> | undefined;
  return headers?.[name];
}

// Every test mounts AuthProvider, which fires exactly one silent
// /auth/refresh attempt on mount (see AuthContext's useEffect) before any
// test-specific action runs. Fixture mocks below have that first call fail
// with a plain 401 (no session cookie yet, as in a fresh browser with no
// prior login) unless a test is specifically about the silent-restore
// behavior itself. This helper lets each test's fetch mock react to whether
// a call is that FIRST /auth/refresh call or a later one.
async function settleMountEffect() {
  // Flushes the mount-time refreshAccessToken() promise chain (and its
  // setState calls) before the test proceeds, so refresh-call counts and
  // isAuthenticated/isInitializing are deterministic instead of racing
  // whatever the test does next.
  await act(async () => {});
}

describe("AuthContext single-flight refresh", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("N concurrent 401s trigger exactly one ADDITIONAL /auth/refresh call, and all requests are retried successfully", async () => {
    let refreshCalls = 0;

    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const path = String(url);

      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "old-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }

      if (path.endsWith("/auth/refresh")) {
        refreshCalls += 1;
        if (refreshCalls === 1) {
          // The mount-time silent-restore attempt -- no session yet.
          return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
        }
        // Simulate real work happening so concurrent callers genuinely
        // overlap in-flight, not just interleave on microtask boundaries.
        await new Promise((resolve) => setTimeout(resolve, 10));
        return new Response(JSON.stringify({ access_token: "new-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Any /monitoring/* call: the OLD access token is now stale (single
      // rotation already happened server-side), NEW token succeeds.
      const auth = headerValue(init, "Authorization");
      if (auth === "Bearer old-access") {
        return new Response(null, { status: 401 });
      }
      if (auth === "Bearer new-access") {
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      throw new Error(`unexpected request: ${path} (${auth})`);
    });

    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();
    expect(refreshCalls).toBe(1); // the failed mount-time attempt

    await act(async () => {
      await result.current.login("admin1@zt.local", "ChangeMe123!");
    });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    const CONCURRENT_REQUESTS = 5;
    let responses: Response[] = [];
    await act(async () => {
      responses = await Promise.all(
        Array.from({ length: CONCURRENT_REQUESTS }, () => result.current.authFetch("/monitoring/stats"))
      );
    });

    expect(refreshCalls).toBe(2); // exactly one MORE call, not five
    expect(responses).toHaveLength(CONCURRENT_REQUESTS);
    responses.forEach((response) => expect(response.status).toBe(200));
  });

  it("a failed refresh logs out every waiter, still after only one refresh call", async () => {
    let refreshCalls = 0;

    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const path = String(url);

      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "old-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.endsWith("/auth/refresh")) {
        refreshCalls += 1;
        if (refreshCalls === 1) {
          return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
        return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
      }
      const auth = headerValue(init, "Authorization");
      if (auth === "Bearer old-access") {
        return new Response(null, { status: 401 });
      }
      throw new Error(`unexpected request: ${path} (${auth})`);
    });

    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("admin1@zt.local", "ChangeMe123!");
    });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    await act(async () => {
      await Promise.all([result.current.authFetch("/monitoring/stats"), result.current.authFetch("/monitoring/alerts")]);
    });

    expect(refreshCalls).toBe(2); // 1 mount-time + exactly 1 for both waiters together
    await waitFor(() => expect(result.current.isAuthenticated).toBe(false));
  });
});

describe("AuthContext 401 detail branching", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("a step_up_required 401 never calls /auth/refresh and logs out with a clear message", async () => {
    let refreshCalls = 0;

    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "old-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.endsWith("/auth/refresh")) {
        refreshCalls += 1;
        if (refreshCalls === 1) {
          return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
        }
        return new Response(JSON.stringify({ access_token: "new-access", token_type: "bearer", expires_in: 900 }), { status: 200 });
      }
      // A scored route returning step_up_required, hypothetically -- the
      // whole point of this test is that this must be structurally
      // unreachable in practice (dashboard only calls /auth/* and exempt
      // /monitoring/* routes), but the guard must hold if it ever weren't.
      return new Response(JSON.stringify({ detail: "step_up_required", challenge_id: "abc" }), { status: 401 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("admin1@zt.local", "ChangeMe123!");
    });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    const refreshCallsBeforeAuthFetch = refreshCalls;
    await act(async () => {
      await result.current.authFetch("/monitoring/stats");
    });

    expect(refreshCalls).toBe(refreshCallsBeforeAuthFetch); // unchanged
    await waitFor(() => expect(result.current.isAuthenticated).toBe(false));
    expect(result.current.error).toMatch(/step-up/i);
  });

  it("an mfa_enrollment_required 401 never calls /auth/refresh and logs out with a clear message", async () => {
    let refreshCalls = 0;

    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "old-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.endsWith("/auth/refresh")) {
        refreshCalls += 1;
        return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
      }
      return new Response(JSON.stringify({ detail: "mfa_enrollment_required" }), { status: 401 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("admin1@zt.local", "ChangeMe123!");
    });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    const refreshCallsBeforeAuthFetch = refreshCalls;
    await act(async () => {
      await result.current.authFetch("/monitoring/stats");
    });

    expect(refreshCalls).toBe(refreshCallsBeforeAuthFetch); // unchanged
    await waitFor(() => expect(result.current.isAuthenticated).toBe(false));
    expect(result.current.error).toMatch(/mfa enrollment/i);
  });

  it("a plain 401 (no special detail) still refreshes exactly once and retries successfully", async () => {
    let refreshCalls = 0;

    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "old-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.endsWith("/auth/refresh")) {
        refreshCalls += 1;
        if (refreshCalls === 1) {
          return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
        }
        return new Response(JSON.stringify({ access_token: "new-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      const auth = headerValue(init, "Authorization");
      if (auth === "Bearer old-access") {
        return new Response(JSON.stringify({ detail: "invalid token" }), { status: 401 });
      }
      if (auth === "Bearer new-access") {
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      throw new Error(`unexpected request: ${path} (${auth})`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("admin1@zt.local", "ChangeMe123!");
    });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    const refreshCallsBeforeAuthFetch = refreshCalls;
    let response: Response | undefined;
    await act(async () => {
      response = await result.current.authFetch("/monitoring/stats");
    });

    expect(refreshCalls).toBe(refreshCallsBeforeAuthFetch + 1);
    expect(response?.status).toBe(200);
    expect(result.current.isAuthenticated).toBe(true);
  });

  it("a successful refresh whose retried request still 401s (e.g. concurrent revocation) logs out", async () => {
    let refreshCalls = 0;

    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "old-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.endsWith("/auth/refresh")) {
        refreshCalls += 1;
        if (refreshCalls === 1) {
          return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
        }
        // The refresh itself succeeds -- a new access token is minted --
        // but the account was revoked server-side in the meantime.
        return new Response(JSON.stringify({ access_token: "new-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      const auth = headerValue(init, "Authorization");
      // BOTH the old and the freshly-rotated token 401 -- the retry with the
      // new token is not a token-freshness problem, it's a revoked account.
      if (auth === "Bearer old-access" || auth === "Bearer new-access") {
        return new Response(JSON.stringify({ detail: "invalid token" }), { status: 401 });
      }
      throw new Error(`unexpected request: ${path} (${auth})`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("admin1@zt.local", "ChangeMe123!");
    });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    let response: Response | undefined;
    await act(async () => {
      response = await result.current.authFetch("/monitoring/stats");
    });

    expect(response?.status).toBe(401);
    await waitFor(() => expect(result.current.isAuthenticated).toBe(false));
  });
});

describe("AuthContext and rate limiting", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("a 429 is returned as-is: never triggers /auth/refresh and never logs the user out", async () => {
    let refreshCalls = 0;

    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "old-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.endsWith("/auth/refresh")) {
        refreshCalls += 1;
        return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
      }
      // Rate limited, not an auth failure -- see middleware/rate_limit.py.
      return new Response(JSON.stringify({ detail: "rate limit exceeded" }), { status: 429 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("admin1@zt.local", "ChangeMe123!");
    });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    const refreshCallsBeforeAuthFetch = refreshCalls;
    let response: Response | undefined;
    await act(async () => {
      response = await result.current.authFetch("/monitoring/stats");
    });

    expect(response?.status).toBe(429);
    expect(refreshCalls).toBe(refreshCallsBeforeAuthFetch); // unchanged
    expect(result.current.isAuthenticated).toBe(true);
  });
});

describe("AuthContext login error messages", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("a 429 during login shows a rate-limit message, not a locked-account message", async () => {
    // 429 on /auth/login can now only ever mean the IP-level rate limit
    // (middleware/rate_limit.py) -- account lockout was folded into the
    // generic 401 below (see routers/auth.py), specifically so it's no
    // longer distinguishable from a plain wrong password. See SECURITY.md.
    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/refresh")) {
        return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
      }
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ detail: "rate limit exceeded" }), { status: 429 });
      }
      throw new Error(`unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("admin1@zt.local", "wrong-but-not-the-point");
    });

    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.error).toMatch(/too many login attempts/i);
    expect(result.current.error).not.toMatch(/locked/i);
    expect(result.current.error).not.toMatch(/check email and password/i);
  });

  it("an ordinary invalid-credentials 401 still shows the generic message", async () => {
    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/refresh")) {
        return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
      }
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ detail: "invalid credentials" }), { status: 401 });
      }
      throw new Error(`unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("admin1@zt.local", "wrong-password");
    });

    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.error).toMatch(/check email and password/i);
  });

  it("a locked account (now mapped to the same 401 as invalid credentials) shows the identical generic message", async () => {
    // The API response for a locked account is now byte-identical to a
    // plain wrong password (see api-gateway's test_account_locked_response_is_byte_identical_to_invalid_credentials) --
    // this proves that indistinguishability holds all the way to the UI,
    // not just at the wire response.
    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/refresh")) {
        return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
      }
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ detail: "invalid credentials" }), { status: 401 });
      }
      throw new Error(`unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("locked-admin@zt.local", "correct-password-but-account-is-locked");
    });

    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.error).toMatch(/check email and password/i);
    expect(result.current.error).not.toMatch(/locked/i);
  });
});

describe("AuthContext silent session restore on mount", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("a successful silent refresh (valid cookie) authenticates without ever calling login()", async () => {
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const path = String(url);
      if (path.endsWith("/auth/refresh")) {
        expect(headerValue(init, "X-Requested-With")).toBe("argus-dashboard");
        return new Response(JSON.stringify({ access_token: "restored-access", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      throw new Error(`unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

    expect(result.current.isInitializing).toBe(true);
    expect(result.current.isAuthenticated).toBe(false);

    await waitFor(() => expect(result.current.isInitializing).toBe(false));
    expect(result.current.isAuthenticated).toBe(true);
  });

  it("a failed silent refresh (no/expired cookie) resolves to the login screen state", async () => {
    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/refresh")) {
        return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
      }
      throw new Error(`unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

    expect(result.current.isInitializing).toBe(true);

    await waitFor(() => expect(result.current.isInitializing).toBe(false));
    expect(result.current.isAuthenticated).toBe(false);
  });
});

describe("AuthContext logout", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("clears client state immediately and calls /auth/logout with the CSRF header", async () => {
    let logoutCalls = 0;

    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const path = String(url);
      if (path.endsWith("/auth/refresh")) {
        return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
      }
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "access-1", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.endsWith("/auth/logout")) {
        logoutCalls += 1;
        expect(headerValue(init, "X-Requested-With")).toBe("argus-dashboard");
        return new Response(JSON.stringify({ detail: "logged out" }), { status: 200 });
      }
      throw new Error(`unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await settleMountEffect();

    await act(async () => {
      await result.current.login("admin1@zt.local", "ChangeMe123!");
    });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    await act(async () => {
      result.current.logout();
      await Promise.resolve();
    });

    expect(result.current.isAuthenticated).toBe(false);
    await waitFor(() => expect(logoutCalls).toBe(1));
  });
});
