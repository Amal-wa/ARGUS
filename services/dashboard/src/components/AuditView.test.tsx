import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider, useAuth } from "../context/AuthContext";
import { AuditView } from "./AuditView";

type LoginFn = (email: string, password: string) => Promise<void>;

// Same convention as AuthContext.test.tsx: drive login explicitly through
// act() rather than relying on it happening as a side effect of rendering
// (unreliable -- React gives no ordering guarantee that a promise kicked off
// during render is flushed by the same act() the mount effect is). This
// harness just hands the test a stable reference to the real login()/
// isAuthenticated from useAuth(), then renders the real AuditView once
// authenticated -- so the test still exercises the genuine AuthProvider +
// AuditView integration, not a mocked context.
function Harness({ onClose, loginRef }: { onClose: () => void; loginRef: { current: LoginFn | null } }) {
  const { login, isAuthenticated } = useAuth();
  loginRef.current = login;
  if (!isAuthenticated) return null;
  return <AuditView onClose={onClose} />;
}

async function settleMountEffect() {
  await act(async () => {});
}

async function renderAuthenticated(onClose: () => void = () => {}) {
  const loginRef: { current: LoginFn | null } = { current: null };
  render(
    <AuthProvider>
      <Harness onClose={onClose} loginRef={loginRef} />
    </AuthProvider>
  );
  await settleMountEffect();
  await act(async () => {
    await loginRef.current!("admin1@zt.local", "ChangeMe123!");
  });
}

const AUDIT_ROWS = {
  rows: [
    {
      id: 1,
      trace_id: "t1",
      created_at: "2026-08-12T09:00:00Z",
      user_id: "u1",
      user_email: "admin1@zt.local",
      role: "admin",
      resource: "/documents",
      action: "read",
      ip_address: "127.0.0.1",
      risk_score: 0.1,
      model_version: "v4",
      is_anomaly: "none",
      decision: "allow",
      policy_name: "risk_allow",
      reason: null,
      latency_ms: 5,
    },
  ],
  page: 1,
  page_size: 25,
  total: 1,
};

describe("AuditView step-up handling", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    // globals: false in vite.config.ts means @testing-library/react can't
    // auto-detect a global afterEach to register its own cleanup -- without
    // this, each test's render() leaves its DOM mounted for the next test,
    // and duplicate "123456" placeholders across tests cause
    // getByPlaceholderText to fail non-deterministically. Confirmed live.
    cleanup();
  });

  it("shows a code prompt (not a generic error, not a logout) when /monitoring/audit returns step_up_required", async () => {
    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "tok", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.includes("/monitoring/audit")) {
        return new Response(JSON.stringify({ detail: "step_up_required", challenge_id: "chal-1" }), { status: 401 });
      }
      return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await renderAuthenticated();

    // getByPlaceholderText throws until the element exists -- waitFor's
    // retry-until-success-or-timeout is the assertion itself, no jest-dom
    // matcher needed (not a dependency of this project).
    await waitFor(() => screen.getByPlaceholderText("123456"));
    expect(screen.queryByText(/degraded/i)).toBeNull();
  });

  it("a correct code resolves the challenge and re-fetches the audit table", async () => {
    let auditCalls = 0;
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "tok", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.endsWith("/mfa/challenge/verify")) {
        const body = JSON.parse(String(init?.body));
        expect(body).toEqual({ challenge_id: "chal-1", code: "654321" });
        return new Response(JSON.stringify({ decision: "allow" }), { status: 200 });
      }
      if (path.includes("/monitoring/audit")) {
        auditCalls += 1;
        if (auditCalls === 1) {
          return new Response(JSON.stringify({ detail: "step_up_required", challenge_id: "chal-1" }), { status: 401 });
        }
        return new Response(JSON.stringify(AUDIT_ROWS), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await renderAuthenticated();
    await waitFor(() => screen.getByPlaceholderText("123456"));

    fireEvent.change(screen.getByPlaceholderText("123456"), { target: { value: "654321" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    });

    await waitFor(() => screen.getByText("admin1@zt.local"));
    expect(auditCalls).toBe(2); // initial 401 + the retry after a successful verify
  });

  it("disables pagination while the step-up prompt is open, so paging doesn't spam new challenges", async () => {
    // Regression test: page/filter controls used to stay live while the
    // step-up prompt was shown, so each Prev/Next click re-ran the fetch
    // effect and hit monitoring_audit_access again -- every click minted a
    // fresh, discarded challenge (and a fresh opa_decision_log "step_up"
    // row) instead of doing nothing until the user actually verifies.
    let auditCalls = 0;
    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "tok", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.includes("/monitoring/audit")) {
        auditCalls += 1;
        if (path.includes("page=2")) {
          return new Response(JSON.stringify({ detail: "step_up_required", challenge_id: "chal-2" }), { status: 401 });
        }
        // total=60 / page_size=25 => totalPages=3, so "Next" is naturally
        // clickable on page 1 -- the point being tested is that it stops
        // being clickable once the step-up prompt takes over, not that it
        // was already disabled for an unrelated reason (end of results).
        return new Response(JSON.stringify({ ...AUDIT_ROWS, total: 60 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await renderAuthenticated();
    await waitFor(() => screen.getByText("admin1@zt.local"));
    const callsAfterFirstLoad = auditCalls;

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Next" }));
    });
    await waitFor(() => screen.getByPlaceholderText("123456"));
    expect(auditCalls).toBe(callsAfterFirstLoad + 1); // the page=2 attempt that surfaced the challenge

    const nextButton = screen.getByRole("button", { name: "Next" }) as HTMLButtonElement;
    expect(nextButton.disabled).toBe(true);

    fireEvent.click(nextButton);
    await act(async () => {});
    expect(auditCalls).toBe(callsAfterFirstLoad + 1); // unchanged -- the click was a no-op
  });

  it("aborts an in-flight audit fetch when the query changes underneath it, instead of letting a stale request finish", async () => {
    // Regression test for a second, related bug: React StrictMode
    // double-invokes mount effects in dev (mount -> cleanup -> mount), and
    // /monitoring/audit has a real server-side side effect on every attempt
    // (monitoring_audit_access mints a fresh MFA challenge and logs a
    // decision unconditionally) -- so the discarded first invocation was
    // still minting and logging its own step-up challenge before the fetch
    // effect started passing an AbortSignal (caught live: opening Audit for
    // the first time logged two step_up rows, not one). This test can't
    // drive React's internal double-invoke directly, but a query change
    // (e.g. switching mode) exercises the exact same effect-cleanup path --
    // what matters is that the stale request's signal actually gets
    // aborted, not just that its result is ignored client-side.
    const capturedSignals: (AbortSignal | undefined)[] = [];
    const fetchMock = vi.fn((url: string | URL, init?: RequestInit) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return Promise.resolve(
          new Response(JSON.stringify({ access_token: "tok", token_type: "bearer", expires_in: 900 }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        );
      }
      if (path.includes("/monitoring/audit")) {
        capturedSignals.push(init?.signal ?? undefined);
        // Never resolves within this test -- only whether its signal gets
        // aborted once the query changes underneath it is being checked.
        return new Promise<Response>(() => {});
      }
      return Promise.resolve(new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 }));
    });
    vi.stubGlobal("fetch", fetchMock);

    await renderAuthenticated();
    await waitFor(() => expect(capturedSignals.length).toBe(1));
    expect(capturedSignals[0]?.aborted).toBe(false);

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Events" }));
    });

    expect(capturedSignals.length).toBe(2); // the mode switch fired a fresh request
    expect(capturedSignals[0]?.aborted).toBe(true); // ...and aborted the stale one, not just ignored it
  });

  it("a wrong code shows a specific inline error and keeps the prompt open", async () => {
    const fetchMock = vi.fn(async (url: string | URL) => {
      const path = String(url);
      if (path.endsWith("/auth/login")) {
        return new Response(JSON.stringify({ access_token: "tok", token_type: "bearer", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.endsWith("/mfa/challenge/verify")) {
        return new Response(JSON.stringify({ detail: "invalid_code" }), { status: 401 });
      }
      if (path.includes("/monitoring/audit")) {
        return new Response(JSON.stringify({ detail: "step_up_required", challenge_id: "chal-1" }), { status: 401 });
      }
      return new Response(JSON.stringify({ detail: "invalid refresh token" }), { status: 401 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await renderAuthenticated();
    await waitFor(() => screen.getByPlaceholderText("123456"));

    fireEvent.change(screen.getByPlaceholderText("123456"), { target: { value: "000000" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    });

    await waitFor(() => screen.getByText(/incorrect code/i));
    // Prompt is still there -- the user can correct and retry without
    // starting over (the challenge is still valid for its own TTL). Throws
    // if absent, which is the assertion.
    screen.getByPlaceholderText("123456");
  });
});
