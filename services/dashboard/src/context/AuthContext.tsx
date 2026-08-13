import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { login as apiLogin, logout as apiLogout, refresh as apiRefresh } from "../api/auth";
import { ApiError, BASE_URL } from "../api/client";
import { isEnrollmentRequired } from "../types";
import type { LoginResponse } from "../types";

interface AuthContextValue {
  isAuthenticated: boolean;
  /** True until the one silent /auth/refresh attempt on mount has resolved
   * (success or failure). Gates the initial render decision in App.tsx so a
   * reload never flashes the login screen before a valid refresh cookie has
   * had a chance to restore the session. */
  isInitializing: boolean;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  /** Adds the current bearer token, retries once through /auth/refresh on a
   * 401, and falls back to logout() (back to the login screen) if refresh
   * also fails. This is the ONLY way components should call the Gateway. */
  authFetch: (path: string, init?: RequestInit) => Promise<Response>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // authFetch must stay a stable callback identity (poll hooks depend on it),
  // but always needs the LATEST access token -- a ref sidesteps that tension
  // without recreating authFetch (and re-triggering every polling effect)
  // whenever the access token rotates.
  const accessTokenRef = useRef(accessToken);
  accessTokenRef.current = accessToken;

  const logout = useCallback(() => {
    setAccessToken(null);
    // Best-effort: revoke server-side and clear the cookie, but client state
    // is already cleared above regardless of whether the network call
    // succeeds -- the refresh token's own rotation/expiry is the backstop if
    // this request is lost (e.g. offline).
    void apiLogout().catch(() => {});
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const body: LoginResponse = await apiLogin(email, password);
      if (isEnrollmentRequired(body)) {
        setError(
          "This account is not enrolled in MFA yet, so it can't be used for the dashboard. " +
            "Admins are enrolled by scripts/seed_users.py / scripts/seed_business_data.py -- " +
            "re-run the seed, or enroll this account out of band, then log in again."
        );
        return;
      }
      accessTokenRef.current = body.access_token;
      setAccessToken(body.access_token);
    } catch (err) {
      // 429 on /auth/login is now ALWAYS the IP-level rate limit
      // (middleware/rate_limit.py) -- account lockout used to also surface
      // as a distinct 429 here (routers/auth.py's ACCOUNT_LOCKED branch),
      // but that made a real, locked account's response distinguishable
      // from a merely-wrong-password one, which is an account-existence
      // oracle (only a real account can ever lock). It's now folded into
      // the same generic 401 as any other invalid-credentials response --
      // see SECURITY.md. A locked-out admin sees the generic message below,
      // same as a mistyped password; this is a deliberate trade-off, not an
      // oversight.
      if (err instanceof ApiError && err.status === 429) {
        setError("Too many login attempts from this network -- wait a moment and try again.");
      } else {
        setError("Login failed -- check email and password.");
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Single-flight refresh: the dashboard runs ~5 concurrent pollers, and a
  // shared access token means they can all hit 401 in the same tick. Each
  // one calling /auth/refresh independently would present the (single-use,
  // rotating) refresh cookie multiple times -- the first call consumes and
  // rotates it correctly, every other call presents an already-used token,
  // which the backend correctly treats as reuse/theft and revokes the WHOLE
  // token family (see AuthService.refresh), hard-logging the user out. This
  // ref holds the one in-flight refresh call so every concurrent 401 waits
  // on and shares it instead of starting its own.
  //
  // Correctness depends on refreshAccessToken() being a PLAIN (non-async)
  // function: assigning refreshPromiseRef.current happens synchronously,
  // before the underlying apiRefresh() call has a chance to resolve, so a
  // second concurrent caller can never observe the ref as still null.
  const refreshPromiseRef = useRef<Promise<string> | null>(null);

  const refreshAccessToken = useCallback((): Promise<string> => {
    if (refreshPromiseRef.current) {
      return refreshPromiseRef.current;
    }
    const promise = apiRefresh()
      .then((pair) => {
        accessTokenRef.current = pair.access_token;
        setAccessToken(pair.access_token);
        return pair.access_token;
      })
      .finally(() => {
        refreshPromiseRef.current = null;
      });
    refreshPromiseRef.current = promise;
    return promise;
  }, []);

  // Silent session restore on mount: the browser already re-sent the
  // httpOnly refresh cookie on this page load (if one exists and is still
  // valid), so one /auth/refresh attempt can restore the session across a
  // reload without ever showing the login screen. isInitializing gates
  // Root's render decision in App.tsx until this resolves either way.
  useEffect(() => {
    let cancelled = false;
    refreshAccessToken()
      .catch(() => {
        // No valid session to restore -- Root falls through to LoginScreen.
      })
      .finally(() => {
        if (!cancelled) setIsInitializing(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const authFetch = useCallback(
    async (path: string, init: RequestInit = {}): Promise<Response> => {
      const withAuth = (token: string | null): RequestInit => ({
        ...init,
        headers: { ...(init.headers ?? {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      });

      const response = await fetch(`${BASE_URL}${path}`, withAuth(accessTokenRef.current));

      if (response.status === 401) {
        // The Gateway's 401 body says WHY -- read it instead of assuming
        // every 401 means "access token expired". clone() so the body is
        // still readable by whatever this function returns to its caller.
        let detail: string | undefined;
        try {
          const body: unknown = await response.clone().json();
          detail = typeof (body as { detail?: unknown })?.detail === "string" ? (body as { detail: string }).detail : undefined;
        } catch {
          detail = undefined;
        }

        // /monitoring/* is exempt from ML-score-driven step-up (see
        // AuthorizationService.authorize's MONITORING_PATH_PREFIX branch),
        // but NOT from monitoring_audit_access (adaptive_access.rego) --
        // /monitoring/audit specifically forces step-up unconditionally,
        // independent of score. So step_up_required IS reachable from this
        // client today, on that one route. What matters here is narrower
        // than it might look: refreshing the access token does nothing for
        // a step-up challenge (so still skip straight past the
        // refresh-and-retry logic below -- refreshing would just burn the
        // single-use refresh token for no benefit), but this is a
        // per-REQUEST need, not a session failure -- the access token stays
        // completely valid for every other route. Logging out here was the
        // actual bug (found live: clicking "Audit" hard-killed the whole
        // dashboard session over a 401 scoped to one panel). The caller
        // (api/monitoring.ts's getJson, used by AuditView) is what turns
        // this into a typed StepUpRequiredError with the challenge_id, so
        // AuditView can resolve it and retry -- this layer just has to NOT
        // treat it as ordinary token expiry.
        if (detail === "step_up_required") {
          return response;
        }
        // POST /mfa/challenge/verify (api/mfa.ts's verifyMfaChallenge, called
        // from AuditView's step-up prompt) also goes through authFetch and
        // can itself 401 for reasons that have nothing to do with the access
        // token: a wrong code, an expired challenge, a replayed code. Same
        // reasoning as step_up_required -- refreshing the access token fixes
        // none of these, so they must not fall into the generic
        // refresh-and-retry branch below either. Found live via this
        // component's own test suite: a wrong code's 401 was being treated
        // as ordinary token expiry, the refresh attempt failed (no real
        // expired-token scenario to recover from), and authFetch logged the
        // whole session out over what should have been an inline "wrong
        // code, try again" in AuditView.
        if (detail === "invalid_code" || detail === "challenge_expired" || detail === "totp_replayed") {
          return response;
        }
        if (detail === "mfa_enrollment_required") {
          setError("This account requires MFA enrollment and cannot be used in the dashboard. Enroll it, then log in again.");
          logout();
          return response;
        }

        // Anything else (no detail, "invalid token", "token revoked", ...)
        // is treated as ordinary access-token expiry/rejection: refresh once,
        // retry once. The retry below is a single, un-recursed fetch -- if
        // it 401s again, that response is returned as-is rather than looping
        // back into this branch, so a request can never trigger more than
        // one refresh cycle.
        try {
          const nextAccessToken = await refreshAccessToken();
          const retried = await fetch(`${BASE_URL}${path}`, withAuth(nextAccessToken));
          // The refresh itself succeeded, but the retried request STILL 401'd
          // (e.g. a concurrent server-side revocation between the refresh
          // and this retry) -- without this, accessToken would stay set,
          // isAuthenticated would stay true, and the client would look
          // "logged in" while every request silently 401s forever instead of
          // returning to the login screen.
          if (retried.status === 401) {
            logout();
          }
          return retried;
        } catch {
          logout();
          return response;
        }
      }

      return response;
    },
    [logout, refreshAccessToken]
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      isAuthenticated: accessToken !== null,
      isInitializing,
      isLoading,
      error,
      login,
      logout,
      authFetch,
    }),
    [accessToken, isInitializing, isLoading, error, login, logout, authFetch]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
