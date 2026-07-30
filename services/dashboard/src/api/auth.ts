import { apiFetch, apiFetchJson } from "./client";
import type { LoginResponse } from "../types";

// Sent on every /auth/refresh and /auth/logout call. The refresh token lives
// in an httpOnly cookie the browser attaches automatically -- including to a
// request forged by a third-party page -- so this custom header is the CSRF
// defence for those two endpoints (see services/api-gateway/app/routers/auth.py
// for why a header, rather than a token, is sufficient here). Keep the value
// in sync with CSRF_HEADER_VALUE there.
const CSRF_HEADERS = { "X-Requested-With": "argus-dashboard" };

export function login(email: string, password: string): Promise<LoginResponse> {
  return apiFetchJson<LoginResponse>("/auth/login", {
    method: "POST",
    // Required so the browser stores the Set-Cookie response sends back
    // (the refresh token) -- without this, fetch ignores Set-Cookie/Cookie
    // entirely for the request.
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
}

export interface RefreshSuccess {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// No refresh token argument -- it's read server-side from the cookie the
// browser sends automatically with credentials: 'include'.
export function refresh(): Promise<RefreshSuccess> {
  return apiFetchJson<RefreshSuccess>("/auth/refresh", {
    method: "POST",
    credentials: "include",
    headers: CSRF_HEADERS,
  });
}

export async function logout(): Promise<void> {
  await apiFetch("/auth/logout", {
    method: "POST",
    credentials: "include",
    headers: CSRF_HEADERS,
  });
}
