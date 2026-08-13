import { ApiError, StepUpRequiredError } from "./client";
import type {
  AlertsResponse,
  AuditResponse,
  DecisionsResponse,
  EventAuditResponse,
  RiskTimelineResponse,
  StatsResponse,
  SystemStatusResponse,
} from "../types";

export type AuthFetch = (path: string, init?: RequestInit) => Promise<Response>;

async function getJson<T>(authFetch: AuthFetch, path: string, signal?: AbortSignal): Promise<T> {
  const response = await authFetch(path, signal ? { signal } : undefined);
  if (!response.ok) {
    // A 401 whose body is specifically step_up_required (today, only
    // possible on /monitoring/audit -- see adaptive_access.rego's
    // monitoring_audit_access) carries a challenge_id a caller needs to
    // resolve it. authFetch itself deliberately does NOT special-case this
    // beyond not treating it as ordinary token expiry (see AuthContext.tsx)
    // -- it's returned as a plain Response, so this is where it gets turned
    // into a typed error a caller can actually act on. clone() so a caller
    // that doesn't care can still read the body itself if it wants to.
    if (response.status === 401) {
      try {
        const body: unknown = await response.clone().json();
        const detail = (body as { detail?: unknown })?.detail;
        const challengeId = (body as { challenge_id?: unknown })?.challenge_id;
        if (detail === "step_up_required" && typeof challengeId === "string") {
          throw new StepUpRequiredError(challengeId);
        }
      } catch (err) {
        if (err instanceof StepUpRequiredError) throw err;
        // Body wasn't JSON / didn't have the expected shape -- fall through
        // to the generic ApiError below.
      }
    }
    // ApiError (not a plain Error) so callers -- specifically the polling
    // hooks' 429 backoff -- can tell "rate limited" apart from every other
    // failure mode without string-matching a message.
    throw new ApiError(response.status, `${path} failed (${response.status})`);
  }
  return (await response.json()) as T;
}

export function getStats(authFetch: AuthFetch, windowMinutes = 60): Promise<StatsResponse> {
  return getJson(authFetch, `/monitoring/stats?window_minutes=${windowMinutes}`);
}

export interface DecisionsQuery {
  limit?: number;
  since?: string;
  userEmail?: string;
}

export function getDecisions(authFetch: AuthFetch, query: DecisionsQuery = {}): Promise<DecisionsResponse> {
  const params = new URLSearchParams();
  if (query.limit) params.set("limit", String(query.limit));
  if (query.since) params.set("since", query.since);
  if (query.userEmail) params.set("user_email", query.userEmail);
  const qs = params.toString();
  return getJson(authFetch, `/monitoring/decisions${qs ? `?${qs}` : ""}`);
}

export interface RiskTimelineQuery {
  userEmail?: string;
  windowMinutes?: number;
}

export function getRiskTimeline(authFetch: AuthFetch, query: RiskTimelineQuery = {}): Promise<RiskTimelineResponse> {
  const params = new URLSearchParams();
  if (query.userEmail) params.set("user_email", query.userEmail);
  params.set("window_minutes", String(query.windowMinutes ?? 30));
  return getJson(authFetch, `/monitoring/risk-timeline?${params.toString()}`);
}

export function getAlerts(authFetch: AuthFetch, limit = 50, windowMinutes = 60): Promise<AlertsResponse> {
  return getJson(authFetch, `/monitoring/alerts?limit=${limit}&window_minutes=${windowMinutes}`);
}

export function getSystemStatus(authFetch: AuthFetch): Promise<SystemStatusResponse> {
  return getJson(authFetch, "/monitoring/system-status");
}

export interface AuditQuery {
  page?: number;
  pageSize?: number;
  userEmail?: string;
  decision?: string;
  from?: string;
  to?: string;
  eventType?: string;
  // /monitoring/audit picks decisions vs. events by whether `event_type` is
  // PRESENT at all (even ""), not by whether it's a non-empty filter value --
  // so "events mode, no specific type" (eventType: "") is a real, distinct
  // state from "decisions mode" (no event_type param at all). Without this
  // flag, buildAuditParams' truthy check on eventType would silently omit
  // the param for an empty selection and the request would fall through to
  // decisions mode -- exactly the bug this flag exists to prevent.
  eventsMode?: boolean;
}

// Single source of truth for building /monitoring/audit's query string --
// shared between getAudit (paginated JSON) and getAuditExportBlob (CSV
// export) so the two can never drift on how a filter is encoded.
function buildAuditParams(query: AuditQuery): URLSearchParams {
  const params = new URLSearchParams();
  params.set("page", String(query.page ?? 1));
  params.set("page_size", String(query.pageSize ?? 50));
  if (query.userEmail) params.set("user_email", query.userEmail);
  if (query.decision) params.set("decision", query.decision);
  if (query.from) params.set("from", query.from);
  if (query.to) params.set("to", query.to);
  if (query.eventsMode) {
    params.set("event_type", query.eventType ?? "");
  } else if (query.eventType) {
    params.set("event_type", query.eventType);
  }
  return params;
}

// Generic over the two audit-view shapes /monitoring/audit can return
// (opa_decision_log rows by default, events rows when query.eventType is
// set -- see that endpoint's own event_type-selects-the-view branching).
// Defaults to AuditResponse so every existing (decisions-mode) call site is
// unaffected.
// signal is plumbed through (unlike the other getX helpers above) because
// getAudit is the one call in this module invoked from a mount effect
// (AuditView) against an endpoint with a real server-side side effect on
// every attempt -- monitoring_audit_access mints a fresh MFA challenge and
// logs a decision unconditionally. React StrictMode's dev-only double-invoke
// of effects would otherwise fire this twice on mount, and cancelling the
// stale invocation client-side (the `cancelled` flag AuditView already uses
// for state updates) doesn't stop its request from reaching the backend and
// being logged -- only an actual abort does. The other getX helpers here are
// plain reads with no such side effect, so a duplicate dev-mode tick is
// inconsequential for them and doesn't need this.
export function getAudit<T extends AuditResponse | EventAuditResponse = AuditResponse>(
  authFetch: AuthFetch,
  query: AuditQuery = {},
  signal?: AbortSignal
): Promise<T> {
  return getJson(authFetch, `/monitoring/audit?${buildAuditParams(query).toString()}`, signal);
}

// CSV export -- reuses buildAuditParams so filters can never drift from
// getAudit's. Not getJson: the response isn't JSON, and this is a
// Bearer-token-authenticated endpoint, so it must go through authFetch (a
// plain <a href="/monitoring/audit?format=csv"> would 401 -- no
// Authorization header on a bare browser navigation).
export async function getAuditExportBlob(authFetch: AuthFetch, query: AuditQuery = {}): Promise<Blob> {
  const params = buildAuditParams(query);
  params.set("format", "csv");
  const path = `/monitoring/audit?${params.toString()}`;
  const response = await authFetch(path);
  if (!response.ok) {
    throw new ApiError(response.status, `${path} failed (${response.status})`);
  }
  return response.blob();
}
