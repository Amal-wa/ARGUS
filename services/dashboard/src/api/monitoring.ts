import { ApiError } from "./client";
import type {
  AlertsResponse,
  AuditResponse,
  DecisionsResponse,
  RiskTimelineResponse,
  StatsResponse,
  SystemStatusResponse,
} from "../types";

export type AuthFetch = (path: string, init?: RequestInit) => Promise<Response>;

async function getJson<T>(authFetch: AuthFetch, path: string): Promise<T> {
  const response = await authFetch(path);
  if (!response.ok) {
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
}

export function getAudit(authFetch: AuthFetch, query: AuditQuery = {}): Promise<AuditResponse> {
  const params = new URLSearchParams();
  params.set("page", String(query.page ?? 1));
  params.set("page_size", String(query.pageSize ?? 50));
  if (query.userEmail) params.set("user_email", query.userEmail);
  if (query.decision) params.set("decision", query.decision);
  if (query.from) params.set("from", query.from);
  if (query.to) params.set("to", query.to);
  if (query.eventType) params.set("event_type", query.eventType);
  return getJson(authFetch, `/monitoring/audit?${params.toString()}`);
}
