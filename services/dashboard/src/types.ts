// Mirrors services/api-gateway/app/routers/monitoring.py and routers/auth.py
// response shapes exactly -- keep these two in sync by hand (no shared schema
// package across the Python/TS boundary).

export type Decision = "allow" | "deny" | "step_up";

export interface LoginSuccess {
  access_token: string;
  token_type: string;
  expires_in: number;
  // No refresh_token field -- it travels only as an httpOnly cookie (see
  // services/api-gateway/app/routers/auth.py), never in a JSON body JS can
  // read.
}

export interface LoginEnrollmentRequired {
  enrollment_token: string;
  token_type: string;
  mfa_enrollment_required: true;
}

export type LoginResponse = LoginSuccess | LoginEnrollmentRequired;

export function isEnrollmentRequired(body: LoginResponse): body is LoginEnrollmentRequired {
  return "mfa_enrollment_required" in body && body.mfa_enrollment_required === true;
}

export interface StatsResponse {
  total_decisions: number;
  allow: number;
  deny: number;
  step_up: number;
  allow_rate: number;
  active_users: number;
  distinct_ips: number;
  window_minutes: number;
}

export interface DecisionRow {
  trace_id: string;
  created_at: string;
  user_id: string;
  user_email: string | null;
  resource: string;
  action: string;
  decision: Decision;
  policy_name: string;
  risk_score: number | null;
  model_version: string | null;
  ip_address: string;
}

export interface DecisionsResponse {
  decisions: DecisionRow[];
}

export interface RiskTimelinePoint {
  created_at: string;
  user_email: string | null;
  risk_score: number | null;
}

export interface RiskTimelineResponse {
  threshold: number | null;
  points: RiskTimelinePoint[];
}

export type AlertType = "step_up" | "anomaly";

export interface AlertRow {
  type: AlertType;
  created_at: string;
  user_email: string | null;
  resource: string | null;
  risk_score: number | null;
  trace_id: string | null;
}

export interface AlertsResponse {
  alerts: AlertRow[];
}

export type AnomalySeverity = "low" | "medium" | "high" | "critical";

export interface AnomalyRow {
  created_at: string;
  user_email: string | null;
  resource: string | null;
  // Not a strict union -- the DB enum (anomaly_type) has a "behavioral"
  // member alongside behavioral-detector's 4 actual rule-based checks
  // (resource_access/authentication/network/authorization, see CLAUDE.md's
  // Behavioral detector section), but nothing currently writes it. Typing
  // this as a union that doesn't cover it would be a silent lie the moment
  // it's used.
  anomaly_type: string;
  severity: AnomalySeverity;
  risk_score: number;
  trace_id: string | null;
}

export interface AnomaliesResponse {
  anomalies: AnomalyRow[];
}

// "no_review_required" exists in the DB enum but nothing currently assigns
// it (canary-validator's repository.py always inserts "pending" -- see
// CLAUDE.md's dead-code history for this column) -- included for
// completeness/forward-compat, not because the panel expects to see it yet.
export type CanaryReviewStatus = "pending" | "no_review_required" | "confirmed" | "rejected";

export interface CanaryComparisonRow {
  id: number;
  trace_id: string;
  created_at: string;
  production_model_version: string;
  candidate_model_version: string;
  production_risk_score: number;
  candidate_risk_score: number;
  review_status: CanaryReviewStatus;
  reviewed_by: string | null;
  reviewed_at: string | null;
}

export interface CanaryComparisonsResponse {
  comparisons: CanaryComparisonRow[];
}

export type ServiceHealthValue = "healthy" | "unhealthy" | "up" | "down";

export interface SystemStatusResponse {
  active_model: string | null;
  active_threshold: number | null;
  candidate_model: string | null;
  training_samples: number | null;
  model_trained_at: string | null;
  score_distribution: Record<string, number> | null;
  services: {
    isolation_forest: ServiceHealthValue;
    opa: ServiceHealthValue;
    redis: ServiceHealthValue;
    postgres: ServiceHealthValue;
  };
}

export interface AuditRow {
  id: number;
  trace_id: string;
  created_at: string;
  user_id: string;
  user_email: string | null;
  role: string;
  resource: string;
  action: string;
  ip_address: string;
  risk_score: number | null;
  model_version: string | null;
  is_anomaly: string;
  decision: Decision;
  policy_name: string;
  reason: string | null;
  latency_ms: number;
}

export interface AuditResponse {
  rows: AuditRow[];
  page: number;
  page_size: number;
  total: number;
}

// Mirrors _serialize_event_audit_row in routers/monitoring.py -- the
// `events` table (gateway-level events: rate limits, auth failures, step-up
// challenges), a DIFFERENT audit view from AuditRow above (which is
// opa_decision_log). Selected via /monitoring/audit's `event_type` query
// param -- see AuditQuery.eventType in api/monitoring.ts.
export interface EventAuditRow {
  id: number;
  trace_id: string;
  created_at: string;
  // Unlike AuditRow, there is no users_table join on this query -- pre-auth
  // failures (e.g. auth_failed) have no verified identity yet, so this is
  // the raw user_id (or null), never an email.
  user_id: string | null;
  ip_address: string;
  http_method: string;
  request_path: string;
  latency_ms: number;
  http_status: number;
  error_code: string | null;
  error_message: string | null;
  event_type: string;
}

export interface EventAuditResponse {
  rows: EventAuditRow[];
  page: number;
  page_size: number;
  total: number;
}
