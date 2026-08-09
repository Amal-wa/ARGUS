import { useEffect, useState } from "react";
import { getAudit, getAuditExportBlob } from "../api/monitoring";
import { useAuth } from "../context/AuthContext";
import type { AuditResponse, EventAuditResponse } from "../types";

interface AuditViewProps {
  onClose: () => void;
}

const PAGE_SIZE = 25;
// user_email is free text -- without this, every keystroke fired a full
// /monitoring/audit request (unlike decision/from/to, which only change on a
// discrete select/date-picker action). Typing a full address could burst
// 15-20 requests in a couple of seconds on top of the ~5 already-running
// dashboard pollers, risking RATE_LIMIT_USER_LIMIT.
const USER_EMAIL_DEBOUNCE_MS = 400;

// The two audit views /monitoring/audit can return -- see that endpoint's
// event_type-selects-the-view branching in routers/monitoring.py. "decisions"
// reads opa_decision_log (the risk/authz decision trail); "events" reads the
// events table (rate limits, pre-auth failures, step-up challenges -- the
// class of thing password-spraying shows up as, which decisions mode can
// never surface since it never reaches AuthorizationService at all).
type AuditMode = "decisions" | "events";

const EVENT_TYPES = [
  "rate_limit_ip_exceeded",
  "rate_limit_user_exceeded",
  "auth_failed",
  "token_revoked_used",
  "replay_detected",
  "mfa_locked",
  "mfa_failed",
  "opa_unavailable",
  "scoring_unavailable",
  "step_up_required",
  "challenge_expired",
  "totp_replay_detected",
];

function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleString([], { dateStyle: "short", timeStyle: "medium" });
}

export function AuditView({ onClose }: AuditViewProps) {
  const { authFetch } = useAuth();
  const [mode, setMode] = useState<AuditMode>("decisions");
  const [page, setPage] = useState(1);
  const [userEmailInput, setUserEmailInput] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [decision, setDecision] = useState("");
  const [eventType, setEventType] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [data, setData] = useState<AuditResponse | EventAuditResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setUserEmail(userEmailInput);
      setPage(1);
    }, USER_EMAIL_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [userEmailInput]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const query = {
      page,
      pageSize: PAGE_SIZE,
      userEmail: userEmail || undefined,
      from: from ? new Date(from).toISOString() : undefined,
      to: to ? new Date(to).toISOString() : undefined,
      ...(mode === "decisions"
        ? { decision: decision || undefined }
        : { eventType: eventType || undefined, eventsMode: true }),
    };
    const request =
      mode === "decisions" ? getAudit<AuditResponse>(authFetch, query) : getAudit<EventAuditResponse>(authFetch, query);
    request
      .then((response) => {
        if (cancelled) return;
        setData(response);
        setError(null);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "request failed");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [authFetch, mode, page, userEmail, decision, eventType, from, to]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  function applyFilter(setter: (value: string) => void) {
    return (value: string) => {
      setter(value);
      setPage(1);
    };
  }

  async function handleExport() {
    setExporting(true);
    try {
      // Same filters the on-screen table currently uses, minus page/pageSize
      // -- the backend ignores those for a CSV export anyway (see
      // MAX_EXPORT_ROWS in routers/monitoring.py).
      const blob = await getAuditExportBlob(authFetch, {
        userEmail: userEmail || undefined,
        from: from ? new Date(from).toISOString() : undefined,
        to: to ? new Date(to).toISOString() : undefined,
        ...(mode === "decisions"
          ? { decision: decision || undefined }
          : { eventType: eventType || undefined, eventsMode: true }),
      });
      // Bearer-token-authenticated endpoint -- a plain <a href="..."> would
      // 401 (no Authorization header on a bare browser navigation), so the
      // download has to go through a Blob + object URL instead.
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `audit-${mode}-export.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "export failed");
    } finally {
      setExporting(false);
    }
  }

  function switchMode(next: AuditMode) {
    if (next === mode) return;
    setMode(next);
    setPage(1);
    // Avoids a one-frame flash of the previous mode's rows rendered under
    // the new mode's column headers while the new fetch is still in flight
    // -- the in-flight-request race itself is already handled by this
    // effect's own `cancelled` guard, this is purely about what's on screen
    // in between.
    setData(null);
  }

  return (
    <div className="audit-overlay" onClick={onClose}>
      <div className="audit-panel" onClick={(e) => e.stopPropagation()}>
        <div className="audit-panel__header">
          <span className="card__title">Audit log</span>
          <span className="pagination">
            <button className="btn" onClick={handleExport} disabled={exporting}>
              {exporting ? "Exporting…" : "Export CSV"}
            </button>
            <button className="btn" onClick={onClose}>
              Back to dashboard
            </button>
          </span>
        </div>

        <div className="chip-row" style={{ marginBottom: 12 }}>
          <button className={`chip ${mode === "decisions" ? "chip--active" : ""}`} onClick={() => switchMode("decisions")}>
            Decisions
          </button>
          <button className={`chip ${mode === "events" ? "chip--active" : ""}`} onClick={() => switchMode("events")}>
            Events
          </button>
        </div>

        <div className="audit-panel__filters">
          <input
            className="text-input"
            placeholder="user_email"
            value={userEmailInput}
            onChange={(e) => setUserEmailInput(e.target.value)}
          />
          {mode === "decisions" ? (
            <select className="select" value={decision} onChange={(e) => applyFilter(setDecision)(e.target.value)}>
              <option value="">any decision</option>
              <option value="allow">allow</option>
              <option value="step_up">step_up</option>
              <option value="deny">deny</option>
            </select>
          ) : (
            <select className="select" value={eventType} onChange={(e) => applyFilter(setEventType)(e.target.value)}>
              <option value="">any event type</option>
              {EVENT_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          )}
          <input
            className="text-input"
            type="datetime-local"
            value={from}
            onChange={(e) => applyFilter(setFrom)(e.target.value)}
            title="from"
          />
          <input
            className="text-input"
            type="datetime-local"
            value={to}
            onChange={(e) => applyFilter(setTo)(e.target.value)}
            title="to"
          />
          {error ? <span className="card__degraded">degraded</span> : null}
        </div>

        <div className="audit-panel__body">
          {loading && !data ? (
            <div className="card__empty">loading…</div>
          ) : !data || data.rows.length === 0 ? (
            <div className="card__empty">no rows for this filter</div>
          ) : mode === "decisions" ? (
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>User</th>
                  <th>Resource</th>
                  <th>Action</th>
                  <th>Decision</th>
                  <th>Policy</th>
                  <th>Risk score</th>
                  <th>IP</th>
                  <th>Trace ID</th>
                </tr>
              </thead>
              <tbody>
                {(data as AuditResponse).rows.map((row) => (
                  <tr key={row.id}>
                    <td>{formatTimestamp(row.created_at)}</td>
                    <td>{row.user_email ?? row.user_id}</td>
                    <td>{row.resource}</td>
                    <td>{row.action}</td>
                    <td>
                      <span className={`badge badge--${row.decision}`}>{row.decision}</span>
                    </td>
                    <td>{row.policy_name}</td>
                    <td>{row.risk_score !== null ? row.risk_score.toFixed(2) : "—"}</td>
                    <td>{row.ip_address}</td>
                    <td>{row.trace_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>User</th>
                  <th>IP</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Status</th>
                  <th>Latency</th>
                  <th>Event type</th>
                  <th>Error</th>
                  <th>Trace ID</th>
                </tr>
              </thead>
              <tbody>
                {(data as EventAuditResponse).rows.map((row) => (
                  <tr key={row.id}>
                    <td>{formatTimestamp(row.created_at)}</td>
                    <td>{row.user_id ?? "—"}</td>
                    <td>{row.ip_address}</td>
                    <td>{row.http_method}</td>
                    <td>{row.request_path}</td>
                    <td>{row.http_status}</td>
                    <td>{row.latency_ms}ms</td>
                    <td>{row.event_type}</td>
                    <td>{row.error_code ?? row.error_message ?? "—"}</td>
                    <td>{row.trace_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="audit-panel__footer">
          <span className="pagination">
            page {page} / {totalPages} · {data?.total ?? 0} rows
          </span>
          <span className="pagination">
            <button className="btn" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
              Prev
            </button>
            <button className="btn" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
              Next
            </button>
          </span>
        </div>
      </div>
    </div>
  );
}
