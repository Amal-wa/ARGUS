import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { StepUpRequiredError } from "../api/client";
import { MfaVerificationError, verifyMfaChallenge } from "../api/mfa";
import { getAudit, getAuditExportBlob } from "../api/monitoring";
import { useAuth } from "../context/AuthContext";
import type { AuditResponse, EventAuditResponse } from "../types";

// Maps POST /mfa/challenge/verify's `detail` values (see
// app/services/mfa_challenge.py's MfaVerificationStatus) to a short,
// specific message -- so a wrong code reads differently from an expired
// challenge, rather than one generic "verification failed".
const MFA_ERROR_MESSAGES: Record<string, string> = {
  invalid_code: "Incorrect code -- try again.",
  challenge_expired: "This challenge expired (2 min TTL) -- close and reopen Audit to get a new one.",
  mfa_locked: "Too many failed attempts -- MFA is temporarily locked for this account.",
  totp_replayed: "That code was already used -- wait for the next one.",
  mfa_not_configured: "This account has no MFA enrolled.",
};

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

  // monitoring_audit_access (adaptive_access.rego) forces step-up
  // unconditionally on /monitoring/audit -- getAudit throws StepUpRequiredError
  // (via getJson) instead of a generic ApiError when that happens. challengeId
  // set means "show the code prompt instead of the table"; retryTick is bumped
  // after a successful verify to re-run the fetch effect below without
  // duplicating its query-building logic.
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaSubmitting, setMfaSubmitting] = useState(false);
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [retryTick, setRetryTick] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      setUserEmail(userEmailInput);
      setPage(1);
    }, USER_EMAIL_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [userEmailInput]);

  useEffect(() => {
    // A pending challenge means the last attempt already came back
    // step_up_required -- page/filter/mode controls are disabled below while
    // challengeId is set, so this dep normally can't change out from under
    // us, but this guard is the actual thing that stops a re-fetch: without
    // it, any future control that's added without remembering to disable it
    // would silently spam a fresh step-up challenge (and a fresh
    // opa_decision_log row) on every interaction instead of just once. The
    // only way out of this branch is a successful verify, which clears
    // challengeId and bumps retryTick together.
    if (challengeId) return;
    let cancelled = false;
    const controller = new AbortController();
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

    // React StrictMode double-invokes mount effects in dev (mount → cleanup
    // → mount, synchronously, before any microtask runs). An AbortController
    // alone doesn't fix this for THIS endpoint: `getAudit`'s underlying
    // fetch is dispatched the moment this effect body runs, and the Gateway
    // pipeline has no disconnect-awareness (nothing in GatewayMiddleware
    // checks `request.is_disconnected()` between steps) -- once dispatched,
    // aborting client-side doesn't stop the server from completing the
    // authorize call and persisting a decision. And /monitoring/audit's
    // decision is never a no-op: monitoring_audit_access mints a fresh MFA
    // challenge and logs a step_up unconditionally on every unresolved
    // attempt. Confirmed live: with only `cancelled` + `controller.abort()`
    // (no defer), opening Audit for the first time still logged two step_up
    // rows, not one -- the abort always lost the race against dispatch.
    //
    // Deferring the actual dispatch by one microtask fixes this at the
    // right layer: StrictMode's cleanup-then-remount happens synchronously,
    // so the first invocation's cleanup always sets its OWN `cancelled` to
    // true before ITS deferred dispatch below ever runs -- the dispatch is
    // skipped entirely rather than fired and then (ineffectively) aborted.
    // The second, surviving invocation's microtask runs normally and is the
    // only one that ever calls the network. A genuine deps change (paging,
    // filtering) isn't double-invoked by StrictMode in the first place, so
    // this one-microtask delay is invisible there -- it only collapses the
    // dev-only synchronous double-mount down to a single real request.
    Promise.resolve().then(() => {
      if (cancelled) return;
      const request =
        mode === "decisions"
          ? getAudit<AuditResponse>(authFetch, query, controller.signal)
          : getAudit<EventAuditResponse>(authFetch, query, controller.signal);
      request
        .then((response) => {
          if (cancelled) return;
          setData(response);
          setError(null);
          setChallengeId(null);
        })
        .catch((err) => {
          if (cancelled) return;
          if (err instanceof StepUpRequiredError) {
            // Not a query failure -- don't touch `error`/`data`, just switch
            // the panel body to the code prompt below.
            setChallengeId(err.challengeId);
            setMfaError(null);
            return;
          }
          setError(err instanceof Error ? err.message : "request failed");
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [authFetch, mode, page, userEmail, decision, eventType, from, to, retryTick, challengeId]);

  async function handleVerify(e: FormEvent) {
    e.preventDefault();
    setMfaSubmitting(true);
    setMfaError(null);
    try {
      await verifyMfaChallenge(authFetch, challengeId!, mfaCode);
      // Success -- clear the prompt and re-run the audit fetch effect above.
      // The action ticket this just consumed is scoped to /monitoring/audit
      // specifically, but the broader grace window (5 min) is what actually
      // covers this retry and any further pagination/filter changes.
      setChallengeId(null);
      setMfaCode("");
      setRetryTick((t) => t + 1);
    } catch (err) {
      const detail = err instanceof MfaVerificationError ? err.detail : "verification_failed";
      setMfaError(MFA_ERROR_MESSAGES[detail] ?? "Verification failed -- try again.");
    } finally {
      setMfaSubmitting(false);
    }
  }

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
            <button className="btn" onClick={handleExport} disabled={exporting || challengeId !== null}>
              {exporting ? "Exporting…" : "Export CSV"}
            </button>
            <button className="btn" onClick={onClose}>
              Back to dashboard
            </button>
          </span>
        </div>

        <div className="chip-row" style={{ marginBottom: 12 }}>
          <button
            className={`chip ${mode === "decisions" ? "chip--active" : ""}`}
            onClick={() => switchMode("decisions")}
            disabled={challengeId !== null}
          >
            Decisions
          </button>
          <button
            className={`chip ${mode === "events" ? "chip--active" : ""}`}
            onClick={() => switchMode("events")}
            disabled={challengeId !== null}
          >
            Events
          </button>
        </div>

        <div className="audit-panel__filters">
          <input
            className="text-input"
            placeholder="user_email"
            value={userEmailInput}
            onChange={(e) => setUserEmailInput(e.target.value)}
            disabled={challengeId !== null}
          />
          {mode === "decisions" ? (
            <select
              className="select"
              value={decision}
              onChange={(e) => applyFilter(setDecision)(e.target.value)}
              disabled={challengeId !== null}
            >
              <option value="">any decision</option>
              <option value="allow">allow</option>
              <option value="step_up">step_up</option>
              <option value="deny">deny</option>
            </select>
          ) : (
            <select
              className="select"
              value={eventType}
              onChange={(e) => applyFilter(setEventType)(e.target.value)}
              disabled={challengeId !== null}
            >
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
            disabled={challengeId !== null}
          />
          <input
            className="text-input"
            type="datetime-local"
            value={to}
            onChange={(e) => applyFilter(setTo)(e.target.value)}
            title="to"
            disabled={challengeId !== null}
          />
          {error ? <span className="card__degraded">degraded</span> : null}
        </div>

        <div className="audit-panel__body">
          {challengeId ? (
            <form className="mfa-step-up" onSubmit={handleVerify}>
              <p>
                Step-up verification required to view the audit log. Enter the 6-digit
                code from your authenticator app.
              </p>
              <input
                className="text-input"
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                autoFocus
                placeholder="123456"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              />
              <div className="chip-row">
                <button className="btn" type="submit" disabled={mfaSubmitting || mfaCode.length !== 6}>
                  {mfaSubmitting ? "Verifying…" : "Verify"}
                </button>
                <button className="btn" type="button" onClick={onClose}>
                  Cancel
                </button>
              </div>
              {mfaError ? <span className="card__degraded">{mfaError}</span> : null}
            </form>
          ) : loading && !data ? (
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
            <button
              className="btn"
              disabled={page <= 1 || challengeId !== null}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Prev
            </button>
            <button
              className="btn"
              disabled={page >= totalPages || challengeId !== null}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </span>
        </div>
      </div>
    </div>
  );
}
