import { useEffect, useState } from "react";
import { getAudit } from "../api/monitoring";
import { useAuth } from "../context/AuthContext";
import type { AuditResponse } from "../types";

interface AuditViewProps {
  onClose: () => void;
}

const PAGE_SIZE = 25;

function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleString([], { dateStyle: "short", timeStyle: "medium" });
}

export function AuditView({ onClose }: AuditViewProps) {
  const { authFetch } = useAuth();
  const [page, setPage] = useState(1);
  const [userEmail, setUserEmail] = useState("");
  const [decision, setDecision] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [data, setData] = useState<AuditResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getAudit(authFetch, {
      page,
      pageSize: PAGE_SIZE,
      userEmail: userEmail || undefined,
      decision: decision || undefined,
      from: from ? new Date(from).toISOString() : undefined,
      to: to ? new Date(to).toISOString() : undefined,
    })
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
  }, [authFetch, page, userEmail, decision, from, to]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  function applyFilter(setter: (value: string) => void) {
    return (value: string) => {
      setter(value);
      setPage(1);
    };
  }

  return (
    <div className="audit-overlay" onClick={onClose}>
      <div className="audit-panel" onClick={(e) => e.stopPropagation()}>
        <div className="audit-panel__header">
          <span className="card__title">Audit log</span>
          <button className="btn" onClick={onClose}>
            Back to dashboard
          </button>
        </div>

        <div className="audit-panel__filters">
          <input
            className="text-input"
            placeholder="user_email"
            value={userEmail}
            onChange={(e) => applyFilter(setUserEmail)(e.target.value)}
          />
          <select className="select" value={decision} onChange={(e) => applyFilter(setDecision)(e.target.value)}>
            <option value="">any decision</option>
            <option value="allow">allow</option>
            <option value="step_up">step_up</option>
            <option value="deny">deny</option>
          </select>
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
          ) : (
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
                {data.rows.map((row) => (
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
