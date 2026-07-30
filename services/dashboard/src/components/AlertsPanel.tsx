import { useEffect, useRef, useState } from "react";
import type { AlertRow } from "../types";

interface AlertsPanelProps {
  alerts: AlertRow[];
  error: string | null;
  rateLimited: boolean;
}

function formatClock(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function AlertsPanel({ alerts, error, rateLimited }: AlertsPanelProps) {
  // Trace_ids seen on a previous render get a brief pulse instead of the
  // default slide-in -- this is what makes a FRESH alert (as opposed to one
  // that was already there) noticeable at a glance.
  const [freshIds, setFreshIds] = useState<Set<string>>(new Set());
  const seenRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    const currentIds = alerts.map((a) => a.trace_id).filter((id): id is string => id !== null);
    const newlySeen = currentIds.filter((id) => !seenRef.current.has(id));
    if (newlySeen.length === 0) return;

    newlySeen.forEach((id) => seenRef.current.add(id));
    setFreshIds(new Set(newlySeen));

    const timer = setTimeout(() => setFreshIds(new Set()), 900);
    return () => clearTimeout(timer);
  }, [alerts]);

  return (
    <div className="card">
      <div className="card__header">
        <span className="card__title">Alerts</span>
        {rateLimited ? (
          <span className="card__rate-limited">rate limited</span>
        ) : error ? (
          <span className="card__degraded">degraded</span>
        ) : null}
      </div>

      {alerts.length === 0 ? (
        <div className="card__empty">no alerts</div>
      ) : (
        <div className="alert-list">
          {alerts.map((alert) => {
            const key = alert.trace_id ?? `${alert.type}-${alert.created_at}`;
            const isFresh = alert.trace_id !== null && freshIds.has(alert.trace_id);
            return (
              <div key={key} className={`alert-item ${isFresh ? "alert-item--pulse" : ""}`}>
                <div className="alert-item__top">
                  <span className="alert-item__user">{alert.user_email ?? "unknown user"}</span>
                  <span className="alert-item__score">{alert.risk_score !== null ? alert.risk_score.toFixed(2) : "—"}</span>
                </div>
                <div className="alert-item__meta">
                  {formatClock(alert.created_at)} · {alert.type} · {alert.resource ?? "—"}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
