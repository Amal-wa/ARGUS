import { useEffect, useRef, useState } from "react";
import type { AnomalyRow } from "../types";

interface AnomaliesPanelProps {
  anomalies: AnomalyRow[];
  error: string | null;
  rateLimited: boolean;
}

// Human-readable label per behavioral-detector rule -- see CLAUDE.md's
// Behavioral detector section for what each one actually catches. Falls
// back to the raw anomaly_type for any value not in this map (the DB enum
// also has an unused "behavioral" member -- see types.ts).
const ANOMALY_TYPE_LABELS: Record<string, string> = {
  resource_access: "Resource enumeration",
  authentication: "Password spraying",
  network: "Session hijack signal",
  authorization: "Authorization abuse",
};

function formatClock(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function AnomaliesPanel({ anomalies, error, rateLimited }: AnomaliesPanelProps) {
  // Same "pulse on new" pattern as AlertsPanel -- trace_id is null for every
  // authentication-type anomaly (no opa_decision_log row to reference, see
  // CLAUDE.md's Data layer section), so those never pulse; an existing,
  // accepted limitation of the same mechanism in AlertsPanel, not something
  // specific to this panel.
  const [freshIds, setFreshIds] = useState<Set<string>>(new Set());
  const seenRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    const currentIds = anomalies.map((a) => a.trace_id).filter((id): id is string => id !== null);
    const newlySeen = currentIds.filter((id) => !seenRef.current.has(id));
    if (newlySeen.length === 0) return;

    newlySeen.forEach((id) => seenRef.current.add(id));
    setFreshIds(new Set(newlySeen));

    const timer = setTimeout(() => setFreshIds(new Set()), 900);
    return () => clearTimeout(timer);
  }, [anomalies]);

  return (
    <div className="card">
      <div className="card__header">
        <span className="card__title">Anomalies</span>
        {rateLimited ? (
          <span className="card__rate-limited">rate limited</span>
        ) : error ? (
          <span className="card__degraded">degraded</span>
        ) : null}
      </div>

      {anomalies.length === 0 ? (
        <div className="card__empty">no anomalies</div>
      ) : (
        <div className="anomaly-list">
          {anomalies.map((anomaly) => {
            const key = anomaly.trace_id ?? `${anomaly.anomaly_type}-${anomaly.created_at}`;
            const isFresh = anomaly.trace_id !== null && freshIds.has(anomaly.trace_id);
            return (
              <div
                key={key}
                className={`anomaly-item anomaly-item--${anomaly.severity} ${isFresh ? "anomaly-item--pulse" : ""}`}
              >
                <div className="anomaly-item__top">
                  <span className="anomaly-item__user">{anomaly.user_email ?? "unknown user"}</span>
                  <span className={`badge badge--${anomaly.severity}`}>{anomaly.severity}</span>
                  <span className="anomaly-item__score">{anomaly.risk_score.toFixed(2)}</span>
                </div>
                <div className="anomaly-item__meta">
                  {formatClock(anomaly.created_at)} · {ANOMALY_TYPE_LABELS[anomaly.anomaly_type] ?? anomaly.anomaly_type} ·{" "}
                  {anomaly.resource ?? "—"}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
