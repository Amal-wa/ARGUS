import { useMemo, useState } from "react";
import type { Decision, DecisionRow } from "../types";

interface DecisionFeedProps {
  rows: DecisionRow[];
  error: string | null;
  rateLimited: boolean;
}

type FilterValue = "all" | Decision;

const FILTERS: { value: FilterValue; label: string }[] = [
  { value: "all", label: "All" },
  { value: "allow", label: "Allow" },
  { value: "step_up", label: "Step-up" },
  { value: "deny", label: "Deny" },
];

function formatClock(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function DecisionFeed({ rows, error, rateLimited }: DecisionFeedProps) {
  const [filter, setFilter] = useState<FilterValue>("all");

  const visible = useMemo(
    () => (filter === "all" ? rows : rows.filter((row) => row.decision === filter)),
    [rows, filter]
  );

  return (
    <div className="card">
      <div className="card__header">
        <span className="card__title">Live decision feed</span>
        {rateLimited ? (
          <span className="card__rate-limited">rate limited</span>
        ) : error ? (
          <span className="card__degraded">degraded</span>
        ) : null}
      </div>

      <div className="chip-row" style={{ marginBottom: 12 }}>
        {FILTERS.map((f) => (
          <button
            key={f.value}
            className={`chip ${filter === f.value ? `chip--active chip--${f.value}` : ""}`}
            onClick={() => setFilter(f.value)}
          >
            {f.label}
          </button>
        ))}
      </div>

      {visible.length === 0 ? (
        <div className="card__empty">no data yet</div>
      ) : (
        <div className="feed">
          {visible.map((row) => (
            <div className="feed-row" key={row.trace_id}>
              <span className="feed-row__time">{formatClock(row.created_at)}</span>
              <span className="feed-row__main">
                <span className="feed-row__user">{row.user_email ?? "unknown"}</span>
                <span className="feed-row__resource">
                  {row.action} {row.resource}
                </span>
              </span>
              <span className="feed-row__score">{row.risk_score !== null ? row.risk_score.toFixed(2) : "—"}</span>
              <span className={`badge badge--${row.decision}`}>{row.decision}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
