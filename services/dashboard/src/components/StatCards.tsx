import { useCountUp } from "../hooks/useCountUp";
import type { StatsResponse } from "../types";

interface StatCardsProps {
  stats: StatsResponse | null;
  anomalyCount: number;
  error: string | null;
  rateLimited: boolean;
}

interface CardSpec {
  label: string;
  value: number;
  suffix?: string;
  decimals?: number;
  alert?: boolean;
}

function StatCard({ label, value, suffix = "", decimals = 0, alert = false }: CardSpec) {
  const animated = useCountUp(value);
  return (
    <div className={`card stat-card ${alert ? "stat-card--alert" : ""}`}>
      <div className="stat-card__value">
        {animated.toFixed(decimals)}
        {suffix}
      </div>
      <div className="stat-card__label">{label}</div>
    </div>
  );
}

export function StatCards({ stats, anomalyCount, error, rateLimited }: StatCardsProps) {
  if (rateLimited && !stats) {
    return (
      <div className="row row--stats">
        <div className="card">
          <div className="card__empty">rate limited -- retrying shortly</div>
        </div>
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="row row--stats">
        <div className="card">
          <div className="card__empty">stats unavailable</div>
        </div>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="row row--stats">
        {["Total decisions", "Allow rate", "Step-ups", "Active users", "Anomalies"].map((label) => (
          <div className="card stat-card" key={label}>
            <div className="stat-card__value">—</div>
            <div className="stat-card__label">{label}</div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="row row--stats" style={{ position: "relative" }}>
      {rateLimited ? <span className="card__rate-limited stats-rate-badge">rate limited</span> : null}
      <StatCard label="Total decisions" value={stats.total_decisions} />
      <StatCard label="Allow rate" value={stats.allow_rate * 100} suffix="%" decimals={1} />
      <StatCard label="Step-ups" value={stats.step_up} alert={stats.step_up > 0} />
      <StatCard label="Active users" value={stats.active_users} />
      <StatCard label="Anomalies" value={anomalyCount} alert={anomalyCount > 0} />
    </div>
  );
}
