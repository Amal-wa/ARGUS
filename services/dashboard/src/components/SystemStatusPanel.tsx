import type { ServiceHealthValue, SystemStatusResponse } from "../types";

interface SystemStatusPanelProps {
  status: SystemStatusResponse | null;
  error: string | null;
  rateLimited: boolean;
}

const HEALTHY_VALUES: ServiceHealthValue[] = ["healthy", "up"];

function ServiceDot({ label, value }: { label: string; value: ServiceHealthValue }) {
  const healthy = HEALTHY_VALUES.includes(value);
  return (
    <div className="service-row">
      <span>
        <span className={`service-dot ${healthy ? "service-dot--healthy" : "service-dot--unhealthy"}`} />
        {label}
      </span>
      <span style={{ color: healthy ? "var(--success)" : "var(--danger-bright)" }}>{value}</span>
    </div>
  );
}

function formatTimestamp(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString([], { dateStyle: "short", timeStyle: "short" });
}

export function SystemStatusPanel({ status, error, rateLimited }: SystemStatusPanelProps) {
  return (
    <div className="card">
      <div className="card__header">
        <span className="card__title">System status</span>
        {rateLimited ? (
          <span className="card__rate-limited">rate limited</span>
        ) : error ? (
          <span className="card__degraded">degraded</span>
        ) : null}
      </div>

      {!status ? (
        <div className="card__empty">no data yet</div>
      ) : (
        <>
          <div className="status-grid">
            <div>
              <div className="status-field__label">Active model</div>
              <div className="status-field__value">{status.active_model ?? "none (bootstrap)"}</div>
            </div>
            <div>
              <div className="status-field__label">Threshold</div>
              <div className="status-field__value">
                {status.active_threshold !== null ? status.active_threshold.toFixed(3) : "—"}
              </div>
            </div>
            <div>
              <div className="status-field__label">Candidate model</div>
              <div className="status-field__value">{status.candidate_model ?? "—"}</div>
            </div>
            <div>
              <div className="status-field__label">Training samples</div>
              <div className="status-field__value">{status.training_samples ?? "—"}</div>
            </div>
            <div>
              <div className="status-field__label">Trained at</div>
              <div className="status-field__value">{formatTimestamp(status.model_trained_at)}</div>
            </div>
            <div>
              <div className="status-field__label">p98 (score dist.)</div>
              <div className="status-field__value">
                {status.score_distribution?.p98 !== undefined ? status.score_distribution.p98.toFixed(3) : "—"}
              </div>
            </div>
          </div>

          <ServiceDot label="Isolation Forest" value={status.services.isolation_forest} />
          <ServiceDot label="OPA" value={status.services.opa} />
          <ServiceDot label="Redis" value={status.services.redis} />
          <ServiceDot label="Postgres" value={status.services.postgres} />
        </>
      )}
    </div>
  );
}
