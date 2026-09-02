import { useMemo, useState } from "react";
import { getAlerts, getAnomalies, getPendingCanaryReviews, getRiskTimeline, getStats, getSystemStatus } from "../api/monitoring";
import { useAuth } from "../context/AuthContext";
import { useDecisionFeed } from "../hooks/useDecisionFeed";
import { usePolling } from "../hooks/usePolling";
import {
  ALERTS_INITIAL_DELAY_MS,
  ALERTS_POLL_MS,
  ANOMALIES_INITIAL_DELAY_MS,
  ANOMALIES_POLL_MS,
  CANARY_INITIAL_DELAY_MS,
  CANARY_POLL_MS,
  RISK_TIMELINE_INITIAL_DELAY_MS,
  RISK_TIMELINE_POLL_MS,
  STATS_INITIAL_DELAY_MS,
  STATS_POLL_MS,
  SYSTEM_STATUS_INITIAL_DELAY_MS,
  SYSTEM_STATUS_POLL_MS,
} from "../pollingIntervals";
import { AlertsPanel } from "./AlertsPanel";
import { AnomaliesPanel } from "./AnomaliesPanel";
import { AuditView } from "./AuditView";
import { CanaryReviewPanel } from "./CanaryReviewPanel";
import { DecisionFeed } from "./DecisionFeed";
import { Header } from "./Header";
import { RiskTimeline } from "./RiskTimeline";
import { StatCards } from "./StatCards";
import { SystemStatusPanel } from "./SystemStatusPanel";

// Alerts and stats must share the same window -- otherwise the two panels
// can visibly disagree about "now" (e.g. the STEP-UPS stat card reads 0 for
// the last hour while the alerts panel, unwindowed, shows step_ups from
// days ago). Keep this in sync with getStats's own default.
const ALERTS_WINDOW_MINUTES = 60;

export function Dashboard() {
  const { authFetch } = useAuth();
  const [selectedUser, setSelectedUser] = useState("all");
  const [showAudit, setShowAudit] = useState(false);

  const stats = usePolling(() => getStats(authFetch, ALERTS_WINDOW_MINUTES), STATS_POLL_MS, [], STATS_INITIAL_DELAY_MS);
  const systemStatus = usePolling(() => getSystemStatus(authFetch), SYSTEM_STATUS_POLL_MS, [], SYSTEM_STATUS_INITIAL_DELAY_MS);
  const alerts = usePolling(
    () => getAlerts(authFetch, 50, ALERTS_WINDOW_MINUTES),
    ALERTS_POLL_MS,
    [],
    ALERTS_INITIAL_DELAY_MS
  );
  const anomalies = usePolling(
    () => getAnomalies(authFetch, 50, ALERTS_WINDOW_MINUTES),
    ANOMALIES_POLL_MS,
    [],
    ANOMALIES_INITIAL_DELAY_MS
  );
  const riskTimeline = usePolling(
    () => getRiskTimeline(authFetch, { userEmail: selectedUser === "all" ? undefined : selectedUser }),
    RISK_TIMELINE_POLL_MS,
    [selectedUser],
    RISK_TIMELINE_INITIAL_DELAY_MS
  );
  // canaryRefreshTick in deps: bumping it restarts usePolling's fetch loop
  // immediately (see usePolling's own docstring on `deps`) instead of
  // waiting out the rest of CANARY_POLL_MS -- CanaryReviewPanel calls this
  // right after a successful PATCH so a reviewed row leaves the queue
  // promptly.
  const [canaryRefreshTick, setCanaryRefreshTick] = useState(0);
  const canaryReviews = usePolling(
    () => getPendingCanaryReviews(authFetch),
    CANARY_POLL_MS,
    [canaryRefreshTick],
    CANARY_INITIAL_DELAY_MS
  );
  const feed = useDecisionFeed();

  const knownUsers = useMemo(() => {
    const emails = new Set<string>();
    feed.rows.forEach((row) => {
      if (row.user_email) emails.add(row.user_email);
    });
    return Array.from(emails).sort();
  }, [feed.rows]);

  // Sourced from the dedicated /monitoring/anomalies feed (AnomaliesPanel
  // below), not by filtering alerts.data -- same underlying event_anomaly
  // rows either way, but this keeps the stat card and the panel it's
  // describing from ever being able to disagree.
  const anomalyCount = anomalies.data?.anomalies.length ?? 0;

  const isLive = stats.error === null && stats.data !== null;

  return (
    <div className="app-shell">
      <Header isLive={isLive} onOpenAudit={() => setShowAudit(true)} />

      <div className="dashboard">
        <StatCards stats={stats.data} anomalyCount={anomalyCount} error={stats.error} rateLimited={stats.rateLimited} />

        <AnomaliesPanel
          anomalies={anomalies.data?.anomalies ?? []}
          error={anomalies.error}
          rateLimited={anomalies.rateLimited}
        />

        <CanaryReviewPanel
          comparisons={canaryReviews.data?.comparisons ?? []}
          error={canaryReviews.error}
          rateLimited={canaryReviews.rateLimited}
          authFetch={authFetch}
          onReviewed={() => setCanaryRefreshTick((tick) => tick + 1)}
        />

        <div className="row row--middle">
          <RiskTimeline
            points={riskTimeline.data?.points ?? []}
            threshold={riskTimeline.data?.threshold ?? null}
            users={knownUsers}
            selectedUser={selectedUser}
            onSelectUser={setSelectedUser}
            error={riskTimeline.error}
            rateLimited={riskTimeline.rateLimited}
          />
          <AlertsPanel alerts={alerts.data?.alerts ?? []} error={alerts.error} rateLimited={alerts.rateLimited} />
        </div>

        <div className="row row--bottom">
          <DecisionFeed rows={feed.rows} error={feed.error} rateLimited={feed.rateLimited} />
          <SystemStatusPanel status={systemStatus.data} error={systemStatus.error} rateLimited={systemStatus.rateLimited} />
        </div>
      </div>

      {showAudit ? <AuditView onClose={() => setShowAudit(false)} /> : null}
    </div>
  );
}
