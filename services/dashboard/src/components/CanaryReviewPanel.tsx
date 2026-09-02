import { useState } from "react";
import type { AuthFetch } from "../api/monitoring";
import { reviewCanary } from "../api/monitoring";
import type { CanaryComparisonRow } from "../types";

interface CanaryReviewPanelProps {
  comparisons: CanaryComparisonRow[];
  error: string | null;
  rateLimited: boolean;
  authFetch: AuthFetch;
  // Bumps Dashboard's canaryRefreshTick, which is in usePolling's deps for
  // this panel's own poller -- restarts the fetch loop immediately instead
  // of waiting out the rest of CANARY_POLL_MS, so a reviewed row disappears
  // from the queue promptly rather than up to 30s later.
  onReviewed: () => void;
}

function formatClock(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function CanaryReviewPanel({ comparisons, error, rateLimited, authFetch, onReviewed }: CanaryReviewPanelProps) {
  // Tracks which row has an in-flight PATCH -- disables both of ITS buttons
  // only, not the whole panel, so an operator can still act on other rows
  // while one review is submitting.
  const [submittingId, setSubmittingId] = useState<number | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function handleReview(id: number, status: "confirmed" | "rejected") {
    setSubmittingId(id);
    setActionError(null);
    try {
      await reviewCanary(authFetch, id, status);
      onReviewed();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "review failed");
    } finally {
      setSubmittingId(null);
    }
  }

  return (
    <div className="card">
      <div className="card__header">
        <span className="card__title">Canary Reviews</span>
        {rateLimited ? (
          <span className="card__rate-limited">rate limited</span>
        ) : error ? (
          <span className="card__degraded">degraded</span>
        ) : null}
      </div>

      {actionError ? <div className="card__degraded">{actionError}</div> : null}

      {comparisons.length === 0 ? (
        <div className="card__empty">no pending reviews</div>
      ) : (
        <div className="canary-list">
          {comparisons.map((row) => (
            <div key={row.id} className="canary-item">
              <div className="canary-item__top">
                <span className="canary-item__versions">
                  {row.candidate_model_version} vs {row.production_model_version}
                </span>
                <span className={`badge badge--${row.review_status}`}>{row.review_status}</span>
              </div>
              <div className="canary-item__scores">
                candidate {row.candidate_risk_score.toFixed(3)} · production {row.production_risk_score.toFixed(3)}
              </div>
              <div className="canary-item__meta">{formatClock(row.created_at)}</div>
              {row.review_status === "pending" ? (
                <div className="canary-item__actions">
                  <button
                    type="button"
                    className="btn btn--primary"
                    disabled={submittingId === row.id}
                    onClick={() => void handleReview(row.id, "confirmed")}
                  >
                    Confirm
                  </button>
                  <button
                    type="button"
                    className="btn btn--danger"
                    disabled={submittingId === row.id}
                    onClick={() => void handleReview(row.id, "rejected")}
                  >
                    Reject
                  </button>
                </div>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
