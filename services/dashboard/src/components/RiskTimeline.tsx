import { useMemo } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { RiskTimelinePoint } from "../types";

const ACCENT = "#2ea3e0";
const DANGER = "#e24b4a";
const GRID = "#1c2333";

interface ChartPoint {
  ts: number;
  time: string;
  risk_score: number;
  user_email: string | null;
  crossed: boolean;
}

interface RiskTimelineProps {
  points: RiskTimelinePoint[];
  threshold: number | null;
  users: string[];
  selectedUser: string;
  onSelectUser: (email: string) => void;
  error: string | null;
  rateLimited: boolean;
}

function formatClock(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function CustomDot(props: { cx?: number; cy?: number; payload?: ChartPoint }) {
  const { cx, cy, payload } = props;
  if (cx === undefined || cy === undefined || !payload) return null;
  return (
    <circle
      cx={cx}
      cy={cy}
      r={payload.crossed ? 5 : 3}
      fill={payload.crossed ? DANGER : ACCENT}
      stroke={payload.crossed ? DANGER : ACCENT}
      strokeWidth={payload.crossed ? 2 : 0}
      fillOpacity={payload.crossed ? 0.9 : 0.85}
    />
  );
}

function TimelineTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: ChartPoint }> }) {
  if (!active || !payload || payload.length === 0) return null;
  const point = payload[0].payload;
  return (
    <div className="tooltip-card">
      <div className="tooltip-card__row">
        <strong>{formatClock(point.ts)}</strong>
      </div>
      <div className="tooltip-card__row">{point.user_email ?? "unknown user"}</div>
      <div className="tooltip-card__row">score: {point.risk_score.toFixed(2)}</div>
      <div className="tooltip-card__row">{point.crossed ? "step_up" : "allow"}</div>
    </div>
  );
}

export function RiskTimeline({ points, threshold, users, selectedUser, onSelectUser, error, rateLimited }: RiskTimelineProps) {
  const chartData = useMemo<ChartPoint[]>(
    () =>
      points
        .filter((p) => p.risk_score !== null)
        .map((p) => ({
          ts: Date.parse(p.created_at),
          time: p.created_at,
          risk_score: p.risk_score as number,
          user_email: p.user_email,
          crossed: threshold !== null && (p.risk_score as number) >= threshold,
        }))
        .sort((a, b) => a.ts - b.ts),
    [points, threshold]
  );

  return (
    <div className="card">
      <div className="timeline-header">
        <span className="card__title">Risk score timeline</span>
        <select className="select" value={selectedUser} onChange={(e) => onSelectUser(e.target.value)}>
          <option value="all">All users</option>
          {users.map((email) => (
            <option key={email} value={email}>
              {email}
            </option>
          ))}
        </select>
      </div>
      <div className="timeline-legend">
        <span>
          <span className="legend-swatch" style={{ background: ACCENT }} />
          below threshold
        </span>
        <span>
          <span className="legend-swatch" style={{ background: DANGER }} />
          at/above threshold ({threshold !== null ? threshold.toFixed(3) : "—"})
        </span>
        {rateLimited ? (
          <span className="card__rate-limited">rate limited</span>
        ) : error ? (
          <span className="card__degraded">degraded</span>
        ) : null}
      </div>

      {chartData.length === 0 ? (
        <div className="card__empty">no data yet</div>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={chartData} margin={{ top: 6, right: 12, left: -12, bottom: 0 }}>
            <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="ts"
              type="number"
              domain={["dataMin", "dataMax"]}
              tickFormatter={formatClock}
              stroke="#5f6b7d"
              tick={{ fontSize: 11 }}
              minTickGap={40}
            />
            <YAxis
              domain={[0.5, 1.0]}
              stroke="#5f6b7d"
              tick={{ fontSize: 11 }}
              tickFormatter={(v: number) => v.toFixed(2)}
            />
            <Tooltip content={<TimelineTooltip />} />
            {threshold !== null && (
              <ReferenceLine
                y={threshold}
                stroke={DANGER}
                strokeDasharray="6 4"
                label={{ value: `threshold ${threshold.toFixed(3)}`, position: "insideTopRight", fill: DANGER, fontSize: 11 }}
              />
            )}
            <Line
              type="monotone"
              dataKey="risk_score"
              stroke={ACCENT}
              strokeWidth={2}
              dot={<CustomDot />}
              isAnimationActive
              animationDuration={250}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
