CREATE TYPE decision_type AS ENUM ('allow', 'deny', 'step_up');
CREATE TYPE anomaly_status AS ENUM ('none', 'pending_classification', 'classified');

CREATE TABLE opa_decision_log (
    id            BIGSERIAL PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trace_id      UUID NOT NULL,
    user_id       UUID NOT NULL,
    jti           UUID NOT NULL,
    role          VARCHAR(100) NOT NULL,
    resource      VARCHAR(255) NOT NULL,   -- derived via FastAPI route matching, same mechanism as feature #9/#10
    action        VARCHAR(50) NOT NULL,
    ip_address    INET NOT NULL,
    risk_score    REAL CHECK (risk_score >= 0.0 AND risk_score <= 1.0),   -- nullable during bootstrap window
    model_version VARCHAR(50),                                            -- nullable during bootstrap window
    is_anomaly    anomaly_status NOT NULL DEFAULT 'none',
    decision      decision_type NOT NULL,
    policy_name   TEXT NOT NULL,
    reason        TEXT,
    latency_ms    INTEGER NOT NULL
);