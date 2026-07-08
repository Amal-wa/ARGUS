CREATE TYPE anomaly_type AS ENUM ( 'behavioral', 'authentication', 'authorization', 'network', 'resource_access' ); 
CREATE TYPE severity_level AS ENUM ( 'low', 'medium', 'high', 'critical' ); 
CREATE TABLE event_anomaly ( 
	id BIGSERIAL PRIMARY KEY, 
	id_log BIGINT NOT NULL 
		REFERENCES opa_decision_log(id) 
		ON DELETE RESTRICT, 
	timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	anomaly_type anomaly_type NOT NULL, 
	risk_score REAL NOT NULL 
		CHECK (risk_score >= 0.0 AND risk_score <= 1.0), 
	severity severity_level NOT NULL,
	contributing_features JSONB NOT NULL
);
CREATE INDEX idx_event_anomaly_timestamp 
ON event_anomaly(timestamp DESC); 
CREATE INDEX idx_event_anomaly_type 
ON event_anomaly(anomaly_type); 
CREATE INDEX idx_event_anomaly_severity 
ON event_anomaly(severity); 
CREATE INDEX idx_event_anomaly_log 
ON event_anomaly(id_log);