-- 01_events.sql
CREATE TYPE event_type AS ENUM (
    'rate_limit_ip_exceeded',
    'rate_limit_user_exceeded',
    'auth_failed',
    'token_revoked_used',
    'replay_detected',
    'mfa_locked',
    'mfa_failed',
    'opa_unavailable',
    'step_up_required',
    'challenge_expired',
    'totp_replay_detected'
);

CREATE TYPE http_method_type AS ENUM (
    'GET',
    'POST',
    'PUT',
    'PATCH',
    'DELETE'
);
CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY,
    -- Identifiant de corrélation de la requête
    trace_id UUID NOT NULL,
    -- Horodatage de l'événement
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Utilisateur (NULL avant authentification réussie)
    user_id UUID NULL,
    -- Informations de la requête HTTP
    ip_address INET NOT NULL,
    http_method http_method_type NOT NULL,
    request_path TEXT NOT NULL,
    -- Temps écoulé jusqu'à la réponse finale ou au timeout
    latency_ms INTEGER NOT NULL
        CHECK (latency_ms >= 0),
    -- Code HTTP retourné
    http_status INTEGER NOT NULL
        CHECK (http_status BETWEEN 100 AND 599),
    -- Informations complémentaires en cas d'erreur
    error_code TEXT,
    error_message TEXT,
    -- Nature de l'événement
    event_type event_type NOT NULL
);
CREATE INDEX idx_events_trace_id
ON events(trace_id);

CREATE INDEX idx_events_user_timestamp
ON events(user_id, timestamp DESC);

CREATE INDEX idx_events_ip_timestamp
ON events(ip_address, timestamp DESC);

CREATE INDEX idx_events_type_timestamp
ON events(event_type, timestamp DESC);

CREATE INDEX idx_events_timestamp
ON events(timestamp DESC);