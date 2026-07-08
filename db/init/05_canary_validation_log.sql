CREATE TYPE canary_review_status AS ENUM ('pending', 'no_review_required', 'confirmed', 'rejected');

CREATE TABLE canary_validation_log (
    id                        BIGSERIAL PRIMARY KEY,
    trace_id                  UUID NOT NULL,
    production_model_version  VARCHAR(50) NOT NULL,
    candidate_model_version   VARCHAR(50) NOT NULL,
    production_risk_score     REAL NOT NULL CHECK (production_risk_score >= 0.0 AND production_risk_score <= 1.0),
    candidate_risk_score      REAL NOT NULL CHECK (candidate_risk_score >= 0.0 AND candidate_risk_score <= 1.0),
    review_status             canary_review_status NOT NULL DEFAULT 'pending',
    reviewed_by               VARCHAR(100),
    reviewed_at               TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);