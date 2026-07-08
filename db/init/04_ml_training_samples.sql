CREATE TABLE ml_training_samples ( 
	id BIGSERIAL PRIMARY KEY, 
	-- Lien logique vers la requête d'origine (sans FK) 
	trace_id UUID NOT NULL, 
	-- Vecteur de 20 features numériques 
	feature_vector FLOAT4[] NOT NULL, 
	CONSTRAINT chk_feature_vector_size 
		CHECK (cardinality(feature_vector) = 20), 
	-- Null pendant la phase de bootstrap (avant le premier modèle) 
	risk_score REAL 
		CHECK (risk_score >= 0.0 AND risk_score <= 1.0), 
	-- Null pendant la phase de bootstrap 
	model_version VARCHAR(50), 
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW() 
); 
CREATE INDEX idx_ml_training_trace 
ON ml_training_samples(trace_id); 
CREATE INDEX idx_ml_training_created_at 
ON ml_training_samples(created_at DESC); 
CREATE INDEX idx_ml_training_model_version 
ON ml_training_samples(model_version); 