BEGIN;

ALTER TABLE retrywise.merchants
    ADD COLUMN diagnosis_mode text NOT NULL DEFAULT 'LOCAL_ML'
        CHECK (diagnosis_mode IN ('LOCAL_ML', 'HYBRID_GEMINI', 'SHADOW'));

CREATE TABLE retrywise.diagnosis_mode_events (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    sequence_number bigint NOT NULL CHECK (sequence_number > 0),
    diagnosis_mode text NOT NULL CHECK (
        diagnosis_mode IN ('LOCAL_ML', 'HYBRID_GEMINI', 'SHADOW')
    ),
    reason_code text NOT NULL CHECK (
        reason_code IN (
            'operator_selected_local_ml',
            'operator_selected_hybrid_gemini',
            'operator_selected_shadow'
        )
    ),
    actor_subject_sha256 retrywise.sha256_digest NOT NULL,
    idempotency_key_sha256 retrywise.sha256_digest NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT diagnosis_mode_events_merchant_fk
        FOREIGN KEY (merchant_id) REFERENCES retrywise.merchants (id),
    UNIQUE (merchant_id, sequence_number),
    UNIQUE (merchant_id, idempotency_key_sha256)
);

CREATE INDEX diagnosis_mode_events_recent_idx
    ON retrywise.diagnosis_mode_events (merchant_id, created_at DESC, id DESC);

CREATE FUNCTION retrywise.reject_diagnosis_mode_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
BEGIN
    RAISE EXCEPTION 'diagnosis mode events are append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER diagnosis_mode_events_immutable
BEFORE UPDATE OR DELETE ON retrywise.diagnosis_mode_events
FOR EACH ROW EXECUTE FUNCTION retrywise.reject_diagnosis_mode_event_mutation();

ALTER TABLE retrywise.decisions
    ADD COLUMN requested_diagnosis_mode text
        CHECK (requested_diagnosis_mode IN ('LOCAL_ML', 'HYBRID_GEMINI', 'SHADOW')),
    ADD COLUMN executed_diagnosis_engine text
        CHECK (executed_diagnosis_engine IN ('LOCAL_ML', 'GEMINI')),
    ADD COLUMN diagnosis_latency_ms integer
        CHECK (diagnosis_latency_ms BETWEEN 0 AND 60000),
    ADD COLUMN diagnosis_fallback_reason_code text CHECK (
        diagnosis_fallback_reason_code IS NULL
        OR diagnosis_fallback_reason_code ~ '^[A-Z][A-Z0-9_]{0,99}$'
    ),
    ADD COLUMN shadow_diagnosis jsonb CHECK (
        shadow_diagnosis IS NULL OR jsonb_typeof(shadow_diagnosis) = 'object'
    );

ALTER TABLE retrywise.decisions
    ADD CONSTRAINT decisions_diagnosis_provenance_complete CHECK (
        (
            requested_diagnosis_mode IS NULL
            AND executed_diagnosis_engine IS NULL
            AND diagnosis_latency_ms IS NULL
            AND diagnosis_fallback_reason_code IS NULL
            AND shadow_diagnosis IS NULL
        )
        OR
        (
            requested_diagnosis_mode IS NOT NULL
            AND executed_diagnosis_engine IS NOT NULL
            AND diagnosis_latency_ms IS NOT NULL
        )
    );

REVOKE ALL ON TABLE retrywise.diagnosis_mode_events FROM PUBLIC;

COMMIT;
