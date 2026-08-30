BEGIN;

CREATE TABLE retrywise.merchant_control_events (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    sequence_number bigint NOT NULL CHECK (sequence_number > 0),
    control_type text NOT NULL CHECK (control_type = 'MERCHANT_KILL_SWITCH'),
    enabled boolean NOT NULL,
    reason_code text NOT NULL CHECK (
        length(btrim(reason_code)) BETWEEN 1 AND 100
    ),
    actor_subject_sha256 retrywise.sha256_digest NOT NULL,
    idempotency_key_sha256 retrywise.sha256_digest NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT merchant_control_events_merchant_fk
        FOREIGN KEY (merchant_id) REFERENCES retrywise.merchants (id),
    UNIQUE (merchant_id, sequence_number),
    UNIQUE (merchant_id, idempotency_key_sha256)
);

CREATE INDEX merchant_control_events_recent_idx
    ON retrywise.merchant_control_events (merchant_id, created_at DESC, id DESC);

CREATE FUNCTION retrywise.reject_merchant_control_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
BEGIN
    RAISE EXCEPTION 'merchant control events are append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER merchant_control_events_immutable
BEFORE UPDATE OR DELETE ON retrywise.merchant_control_events
FOR EACH ROW EXECUTE FUNCTION retrywise.reject_merchant_control_event_mutation();

REVOKE ALL ON TABLE retrywise.merchant_control_events FROM PUBLIC;

COMMIT;
