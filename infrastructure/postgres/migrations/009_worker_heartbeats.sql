BEGIN;

CREATE TABLE retrywise.worker_heartbeats (
    worker_id text PRIMARY KEY CHECK (
        length(btrim(worker_id)) BETWEEN 1 AND 128
    ),
    role text NOT NULL CHECK (role IN ('OUTBOX')),
    code_revision text NOT NULL CHECK (
        length(btrim(code_revision)) BETWEEN 1 AND 128
    ),
    started_at timestamptz NOT NULL,
    heartbeat_at timestamptz NOT NULL,
    last_poll_selected integer NOT NULL DEFAULT 0 CHECK (
        last_poll_selected >= 0
    ),
    last_poll_succeeded integer NOT NULL DEFAULT 0 CHECK (
        last_poll_succeeded >= 0
    ),
    last_poll_retried integer NOT NULL DEFAULT 0 CHECK (
        last_poll_retried >= 0
    ),
    last_poll_dead_lettered integer NOT NULL DEFAULT 0 CHECK (
        last_poll_dead_lettered >= 0
    ),
    last_error_code text,
    CHECK (heartbeat_at >= started_at)
);

CREATE INDEX worker_heartbeats_freshness_idx
    ON retrywise.worker_heartbeats (role, heartbeat_at DESC);

REVOKE ALL ON TABLE retrywise.worker_heartbeats FROM PUBLIC;

COMMIT;
