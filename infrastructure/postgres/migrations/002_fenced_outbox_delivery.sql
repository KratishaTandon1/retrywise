BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

CREATE TYPE retrywise.outbox_retry_mode AS ENUM (
    'NORMAL',
    'RECONCILE_ONLY',
    'RETRY_SAME_EFFECT'
);

ALTER TABLE retrywise.outbox_jobs
    ADD COLUMN delivery_version bigint NOT NULL DEFAULT 0
        CHECK (delivery_version >= 0),
    ADD COLUMN lease_token text,
    ADD COLUMN retry_mode retrywise.outbox_retry_mode NOT NULL DEFAULT 'NORMAL',
    ADD COLUMN completion_reference text;

-- A lease created before fencing tokens existed cannot safely authorize work.
-- Preserve the row as terminal evidence instead of manufacturing ownership.
UPDATE retrywise.outbox_jobs
SET status = 'DEAD_LETTER',
    delivery_version = delivery_version + 1,
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error_code = 'legacy_unfenced_lease',
    last_error_at = clock_timestamp(),
    dead_lettered_at = clock_timestamp(),
    dead_letter_reason = 'legacy_unfenced_lease_requires_operator_reconciliation',
    retry_mode = 'RECONCILE_ONLY',
    updated_at = clock_timestamp()
WHERE status = 'IN_PROGRESS';

ALTER TABLE retrywise.outbox_jobs
    DROP CONSTRAINT outbox_jobs_lease_ck,
    ADD CONSTRAINT outbox_jobs_lease_ck CHECK (
        (
            status = 'IN_PROGRESS'
            AND lease_owner IS NOT NULL
            AND length(btrim(lease_owner)) BETWEEN 1 AND 128
            AND lease_token IS NOT NULL
            AND length(btrim(lease_token)) BETWEEN 1 AND 200
            AND lease_expires_at IS NOT NULL
        )
        OR
        (
            status <> 'IN_PROGRESS'
            AND lease_owner IS NULL
            AND lease_token IS NULL
            AND lease_expires_at IS NULL
        )
    ),
    ADD CONSTRAINT outbox_jobs_completion_reference_ck CHECK (
        (
            status = 'SUCCEEDED'
            AND (
                (
                    delivery_version = 0
                    AND completion_reference IS NULL
                )
                OR
                (
                    delivery_version > 0
                    AND completion_reference IS NOT NULL
                    AND length(btrim(completion_reference)) BETWEEN 1 AND 500
                )
            )
        )
        OR
        (
            status <> 'SUCCEEDED'
            AND completion_reference IS NULL
        )
    );

CREATE OR REPLACE FUNCTION retrywise.enforce_outbox_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING'
           OR NEW.attempt_count <> 0
           OR NEW.delivery_version <> 0
           OR NEW.retry_mode <> 'NORMAL' THEN
            RAISE EXCEPTION
                'outbox jobs must start PENDING at attempt/version zero in NORMAL mode'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.status NOT IN ('SUCCEEDED', 'DEAD_LETTER', 'CANCELLED') THEN
            RAISE EXCEPTION 'only terminal outbox jobs can be removed by retention'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.aggregate_type,
        NEW.aggregate_id,
        NEW.command_type,
        NEW.command_schema_version,
        NEW.command_payload,
        NEW.idempotency_key,
        NEW.max_attempts,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.aggregate_type,
        OLD.aggregate_id,
        OLD.command_type,
        OLD.command_schema_version,
        OLD.command_payload,
        OLD.idempotency_key,
        OLD.max_attempts,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'outbox command identity and payload are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status IN ('SUCCEEDED', 'DEAD_LETTER', 'CANCELLED') THEN
        RAISE EXCEPTION 'terminal outbox delivery evidence is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.delivery_version <> OLD.delivery_version + 1 THEN
        RAISE EXCEPTION 'outbox delivery_version must increase by exactly one'
            USING ERRCODE = '40001';
    END IF;

    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'outbox updated_at cannot move backwards'
            USING ERRCODE = '22007';
    END IF;

    IF NEW.attempt_count < OLD.attempt_count
       OR NEW.attempt_count > OLD.attempt_count + 1 THEN
        RAISE EXCEPTION 'outbox attempt_count must stay fixed or increase by one'
            USING ERRCODE = '55000';
    END IF;

    allowed :=
        (
            OLD.status IN ('PENDING', 'RETRY_SCHEDULED')
            AND NEW.status = 'IN_PROGRESS'
            AND NEW.attempt_count = OLD.attempt_count + 1
        )
        OR
        (
            OLD.status = 'IN_PROGRESS'
            AND NEW.status = 'IN_PROGRESS'
            AND OLD.lease_expires_at <= NEW.updated_at
            AND NEW.attempt_count = OLD.attempt_count + 1
            AND NEW.retry_mode = 'RECONCILE_ONLY'
            AND NEW.lease_token IS DISTINCT FROM OLD.lease_token
        )
        OR
        (
            OLD.status = 'IN_PROGRESS'
            AND NEW.status IN (
                'SUCCEEDED', 'RETRY_SCHEDULED', 'DEAD_LETTER', 'CANCELLED'
            )
            AND NEW.attempt_count = OLD.attempt_count
        )
        OR
        (
            OLD.status IN ('PENDING', 'RETRY_SCHEDULED')
            AND NEW.status IN ('CANCELLED', 'DEAD_LETTER')
            AND NEW.attempt_count = OLD.attempt_count
        );

    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid fenced outbox transition: % -> %',
            OLD.status, NEW.status USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON COLUMN retrywise.outbox_jobs.delivery_version IS
    'Monotonic compare-and-swap version; every delivery-state mutation increments exactly once.';
COMMENT ON COLUMN retrywise.outbox_jobs.lease_token IS
    'Per-claim fencing token required together with owner, version, and unexpired lease.';
COMMENT ON COLUMN retrywise.outbox_jobs.retry_mode IS
    'RECONCILE_ONLY prevents a reclaimed or ambiguous effect from being repeated blindly.';

COMMIT;
