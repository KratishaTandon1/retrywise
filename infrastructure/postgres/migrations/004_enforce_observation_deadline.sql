BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

ALTER TABLE retrywise.recovery_cases
    ADD COLUMN observation_started_at timestamptz,
    ADD COLUMN observation_contract_version smallint NOT NULL DEFAULT 0
        CHECK (observation_contract_version IN (0, 1));

ALTER TABLE retrywise.recovery_cases
    DROP CONSTRAINT recovery_cases_observation_ck,
    ADD CONSTRAINT recovery_cases_observation_ck CHECK (
        observation_contract_version = 0
        OR (
            observation_contract_version = 1
            AND observation_started_at IS NOT NULL
            AND observation_deadline_at IS NOT NULL
            AND observation_deadline_at >=
                observation_started_at + interval '2 minutes'
        )
    );

CREATE FUNCTION retrywise.enforce_observation_deadline()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    database_now timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        database_now := clock_timestamp();
        NEW.observation_contract_version := 1;
        NEW.observation_started_at := database_now;
        NEW.observation_deadline_at := GREATEST(
            COALESCE(
                NEW.observation_deadline_at,
                database_now + interval '2 minutes'
            ),
            database_now + interval '2 minutes'
        );
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF NEW.observation_contract_version IS DISTINCT FROM
           OLD.observation_contract_version THEN
            RAISE EXCEPTION
                'recovery observation contract version is immutable'
                USING ERRCODE = '55000';
        END IF;

        IF OLD.observation_contract_version = 0
           AND NEW.state IS DISTINCT FROM OLD.state
           AND NEW.state IN (
               'ASSESSING',
               'WAITING',
               'APPROVAL_REQUIRED',
               'ACTION_QUEUED',
               'EXECUTING',
               'ACTION_UNCERTAIN',
               'ACTIVE',
               'RECOVERED'
           ) THEN
            RAISE EXCEPTION
                'legacy recovery case lacks trusted observation evidence and cannot advance'
                USING ERRCODE = '23514';
        END IF;

        IF ROW(
               NEW.observation_started_at,
               NEW.observation_deadline_at
           ) IS DISTINCT FROM ROW(
               OLD.observation_started_at,
               OLD.observation_deadline_at
           ) THEN
            RAISE EXCEPTION
                'recovery observation timing is immutable'
                USING ERRCODE = '55000';
        END IF;

        IF OLD.state = 'OBSERVING'
           AND NEW.state = 'ASSESSING'
           AND (
               OLD.observation_contract_version <> 1
               OR OLD.observation_deadline_at IS NULL
               OR clock_timestamp() < OLD.observation_deadline_at
           ) THEN
            RAISE EXCEPTION
                'recovery assessment cannot start before observation deadline'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION retrywise.enforce_observation_deadline() IS
    'Assigns trusted observation time, clamps the two-minute floor, quarantines legacy evidence gaps, and blocks early assessment.';

COMMENT ON COLUMN retrywise.recovery_cases.observation_contract_version IS
    '0 identifies pre-hardening legacy rows that cannot advance into collection; 1 proves database-owned observation timing.';

CREATE TRIGGER recovery_cases_05_enforce_observation_deadline
BEFORE INSERT OR UPDATE ON retrywise.recovery_cases
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_observation_deadline();

COMMIT;
