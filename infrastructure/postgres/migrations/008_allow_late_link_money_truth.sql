BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

LOCK TABLE retrywise.recovery_instruments IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF to_regprocedure(
        'retrywise.enforce_recovery_instrument_lifecycle()'
    ) IS NULL THEN
        RAISE EXCEPTION
            'migration 008 requires recovery instrument lifecycle enforcement';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_trigger AS trigger
        WHERE trigger.tgrelid = to_regclass('retrywise.recovery_instruments')
          AND trigger.tgname = 'recovery_instruments_10_enforce_lifecycle'
          AND trigger.tgenabled <> 'D'
    ) THEN
        RAISE EXCEPTION
            'migration 008 requires the enabled recovery instrument lifecycle trigger';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION retrywise.enforce_recovery_instrument_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'CREATING' THEN
            RAISE EXCEPTION 'recovery instruments must start in CREATING'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.provider_payment_link_id IS NOT NULL
           OR NEW.provider_order_id IS NOT NULL
           OR NEW.provider_payment_id IS NOT NULL THEN
            RAISE EXCEPTION 'a new recovery instrument cannot preclaim provider ids'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM retrywise.actions AS a
             WHERE a.merchant_id = NEW.merchant_id
               AND a.id = NEW.action_id
               AND a.recovery_case_id = NEW.recovery_case_id
               AND a.action_type = 'CREATE_STANDARD_PAYMENT_LINK'
        ) THEN
            RAISE EXCEPTION 'recovery instrument requires a create-link action'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'recovery instruments cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.recovery_case_id,
        NEW.logical_order_id,
        NEW.provider_account_id,
        NEW.action_id,
        NEW.reference_id,
        NEW.amount_minor,
        NEW.currency,
        NEW.accept_partial,
        NEW.expires_at,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.recovery_case_id,
        OLD.logical_order_id,
        OLD.provider_account_id,
        OLD.action_id,
        OLD.reference_id,
        OLD.amount_minor,
        OLD.currency,
        OLD.accept_partial,
        OLD.expires_at,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'recovery instrument identity and collection terms are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF (OLD.provider_payment_link_id IS NOT NULL AND
        NEW.provider_payment_link_id IS DISTINCT FROM
            OLD.provider_payment_link_id)
       OR (OLD.provider_order_id IS NOT NULL AND
           NEW.provider_order_id IS DISTINCT FROM OLD.provider_order_id)
       OR (OLD.provider_payment_id IS NOT NULL AND
           NEW.provider_payment_id IS DISTINCT FROM OLD.provider_payment_id) THEN
        RAISE EXCEPTION 'provider ids on a recovery instrument are write-once'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.collected_minor < OLD.collected_minor
       OR NEW.refunded_minor < OLD.refunded_minor THEN
        RAISE EXCEPTION 'recovery instrument money cannot decrease'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.last_reconciled_at IS NOT NULL AND
       (NEW.last_reconciled_at IS NULL OR
        NEW.last_reconciled_at < OLD.last_reconciled_at) THEN
        RAISE EXCEPTION 'instrument reconciliation time cannot regress'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    allowed :=
        (OLD.status = 'CREATING' AND
         NEW.status IN ('UNCERTAIN', 'ISSUED', 'ACTIVE', 'FAILED'))
        OR (OLD.status = 'UNCERTAIN' AND
            NEW.status IN (
                'CREATING', 'ISSUED', 'ACTIVE', 'CANCEL_PENDING', 'FAILED'
            ))
        OR (OLD.status = 'ISSUED' AND
            NEW.status IN (
                'ACTIVE', 'CANCEL_PENDING', 'PAID', 'PARTIALLY_PAID',
                'CANCELLED', 'EXPIRED', 'FAILED'
            ))
        OR (OLD.status = 'ACTIVE' AND
            NEW.status IN (
                'CANCEL_PENDING', 'PAID', 'PARTIALLY_PAID',
                'CANCELLED', 'EXPIRED', 'FAILED'
            ))
        OR (OLD.status = 'CANCEL_PENDING' AND
            NEW.status IN (
                'ACTIVE', 'PAID', 'PARTIALLY_PAID',
                'CANCELLED', 'EXPIRED', 'FAILED'
            ))
        OR (OLD.status = 'PARTIALLY_PAID' AND NEW.status = 'PAID')
        -- Provider money truth dominates an earlier link-control terminal
        -- snapshot. These transitions must only be used with exact,
        -- authenticated collection evidence and monotonic collected_minor.
        OR (OLD.status IN ('CANCELLED', 'EXPIRED') AND
            NEW.status IN ('PAID', 'PARTIALLY_PAID'));

    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid recovery instrument transition: % -> %',
            OLD.status, NEW.status USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION retrywise.enforce_recovery_instrument_lifecycle() IS
    'Enforces immutable recovery instruments and lets authenticated late money truth dominate cancelled or expired link snapshots (migration 008).';

COMMIT;
