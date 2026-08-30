BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- Provider evidence is append-only, so an unsafe legacy attribution cannot be
-- rewritten honestly.  Fail with an actionable preflight error instead of
-- installing a trigger that would silently grandfather misbound evidence.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM retrywise.provider_events AS event
        WHERE NOT EXISTS (
            SELECT 1
            FROM retrywise.provider_accounts AS account
            WHERE account.merchant_id = event.merchant_id
              AND account.id = event.provider_account_id
              AND account.provider = 'RAZORPAY'
              AND account.environment = 'TEST'
              AND account.provider_account_identifier =
                  event.canonical_event ->> 'provider_account_id'
        )
    ) THEN
        RAISE EXCEPTION
            'legacy provider evidence has an unsafe account binding'
            USING ERRCODE = '23514',
                  HINT = 'Quarantine and review the affected append-only evidence before retrying migration 005.';
    END IF;
END;
$$;

CREATE FUNCTION retrywise.enforce_provider_event_account_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM retrywise.provider_accounts AS account
        WHERE account.merchant_id = NEW.merchant_id
          AND account.id = NEW.provider_account_id
          AND account.provider = 'RAZORPAY'
          AND account.environment = 'TEST'
          AND account.enabled
          AND account.provider_account_identifier =
              NEW.canonical_event ->> 'provider_account_id'
    ) THEN
        RAISE EXCEPTION
            'provider event does not match an enabled Razorpay TEST account binding'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION retrywise.enforce_provider_event_account_binding() IS
    'Prevents signed evidence from one provider account being attributed to another tenant account row.';

CREATE TRIGGER provider_events_05_enforce_account_binding
BEFORE INSERT ON retrywise.provider_events
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_provider_event_account_binding();

COMMIT;
