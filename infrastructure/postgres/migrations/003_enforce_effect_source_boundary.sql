BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- Quarantine any in-flight legacy provider effect carrying replay/simulation
-- provenance before the boundary trigger becomes active.  This is a safe,
-- monotonic EXECUTING -> FAILED_SAFE transition; it never calls a provider and
-- preserves the original source label for audit.
UPDATE retrywise.actions
SET status = 'FAILED_SAFE',
    lease_owner = NULL,
    lease_expires_at = NULL,
    completed_at = clock_timestamp(),
    last_error_code = 'migration_quarantined_non_test_effect'
WHERE status IN ('EXECUTING', 'RECONCILING')
  AND source_label <> 'RAZORPAY_TEST_MODE'
  AND action_type IN (
      'CREATE_STANDARD_PAYMENT_LINK',
      'NOTIFY_EXISTING_LINK',
      'CANCEL_PAYMENT_LINK'
  );

UPDATE retrywise.actions
SET status = 'CANCELLED',
    completed_at = clock_timestamp(),
    last_error_code = 'migration_quarantined_non_test_effect'
WHERE status IN ('PLANNED', 'QUEUED', 'FAILED_RETRYABLE')
  AND source_label <> 'RAZORPAY_TEST_MODE'
  AND action_type IN (
      'CREATE_STANDARD_PAYMENT_LINK',
      'NOTIFY_EXISTING_LINK',
      'CANCEL_PAYMENT_LINK'
  );

UPDATE retrywise.actions
SET status = 'DEAD_LETTER',
    completed_at = clock_timestamp(),
    last_error_code = 'migration_quarantined_non_test_effect',
    dead_lettered_at = clock_timestamp(),
    dead_letter_reason = 'migration_quarantined_non_test_effect'
WHERE status = 'UNCERTAIN'
  AND source_label <> 'RAZORPAY_TEST_MODE'
  AND action_type IN (
      'CREATE_STANDARD_PAYMENT_LINK',
      'NOTIFY_EXISTING_LINK',
      'CANCEL_PAYMENT_LINK'
  );

CREATE FUNCTION retrywise.enforce_effect_source_boundary()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
BEGIN
    IF NEW.status = 'EXECUTING'
       AND (TG_OP = 'INSERT' OR NEW.status IS DISTINCT FROM OLD.status)
       AND NEW.action_type IN (
           'CREATE_STANDARD_PAYMENT_LINK',
           'NOTIFY_EXISTING_LINK',
           'CANCEL_PAYMENT_LINK'
       )
       AND NEW.source_label <> 'RAZORPAY_TEST_MODE' THEN
        RAISE EXCEPTION
            'provider effects are forbidden outside RAZORPAY_TEST_MODE'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION retrywise.enforce_effect_source_boundary() IS
    'Defense in depth: replay and simulation evidence can never enter a provider-effect execution state.';

CREATE TRIGGER actions_05_enforce_effect_source_boundary
BEFORE INSERT OR UPDATE ON retrywise.actions
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_effect_source_boundary();

COMMIT;
