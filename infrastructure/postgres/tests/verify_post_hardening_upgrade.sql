\set ON_ERROR_STOP on

DO $$
DECLARE
    terminal_contract smallint;
    terminal_start timestamptz;
    terminal_deadline timestamptz;
BEGIN
    SELECT
        observation_contract_version,
        observation_started_at,
        observation_deadline_at
    INTO terminal_contract, terminal_start, terminal_deadline
    FROM retrywise.recovery_cases
    WHERE id = '01J00000000000000000000005';

    IF terminal_contract <> 0
       OR terminal_start IS NOT NULL
       OR terminal_deadline IS NOT NULL THEN
        RAISE EXCEPTION 'migration invented observation evidence for a legacy terminal row';
    END IF;

    BEGIN
        UPDATE retrywise.recovery_cases
        SET state = 'ASSESSING',
            version = version + 1
        WHERE id = '01J00000000000000000000006';
        RAISE EXCEPTION 'legacy active row advanced without trusted observation evidence';
    EXCEPTION
        WHEN SQLSTATE '23514' THEN NULL;
    END;
END;
$$;

-- Migration 006 must not fabricate outbound authorization for the legacy
-- account. Version-zero rows remain valid webhook-ingress bindings.
DO $$
DECLARE
    binding_version bigint;
    key_digest bytea;
BEGIN
    SELECT credential_binding_version, credential_key_id_sha256
    INTO binding_version, key_digest
    FROM retrywise.provider_accounts
    WHERE id = '01J00000000000000000000002';

    IF binding_version <> 0 OR key_digest IS NOT NULL THEN
        RAISE EXCEPTION 'migration invented credential enrollment evidence';
    END IF;
END;
$$;

INSERT INTO retrywise.provider_events (
    id,
    merchant_id,
    provider_account_id,
    provider_event_id,
    event_type,
    resource_type,
    resource_id,
    body_sha256,
    normalized_schema_version,
    canonical_event,
    provider_occurred_at,
    received_at
) VALUES (
    '01J00000000000000000000010',
    '01J00000000000000000000001',
    '01J00000000000000000000002',
    'event_upgrade_fixture_v0_ingress',
    'payment.failed',
    'payment',
    'pay_upgrade_fixture_v0_ingress',
    decode(repeat('cd', 32), 'hex'),
    1,
    '{"provider_account_id":"acct_upgrade_fixture"}'::jsonb,
    clock_timestamp(),
    clock_timestamp()
);

DO $$
DECLARE
    binding_version bigint;
    key_digest bytea;
BEGIN
    BEGIN
        UPDATE retrywise.provider_accounts
        SET credential_binding_version = 1
        WHERE id = '01J00000000000000000000002';
        RAISE EXCEPTION 'version advanced without enrolled material';
    EXCEPTION
        WHEN SQLSTATE '23514' THEN NULL;
    END;

    BEGIN
        UPDATE retrywise.provider_accounts
        SET credential_secret_ref = 'secret/ref/test-key-unenrolled-rotation'
        WHERE id = '01J00000000000000000000002';
        RAISE EXCEPTION 'legacy secret reference changed without enrollment';
    EXCEPTION
        WHEN SQLSTATE '23514' THEN NULL;
    END;

    UPDATE retrywise.provider_accounts
    SET credential_key_id_sha256 = decode(
            'e1880d21e6626593bea19346d3e32702c3d2717c59afa73f3b5fd5fc566b0e99',
            'hex'
        ),
        credential_binding_version = 1
    WHERE id = '01J00000000000000000000002';

    BEGIN
        UPDATE retrywise.provider_accounts
        SET credential_binding_version = 2
        WHERE id = '01J00000000000000000000002';
        RAISE EXCEPTION 'version advanced without credential rotation';
    EXCEPTION
        WHEN SQLSTATE '23514' THEN NULL;
    END;

    BEGIN
        UPDATE retrywise.provider_accounts
        SET credential_secret_ref = 'secret/ref/test-key-version-2',
            credential_key_id_sha256 = decode(
                'a87b41057f679fd821d3a64f725ece2096f2eccf434f1f5ff89d250077da18d6',
                'hex'
            ),
            credential_binding_version = 3
        WHERE id = '01J00000000000000000000002';
        RAISE EXCEPTION 'credential generation skipped a version';
    EXCEPTION
        WHEN SQLSTATE '23514' THEN NULL;
    END;

    BEGIN
        UPDATE retrywise.provider_accounts
        SET environment = 'LIVE'
        WHERE id = '01J00000000000000000000002';
        RAISE EXCEPTION 'provider account environment mutation succeeded';
    EXCEPTION
        WHEN SQLSTATE '55000' THEN NULL;
    END;

    UPDATE retrywise.provider_accounts
    SET credential_secret_ref = 'secret/ref/test-key-version-2',
        credential_key_id_sha256 = decode(
            'a87b41057f679fd821d3a64f725ece2096f2eccf434f1f5ff89d250077da18d6',
            'hex'
        ),
        credential_binding_version = 2
    WHERE id = '01J00000000000000000000002';

    SELECT credential_binding_version, credential_key_id_sha256
    INTO binding_version, key_digest
    FROM retrywise.provider_accounts
    WHERE id = '01J00000000000000000000002';

    IF binding_version <> 2
       OR key_digest <> decode(
           'a87b41057f679fd821d3a64f725ece2096f2eccf434f1f5ff89d250077da18d6',
           'hex'
       ) THEN
        RAISE EXCEPTION 'valid credential rotation was not persisted exactly';
    END IF;
END;
$$;

INSERT INTO retrywise.logical_orders (
    id,
    merchant_id,
    provider_account_id,
    merchant_order_reference,
    amount_due_minor,
    currency,
    canonical_truth,
    truth_version,
    provider_snapshot_at
) VALUES (
    '01J00000000000000000000008',
    '01J00000000000000000000001',
    '01J00000000000000000000002',
    'post-hardening-order',
    30000,
    'INR',
    'UNPAID',
    1,
    clock_timestamp()
);

-- The caller intentionally supplies its own exact two-minute deadline.  The
-- trigger must use one later PostgreSQL clock and clamp the value instead of
-- rejecting it because of application-to-database latency.
INSERT INTO retrywise.recovery_cases (
    id,
    merchant_id,
    logical_order_id,
    provider_account_id,
    currency,
    amount_due_snapshot_minor,
    state,
    observation_deadline_at
) VALUES (
    '01J00000000000000000000009',
    '01J00000000000000000000001',
    '01J00000000000000000000008',
    '01J00000000000000000000002',
    'INR',
    30000,
    'OBSERVING',
    clock_timestamp() + interval '2 minutes'
);

DO $$
DECLARE
    start_at timestamptz;
    deadline_at timestamptz;
    contract_version smallint;
BEGIN
    SELECT
        observation_started_at,
        observation_deadline_at,
        observation_contract_version
    INTO start_at, deadline_at, contract_version
    FROM retrywise.recovery_cases
    WHERE id = '01J00000000000000000000009';

    IF contract_version <> 1
       OR start_at IS NULL
       OR deadline_at < start_at + interval '2 minutes' THEN
        RAISE EXCEPTION 'new case lacks the database-owned observation floor';
    END IF;

    BEGIN
        UPDATE retrywise.recovery_cases
        SET observation_deadline_at = observation_deadline_at + interval '1 second',
            version = version + 1
        WHERE id = '01J00000000000000000000009';
        RAISE EXCEPTION 'observation timing mutation unexpectedly succeeded';
    EXCEPTION
        WHEN SQLSTATE '55000' THEN NULL;
    END;

    BEGIN
        UPDATE retrywise.recovery_cases
        SET state = 'ASSESSING',
            version = version + 1
        WHERE id = '01J00000000000000000000009';
        RAISE EXCEPTION 'early assessment unexpectedly succeeded';
    EXCEPTION
        WHEN SQLSTATE '23514' THEN NULL;
    END;
END;
$$;
