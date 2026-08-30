\set ON_ERROR_STOP on

-- A realistic pre-003/004/005 database can contain a terminal case whose old
-- schema allowed the observation deadline to be cleared, an active legacy case,
-- and correctly attributed append-only provider evidence.  Later migrations
-- must upgrade this state without inventing safety evidence.

INSERT INTO retrywise.merchants (
    id,
    display_name,
    default_policy_version
) VALUES (
    '01J00000000000000000000001',
    'Upgrade fixture merchant',
    'policy-v1'
);

INSERT INTO retrywise.provider_accounts (
    id,
    merchant_id,
    provider,
    provider_account_identifier,
    environment,
    credential_secret_ref,
    webhook_secret_current_ref
) VALUES (
    '01J00000000000000000000002',
    '01J00000000000000000000001',
    'RAZORPAY',
    'acct_upgrade_fixture',
    'TEST',
    'secret/ref/test-key',
    'secret/ref/webhook-current'
);

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
) VALUES
(
    '01J00000000000000000000003',
    '01J00000000000000000000001',
    '01J00000000000000000000002',
    'upgrade-terminal-order',
    10000,
    'INR',
    'UNPAID',
    1,
    clock_timestamp()
),
(
    '01J00000000000000000000004',
    '01J00000000000000000000001',
    '01J00000000000000000000002',
    'upgrade-active-order',
    20000,
    'INR',
    'UNPAID',
    1,
    clock_timestamp()
);

INSERT INTO retrywise.recovery_cases (
    id,
    merchant_id,
    logical_order_id,
    provider_account_id,
    currency,
    amount_due_snapshot_minor,
    state,
    observation_deadline_at
) VALUES
(
    '01J00000000000000000000005',
    '01J00000000000000000000001',
    '01J00000000000000000000003',
    '01J00000000000000000000002',
    'INR',
    10000,
    'OBSERVING',
    clock_timestamp() + interval '5 minutes'
),
(
    '01J00000000000000000000006',
    '01J00000000000000000000001',
    '01J00000000000000000000004',
    '01J00000000000000000000002',
    'INR',
    20000,
    'OBSERVING',
    clock_timestamp() + interval '5 minutes'
);

UPDATE retrywise.recovery_cases
SET state = 'SUPPRESSED_PAID',
    version = version + 1,
    observation_deadline_at = NULL,
    terminal_reason_code = 'legacy_upgrade_fixture',
    terminal_at = clock_timestamp()
WHERE id = '01J00000000000000000000005';

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
    '01J00000000000000000000007',
    '01J00000000000000000000001',
    '01J00000000000000000000002',
    'event_upgrade_fixture',
    'payment.failed',
    'payment',
    'pay_upgrade_fixture',
    decode(repeat('ab', 32), 'hex'),
    1,
    '{"provider_account_id":"acct_upgrade_fixture"}'::jsonb,
    clock_timestamp(),
    clock_timestamp()
);
