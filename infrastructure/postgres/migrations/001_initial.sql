BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

CREATE SCHEMA IF NOT EXISTS retrywise;

CREATE DOMAIN retrywise.ulid AS varchar(26)
    CHECK (VALUE ~ '^[0-9A-HJKMNP-TV-Z]{26}$');

CREATE DOMAIN retrywise.currency_code AS varchar(3)
    CHECK (VALUE ~ '^[A-Z]{3}$');

CREATE DOMAIN retrywise.sha256_digest AS bytea
    CHECK (octet_length(VALUE) = 32);

CREATE TYPE retrywise.merchant_status AS ENUM (
    'ACTIVE', 'SUSPENDED', 'OFFBOARDED'
);

CREATE TYPE retrywise.provider_name AS ENUM ('RAZORPAY');
CREATE TYPE retrywise.provider_environment AS ENUM ('TEST', 'LIVE');

CREATE TYPE retrywise.inbox_status AS ENUM (
    'RECEIVED',
    'PROCESSING',
    'PROCESSED',
    'IGNORED',
    'RETRY_SCHEDULED',
    'DEAD_LETTER'
);

CREATE TYPE retrywise.canonical_payment_truth AS ENUM (
    'UNKNOWN',
    'UNPAID',
    'AUTHORIZED',
    'PARTIALLY_PAID',
    'PAID',
    'OVERPAID',
    'EXCEPTION'
);

CREATE TYPE retrywise.order_mapping_status AS ENUM (
    'UNMAPPED', 'MAPPED', 'AMBIGUOUS', 'CONFLICT'
);

CREATE TYPE retrywise.provider_payment_status AS ENUM (
    'UNKNOWN', 'CREATED', 'AUTHORIZED', 'CAPTURED', 'REFUNDED', 'FAILED'
);

CREATE TYPE retrywise.recovery_case_state AS ENUM (
    'OBSERVING',
    'ASSESSING',
    'WAITING',
    'APPROVAL_REQUIRED',
    'ACTION_QUEUED',
    'EXECUTING',
    'ACTION_UNCERTAIN',
    'ACTIVE',
    'RECOVERED',
    'SUPPRESSED_PAID',
    'SUPPRESSED_POLICY',
    'EXHAUSTED',
    'FAILED_SAFE',
    'ESCALATED',
    'DUPLICATE_REVIEW'
);

CREATE TYPE retrywise.recovery_instrument_status AS ENUM (
    'CREATING',
    'UNCERTAIN',
    'ISSUED',
    'ACTIVE',
    'CANCEL_PENDING',
    'PAID',
    'PARTIALLY_PAID',
    'CANCELLED',
    'EXPIRED',
    'FAILED'
);

CREATE TYPE retrywise.incident_state AS ENUM (
    'NORMAL', 'SUSPECTED', 'CONFIRMED', 'COOLING'
);

CREATE TYPE retrywise.incident_severity AS ENUM (
    'LOW', 'MEDIUM', 'HIGH'
);

CREATE TYPE retrywise.source_label AS ENUM (
    'RAZORPAY_TEST_MODE', 'REPLAY', 'SIMULATION'
);

CREATE TYPE retrywise.action_type AS ENUM (
    'WAIT',
    'CREATE_STANDARD_PAYMENT_LINK',
    'NOTIFY_EXISTING_LINK',
    'CANCEL_PAYMENT_LINK',
    'ESCALATE',
    'STOP'
);

CREATE TYPE retrywise.gate_verdict AS ENUM (
    'ALLOWED', 'BLOCKED', 'APPROVAL_REQUIRED'
);

CREATE TYPE retrywise.approval_verdict AS ENUM (
    'PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED'
);

CREATE TYPE retrywise.action_status AS ENUM (
    'PLANNED',
    'QUEUED',
    'EXECUTING',
    'SUCCEEDED',
    'FAILED_RETRYABLE',
    'FAILED_SAFE',
    'UNCERTAIN',
    'RECONCILING',
    'RECONCILED',
    'DEAD_LETTER',
    'CANCELLED'
);

CREATE TYPE retrywise.reconciliation_status AS ENUM (
    'NOT_REQUIRED', 'PENDING', 'CONFIRMED', 'CONFLICT', 'UNKNOWN'
);

CREATE TYPE retrywise.audit_actor_type AS ENUM (
    'SYSTEM', 'WORKER', 'OPERATOR', 'MODEL', 'PROVIDER'
);

CREATE TYPE retrywise.outbox_status AS ENUM (
    'PENDING',
    'IN_PROGRESS',
    'RETRY_SCHEDULED',
    'SUCCEEDED',
    'DEAD_LETTER',
    'CANCELLED'
);

CREATE TYPE retrywise.evaluation_status AS ENUM (
    'PLANNED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED'
);

CREATE FUNCTION retrywise.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
BEGIN
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.forbid_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE FUNCTION retrywise.enforce_merchant_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'merchants cannot be deleted; offboard them instead'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'merchant identity and creation time are immutable'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TABLE retrywise.merchants (
    id retrywise.ulid PRIMARY KEY,
    display_name text NOT NULL CHECK (
        length(btrim(display_name)) BETWEEN 1 AND 200
    ),
    status retrywise.merchant_status NOT NULL DEFAULT 'ACTIVE',
    timezone text NOT NULL DEFAULT 'UTC' CHECK (
        length(btrim(timezone)) BETWEEN 1 AND 100
    ),
    kill_switch_enabled boolean NOT NULL DEFAULT false,
    default_policy_version text NOT NULL CHECK (
        length(btrim(default_policy_version)) BETWEEN 1 AND 100
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (updated_at >= created_at),
    UNIQUE (id, status)
);

CREATE TABLE retrywise.provider_accounts (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    provider retrywise.provider_name NOT NULL,
    provider_account_identifier text NOT NULL CHECK (
        length(btrim(provider_account_identifier)) BETWEEN 1 AND 128
    ),
    environment retrywise.provider_environment NOT NULL,
    credential_secret_ref text NOT NULL CHECK (
        length(btrim(credential_secret_ref)) BETWEEN 1 AND 500
    ),
    webhook_secret_current_ref text NOT NULL CHECK (
        length(btrim(webhook_secret_current_ref)) BETWEEN 1 AND 500
    ),
    webhook_secret_previous_ref text,
    webhook_secret_previous_valid_until timestamptz,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT provider_accounts_merchant_fk
        FOREIGN KEY (merchant_id) REFERENCES retrywise.merchants (id),
    CONSTRAINT provider_accounts_previous_secret_pair_ck CHECK (
        (webhook_secret_previous_ref IS NULL AND
         webhook_secret_previous_valid_until IS NULL)
        OR
        (webhook_secret_previous_ref IS NOT NULL AND
         length(btrim(webhook_secret_previous_ref)) BETWEEN 1 AND 500 AND
         webhook_secret_previous_valid_until IS NOT NULL)
    ),
    CHECK (updated_at >= created_at),
    UNIQUE (merchant_id, id),
    UNIQUE (provider, provider_account_identifier, environment)
);

CREATE TABLE retrywise.provider_events (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    provider_account_id retrywise.ulid NOT NULL,
    provider_event_id text NOT NULL CHECK (
        length(btrim(provider_event_id)) BETWEEN 1 AND 256
    ),
    event_type text NOT NULL CHECK (
        length(btrim(event_type)) BETWEEN 1 AND 200
    ),
    resource_type text NOT NULL CHECK (
        length(btrim(resource_type)) BETWEEN 1 AND 100
    ),
    resource_id text,
    body_sha256 retrywise.sha256_digest NOT NULL,
    signature_version smallint NOT NULL DEFAULT 1 CHECK (signature_version > 0),
    signature_verified boolean NOT NULL DEFAULT true
        CHECK (signature_verified),
    account_verified boolean NOT NULL DEFAULT true
        CHECK (account_verified),
    normalized_schema_version integer NOT NULL CHECK (
        normalized_schema_version > 0
    ),
    canonical_event jsonb NOT NULL CHECK (
        jsonb_typeof(canonical_event) = 'object'
    ),
    provider_occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    raw_evidence_ref text,
    raw_evidence_expires_at timestamptz,
    retention_class text NOT NULL DEFAULT 'AUDIT' CHECK (
        length(btrim(retention_class)) BETWEEN 1 AND 50
    ),
    CONSTRAINT provider_events_provider_account_fk
        FOREIGN KEY (merchant_id, provider_account_id)
        REFERENCES retrywise.provider_accounts (merchant_id, id),
    CONSTRAINT provider_events_evidence_pair_ck CHECK (
        (raw_evidence_ref IS NULL AND raw_evidence_expires_at IS NULL)
        OR
        (raw_evidence_ref IS NOT NULL AND
         length(btrim(raw_evidence_ref)) BETWEEN 1 AND 1000 AND
         raw_evidence_expires_at IS NOT NULL)
    ),
    UNIQUE (provider_account_id, provider_event_id),
    UNIQUE (merchant_id, provider_account_id, id)
);

CREATE TABLE retrywise.inbox_events (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    provider_account_id retrywise.ulid NOT NULL,
    provider_event_record_id retrywise.ulid NOT NULL,
    status retrywise.inbox_status NOT NULL DEFAULT 'RECEIVED',
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL DEFAULT 8 CHECK (max_attempts > 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_owner text,
    lease_expires_at timestamptz,
    last_error_code text,
    last_error_at timestamptz,
    dead_lettered_at timestamptz,
    dead_letter_reason text,
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    processed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT inbox_events_provider_event_fk
        FOREIGN KEY (merchant_id, provider_account_id, provider_event_record_id)
        REFERENCES retrywise.provider_events
            (merchant_id, provider_account_id, id),
    CONSTRAINT inbox_events_attempt_bound_ck CHECK (
        attempt_count <= max_attempts
    ),
    CONSTRAINT inbox_events_lease_ck CHECK (
        (status = 'PROCESSING' AND lease_owner IS NOT NULL AND
         length(btrim(lease_owner)) > 0 AND lease_expires_at IS NOT NULL)
        OR
        (status <> 'PROCESSING' AND lease_owner IS NULL AND
         lease_expires_at IS NULL)
    ),
    CONSTRAINT inbox_events_dead_letter_ck CHECK (
        (status = 'DEAD_LETTER' AND dead_lettered_at IS NOT NULL AND
         dead_letter_reason IS NOT NULL AND
         length(btrim(dead_letter_reason)) > 0)
        OR
        (status <> 'DEAD_LETTER' AND dead_lettered_at IS NULL AND
         dead_letter_reason IS NULL)
    ),
    CONSTRAINT inbox_events_processed_ck CHECK (
        (status IN ('PROCESSED', 'IGNORED') AND processed_at IS NOT NULL)
        OR
        (status NOT IN ('PROCESSED', 'IGNORED') AND processed_at IS NULL)
    ),
    CHECK (updated_at >= accepted_at),
    UNIQUE (merchant_id, provider_event_record_id)
);

CREATE TABLE retrywise.logical_orders (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    provider_account_id retrywise.ulid NOT NULL,
    merchant_order_reference text NOT NULL CHECK (
        length(btrim(merchant_order_reference)) BETWEEN 1 AND 200
    ),
    original_provider_order_id text,
    amount_due_minor bigint NOT NULL CHECK (amount_due_minor > 0),
    currency retrywise.currency_code NOT NULL,
    captured_total_minor bigint NOT NULL DEFAULT 0 CHECK (
        captured_total_minor >= 0
    ),
    refunded_total_minor bigint NOT NULL DEFAULT 0 CHECK (
        refunded_total_minor >= 0 AND
        refunded_total_minor <= captured_total_minor
    ),
    canonical_truth retrywise.canonical_payment_truth NOT NULL DEFAULT 'UNKNOWN',
    truth_version bigint NOT NULL DEFAULT 0 CHECK (truth_version >= 0),
    provider_snapshot_at timestamptz,
    mapping_status retrywise.order_mapping_status NOT NULL DEFAULT 'UNMAPPED',
    mapping_reason_code text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT logical_orders_provider_account_fk
        FOREIGN KEY (merchant_id, provider_account_id)
        REFERENCES retrywise.provider_accounts (merchant_id, id),
    CONSTRAINT logical_orders_truth_amount_ck CHECK (
        canonical_truth IN ('UNKNOWN', 'EXCEPTION')
        OR (canonical_truth IN ('UNPAID', 'AUTHORIZED') AND
            captured_total_minor = 0)
        OR (canonical_truth = 'PARTIALLY_PAID' AND
            captured_total_minor > 0 AND
            captured_total_minor < amount_due_minor)
        OR (canonical_truth = 'PAID' AND
            captured_total_minor = amount_due_minor)
        OR (canonical_truth = 'OVERPAID' AND
            captured_total_minor > amount_due_minor)
    ),
    CONSTRAINT logical_orders_snapshot_ck CHECK (
        canonical_truth = 'UNKNOWN' OR provider_snapshot_at IS NOT NULL
    ),
    CONSTRAINT logical_orders_mapping_ck CHECK (
        mapping_status <> 'MAPPED' OR original_provider_order_id IS NOT NULL
    ),
    CHECK (updated_at >= created_at),
    UNIQUE (merchant_id, id),
    UNIQUE (merchant_id, id, provider_account_id, currency),
    UNIQUE (
        merchant_id,
        id,
        provider_account_id,
        currency,
        amount_due_minor
    ),
    UNIQUE (merchant_id, provider_account_id, merchant_order_reference)
);

CREATE UNIQUE INDEX logical_orders_provider_order_uidx
    ON retrywise.logical_orders
        (merchant_id, provider_account_id, original_provider_order_id)
    WHERE original_provider_order_id IS NOT NULL;

CREATE TABLE retrywise.provider_payments (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    provider_account_id retrywise.ulid NOT NULL,
    logical_order_id retrywise.ulid NOT NULL,
    provider_payment_id text NOT NULL CHECK (
        length(btrim(provider_payment_id)) BETWEEN 1 AND 128
    ),
    provider_order_id text,
    status retrywise.provider_payment_status NOT NULL DEFAULT 'UNKNOWN',
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    currency retrywise.currency_code NOT NULL,
    captured_minor bigint NOT NULL DEFAULT 0 CHECK (
        captured_minor >= 0 AND captured_minor <= amount_minor
    ),
    refunded_minor bigint NOT NULL DEFAULT 0 CHECK (
        refunded_minor >= 0 AND refunded_minor <= captured_minor
    ),
    payment_method text CHECK (
        payment_method IS NULL OR length(btrim(payment_method)) BETWEEN 1 AND 50
    ),
    instrument_context jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(instrument_context) = 'object'
    ),
    error_facts jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(error_facts) = 'object'
    ),
    provider_created_at timestamptz,
    provider_snapshot_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT provider_payments_logical_order_fk
        FOREIGN KEY (
            merchant_id, logical_order_id, provider_account_id, currency
        )
        REFERENCES retrywise.logical_orders
            (merchant_id, id, provider_account_id, currency),
    CONSTRAINT provider_payments_status_money_ck CHECK (
        status = 'UNKNOWN'
        OR (status IN ('CREATED', 'AUTHORIZED', 'FAILED') AND
            captured_minor = 0 AND refunded_minor = 0)
        OR (status = 'CAPTURED' AND captured_minor > 0)
        OR (status = 'REFUNDED' AND captured_minor > 0 AND refunded_minor > 0)
    ),
    CHECK (updated_at >= created_at),
    UNIQUE (merchant_id, id),
    UNIQUE (provider_account_id, provider_payment_id)
);

CREATE TABLE retrywise.incidents (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    provider_account_id retrywise.ulid NOT NULL,
    payment_method text NOT NULL CHECK (
        length(btrim(payment_method)) BETWEEN 1 AND 50
    ),
    instrument_key text NOT NULL CHECK (
        length(btrim(instrument_key)) BETWEEN 1 AND 300
    ),
    instrument_scope jsonb NOT NULL CHECK (
        jsonb_typeof(instrument_scope) = 'object'
    ),
    state retrywise.incident_state NOT NULL,
    severity retrywise.incident_severity NOT NULL,
    confidence numeric(6,5) NOT NULL CHECK (
        confidence >= 0 AND confidence <= 1
    ),
    evidence_summary jsonb NOT NULL CHECK (
        jsonb_typeof(evidence_summary) = 'object'
    ),
    provider_downtime_id text,
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    cooling_deadline_at timestamptz,
    detector_version text NOT NULL CHECK (
        length(btrim(detector_version)) BETWEEN 1 AND 100
    ),
    threshold_version text NOT NULL CHECK (
        length(btrim(threshold_version)) BETWEEN 1 AND 100
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT incidents_provider_account_fk
        FOREIGN KEY (merchant_id, provider_account_id)
        REFERENCES retrywise.provider_accounts (merchant_id, id),
    CONSTRAINT incidents_timeline_ck CHECK (
        first_seen_at <= last_seen_at AND
        last_seen_at <= expires_at AND
        (cooling_deadline_at IS NULL OR cooling_deadline_at >= last_seen_at)
    ),
    CHECK (updated_at >= created_at),
    UNIQUE (merchant_id, id),
    UNIQUE (merchant_id, id, provider_account_id)
);

CREATE UNIQUE INDEX incidents_provider_downtime_uidx
    ON retrywise.incidents (provider_account_id, provider_downtime_id)
    WHERE provider_downtime_id IS NOT NULL;

CREATE UNIQUE INDEX incidents_active_scope_uidx
    ON retrywise.incidents
        (merchant_id, provider_account_id, payment_method, instrument_key)
    WHERE state IN ('SUSPECTED', 'CONFIRMED', 'COOLING');

CREATE TABLE retrywise.recovery_cases (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    logical_order_id retrywise.ulid NOT NULL,
    provider_account_id retrywise.ulid NOT NULL,
    currency retrywise.currency_code NOT NULL,
    amount_due_snapshot_minor bigint NOT NULL CHECK (
        amount_due_snapshot_minor > 0
    ),
    state retrywise.recovery_case_state NOT NULL,
    incident_id retrywise.ulid,
    incident_scope jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(incident_scope) = 'object'
    ),
    observation_deadline_at timestamptz,
    evaluation_deadline_at timestamptz,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    contact_count integer NOT NULL DEFAULT 0 CHECK (contact_count >= 0),
    terminal_reason_code text,
    terminal_at timestamptz,
    last_decision_id retrywise.ulid,
    last_decision_at timestamptz,
    last_action_id retrywise.ulid,
    last_action_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT recovery_cases_logical_order_fk
        FOREIGN KEY (
            merchant_id,
            logical_order_id,
            provider_account_id,
            currency,
            amount_due_snapshot_minor
        )
        REFERENCES retrywise.logical_orders
            (merchant_id, id, provider_account_id, currency, amount_due_minor),
    CONSTRAINT recovery_cases_incident_fk
        FOREIGN KEY (merchant_id, incident_id, provider_account_id)
        REFERENCES retrywise.incidents (merchant_id, id, provider_account_id),
    CONSTRAINT recovery_cases_observation_ck CHECK (
        state <> 'OBSERVING' OR observation_deadline_at IS NOT NULL
    ),
    CONSTRAINT recovery_cases_terminal_ck CHECK (
        (
            state IN (
                'RECOVERED', 'SUPPRESSED_PAID', 'SUPPRESSED_POLICY',
                'EXHAUSTED', 'FAILED_SAFE', 'ESCALATED', 'DUPLICATE_REVIEW'
            )
            AND terminal_reason_code IS NOT NULL
            AND length(btrim(terminal_reason_code)) > 0
            AND terminal_at IS NOT NULL
        )
        OR
        (
            state NOT IN (
                'RECOVERED', 'SUPPRESSED_PAID', 'SUPPRESSED_POLICY',
                'EXHAUSTED', 'FAILED_SAFE', 'ESCALATED', 'DUPLICATE_REVIEW'
            )
            AND terminal_reason_code IS NULL
            AND terminal_at IS NULL
        )
    ),
    CONSTRAINT recovery_cases_last_decision_pair_ck CHECK (
        (last_decision_id IS NULL AND last_decision_at IS NULL)
        OR (last_decision_id IS NOT NULL AND last_decision_at IS NOT NULL)
    ),
    CONSTRAINT recovery_cases_last_action_pair_ck CHECK (
        (last_action_id IS NULL AND last_action_at IS NULL)
        OR (last_action_id IS NOT NULL AND last_action_at IS NOT NULL)
    ),
    CHECK (updated_at >= created_at),
    UNIQUE (merchant_id, id),
    UNIQUE (merchant_id, id, logical_order_id),
    UNIQUE (
        merchant_id,
        id,
        logical_order_id,
        provider_account_id,
        currency,
        amount_due_snapshot_minor
    )
);

CREATE UNIQUE INDEX recovery_cases_one_open_order_currency_uidx
    ON retrywise.recovery_cases (merchant_id, logical_order_id, currency)
    WHERE state IN (
        'OBSERVING',
        'ASSESSING',
        'WAITING',
        'APPROVAL_REQUIRED',
        'ACTION_QUEUED',
        'EXECUTING',
        'ACTION_UNCERTAIN',
        'ACTIVE'
    );

CREATE TABLE retrywise.decisions (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    recovery_case_id retrywise.ulid NOT NULL,
    logical_order_id retrywise.ulid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version >= 0),
    feature_schema_version integer NOT NULL CHECK (feature_schema_version > 0),
    feature_snapshot jsonb NOT NULL CHECK (
        jsonb_typeof(feature_snapshot) = 'object'
    ),
    feature_snapshot_sha256 retrywise.sha256_digest NOT NULL,
    model_name text NOT NULL CHECK (
        length(btrim(model_name)) BETWEEN 1 AND 100
    ),
    model_version text NOT NULL CHECK (
        length(btrim(model_version)) BETWEEN 1 AND 100
    ),
    class_probabilities jsonb NOT NULL CHECK (
        jsonb_typeof(class_probabilities) = 'object'
    ),
    abstained boolean NOT NULL,
    out_of_distribution boolean NOT NULL,
    policy_name text NOT NULL CHECK (
        length(btrim(policy_name)) BETWEEN 1 AND 100
    ),
    policy_version text NOT NULL CHECK (
        length(btrim(policy_version)) BETWEEN 1 AND 100
    ),
    candidates jsonb NOT NULL CHECK (jsonb_typeof(candidates) = 'array'),
    selected_action retrywise.action_type,
    planning_gate_verdict retrywise.gate_verdict NOT NULL,
    planning_gate_reason_codes text[] NOT NULL DEFAULT '{}'::text[] CHECK (
        array_position(planning_gate_reason_codes, NULL) IS NULL
    ),
    expected_value_inputs jsonb NOT NULL CHECK (
        jsonb_typeof(expected_value_inputs) = 'object'
    ),
    expected_value_minor numeric(24,6),
    source_label retrywise.source_label NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT decisions_case_fk
        FOREIGN KEY (merchant_id, recovery_case_id, logical_order_id)
        REFERENCES retrywise.recovery_cases
            (merchant_id, id, logical_order_id),
    CONSTRAINT decisions_selected_action_ck CHECK (
        (planning_gate_verdict = 'BLOCKED' AND selected_action IS NULL)
        OR
        (planning_gate_verdict <> 'BLOCKED' AND selected_action IS NOT NULL)
    ),
    UNIQUE (merchant_id, recovery_case_id, aggregate_version),
    UNIQUE (merchant_id, id),
    UNIQUE (merchant_id, id, recovery_case_id),
    UNIQUE (
        merchant_id,
        id,
        recovery_case_id,
        aggregate_version
    ),
    UNIQUE (
        merchant_id,
        id,
        recovery_case_id,
        aggregate_version,
        source_label
    )
);

CREATE TABLE retrywise.approvals (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    recovery_case_id retrywise.ulid NOT NULL,
    decision_id retrywise.ulid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version >= 0),
    verdict retrywise.approval_verdict NOT NULL DEFAULT 'PENDING',
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    approver_subject text,
    reason_code text,
    acted_at timestamptz,
    CONSTRAINT approvals_decision_fk
        FOREIGN KEY (
            merchant_id, decision_id, recovery_case_id, aggregate_version
        )
        REFERENCES retrywise.decisions
            (merchant_id, id, recovery_case_id, aggregate_version),
    CONSTRAINT approvals_timeline_ck CHECK (expires_at > requested_at),
    CONSTRAINT approvals_verdict_ck CHECK (
        (
            verdict = 'PENDING'
            AND approver_subject IS NULL
            AND reason_code IS NULL
            AND acted_at IS NULL
        )
        OR
        (
            verdict <> 'PENDING'
            AND acted_at IS NOT NULL
            AND acted_at >= requested_at
            AND (verdict <> 'APPROVED' OR acted_at <= expires_at)
            AND reason_code IS NOT NULL
            AND length(btrim(reason_code)) > 0
            AND (
                verdict IN ('EXPIRED', 'CANCELLED')
                OR (approver_subject IS NOT NULL AND
                    length(btrim(approver_subject)) > 0)
            )
        )
    ),
    UNIQUE (merchant_id, id),
    UNIQUE (merchant_id, decision_id),
    UNIQUE (
        merchant_id,
        id,
        decision_id,
        recovery_case_id,
        aggregate_version
    )
);

CREATE TABLE retrywise.actions (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    recovery_case_id retrywise.ulid NOT NULL,
    decision_id retrywise.ulid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version >= 0),
    approval_id retrywise.ulid,
    action_key text NOT NULL CHECK (
        length(btrim(action_key)) BETWEEN 1 AND 200
    ),
    action_type retrywise.action_type NOT NULL,
    source_label retrywise.source_label NOT NULL,
    status retrywise.action_status NOT NULL DEFAULT 'PLANNED',
    attempt_number integer NOT NULL DEFAULT 0 CHECK (attempt_number >= 0),
    max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts > 0),
    lease_owner text,
    lease_expires_at timestamptz,
    effect_gate_snapshot jsonb CHECK (
        effect_gate_snapshot IS NULL OR
        jsonb_typeof(effect_gate_snapshot) = 'object'
    ),
    effect_gate_verdict retrywise.gate_verdict,
    effect_gate_reason_codes text[] NOT NULL DEFAULT '{}'::text[] CHECK (
        array_position(effect_gate_reason_codes, NULL) IS NULL
    ),
    request_metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(request_metadata) = 'object'
    ),
    response_metadata jsonb CHECK (
        response_metadata IS NULL OR jsonb_typeof(response_metadata) = 'object'
    ),
    provider_status text,
    reconciliation_status retrywise.reconciliation_status NOT NULL
        DEFAULT 'NOT_REQUIRED',
    external_reference_id text,
    provider_resource_id text,
    scheduled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    first_attempted_at timestamptz,
    last_attempted_at timestamptz,
    completed_at timestamptz,
    last_error_code text,
    dead_lettered_at timestamptz,
    dead_letter_reason text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT actions_decision_fk
        FOREIGN KEY (
            merchant_id,
            decision_id,
            recovery_case_id,
            aggregate_version,
            source_label
        )
        REFERENCES retrywise.decisions
            (merchant_id, id, recovery_case_id, aggregate_version, source_label),
    CONSTRAINT actions_approval_fk
        FOREIGN KEY (
            merchant_id,
            approval_id,
            decision_id,
            recovery_case_id,
            aggregate_version
        )
        REFERENCES retrywise.approvals
            (merchant_id, id, decision_id, recovery_case_id, aggregate_version),
    CONSTRAINT actions_attempt_bound_ck CHECK (
        attempt_number <= max_attempts
    ),
    CONSTRAINT actions_lease_ck CHECK (
        (
            status IN ('EXECUTING', 'RECONCILING')
            AND lease_owner IS NOT NULL
            AND length(btrim(lease_owner)) > 0
            AND lease_expires_at IS NOT NULL
        )
        OR
        (
            status NOT IN ('EXECUTING', 'RECONCILING')
            AND lease_owner IS NULL
            AND lease_expires_at IS NULL
        )
    ),
    CONSTRAINT actions_attempt_timeline_ck CHECK (
        (first_attempted_at IS NULL AND last_attempted_at IS NULL)
        OR
        (first_attempted_at IS NOT NULL AND last_attempted_at IS NOT NULL AND
         last_attempted_at >= first_attempted_at)
    ),
    CONSTRAINT actions_effect_gate_pair_ck CHECK (
        (
            effect_gate_snapshot IS NULL
            AND effect_gate_verdict IS NULL
            AND cardinality(effect_gate_reason_codes) = 0
        )
        OR
        (
            effect_gate_snapshot IS NOT NULL
            AND effect_gate_verdict IS NOT NULL
            AND (
                effect_gate_verdict = 'ALLOWED'
                OR cardinality(effect_gate_reason_codes) > 0
            )
        )
    ),
    CONSTRAINT actions_execution_evidence_ck CHECK (
        status NOT IN (
            'EXECUTING', 'SUCCEEDED', 'FAILED_RETRYABLE', 'FAILED_SAFE',
            'UNCERTAIN', 'RECONCILING', 'RECONCILED'
        )
        OR
        (
            effect_gate_snapshot IS NOT NULL
            AND effect_gate_verdict = 'ALLOWED'
            AND first_attempted_at IS NOT NULL
        )
    ),
    CONSTRAINT actions_completion_ck CHECK (
        (
            status IN (
                'SUCCEEDED', 'FAILED_SAFE', 'RECONCILED',
                'DEAD_LETTER', 'CANCELLED'
            )
            AND completed_at IS NOT NULL
        )
        OR
        (
            status NOT IN (
                'SUCCEEDED', 'FAILED_SAFE', 'RECONCILED',
                'DEAD_LETTER', 'CANCELLED'
            )
            AND completed_at IS NULL
        )
    ),
    CONSTRAINT actions_dead_letter_ck CHECK (
        (
            status = 'DEAD_LETTER'
            AND dead_lettered_at IS NOT NULL
            AND dead_letter_reason IS NOT NULL
            AND length(btrim(dead_letter_reason)) > 0
        )
        OR
        (
            status <> 'DEAD_LETTER'
            AND dead_lettered_at IS NULL
            AND dead_letter_reason IS NULL
        )
    ),
    CHECK (updated_at >= created_at),
    UNIQUE (merchant_id, id),
    UNIQUE (merchant_id, id, recovery_case_id),
    UNIQUE (merchant_id, action_key)
);

CREATE TABLE retrywise.recovery_instruments (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    recovery_case_id retrywise.ulid NOT NULL,
    logical_order_id retrywise.ulid NOT NULL,
    provider_account_id retrywise.ulid NOT NULL,
    action_id retrywise.ulid NOT NULL,
    provider_payment_link_id text,
    provider_order_id text,
    provider_payment_id text,
    reference_id text NOT NULL CHECK (
        length(btrim(reference_id)) BETWEEN 1 AND 40
    ),
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    currency retrywise.currency_code NOT NULL,
    status retrywise.recovery_instrument_status NOT NULL,
    accept_partial boolean NOT NULL DEFAULT false CHECK (NOT accept_partial),
    collected_minor bigint NOT NULL DEFAULT 0 CHECK (
        collected_minor >= 0 AND collected_minor <= amount_minor
    ),
    refunded_minor bigint NOT NULL DEFAULT 0 CHECK (
        refunded_minor >= 0 AND refunded_minor <= collected_minor
    ),
    expires_at timestamptz NOT NULL,
    last_provider_status text,
    reconciliation_status retrywise.reconciliation_status NOT NULL
        DEFAULT 'PENDING',
    last_reconciled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT recovery_instruments_case_fk
        FOREIGN KEY (
            merchant_id,
            recovery_case_id,
            logical_order_id,
            provider_account_id,
            currency,
            amount_minor
        )
        REFERENCES retrywise.recovery_cases
            (
                merchant_id,
                id,
                logical_order_id,
                provider_account_id,
                currency,
                amount_due_snapshot_minor
            ),
    CONSTRAINT recovery_instruments_action_fk
        FOREIGN KEY (merchant_id, action_id, recovery_case_id)
        REFERENCES retrywise.actions (merchant_id, id, recovery_case_id),
    CONSTRAINT recovery_instruments_provider_id_ck CHECK (
        provider_payment_link_id IS NOT NULL
        OR status IN ('CREATING', 'UNCERTAIN', 'FAILED')
    ),
    CONSTRAINT recovery_instruments_collection_ck CHECK (
        (status = 'PAID' AND collected_minor = amount_minor)
        OR
        (status = 'PARTIALLY_PAID' AND collected_minor > 0 AND
         collected_minor < amount_minor)
        OR (status NOT IN ('PAID', 'PARTIALLY_PAID') AND
            collected_minor = 0)
    ),
    CONSTRAINT recovery_instruments_expiry_ck CHECK (expires_at > created_at),
    CHECK (updated_at >= created_at),
    UNIQUE (merchant_id, id),
    UNIQUE (merchant_id, action_id),
    UNIQUE (provider_account_id, reference_id)
);

CREATE UNIQUE INDEX recovery_instruments_provider_link_uidx
    ON retrywise.recovery_instruments
        (provider_account_id, provider_payment_link_id)
    WHERE provider_payment_link_id IS NOT NULL;

CREATE UNIQUE INDEX recovery_instruments_one_collectable_uidx
    ON retrywise.recovery_instruments
        (merchant_id, logical_order_id, currency)
    WHERE status IN (
        'CREATING', 'UNCERTAIN', 'ISSUED', 'ACTIVE', 'CANCEL_PENDING'
    );

CREATE TABLE retrywise.audit_entries (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    recovery_case_id retrywise.ulid NOT NULL,
    sequence_number bigint NOT NULL CHECK (sequence_number > 0),
    entry_type text NOT NULL CHECK (
        length(btrim(entry_type)) BETWEEN 1 AND 100
    ),
    actor_type retrywise.audit_actor_type NOT NULL,
    actor_subject text,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    previous_entry_hash retrywise.sha256_digest,
    entry_hash retrywise.sha256_digest NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_entries_case_fk
        FOREIGN KEY (merchant_id, recovery_case_id)
        REFERENCES retrywise.recovery_cases (merchant_id, id),
    CONSTRAINT audit_entries_chain_shape_ck CHECK (
        (sequence_number = 1 AND previous_entry_hash IS NULL)
        OR (sequence_number > 1 AND previous_entry_hash IS NOT NULL)
    ),
    UNIQUE (merchant_id, recovery_case_id, sequence_number),
    UNIQUE (merchant_id, recovery_case_id, entry_hash)
);

CREATE TABLE retrywise.outbox_jobs (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    aggregate_type text NOT NULL CHECK (
        length(btrim(aggregate_type)) BETWEEN 1 AND 100
    ),
    aggregate_id text NOT NULL CHECK (
        length(btrim(aggregate_id)) BETWEEN 1 AND 200
    ),
    command_type text NOT NULL CHECK (
        length(btrim(command_type)) BETWEEN 1 AND 100
    ),
    command_schema_version integer NOT NULL CHECK (command_schema_version > 0),
    command_payload jsonb NOT NULL CHECK (
        jsonb_typeof(command_payload) = 'object'
    ),
    idempotency_key text NOT NULL CHECK (
        length(btrim(idempotency_key)) BETWEEN 1 AND 300
    ),
    status retrywise.outbox_status NOT NULL DEFAULT 'PENDING',
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL DEFAULT 8 CHECK (max_attempts > 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_owner text,
    lease_expires_at timestamptz,
    last_error_code text,
    last_error_at timestamptz,
    dead_lettered_at timestamptz,
    dead_letter_reason text,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT outbox_jobs_merchant_fk
        FOREIGN KEY (merchant_id) REFERENCES retrywise.merchants (id),
    CONSTRAINT outbox_jobs_attempt_bound_ck CHECK (
        attempt_count <= max_attempts
    ),
    CONSTRAINT outbox_jobs_lease_ck CHECK (
        (
            status = 'IN_PROGRESS'
            AND lease_owner IS NOT NULL
            AND length(btrim(lease_owner)) > 0
            AND lease_expires_at IS NOT NULL
        )
        OR
        (
            status <> 'IN_PROGRESS'
            AND lease_owner IS NULL
            AND lease_expires_at IS NULL
        )
    ),
    CONSTRAINT outbox_jobs_dead_letter_ck CHECK (
        (
            status = 'DEAD_LETTER'
            AND dead_lettered_at IS NOT NULL
            AND dead_letter_reason IS NOT NULL
            AND length(btrim(dead_letter_reason)) > 0
        )
        OR
        (
            status <> 'DEAD_LETTER'
            AND dead_lettered_at IS NULL
            AND dead_letter_reason IS NULL
        )
    ),
    CONSTRAINT outbox_jobs_completion_ck CHECK (
        (
            status IN ('SUCCEEDED', 'CANCELLED')
            AND completed_at IS NOT NULL
        )
        OR
        (
            status NOT IN ('SUCCEEDED', 'CANCELLED')
            AND completed_at IS NULL
        )
    ),
    CHECK (updated_at >= created_at),
    UNIQUE (merchant_id, id),
    UNIQUE (merchant_id, idempotency_key)
);

CREATE TABLE retrywise.evaluation_runs (
    id retrywise.ulid PRIMARY KEY,
    merchant_id retrywise.ulid NOT NULL,
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    source_label retrywise.source_label NOT NULL,
    status retrywise.evaluation_status NOT NULL DEFAULT 'PLANNED',
    seed_set jsonb NOT NULL CHECK (jsonb_typeof(seed_set) = 'array'),
    dataset_sha256 retrywise.sha256_digest NOT NULL,
    code_revision text NOT NULL CHECK (
        length(btrim(code_revision)) BETWEEN 1 AND 200
    ),
    policy_version text NOT NULL CHECK (
        length(btrim(policy_version)) BETWEEN 1 AND 100
    ),
    model_version text NOT NULL CHECK (
        length(btrim(model_version)) BETWEEN 1 AND 100
    ),
    cost_version text NOT NULL CHECK (
        length(btrim(cost_version)) BETWEEN 1 AND 100
    ),
    manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    manifest_sha256 retrywise.sha256_digest NOT NULL,
    aggregate_metrics jsonb CHECK (
        aggregate_metrics IS NULL OR jsonb_typeof(aggregate_metrics) = 'object'
    ),
    artifact_references jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(artifact_references) = 'array'
    ),
    failure_code text,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT evaluation_runs_merchant_fk
        FOREIGN KEY (merchant_id) REFERENCES retrywise.merchants (id),
    CONSTRAINT evaluation_runs_status_ck CHECK (
        (status = 'PLANNED' AND started_at IS NULL AND completed_at IS NULL)
        OR
        (status = 'RUNNING' AND started_at IS NOT NULL AND completed_at IS NULL)
        OR
        (status IN ('SUCCEEDED', 'FAILED', 'CANCELLED') AND
         completed_at IS NOT NULL AND
         (started_at IS NULL OR completed_at >= started_at))
    ),
    CONSTRAINT evaluation_runs_result_ck CHECK (
        (status = 'SUCCEEDED' AND aggregate_metrics IS NOT NULL AND
         failure_code IS NULL)
        OR
        (status = 'FAILED' AND failure_code IS NOT NULL AND
         length(btrim(failure_code)) > 0)
        OR
        status NOT IN ('SUCCEEDED', 'FAILED')
    ),
    CHECK (updated_at >= created_at),
    UNIQUE (merchant_id, id)
);

ALTER TABLE retrywise.recovery_cases
    ADD CONSTRAINT recovery_cases_last_decision_fk
    FOREIGN KEY (merchant_id, last_decision_id, id)
    REFERENCES retrywise.decisions (merchant_id, id, recovery_case_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE retrywise.recovery_cases
    ADD CONSTRAINT recovery_cases_last_action_fk
    FOREIGN KEY (merchant_id, last_action_id, id)
    REFERENCES retrywise.actions (merchant_id, id, recovery_case_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION retrywise.enforce_provider_account_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'provider accounts cannot be deleted; disable them instead'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.provider,
        NEW.provider_account_identifier,
        NEW.environment,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.provider,
        OLD.provider_account_identifier,
        OLD.environment,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'provider account identity and environment are immutable'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.enforce_logical_order_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'logical orders cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.provider_account_id,
        NEW.merchant_order_reference,
        NEW.amount_due_minor,
        NEW.currency,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.provider_account_id,
        OLD.merchant_order_reference,
        OLD.amount_due_minor,
        OLD.currency,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'logical order tenant, provider, identity, and money are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.original_provider_order_id IS NOT NULL
       AND NEW.original_provider_order_id IS DISTINCT FROM
           OLD.original_provider_order_id THEN
        RAISE EXCEPTION 'original provider order id is write-once'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.truth_version <> OLD.truth_version + 1 THEN
        RAISE EXCEPTION 'logical order truth_version must advance exactly by one'
            USING ERRCODE = '40001';
    END IF;

    IF NEW.captured_total_minor < OLD.captured_total_minor
       OR NEW.refunded_total_minor < OLD.refunded_total_minor THEN
        RAISE EXCEPTION 'logical order financial totals cannot decrease'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.provider_snapshot_at IS NOT NULL AND
       (NEW.provider_snapshot_at IS NULL OR
        NEW.provider_snapshot_at < OLD.provider_snapshot_at) THEN
        RAISE EXCEPTION 'provider snapshot time cannot regress'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.canonical_truth = OLD.canonical_truth THEN
        RETURN NEW;
    END IF;

    allowed :=
        (OLD.canonical_truth = 'UNKNOWN')
        OR (OLD.canonical_truth = 'UNPAID' AND
            NEW.canonical_truth IN (
                'AUTHORIZED', 'PARTIALLY_PAID', 'PAID',
                'OVERPAID', 'EXCEPTION'
            ))
        OR (OLD.canonical_truth = 'AUTHORIZED' AND
            NEW.canonical_truth IN (
                'PARTIALLY_PAID', 'PAID', 'OVERPAID', 'EXCEPTION'
            ))
        OR (OLD.canonical_truth = 'PARTIALLY_PAID' AND
            NEW.canonical_truth IN ('PAID', 'OVERPAID', 'EXCEPTION'))
        OR (OLD.canonical_truth = 'PAID' AND
            NEW.canonical_truth IN ('OVERPAID', 'EXCEPTION'))
        OR (OLD.canonical_truth = 'OVERPAID' AND
            NEW.canonical_truth = 'EXCEPTION');

    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid canonical truth transition: % -> %',
            OLD.canonical_truth, NEW.canonical_truth
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.enforce_recovery_case_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'OBSERVING' THEN
            RAISE EXCEPTION 'recovery cases must start in OBSERVING'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM retrywise.logical_orders AS lo
             WHERE lo.merchant_id = NEW.merchant_id
               AND lo.id = NEW.logical_order_id
               AND lo.provider_account_id = NEW.provider_account_id
               AND lo.currency = NEW.currency
               AND lo.amount_due_minor = NEW.amount_due_snapshot_minor
               AND lo.canonical_truth IN ('UNKNOWN', 'UNPAID')
        ) THEN
            RAISE EXCEPTION 'a recovery case cannot observe paid or unsafe truth'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'recovery cases cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.logical_order_id,
        NEW.provider_account_id,
        NEW.currency,
        NEW.amount_due_snapshot_minor,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.logical_order_id,
        OLD.provider_account_id,
        OLD.currency,
        OLD.amount_due_snapshot_minor,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'recovery case tenant, order, provider, and money are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'recovery case version must advance exactly by one'
            USING ERRCODE = '40001';
    END IF;

    IF NEW.attempt_count < OLD.attempt_count
       OR NEW.contact_count < OLD.contact_count THEN
        RAISE EXCEPTION 'recovery case counters cannot decrease'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.last_decision_at IS NOT NULL AND
       (NEW.last_decision_at IS NULL OR
        NEW.last_decision_at < OLD.last_decision_at) THEN
        RAISE EXCEPTION 'last decision time cannot regress'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.last_action_at IS NOT NULL AND
       (NEW.last_action_at IS NULL OR
        NEW.last_action_at < OLD.last_action_at) THEN
        RAISE EXCEPTION 'last action time cannot regress'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.state IN (
        'ASSESSING', 'WAITING', 'APPROVAL_REQUIRED', 'ACTION_QUEUED',
        'EXECUTING', 'ACTION_UNCERTAIN', 'ACTIVE'
    ) AND NOT EXISTS (
        SELECT 1
          FROM retrywise.logical_orders AS lo
         WHERE lo.merchant_id = NEW.merchant_id
           AND lo.id = NEW.logical_order_id
           AND lo.provider_account_id = NEW.provider_account_id
           AND lo.canonical_truth = 'UNPAID'
    ) THEN
        RAISE EXCEPTION 'active recovery workflow requires canonical UNPAID truth'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.state = OLD.state THEN
        RETURN NEW;
    END IF;

    allowed :=
        NEW.state = 'DUPLICATE_REVIEW'
        OR (OLD.state = 'OBSERVING' AND
            NEW.state IN ('ASSESSING', 'SUPPRESSED_PAID'))
        OR (OLD.state = 'ASSESSING' AND
            NEW.state IN (
                'WAITING', 'APPROVAL_REQUIRED', 'ACTION_QUEUED',
                'EXHAUSTED', 'SUPPRESSED_POLICY', 'SUPPRESSED_PAID',
                'ESCALATED'
            ))
        OR (OLD.state = 'WAITING' AND
            NEW.state IN (
                'ASSESSING', 'SUPPRESSED_PAID',
                'SUPPRESSED_POLICY', 'EXHAUSTED'
            ))
        OR (OLD.state = 'APPROVAL_REQUIRED' AND
            NEW.state IN (
                'ACTION_QUEUED', 'SUPPRESSED_POLICY', 'SUPPRESSED_PAID'
            ))
        OR (OLD.state = 'ACTION_QUEUED' AND
            NEW.state IN (
                'EXECUTING', 'SUPPRESSED_PAID', 'SUPPRESSED_POLICY'
            ))
        OR (OLD.state = 'EXECUTING' AND
            NEW.state IN (
                'ACTIVE', 'ACTION_UNCERTAIN',
                'FAILED_SAFE', 'SUPPRESSED_PAID'
            ))
        OR (OLD.state = 'ACTION_UNCERTAIN' AND
            NEW.state IN (
                'ACTIVE', 'ACTION_QUEUED', 'ESCALATED', 'SUPPRESSED_PAID'
            ))
        OR (OLD.state = 'ACTIVE' AND
            NEW.state IN (
                'RECOVERED', 'SUPPRESSED_PAID', 'ASSESSING', 'EXHAUSTED'
            ));

    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid recovery case transition: % -> %',
            OLD.state, NEW.state USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.enforce_recovery_instrument_lifecycle()
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
        OR (OLD.status = 'PARTIALLY_PAID' AND NEW.status = 'PAID');

    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid recovery instrument transition: % -> %',
            OLD.status, NEW.status USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.enforce_approval_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.verdict <> 'PENDING' THEN
            RAISE EXCEPTION 'approvals must start in PENDING'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'approvals cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.recovery_case_id,
        NEW.decision_id,
        NEW.aggregate_version,
        NEW.requested_at,
        NEW.expires_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.recovery_case_id,
        OLD.decision_id,
        OLD.aggregate_version,
        OLD.requested_at,
        OLD.expires_at
    ) THEN
        RAISE EXCEPTION 'approval request identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.verdict <> 'PENDING' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'a final approval verdict cannot be changed'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.verdict = 'PENDING' AND NEW.verdict = 'PENDING'
       AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'pending approvals cannot be refreshed in place'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.enforce_action_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    allowed boolean := false;
    decision_action retrywise.action_type;
    decision_gate retrywise.gate_verdict;
    approval_is_valid boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PLANNED' OR NEW.attempt_number <> 0 THEN
            RAISE EXCEPTION 'actions must start in PLANNED with zero attempts'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.effect_gate_snapshot IS NOT NULL
           OR NEW.effect_gate_verdict IS NOT NULL
           OR cardinality(NEW.effect_gate_reason_codes) <> 0
           OR NEW.first_attempted_at IS NOT NULL
           OR NEW.last_attempted_at IS NOT NULL
           OR NEW.completed_at IS NOT NULL
           OR NEW.response_metadata IS NOT NULL
           OR NEW.provider_status IS NOT NULL
           OR NEW.provider_resource_id IS NOT NULL
           OR NEW.last_error_code IS NOT NULL
           OR NEW.dead_lettered_at IS NOT NULL
           OR NEW.dead_letter_reason IS NOT NULL
           OR NEW.reconciliation_status <> 'NOT_REQUIRED' THEN
            RAISE EXCEPTION 'new actions cannot contain execution results or gate evidence'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.action_type = 'CREATE_STANDARD_PAYMENT_LINK' AND
           (
               NEW.external_reference_id IS NULL
               OR length(btrim(NEW.external_reference_id)) NOT BETWEEN 1 AND 40
           ) THEN
            RAISE EXCEPTION 'create-link actions require a reference id of at most 40 characters'
                USING ERRCODE = '23514';
        END IF;

        SELECT d.selected_action, d.planning_gate_verdict
          INTO decision_action, decision_gate
          FROM retrywise.decisions AS d
         WHERE d.merchant_id = NEW.merchant_id
           AND d.id = NEW.decision_id
           AND d.recovery_case_id = NEW.recovery_case_id
           AND d.aggregate_version = NEW.aggregate_version
           AND d.source_label = NEW.source_label;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'action decision binding does not exist'
                USING ERRCODE = '23503';
        END IF;

        IF decision_gate = 'BLOCKED'
           OR decision_action IS DISTINCT FROM NEW.action_type THEN
            RAISE EXCEPTION 'action does not match an executable decision'
                USING ERRCODE = '23514';
        END IF;

        IF NEW.approval_id IS NOT NULL THEN
            SELECT EXISTS (
                SELECT 1
                  FROM retrywise.approvals AS ap
                 WHERE ap.merchant_id = NEW.merchant_id
                   AND ap.id = NEW.approval_id
                   AND ap.decision_id = NEW.decision_id
                   AND ap.recovery_case_id = NEW.recovery_case_id
                   AND ap.aggregate_version = NEW.aggregate_version
                   AND ap.verdict = 'APPROVED'
                   AND ap.acted_at <= ap.expires_at
                   AND (
                       (NEW.source_label = 'RAZORPAY_TEST_MODE' AND
                        clock_timestamp() <= ap.expires_at)
                       OR
                       (NEW.source_label <> 'RAZORPAY_TEST_MODE' AND
                        NEW.created_at <= ap.expires_at)
                   )
            ) INTO approval_is_valid;
        END IF;

        IF decision_gate = 'APPROVAL_REQUIRED' AND NOT approval_is_valid THEN
            RAISE EXCEPTION 'action requires a matching unexpired approval verdict'
                USING ERRCODE = '23514';
        END IF;

        IF NEW.approval_id IS NOT NULL AND NOT approval_is_valid THEN
            RAISE EXCEPTION 'attached approval is not a valid APPROVED verdict'
                USING ERRCODE = '23514';
        END IF;

        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'actions cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.recovery_case_id,
        NEW.decision_id,
        NEW.aggregate_version,
        NEW.approval_id,
        NEW.action_key,
        NEW.action_type,
        NEW.source_label,
        NEW.max_attempts,
        NEW.request_metadata,
        NEW.external_reference_id,
        NEW.scheduled_at,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.recovery_case_id,
        OLD.decision_id,
        OLD.aggregate_version,
        OLD.approval_id,
        OLD.action_key,
        OLD.action_type,
        OLD.source_label,
        OLD.max_attempts,
        OLD.request_metadata,
        OLD.external_reference_id,
        OLD.scheduled_at,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'action intent and binding are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.attempt_number < OLD.attempt_number THEN
        RAISE EXCEPTION 'action attempt_number cannot decrease'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.effect_gate_snapshot IS NOT NULL AND ROW(
        NEW.effect_gate_snapshot,
        NEW.effect_gate_verdict,
        NEW.effect_gate_reason_codes
    ) IS DISTINCT FROM ROW(
        OLD.effect_gate_snapshot,
        OLD.effect_gate_verdict,
        OLD.effect_gate_reason_codes
    ) THEN
        RAISE EXCEPTION 'effect-gate evidence is write-once'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.effect_gate_snapshot IS NULL
       AND NEW.effect_gate_snapshot IS NOT NULL
       AND (
           NEW.status = OLD.status
           OR NEW.status NOT IN ('EXECUTING', 'CANCELLED')
       ) THEN
        RAISE EXCEPTION 'effect-gate evidence must be recorded with its transition'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.first_attempted_at IS NOT NULL
       AND NEW.first_attempted_at IS DISTINCT FROM OLD.first_attempted_at THEN
        RAISE EXCEPTION 'first_attempted_at is write-once'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.first_attempted_at IS NULL
       AND NEW.first_attempted_at IS NOT NULL
       AND NEW.status <> 'EXECUTING' THEN
        RAISE EXCEPTION 'first_attempted_at must be set when execution starts'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status = 'EXECUTING'
       AND NEW.status IS DISTINCT FROM OLD.status
       AND NEW.source_label = 'RAZORPAY_TEST_MODE'
       AND NEW.action_type IN (
           'CREATE_STANDARD_PAYMENT_LINK',
           'NOTIFY_EXISTING_LINK',
           'CANCEL_PAYMENT_LINK'
       )
       AND NOT EXISTS (
           SELECT 1
             FROM retrywise.recovery_cases AS rc
             JOIN retrywise.provider_accounts AS pa
               ON pa.merchant_id = rc.merchant_id
              AND pa.id = rc.provider_account_id
            WHERE rc.merchant_id = NEW.merchant_id
              AND rc.id = NEW.recovery_case_id
              AND pa.environment = 'TEST'
              AND pa.enabled
       ) THEN
        RAISE EXCEPTION 'test-mode effects require an enabled TEST provider account'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.status = 'EXECUTING'
       AND NEW.status IS DISTINCT FROM OLD.status
       AND NEW.action_type IN (
           'CREATE_STANDARD_PAYMENT_LINK', 'NOTIFY_EXISTING_LINK'
       )
       AND NOT EXISTS (
           SELECT 1
             FROM retrywise.recovery_cases AS rc
             JOIN retrywise.logical_orders AS lo
               ON lo.merchant_id = rc.merchant_id
              AND lo.id = rc.logical_order_id
              AND lo.provider_account_id = rc.provider_account_id
             JOIN retrywise.provider_accounts AS pa
               ON pa.merchant_id = rc.merchant_id
              AND pa.id = rc.provider_account_id
             JOIN retrywise.merchants AS m
               ON m.id = rc.merchant_id
            WHERE rc.merchant_id = NEW.merchant_id
              AND rc.id = NEW.recovery_case_id
              AND rc.state = 'EXECUTING'
              AND rc.last_action_id = NEW.id
              AND lo.canonical_truth = 'UNPAID'
              AND (
                  NEW.source_label <> 'RAZORPAY_TEST_MODE'
                  OR (
                      pa.enabled
                      AND m.status = 'ACTIVE'
                      AND NOT m.kill_switch_enabled
                  )
              )
       ) THEN
        RAISE EXCEPTION 'collection execution failed case, truth, or kill-switch guard'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.status = 'EXECUTING'
       AND NEW.status IS DISTINCT FROM OLD.status
       AND NEW.action_type = 'CREATE_STANDARD_PAYMENT_LINK'
       AND NOT EXISTS (
           SELECT 1
             FROM retrywise.recovery_instruments AS ri
            WHERE ri.merchant_id = NEW.merchant_id
              AND ri.recovery_case_id = NEW.recovery_case_id
              AND ri.action_id = NEW.id
              AND ri.reference_id = NEW.external_reference_id
              AND ri.status = 'CREATING'
       ) THEN
        RAISE EXCEPTION 'create-link execution requires a reserved instrument'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.status = 'EXECUTING'
       AND NEW.status IS DISTINCT FROM OLD.status THEN
        SELECT d.planning_gate_verdict
          INTO decision_gate
          FROM retrywise.decisions AS d
         WHERE d.merchant_id = NEW.merchant_id
           AND d.id = NEW.decision_id
           AND d.recovery_case_id = NEW.recovery_case_id
           AND d.aggregate_version = NEW.aggregate_version
           AND d.source_label = NEW.source_label;

        IF decision_gate = 'APPROVAL_REQUIRED' AND NOT EXISTS (
            SELECT 1
              FROM retrywise.approvals AS ap
             WHERE ap.merchant_id = NEW.merchant_id
               AND ap.id = NEW.approval_id
               AND ap.decision_id = NEW.decision_id
               AND ap.recovery_case_id = NEW.recovery_case_id
               AND ap.aggregate_version = NEW.aggregate_version
               AND ap.verdict = 'APPROVED'
               AND ap.acted_at <= ap.expires_at
               AND (
                   (NEW.source_label = 'RAZORPAY_TEST_MODE' AND
                    clock_timestamp() <= ap.expires_at)
                   OR
                   (NEW.source_label <> 'RAZORPAY_TEST_MODE' AND
                    NEW.first_attempted_at <= ap.expires_at)
               )
        ) THEN
            RAISE EXCEPTION 'approval expired before action execution'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF OLD.status IN (
        'SUCCEEDED', 'FAILED_SAFE', 'RECONCILED',
        'DEAD_LETTER', 'CANCELLED'
    ) THEN
        RAISE EXCEPTION 'completed action results are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    allowed :=
        (OLD.status = 'PLANNED' AND NEW.status IN ('QUEUED', 'CANCELLED'))
        OR (OLD.status = 'QUEUED' AND
            NEW.status IN ('EXECUTING', 'CANCELLED', 'DEAD_LETTER'))
        OR (OLD.status = 'EXECUTING' AND
            NEW.status IN (
                'SUCCEEDED', 'FAILED_RETRYABLE', 'FAILED_SAFE',
                'UNCERTAIN', 'CANCELLED'
            ))
        OR (OLD.status = 'FAILED_RETRYABLE' AND
            NEW.status IN ('QUEUED', 'DEAD_LETTER', 'CANCELLED'))
        OR (OLD.status = 'UNCERTAIN' AND
            NEW.status IN ('RECONCILING', 'DEAD_LETTER'))
        OR (OLD.status = 'RECONCILING' AND
            NEW.status IN (
                'RECONCILED', 'QUEUED', 'FAILED_SAFE', 'DEAD_LETTER'
            ));

    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid action status transition: % -> %',
            OLD.status, NEW.status USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.enforce_inbox_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'RECEIVED' OR NEW.attempt_count <> 0 THEN
            RAISE EXCEPTION 'inbox events must start in RECEIVED with zero attempts'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.status NOT IN ('PROCESSED', 'IGNORED', 'DEAD_LETTER') THEN
            RAISE EXCEPTION 'only terminal inbox events can be removed by retention'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.provider_account_id,
        NEW.provider_event_record_id,
        NEW.max_attempts,
        NEW.accepted_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.provider_account_id,
        OLD.provider_event_record_id,
        OLD.max_attempts,
        OLD.accepted_at
    ) THEN
        RAISE EXCEPTION 'inbox event identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.attempt_count < OLD.attempt_count THEN
        RAISE EXCEPTION 'inbox attempt_count cannot decrease'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status IN ('PROCESSED', 'IGNORED', 'DEAD_LETTER') THEN
        RAISE EXCEPTION 'terminal inbox processing evidence is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    allowed :=
        (OLD.status IN ('RECEIVED', 'RETRY_SCHEDULED') AND
         NEW.status IN ('PROCESSING', 'DEAD_LETTER'))
        OR
        (OLD.status = 'PROCESSING' AND
         NEW.status IN (
             'PROCESSED', 'IGNORED', 'RETRY_SCHEDULED', 'DEAD_LETTER'
         ));

    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid inbox status transition: % -> %',
            OLD.status, NEW.status USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.enforce_outbox_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING' OR NEW.attempt_count <> 0 THEN
            RAISE EXCEPTION 'outbox jobs must start in PENDING with zero attempts'
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

    IF NEW.attempt_count < OLD.attempt_count THEN
        RAISE EXCEPTION 'outbox attempt_count cannot decrease'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status IN ('SUCCEEDED', 'DEAD_LETTER', 'CANCELLED') THEN
        RAISE EXCEPTION 'terminal outbox delivery evidence is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    allowed :=
        (OLD.status IN ('PENDING', 'RETRY_SCHEDULED') AND
         NEW.status IN ('IN_PROGRESS', 'CANCELLED', 'DEAD_LETTER'))
        OR
        (OLD.status = 'IN_PROGRESS' AND
         NEW.status IN (
             'SUCCEEDED', 'RETRY_SCHEDULED', 'DEAD_LETTER', 'CANCELLED'
         ));

    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid outbox status transition: % -> %',
            OLD.status, NEW.status USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.enforce_evaluation_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PLANNED' THEN
            RAISE EXCEPTION 'evaluation runs must start in PLANNED'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'evaluation runs are immutable records'
            USING ERRCODE = '55000';
    END IF;

    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.name,
        NEW.source_label,
        NEW.seed_set,
        NEW.dataset_sha256,
        NEW.code_revision,
        NEW.policy_version,
        NEW.model_version,
        NEW.cost_version,
        NEW.manifest,
        NEW.manifest_sha256,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.name,
        OLD.source_label,
        OLD.seed_set,
        OLD.dataset_sha256,
        OLD.code_revision,
        OLD.policy_version,
        OLD.model_version,
        OLD.cost_version,
        OLD.manifest,
        OLD.manifest_sha256,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'evaluation manifest and source label are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status IN ('SUCCEEDED', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'completed evaluation results are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    allowed :=
        (OLD.status = 'PLANNED' AND
         NEW.status IN ('RUNNING', 'FAILED', 'CANCELLED'))
        OR
        (OLD.status = 'RUNNING' AND
         NEW.status IN ('SUCCEEDED', 'FAILED', 'CANCELLED'));

    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid evaluation status transition: % -> %',
            OLD.status, NEW.status USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION retrywise.enforce_audit_chain()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    prior_sequence bigint;
    prior_hash retrywise.sha256_digest;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended(NEW.merchant_id::text || ':' ||
                         NEW.recovery_case_id::text, 0)
    );

    SELECT sequence_number, entry_hash
      INTO prior_sequence, prior_hash
      FROM retrywise.audit_entries
     WHERE merchant_id = NEW.merchant_id
       AND recovery_case_id = NEW.recovery_case_id
     ORDER BY sequence_number DESC
     LIMIT 1;

    IF NOT FOUND THEN
        IF NEW.sequence_number <> 1 OR NEW.previous_entry_hash IS NOT NULL THEN
            RAISE EXCEPTION 'first audit entry must have sequence 1 and no prior hash'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.sequence_number <> prior_sequence + 1 THEN
            RAISE EXCEPTION 'audit sequence must advance exactly by one'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.previous_entry_hash IS DISTINCT FROM prior_hash THEN
            RAISE EXCEPTION 'audit previous hash does not match chain head'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER merchants_10_enforce_identity
BEFORE UPDATE OR DELETE ON retrywise.merchants
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_merchant_identity();

CREATE TRIGGER merchants_90_set_updated_at
BEFORE UPDATE ON retrywise.merchants
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER provider_accounts_10_enforce_identity
BEFORE UPDATE OR DELETE ON retrywise.provider_accounts
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_provider_account_identity();

CREATE TRIGGER provider_accounts_90_set_updated_at
BEFORE UPDATE ON retrywise.provider_accounts
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER inbox_events_10_enforce_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON retrywise.inbox_events
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_inbox_lifecycle();

CREATE TRIGGER inbox_events_90_set_updated_at
BEFORE UPDATE ON retrywise.inbox_events
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER logical_orders_10_enforce_lifecycle
BEFORE UPDATE OR DELETE ON retrywise.logical_orders
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_logical_order_lifecycle();

CREATE TRIGGER logical_orders_90_set_updated_at
BEFORE UPDATE ON retrywise.logical_orders
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER provider_payments_set_updated_at
BEFORE UPDATE ON retrywise.provider_payments
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER incidents_set_updated_at
BEFORE UPDATE ON retrywise.incidents
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER recovery_cases_10_enforce_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON retrywise.recovery_cases
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_recovery_case_lifecycle();

CREATE TRIGGER recovery_cases_90_set_updated_at
BEFORE UPDATE ON retrywise.recovery_cases
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER recovery_instruments_10_enforce_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON retrywise.recovery_instruments
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_recovery_instrument_lifecycle();

CREATE TRIGGER recovery_instruments_90_set_updated_at
BEFORE UPDATE ON retrywise.recovery_instruments
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER approvals_enforce_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON retrywise.approvals
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_approval_lifecycle();

CREATE TRIGGER actions_10_enforce_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON retrywise.actions
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_action_lifecycle();

CREATE TRIGGER actions_90_set_updated_at
BEFORE UPDATE ON retrywise.actions
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER outbox_jobs_10_enforce_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON retrywise.outbox_jobs
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_outbox_lifecycle();

CREATE TRIGGER outbox_jobs_90_set_updated_at
BEFORE UPDATE ON retrywise.outbox_jobs
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER evaluation_runs_10_enforce_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON retrywise.evaluation_runs
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_evaluation_lifecycle();

CREATE TRIGGER evaluation_runs_90_set_updated_at
BEFORE UPDATE ON retrywise.evaluation_runs
FOR EACH ROW EXECUTE FUNCTION retrywise.set_updated_at();

CREATE TRIGGER provider_events_forbid_mutation
BEFORE UPDATE OR DELETE ON retrywise.provider_events
FOR EACH ROW EXECUTE FUNCTION retrywise.forbid_immutable_mutation();

CREATE TRIGGER decisions_forbid_mutation
BEFORE UPDATE OR DELETE ON retrywise.decisions
FOR EACH ROW EXECUTE FUNCTION retrywise.forbid_immutable_mutation();

CREATE TRIGGER audit_entries_10_enforce_chain
BEFORE INSERT ON retrywise.audit_entries
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_audit_chain();

CREATE TRIGGER audit_entries_90_forbid_mutation
BEFORE UPDATE OR DELETE ON retrywise.audit_entries
FOR EACH ROW EXECUTE FUNCTION retrywise.forbid_immutable_mutation();

CREATE INDEX provider_events_received_idx
    ON retrywise.provider_events (merchant_id, received_at DESC, id DESC);

CREATE INDEX provider_events_resource_idx
    ON retrywise.provider_events
        (merchant_id, provider_account_id, resource_type, resource_id)
    WHERE resource_id IS NOT NULL;

CREATE INDEX inbox_events_due_idx
    ON retrywise.inbox_events (next_attempt_at, id)
    WHERE status IN ('RECEIVED', 'RETRY_SCHEDULED');

CREATE INDEX inbox_events_stale_lease_idx
    ON retrywise.inbox_events (lease_expires_at, id)
    WHERE status = 'PROCESSING';

CREATE INDEX logical_orders_truth_idx
    ON retrywise.logical_orders
        (merchant_id, canonical_truth, updated_at DESC, id DESC);

CREATE INDEX provider_payments_provider_id_idx
    ON retrywise.provider_payments (merchant_id, provider_payment_id);

CREATE INDEX provider_payments_order_idx
    ON retrywise.provider_payments
        (merchant_id, logical_order_id, provider_snapshot_at DESC, id DESC);

CREATE INDEX incidents_scope_state_idx
    ON retrywise.incidents
        (
            merchant_id,
            provider_account_id,
            payment_method,
            instrument_key,
            state,
            updated_at DESC
        );

CREATE INDEX incidents_expiry_idx
    ON retrywise.incidents (expires_at, id)
    WHERE state IN ('SUSPECTED', 'CONFIRMED', 'COOLING');

CREATE INDEX recovery_cases_state_idx
    ON retrywise.recovery_cases
        (merchant_id, state, updated_at DESC, id DESC);

CREATE INDEX recovery_cases_evaluation_due_idx
    ON retrywise.recovery_cases (evaluation_deadline_at, id)
    WHERE state IN ('OBSERVING', 'WAITING');

CREATE INDEX decisions_case_idx
    ON retrywise.decisions
        (merchant_id, recovery_case_id, created_at DESC, id DESC);

CREATE INDEX approvals_pending_expiry_idx
    ON retrywise.approvals (expires_at, id)
    WHERE verdict = 'PENDING';

CREATE INDEX actions_case_status_idx
    ON retrywise.actions
        (merchant_id, recovery_case_id, status, updated_at DESC, id DESC);

CREATE INDEX actions_stale_lease_idx
    ON retrywise.actions (lease_expires_at, id)
    WHERE status IN ('EXECUTING', 'RECONCILING');

CREATE INDEX recovery_instruments_provider_payment_idx
    ON retrywise.recovery_instruments
        (merchant_id, provider_payment_id)
    WHERE provider_payment_id IS NOT NULL;

CREATE INDEX recovery_instruments_case_idx
    ON retrywise.recovery_instruments
        (merchant_id, recovery_case_id, updated_at DESC, id DESC);

CREATE INDEX audit_entries_case_sequence_idx
    ON retrywise.audit_entries
        (merchant_id, recovery_case_id, sequence_number DESC);

CREATE INDEX outbox_jobs_due_idx
    ON retrywise.outbox_jobs (next_attempt_at, id)
    WHERE status IN ('PENDING', 'RETRY_SCHEDULED');

CREATE INDEX outbox_jobs_stale_lease_idx
    ON retrywise.outbox_jobs (lease_expires_at, id)
    WHERE status = 'IN_PROGRESS';

CREATE INDEX evaluation_runs_list_idx
    ON retrywise.evaluation_runs
        (merchant_id, source_label, status, created_at DESC, id DESC);

COMMENT ON SCHEMA retrywise IS
    'Authoritative RetryWise tenant, payment, workflow, audit, and queue data.';

COMMENT ON TABLE retrywise.provider_events IS
    'Append-only, verified Razorpay evidence; raw bodies live behind encrypted retention references.';

COMMENT ON TABLE retrywise.inbox_events IS
    'At-least-once processing state for accepted provider evidence.';

COMMENT ON TABLE retrywise.decisions IS
    'Immutable model/policy/gate decision evidence; models do not authorize effects.';

COMMENT ON TABLE retrywise.actions IS
    'Immutable effect intent with a constrained, monotonic execution lifecycle.';

COMMENT ON TABLE retrywise.audit_entries IS
    'Append-only per-case hash chain; the application computes canonical entry hashes.';

COMMENT ON TABLE retrywise.outbox_jobs IS
    'Transactional commands committed with domain state and delivered effectively once.';

COMMENT ON COLUMN retrywise.provider_accounts.credential_secret_ref IS
    'Reference to managed encrypted secret material; never plaintext credentials.';

COMMENT ON COLUMN retrywise.evaluation_runs.source_label IS
    'Immutable provenance that prevents replay/simulation metrics being relabelled as provider-observed.';

COMMIT;
