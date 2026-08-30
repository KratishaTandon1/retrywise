#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"

initial_migration_path="${1:-/migrations/001_initial.sql}"
fenced_outbox_migration_path="${2:-/migrations/002_fenced_outbox_delivery.sql}"
effect_boundary_migration_path="${3:-/migrations/003_enforce_effect_source_boundary.sql}"
observation_deadline_migration_path="${4:-/migrations/004_enforce_observation_deadline.sql}"
provider_account_binding_migration_path="${5:-/migrations/005_bind_provider_event_account.sql}"
credential_binding_version_migration_path="${6:-/migrations/006_version_credential_binding.sql}"
provider_event_body_index_migration_path="${7:-/migrations/007_index_provider_event_body_reuse.sql}"
late_link_money_migration_path="${8:-/migrations/008_allow_late_link_money_truth.sql}"
worker_heartbeat_migration_path="${9:-/migrations/009_worker_heartbeats.sql}"
merchant_control_migration_path="${10:-/migrations/010_merchant_control_events.sql}"
diagnosis_routing_migration_path="${11:-/migrations/011_diagnosis_engine_routing.sql}"
for migration_path in \
    "${initial_migration_path}" \
    "${fenced_outbox_migration_path}" \
    "${effect_boundary_migration_path}" \
    "${observation_deadline_migration_path}" \
    "${provider_account_binding_migration_path}" \
    "${credential_binding_version_migration_path}" \
    "${provider_event_body_index_migration_path}" \
    "${late_link_money_migration_path}" \
    "${worker_heartbeat_migration_path}" \
    "${merchant_control_migration_path}" \
    "${diagnosis_routing_migration_path}"; do
    if [ ! -r "${migration_path}" ]; then
        echo "migration is not readable: ${migration_path}" >&2
        exit 1
    fi
done

schema_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "SELECT CASE
           WHEN to_regclass('retrywise.merchants') IS NOT NULL
            AND to_regclass('retrywise.provider_events') IS NOT NULL
            AND to_regclass('retrywise.outbox_jobs') IS NOT NULL
            AND to_regclass('retrywise.evaluation_runs') IS NOT NULL
             THEN 'applied'
           WHEN to_regclass('retrywise.merchants') IS NULL
            AND to_regclass('retrywise.provider_events') IS NULL
            AND to_regclass('retrywise.outbox_jobs') IS NULL
            AND to_regclass('retrywise.evaluation_runs') IS NULL
             THEN 'missing'
           ELSE 'partial'
         END"
)"

case "${schema_state}" in
    applied)
        echo "RetryWise migration 001 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -f "${initial_migration_path}"
        ;;
    partial)
        echo "RetryWise schema is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise schema state: ${schema_state}" >&2
        exit 1
        ;;
esac

fenced_outbox_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "WITH state AS (
             SELECT
                 to_regtype('retrywise.outbox_retry_mode') IS NOT NULL AS has_type,
                 (
                     SELECT count(*) = 4
                     FROM pg_catalog.pg_attribute AS attribute
                     WHERE attribute.attrelid = to_regclass('retrywise.outbox_jobs')
                       AND attribute.attname IN (
                           'delivery_version',
                           'lease_token',
                           'retry_mode',
                           'completion_reference'
                       )
                       AND NOT attribute.attisdropped
                 ) AS has_columns,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_proc AS procedure
                     JOIN pg_catalog.pg_namespace AS namespace
                       ON namespace.oid = procedure.pronamespace
                     WHERE namespace.nspname = 'retrywise'
                       AND procedure.proname = 'enforce_outbox_lifecycle'
                       AND position(
                           'delivery_version must increase by exactly one'
                           IN pg_get_functiondef(procedure.oid)
                       ) > 0
                 ) AS has_fenced_function
         )
         SELECT CASE
             WHEN has_type AND has_columns AND has_fenced_function THEN 'applied'
             WHEN NOT has_type AND NOT has_columns THEN 'missing'
             ELSE 'partial'
         END
         FROM state"
)"

case "${fenced_outbox_state}" in
    applied)
        echo "RetryWise migration 002 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -f "${fenced_outbox_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 002 is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 002 state: ${fenced_outbox_state}" >&2
        exit 1
        ;;
esac

effect_boundary_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "WITH state AS (
             SELECT
                 to_regprocedure(
                     'retrywise.enforce_effect_source_boundary()'
                 ) IS NOT NULL AS has_function,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_trigger AS trigger
                     WHERE trigger.tgrelid = to_regclass('retrywise.actions')
                       AND trigger.tgname = 'actions_05_enforce_effect_source_boundary'
                       AND trigger.tgenabled <> 'D'
                 ) AS has_trigger,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_proc AS procedure
                     JOIN pg_catalog.pg_namespace AS namespace
                       ON namespace.oid = procedure.pronamespace
                     WHERE namespace.nspname = 'retrywise'
                       AND procedure.proname = 'enforce_effect_source_boundary'
                       AND position(
                           'TG_OP = ''INSERT'''
                           IN pg_get_functiondef(procedure.oid)
                       ) > 0
                 ) AS has_insert_guard
         )
         SELECT CASE
             WHEN has_function AND has_trigger AND has_insert_guard THEN 'applied'
             WHEN NOT has_function AND NOT has_trigger THEN 'missing'
             ELSE 'partial'
         END
         FROM state"
)"

case "${effect_boundary_state}" in
    applied)
        echo "RetryWise migration 003 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -f "${effect_boundary_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 003 is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 003 state: ${effect_boundary_state}" >&2
        exit 1
        ;;
esac

observation_deadline_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "WITH state AS (
             SELECT
                 to_regprocedure(
                     'retrywise.enforce_observation_deadline()'
                 ) IS NOT NULL AS has_function,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_trigger AS trigger
                     WHERE trigger.tgrelid = to_regclass('retrywise.recovery_cases')
                       AND trigger.tgname = 'recovery_cases_05_enforce_observation_deadline'
                       AND trigger.tgenabled <> 'D'
                 ) AS has_trigger,
                 (
                     SELECT count(*) = 2
                     FROM pg_catalog.pg_attribute AS attribute
                     WHERE attribute.attrelid = to_regclass('retrywise.recovery_cases')
                       AND attribute.attname IN (
                           'observation_started_at',
                           'observation_contract_version'
                       )
                       AND NOT attribute.attisdropped
                 ) AS has_contract_columns
         )
         SELECT CASE
             WHEN has_function AND has_trigger AND has_contract_columns THEN 'applied'
             WHEN NOT has_function AND NOT has_trigger AND NOT has_contract_columns
                 THEN 'missing'
             ELSE 'partial'
         END
         FROM state"
)"

case "${observation_deadline_state}" in
    applied)
        echo "RetryWise migration 004 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -f "${observation_deadline_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 004 is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 004 state: ${observation_deadline_state}" >&2
        exit 1
        ;;
esac

provider_account_binding_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "SELECT CASE
             WHEN to_regprocedure(
                      'retrywise.enforce_provider_event_account_binding()'
                  ) IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_trigger AS trigger
                  WHERE trigger.tgrelid = to_regclass('retrywise.provider_events')
                    AND trigger.tgname = 'provider_events_05_enforce_account_binding'
                    AND trigger.tgenabled <> 'D'
              ) THEN 'applied'
             WHEN to_regprocedure(
                      'retrywise.enforce_provider_event_account_binding()'
                  ) IS NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_trigger AS trigger
                  WHERE trigger.tgrelid = to_regclass('retrywise.provider_events')
                    AND trigger.tgname = 'provider_events_05_enforce_account_binding'
              ) THEN 'missing'
             ELSE 'partial'
         END"
)"

case "${provider_account_binding_state}" in
    applied)
        echo "RetryWise migration 005 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -f "${provider_account_binding_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 005 is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 005 state: ${provider_account_binding_state}" >&2
        exit 1
        ;;
esac

credential_binding_version_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "WITH state AS (
             SELECT
                 (
                     SELECT count(*) = 2
                     FROM pg_catalog.pg_attribute AS attribute
                     WHERE attribute.attrelid = to_regclass('retrywise.provider_accounts')
                       AND attribute.attname IN (
                           'credential_key_id_sha256',
                           'credential_binding_version'
                       )
                       AND NOT attribute.attisdropped
                 ) AS has_columns,
                 to_regprocedure(
                     'retrywise.enforce_provider_account_credential_binding()'
                 ) IS NOT NULL AS has_function,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_constraint AS constraint_record
                     WHERE constraint_record.conrelid =
                           to_regclass('retrywise.provider_accounts')
                       AND constraint_record.conname =
                           'provider_accounts_credential_binding_pair_ck'
                       AND constraint_record.contype = 'c'
                       AND constraint_record.convalidated
                 ) AS has_pair_check,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_trigger AS trigger
                     WHERE trigger.tgrelid = to_regclass('retrywise.provider_accounts')
                       AND trigger.tgname =
                           'provider_accounts_20_enforce_credential_binding'
                       AND trigger.tgenabled <> 'D'
                 ) AS has_trigger,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_class AS index_relation
                     JOIN pg_catalog.pg_namespace AS namespace
                       ON namespace.oid = index_relation.relnamespace
                     JOIN pg_catalog.pg_index AS index_record
                       ON index_record.indexrelid = index_relation.oid
                     WHERE namespace.nspname = 'retrywise'
                       AND index_relation.relname =
                           'provider_accounts_credential_key_uidx'
                       AND index_record.indisunique
                       AND index_record.indisvalid
                 ) AS has_unique_index
         )
         SELECT CASE
             WHEN has_columns AND has_function AND has_pair_check
                  AND has_trigger AND has_unique_index THEN 'applied'
             WHEN NOT has_columns AND NOT has_function AND NOT has_pair_check
                  AND NOT has_trigger AND NOT has_unique_index THEN 'missing'
             ELSE 'partial'
         END
         FROM state"
)"

case "${credential_binding_version_state}" in
    applied)
        echo "RetryWise migration 006 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 \
            -f "${credential_binding_version_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 006 is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 006 state: ${credential_binding_version_state}" >&2
        exit 1
        ;;
esac

provider_event_body_index_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "SELECT CASE
             WHEN EXISTS (
                 SELECT 1
                 FROM pg_catalog.pg_index AS index_state
                 WHERE index_state.indexrelid = to_regclass(
                           'retrywise.provider_events_body_reuse_lookup_idx'
                       )
                   AND index_state.indisvalid
                   AND index_state.indisready
                   AND position(
                       '(merchant_id, provider_account_id, body_sha256, received_at, id) INCLUDE (provider_event_id)'
                       IN pg_get_indexdef(index_state.indexrelid)
                   ) > 0
             ) THEN 'applied'
             WHEN to_regclass(
                      'retrywise.provider_events_body_reuse_lookup_idx'
                  ) IS NULL THEN 'missing'
             ELSE 'partial'
         END"
)"

case "${provider_event_body_index_state}" in
    applied)
        echo "RetryWise migration 007 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 \
            -f "${provider_event_body_index_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 007 is partial or invalid; refusing to treat it as applied." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 007 state: ${provider_event_body_index_state}" >&2
        exit 1
        ;;
esac

late_link_money_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "WITH state AS (
             SELECT
                 to_regprocedure(
                     'retrywise.enforce_recovery_instrument_lifecycle()'
                 ) IS NOT NULL AS has_function,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_trigger AS trigger
                     WHERE trigger.tgrelid =
                           to_regclass('retrywise.recovery_instruments')
                       AND trigger.tgname =
                           'recovery_instruments_10_enforce_lifecycle'
                       AND trigger.tgenabled <> 'D'
                 ) AS has_trigger,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_proc AS procedure
                     JOIN pg_catalog.pg_namespace AS namespace
                       ON namespace.oid = procedure.pronamespace
                     WHERE namespace.nspname = 'retrywise'
                       AND procedure.proname =
                           'enforce_recovery_instrument_lifecycle'
                       AND position(
                           'OLD.status IN (''CANCELLED'', ''EXPIRED'')'
                           IN pg_get_functiondef(procedure.oid)
                       ) > 0
                       AND position(
                           'NEW.status IN (''PAID'', ''PARTIALLY_PAID'')'
                           IN pg_get_functiondef(procedure.oid)
                       ) > 0
                 ) AS has_late_money_transition
         )
         SELECT CASE
             WHEN has_function AND has_trigger AND has_late_money_transition
                 THEN 'applied'
             WHEN has_function AND has_trigger AND NOT has_late_money_transition
                 THEN 'missing'
             ELSE 'partial'
         END
         FROM state"
)"

case "${late_link_money_state}" in
    applied)
        echo "RetryWise migration 008 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 \
            -f "${late_link_money_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 008 is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 008 state: ${late_link_money_state}" >&2
        exit 1
        ;;
esac

worker_heartbeat_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "SELECT CASE
             WHEN to_regclass('retrywise.worker_heartbeats') IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_index AS index_state
                  WHERE index_state.indexrelid = to_regclass(
                            'retrywise.worker_heartbeats_freshness_idx'
                        )
                    AND index_state.indisvalid
                    AND index_state.indisready
              ) THEN 'applied'
             WHEN to_regclass('retrywise.worker_heartbeats') IS NULL
              AND to_regclass(
                      'retrywise.worker_heartbeats_freshness_idx'
                  ) IS NULL THEN 'missing'
             ELSE 'partial'
         END"
)"

case "${worker_heartbeat_state}" in
    applied)
        echo "RetryWise migration 009 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 \
            -f "${worker_heartbeat_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 009 is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 009 state: ${worker_heartbeat_state}" >&2
        exit 1
        ;;
esac

merchant_control_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "WITH state AS (
             SELECT
                 to_regclass('retrywise.merchant_control_events') IS NOT NULL AS has_table,
                 to_regprocedure(
                     'retrywise.reject_merchant_control_event_mutation()'
                 ) IS NOT NULL AS has_function,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_trigger AS trigger
                     WHERE trigger.tgrelid = to_regclass(
                               'retrywise.merchant_control_events'
                           )
                       AND trigger.tgname = 'merchant_control_events_immutable'
                       AND trigger.tgenabled <> 'D'
                 ) AS has_trigger
         )
         SELECT CASE
             WHEN has_table AND has_function AND has_trigger THEN 'applied'
             WHEN NOT has_table AND NOT has_function AND NOT has_trigger THEN 'missing'
             ELSE 'partial'
         END
         FROM state"
)"

case "${merchant_control_state}" in
    applied)
        echo "RetryWise migration 010 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 \
            -f "${merchant_control_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 010 is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 010 state: ${merchant_control_state}" >&2
        exit 1
        ;;
esac

diagnosis_routing_state="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "WITH state AS (
             SELECT
                 to_regclass('retrywise.diagnosis_mode_events') IS NOT NULL AS has_table,
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_attribute
                     WHERE attrelid = to_regclass('retrywise.merchants')
                       AND attname = 'diagnosis_mode'
                       AND NOT attisdropped
                 ) AS has_merchant_mode,
                 (
                     SELECT count(*) = 5
                     FROM pg_catalog.pg_attribute
                     WHERE attrelid = to_regclass('retrywise.decisions')
                       AND attname IN (
                           'requested_diagnosis_mode',
                           'executed_diagnosis_engine',
                           'diagnosis_latency_ms',
                           'diagnosis_fallback_reason_code',
                           'shadow_diagnosis'
                       )
                       AND NOT attisdropped
                 ) AS has_decision_provenance
         )
         SELECT CASE
             WHEN has_table AND has_merchant_mode AND has_decision_provenance THEN 'applied'
             WHEN NOT has_table AND NOT has_merchant_mode AND NOT has_decision_provenance
                 THEN 'missing'
             ELSE 'partial'
         END
         FROM state"
)"

case "${diagnosis_routing_state}" in
    applied)
        echo "RetryWise migration 011 is already applied."
        ;;
    missing)
        psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 \
            -f "${diagnosis_routing_migration_path}"
        ;;
    partial)
        echo "RetryWise migration 011 is partial; refusing to guess or overwrite it." >&2
        exit 1
        ;;
    *)
        echo "unexpected RetryWise migration 011 state: ${diagnosis_routing_state}" >&2
        exit 1
        ;;
esac

outbox_ready="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "SELECT
             to_regclass('retrywise.outbox_jobs') IS NOT NULL
             AND to_regtype('retrywise.outbox_retry_mode') IS NOT NULL
             AND (
                 SELECT count(*) = 4
                 FROM pg_catalog.pg_attribute AS attribute
                 WHERE attribute.attrelid = to_regclass('retrywise.outbox_jobs')
                   AND attribute.attname IN (
                       'delivery_version',
                       'lease_token',
                       'retry_mode',
                       'completion_reference'
                   )
                   AND NOT attribute.attisdropped
             )"
)"
if [ "${outbox_ready}" != "t" ]; then
    echo "RetryWise fenced outbox schema verification failed." >&2
    exit 1
fi

credential_binding_ready="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "SELECT
             to_regprocedure(
                 'retrywise.enforce_provider_account_credential_binding()'
             ) IS NOT NULL
             AND (
                 SELECT count(*) = 2
                 FROM pg_catalog.pg_attribute AS attribute
                 WHERE attribute.attrelid = to_regclass('retrywise.provider_accounts')
                   AND attribute.attname IN (
                       'credential_key_id_sha256',
                       'credential_binding_version'
                   )
                   AND NOT attribute.attisdropped
             )"
)"
if [ "${credential_binding_ready}" != "t" ]; then
    echo "RetryWise credential binding schema verification failed." >&2
    exit 1
fi

provider_event_body_index_ready="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "SELECT EXISTS (
             SELECT 1
             FROM pg_catalog.pg_index AS index_state
             WHERE index_state.indexrelid = to_regclass(
                       'retrywise.provider_events_body_reuse_lookup_idx'
                   )
               AND index_state.indisvalid
               AND index_state.indisready
         )"
)"
if [ "${provider_event_body_index_ready}" != "t" ]; then
    echo "RetryWise provider-event body-reuse index verification failed." >&2
    exit 1
fi

late_link_money_ready="$(
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -Atqc \
        "SELECT EXISTS (
             SELECT 1
             FROM pg_catalog.pg_proc AS procedure
             JOIN pg_catalog.pg_namespace AS namespace
               ON namespace.oid = procedure.pronamespace
             WHERE namespace.nspname = 'retrywise'
               AND procedure.proname =
                   'enforce_recovery_instrument_lifecycle'
               AND position(
                   'OLD.status IN (''CANCELLED'', ''EXPIRED'')'
                   IN pg_get_functiondef(procedure.oid)
               ) > 0
               AND position(
                   'NEW.status IN (''PAID'', ''PARTIALLY_PAID'')'
                   IN pg_get_functiondef(procedure.oid)
               ) > 0
         )"
)"
if [ "${late_link_money_ready}" != "t" ]; then
    echo "RetryWise late Payment Link money transition verification failed." >&2
    exit 1
fi

echo "RetryWise migrations 001 through 011 are ready."
