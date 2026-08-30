# RetryWise PostgreSQL authority

PostgreSQL 16 is the system of record for verified provider evidence, canonical
payment truth, recovery workflow state, immutable decisions and effect intent,
the audit chain, and inbox/outbox delivery state. The schema is advanced only by
numbered, forward-only migrations:

- [`migrations/001_initial.sql`](migrations/001_initial.sql) creates the authority.
- [`migrations/002_fenced_outbox_delivery.sql`](migrations/002_fenced_outbox_delivery.sql)
  adds fenced delivery versions, lease tokens, retry modes, and lifecycle checks.
- [`migrations/003_enforce_effect_source_boundary.sql`](migrations/003_enforce_effect_source_boundary.sql)
  makes provider-effect execution impossible for Replay or Simulation rows.
- [`migrations/004_enforce_observation_deadline.sql`](migrations/004_enforce_observation_deadline.sql)
  assigns database-owned observation time, clamps the two-minute floor, makes it
  immutable, and quarantines pre-hardening cases that lack trusted timing evidence.
- [`migrations/005_bind_provider_event_account.sql`](migrations/005_bind_provider_event_account.sql)
  validates legacy attribution and binds new canonical webhook account identity to
  one enabled Razorpay TEST account row.
- [`migrations/006_version_credential_binding.sql`](migrations/006_version_credential_binding.sql)
  enrolls an exact Test key-ID digest and monotonic credential generation; legacy
  version-zero rows remain ingress-only and cannot authorize outbound effects.
- [`migrations/007_index_provider_event_body_reuse.sql`](migrations/007_index_provider_event_body_reuse.sql)
  adds the concurrent lookup index used to detect the same signed body arriving
  under a different provider event ID without globally rejecting valid bodies.
- [`migrations/008_allow_late_link_money_truth.sql`](migrations/008_allow_late_link_money_truth.sql)
  permits authenticated late payment truth to move a cancelled or expired recovery
  instrument into paid review without weakening monotonic money constraints.
- [`migrations/009_worker_heartbeats.sql`](migrations/009_worker_heartbeats.sql)
  adds exact-code-revision worker heartbeats used by API readiness.
- [`migrations/010_merchant_control_events.sql`](migrations/010_merchant_control_events.sql)
  adds append-only, idempotent evidence for merchant effect kill-switch changes.
- [`migrations/011_diagnosis_engine_routing.sql`](migrations/011_diagnosis_engine_routing.sql)
  adds merchant diagnosis routing, immutable mode-change evidence, and per-decision
  engine, latency, fallback, and shadow provenance.

## Apply

Apply migrations with a role that can create the `retrywise` schema, domains,
enum types, tables, functions, triggers, and indexes:

```sh
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/001_initial.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/002_fenced_outbox_delivery.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/003_enforce_effect_source_boundary.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/004_enforce_observation_deadline.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/005_bind_provider_event_account.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/006_version_credential_binding.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/007_index_provider_event_body_reuse.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/008_allow_late_link_money_truth.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/009_worker_heartbeats.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/010_merchant_control_events.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f retrywise/infrastructure/postgres/migrations/011_diagnosis_engine_routing.sql
```

Migrations `001` through `006`, and `008` through `011` are transactional. Migration `007` deliberately
uses `CREATE INDEX CONCURRENTLY` and must run outside a transaction. Apply every
migration exactly once and in numeric order. The local Compose migrator uses
`apply-local-migration.sh` to distinguish missing, complete, and partial local
schema states, including index validity/readiness; it refuses to guess when a
migration is partial. This guard is not a replacement for a production migration
ledger with checksums.

## Important contracts

- Application-generated IDs are uppercase Crockford ULIDs.
- Amounts are integer minor units and currencies are uppercase ISO codes.
- Every tenant table carries `merchant_id`; composite foreign keys prevent a
  case, decision, action, incident, instrument, or provider event from crossing
  merchant/provider-account boundaries.
- A provider account owns one environment. Binding cases and instruments to the
  order's same provider account prevents Test and Live data from mixing.
- Outbound credentials require credential-binding generation greater than zero,
  an enrolled key-ID SHA-256, and a versioned managed-secret reference. Secret
  material rotation must advance the database generation by exactly one.
- `provider_events`, `decisions`, and `audit_entries` are append-only.
  Approval requests and action intents are immutable while their lifecycle
  fields advance only through permitted transitions.
- Logical-order truth and recovery-case versions advance exactly once per
  update. Triggers reject decreasing financial projections, stale versions,
  invalid workflow transitions, terminal reopening, and TEST/LIVE rebinding.
- An action must match its decision's selected action. Approval-gated actions
  require a matching, timely `APPROVED` verdict, and collection execution
  requires durable effect-gate evidence plus current canonical `UNPAID` truth.
- The open-case partial unique index allows one collection workflow per logical
  order/currency. The collectable-instrument index also treats `UNCERTAIN` and
  `CANCEL_PENDING` links as active because either may still collect money.
- Provider event ingestion and its `inbox_events` row must commit together.
  Domain state and each `outbox_jobs` command must also commit in one database
  transaction. PostgreSQL provides at-least-once processing; stable action keys
  and provider reconciliation provide effectively-once effects.
- Workers claim due rows with `FOR UPDATE SKIP LOCKED`, increment a delivery
  version, and atomically bind owner, token, and expiry. Settlement compares all
  fence dimensions and requires an unexpired lease. Reclaimed work is forced
  into reconciliation-only mode; attempt limits and dead-letter evidence are
  database constrained. Retention may delete only terminal inbox/outbox rows;
  provider evidence and audit records remain.
- The application canonicalizes audit JSON and computes SHA-256. PostgreSQL
  validates 32-byte hash shapes, serializes appends per case with an advisory
  transaction lock, and enforces sequence continuity and prior-hash equality.
  This is tamper evidence, not deletion prevention by itself.
- Evaluation provenance is immutable. A `REPLAY` or `SIMULATION` run cannot be
  relabelled as `RAZORPAY_TEST_MODE` after creation.

## Security and operations

The database stores managed-secret references, never Razorpay API or webhook
secrets. Raw webhook bodies require an encrypted external evidence store with
access logging and expiry; the database retains their SHA-256 digest.

Use separate least-privilege roles for migrations, the API, workers, and
read-only reporting. Application queries must always include the authenticated
`merchant_id`; row-level security can be added in a later migration once the
deployment's connection-pooling identity model is fixed. Backups, point-in-time
recovery, retention jobs, and external audit export remain operational
requirements beyond schema constraints.

The effect worker still owns checks that require live context: a fresh Razorpay
read, snapshot-age policy, kill switches, consent/contact rules, incident
freshness, and the current approval at the exact instant before an external
call. Database constraints are a second safety layer, not a substitute for that
pre-effect gate.
