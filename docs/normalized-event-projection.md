# Normalized provider-event projection

## Implemented boundary

`PROCESS_NORMALIZED_PROVIDER_EVENT` has one closed version-one command schema and
a closed worker router. It sends `payment.failed` to the failure projector and
`payment.captured`, `payment_link.paid`, and `payment_link.partially_paid` to the
terminal projector. Projection performs no model call or direct money-adjacent
effect.

For an eligible failure, one transaction:

1. locks and verifies the current fenced outbox delivery;
2. locks the tenant-scoped inbox row and joins the same enabled Razorpay TEST
   account, including its signed external `account_id`;
3. validates the immutable provider-event columns against the strict canonical
   event and command envelope;
4. rejects the same signed-body digest under a different provider event ID as
   suspicious;
5. locks an existing provider payment and logical order, requiring exact
   payment ID, order ID, account, amount, currency, mapping state, and method
   when the event supplies one;
6. rejects a failure older than the stored provider snapshot, then projects
   only `UNKNOWN` or `CREATED` payment state to `FAILED`—an
   `AUTHORIZED`, `CAPTURED`, or `REFUNDED` state always dominates a stale
   failure event;
7. inserts or reuses the single open recovery case and verifies PostgreSQL
   returned observation-contract version `1` with a database-owned start and
   deadline at least two minutes apart; and
8. if trusted mapping does not exist, queues one `ENRICH_FAILED_PAYMENT` command;
   that handler fetches the current Razorpay Payment and Order, rejects any
   binding disagreement, persists the minimal canonical projection, and
   requeues the same failure evidence; and
9. marks the inbox `PROCESSED`, `DEFERRED`, or explicitly `IGNORED` in the same
   transaction.

The handler returns a `HandlerResult` for the existing bounded `OutboxWorker`.
If the process dies after projection commits but before the outbox row is
settled, redelivery sees the terminal inbox state and completes without another
payment mutation or recovery case.

## Fail-closed outcomes

- Unknown command fields, versions, tenant bindings, aggregate bindings, or
  idempotency keys dead-letter the outbox command.
- Malformed or internally inconsistent canonical evidence dead-letters without
  projecting financial state.
- Mapping conflicts, unsupported event types, reused body digests, and
  capture-capable payment states are marked `IGNORED` with bounded non-PII
  reason codes. A merely missing mapping is enriched from fresh provider truth.
- Database errors are not translated into success; the worker's existing
  reconciliation-only retry behavior applies.
- Persisted error facts are limited to bounded categorical provider fields and
  reject contact-number-shaped values. No contact, customer, credential,
  payment token, or free-form description is introduced by this path.

## Composition boundary

The executable worker schedules assessments after the database-owned deadline,
runs diagnosis and policy, persists wait/block/approval/create outcomes, appends
audit evidence, executes Razorpay Test Payment Links, projects supported terminal
events, and schedules protective cancellation. Downtime webhook projection is
not part of this router; method health is read from the incident authority.
Migrations `001` through `011` are required, and a live PostgreSQL
crash/concurrency run remains an external release gate in addition to the
focused transaction regressions.
