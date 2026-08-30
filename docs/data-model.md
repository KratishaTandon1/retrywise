# RetryWise data model and tenancy contract

## 1. Database role

PostgreSQL is the intended authoritative store for accepted provider evidence,
canonical payment truth, recovery workflow state, decisions, approvals, actions,
audit entries, and the transactional outbox. The API writes provider evidence
plus inbox/outbox ingress rows; the worker commits projection, assessment,
approval, action, instrument, cancellation, and audit transitions. Redis is
deliberately absent from the first release:
correctness cannot depend on an evictable cache.

Every tenant-owned table carries `merchant_id`. Provider identifiers are never assumed globally unique; lookups use `(merchant_id, provider_account_id, provider_id)`. API requests derive merchant scope from authenticated server claims, never from a trusted client-supplied header.

## 2. Core identities

| Concept | Identifier | Rule |
| --- | --- | --- |
| Merchant | ULID | Stable tenant boundary |
| Provider account | ULID plus Razorpay `account_id` | One credential/test-live boundary |
| Logical order | ULID | Correlates original order and every recovery path |
| Recovery case | ULID | At most one open case per logical order/currency |
| Decision | ULID | Immutable, bound to aggregate version and feature snapshot |
| Action | ULID plus deterministic action key | Immutable intent; lifecycle advances monotonically |
| Provider event | Razorpay event ID | Unique inside provider account |
| Audit entry | Per-case sequence | Hash chained, append only |

ULIDs are generated server-side. Provider IDs and public case IDs may be returned to the console, but internal credential references never are.

## 3. Tables

### `merchants`

- `id`, `display_name`, `status`, `timezone`, `created_at`, `updated_at`
- `kill_switch_enabled`, `default_policy_version`, `diagnosis_mode`

### `provider_accounts`

- `id`, `merchant_id`, `provider`, `provider_account_identifier`, `environment`
- managed-secret reference, enrolled key-ID SHA-256, and monotonic credential-binding generation; never plaintext secrets
- unique `(provider, provider_account_identifier, environment)` and unique enrolled key digest per provider/environment
- generation zero is ingress-only; material rotation must advance the generation by exactly one

### `provider_events`

- `merchant_id`, `provider_account_id`, `provider_event_id`, `event_type`
- exact-body SHA-256 digest, signature version, verification result
- provider occurrence time and receive time
- immutable encrypted/raw evidence reference with a retention policy
- unique `(provider_account_id, provider_event_id)`

### `logical_orders`

- tenant/provider correlation, merchant order reference, original Razorpay order ID
- `amount_due_minor`, `currency`, `captured_total_minor`, `refunded_total_minor`
- canonical truth, truth version, provider snapshot time, mapping status
- check constraints keep money non-negative and currency three uppercase characters

### `recovery_cases`

- logical order, workflow state, incident scope, database-owned observation start,
  immutable observation/evaluation deadlines, and observation contract version
- aggregate `version`, attempt/contact counters, terminal reason
- last decision/action identifiers and timestamps
- unique partial index prevents multiple non-terminal cases per logical order/currency

### `recovery_instruments`

- case, action, provider Payment Link ID/order ID, stable `reference_id`
- amount/currency, status, expiry, last reconciliation time
- partial unique index permits one `CREATING`, `UNCERTAIN`, `ISSUED`, `ACTIVE`, or `CANCEL_PENDING` instrument per logical order/currency
- `accept_partial` is constrained false in version one

### `decisions`

- immutable feature snapshot and its schema version
- model name/version, calibrated class probabilities, abstention/OOD flags
- requested diagnosis mode, executed engine, bounded latency, fallback reason,
  and optional schema-validated shadow comparison
- policy name/version, candidates and scores, selected action
- planning-gate verdict/reason codes, expected-value inputs and output
- source label: `RAZORPAY_TEST_MODE`, `REPLAY`, or `SIMULATION`

### `approvals`

- decision ID, case ID, aggregate version, requested/expiry times
- approver subject, verdict, reason, acted time
- one final verdict; a mismatch or expiry cannot be refreshed in place

### `diagnosis_mode_events`

- tenant, monotonic sequence, selected closed mode, and stable reason code
- SHA-256 operator subject and idempotency-key digests; no bearer token or API key
- append-only evidence; the current merchant mode and event commit atomically

### `actions`

- immutable decision and case binding, deterministic `action_key`
- action type, status, attempt number, lease owner/expiry
- effect-gate snapshot and reason codes
- redacted request/response metadata, provider status, reconciliation status
- unique `(merchant_id, action_key)`

### `incidents`

- merchant/method/instrument scope, state, severity, confidence
- evidence summary, provider downtime ID, first/last seen, TTL, cooling deadline
- detector and threshold versions

### `audit_entries`

- case, monotonic sequence, entry type, actor type/subject
- canonical JSON payload, prior hash, entry hash, created time
- unique `(recovery_case_id, sequence)` and `(recovery_case_id, entry_hash)`

The hash chain is tamper evidence, not deletion prevention. Database permissions, backups, retention controls, and external log export provide the surrounding operational controls.

### `inbox_events` and `outbox_jobs`

Inbox rows record acceptance and processing status for at-least-once provider delivery. Outbox rows contain versioned commands, next-attempt time, bounded retry count, monotonic delivery version, owner/token/expiry fence, explicit retry mode, completion reference, and dead-letter metadata. A reclaimed or ambiguous effect is reconciliation-only until a completed negative provider lookup explicitly permits the same effect. The runtime commits business state and its outbox job in one transaction across ingress, enrichment, assessment, approval, create, terminal projection, and protective cancellation boundaries.

### `evaluation_runs`

- immutable run manifest: seed set, dataset hash, code revision, policy/model/cost versions
- environment label and status
- aggregate metrics plus artifact references
- results cannot be relabelled from simulation/replay to observed revenue

## 4. Required database constraints

1. Money is integer minor units and never negative.
2. Currency and amount on an instrument match its logical order snapshot.
3. Provider event identity is unique inside a provider account.
4. Action keys are unique inside a merchant.
5. Only one active recovery instrument exists per logical order and currency.
6. Every action references one immutable decision from the same case and tenant.
7. Approval decision/case/version must match the action intent.
8. Audit sequence is strictly increasing per case.
9. Test and live provider accounts cannot be joined into one case.
10. Provider-affecting actions cannot enter `EXECUTING` from Replay or Simulation evidence.
11. Every new case stores a PostgreSQL-assigned observation start and an immutable deadline at least two minutes later. PostgreSQL clamps shorter caller values to its own clock and must reach the deadline before initial assessment. Provider occurrence time cannot start, shorten, or backdate this floor. Pre-hardening rows carry contract version `0` and cannot advance into collection states; new rows carry version `1`.
12. Canonical webhook account identity must match the same enabled Razorpay TEST account row referenced by the tenant-scoped event.
13. Outbound credential material requires an enrolled key-ID digest and positive generation; material changes advance exactly one generation and account identity/environment are immutable.
14. Cross-event-ID body-digest reuse is indexed for bounded suspicious-replay detection; the digest is deliberately not globally unique.

Cross-row financial invariants are enforced in a serializable command transaction and repeated in the action worker immediately before an effect; constraints alone are not sufficient.

## 5. Retention and privacy

- Store no PAN, CVV, UPI PIN, bank credentials, or provider payment tokens.
- Mask email/phone in the console; prefer Razorpay notification delivery so contact details need not enter RetryWise.
- Keep the verified-body digest for the audit horizon. Raw webhook bodies require explicit encryption, access logging, and expiry.
- Keep decision features structured and redacted. Free-form provider text never reaches a model without a separate sanitisation contract.
- Delete or cryptographically destroy tenant secrets when an integration is removed; preserve non-sensitive audit evidence under the merchant's retention policy.

## 6. Query and scale strategy

Initial indexes prioritize `(merchant_id, state, updated_at)`, `(merchant_id, provider_payment_id)`, outbox due time, incident scope/state, audit case/sequence, and tenant/account/body-digest provider-event reuse lookup. Large append-only tables partition by receive/create month after measured need. All operator lists use stable cursor pagination rather than offsets.
