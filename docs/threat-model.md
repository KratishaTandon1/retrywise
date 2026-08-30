# Threat model and safety invariants

## Security objective

Maximise incremental recovered value subject to zero hard safety violations.

RetryWise is not legally or regulatorily certified by this design. Production launch still requires merchant, privacy, security, and legal review. The implementation can accurately claim that it is consent-, policy-, and escalation-aware.

These are release invariants. Pure domain gates, schema constraints, ingress,
the composed effect/audit worker, and adversarial tests enforce them. A
credentialed provider run and live PostgreSQL crash/concurrency exercise have
not yet validated the whole set end to end, so production deployment is not
claimed.

## Hard invariants

These invariants must exist as executable predicates, database constraints where possible, runtime assertions, and adversarial tests.

1. **Paid means stop.** Only freshly reconciled `UNPAID` truth permits collection.
2. **Fresh truth before effect.** Fetch provider truth at decision time and immediately before an outbound money-adjacent action.
3. **One recovery instrument.** A partial unique index prevents multiple `CREATING`, `UNCERTAIN`, `ISSUED`, `ACTIVE`, or `CANCEL_PENDING` instruments per logical order and currency.
4. **Convergent effects, not exactly once.** Use a durable inbox, transactional outbox, deterministic action key, unique Payment Link reference, and reconciliation after uncertainty.
5. **Amount conservation.** The verified remaining amount and currency come from deterministic provider/order data, never a model.
6. **No model authorization.** Models classify, rank, or explain; policy code authorizes.
7. **Two-stage gate.** Evaluate constraints during planning and again inside the action worker.
8. **Bounded customer contact.** Enforce consent, opt-out, quiet hours, rolling caps, cooldown, expiry, and a global kill switch.
9. **High-risk abstention.** High-value, low-confidence, unknown, out-of-distribution, partial-payment, or mapping-conflict cases require approval or escalation.
10. **Incident-aware methods.** Never recommend a method under confirmed degradation. Stale health data fails closed.
11. **Late-success compensation.** Original authorization/capture/order-paid state revokes pending interventions. If cancellation is too late, open duplicate review.
12. **No automatic refund.** Duplicate collection is detected and escalated; automatic refunding is outside scope.
13. **Audit before effect.** If intent and gate evidence cannot commit durably, no external call occurs.
14. **Tenant isolation.** The signed provider `account_id` must match the internal row's tenant, provider, TEST environment, and enabled state at readiness and write time.
15. **Safe degradation.** Model outage, malformed output, stale data, provider timeout, or queue overload resolves to wait, suppress, or review.
16. **Kill-switch nuance.** The kill switch blocks new collection/contact but still permits reconciliation and cancellation.
17. **Observation floor is not model-controlled.** Even a permanent-looking diagnosis cannot shorten the immutable 120-second late-capture protection window, which begins from trusted receive/database time.

## Execution gate

```text
allow(action) only if:
  environment permits effects
  AND global and merchant kill switches are off
  AND action type is allow-listed
  AND aggregate version matches
  AND canonical payment truth == UNPAID
  AND provider snapshot is fresh
  AND the deterministic late-capture observation floor has elapsed
  AND no active recovery instrument exists
  AND amount and currency equal verified amount due
  AND consent, opt-out, cooldown, caps and quiet hours pass
  AND the proposed method is healthy
  AND attempt budget remains
  AND confidence/abstention policy passes
  AND current approval matches when approval is required
```

Every failed predicate emits a stable machine-readable reason code.

## Threats and controls

| Threat | Consequence | Required control |
| --- | --- | --- |
| Forged webhook | False recovery action | HMAC over exact raw bytes; reject before parse/queue |
| Valid replay | Repeated action/contact | Unique provider event inbox and idempotent projection |
| Same signed body replayed with a changed unsigned event-ID header | Repeated projection under a new inbox key | Detect cross-ID body-digest reuse, emit suspicious evidence, and make payment/case transitions idempotent by provider resource and monotonic state |
| Out-of-order delivery | Recovery after payment | Monotonic payment projection plus fresh provider reads |
| Concurrent workers | Multiple links | Aggregate version, per-order lock, partial unique index |
| Accepted create with lost response | Duplicate link on retry | `ACTION_UNCERTAIN`; lookup deterministic reference |
| Cross-tenant ID collision or misbinding | Data/action leak | Signed account check, row lock, DB trigger, provider/TEST binding, and composite tenant keys |
| Stolen provider secrets | Unauthorized actions | Server-only secrets, rotation, test/live separation |
| Previous webhook secret never retired | Extended forged-ingress window | Paired canonical UTC expiry, startup rejection when expired, per-request exclusion at deadline |
| Database interception or endpoint spoofing | Tenant/payment evidence disclosure or mutation | Deployed profiles force PostgreSQL `verify-full` over an unambiguous TCP host with trusted CA and hostname validation |
| Prompt injection in notes/error text | Model-directed effect | Closed structured features, no tools/secrets, strict schema |
| Gemini returns schema-valid but inconsistent probabilities | Misclassification presented as evidence | Exact taxonomy, integer basis-point sum, first-winner consistency, confidence and OOD validation before acceptance |
| Gemini timeout, rate limit, or vendor outage | Assessment backlog or silent unsafe degradation | Eight-second bound, low thinking level, three-failure circuit breaker, immediate Local ML fallback, and mandatory operator approval or rejection in Hybrid mode |
| Gemini key disclosure or unintended prompt retention | Unauthorized vendor usage or unnecessary data retention | Owner-only server file, fixed-origin header authentication, `store=false`, redacted representations, no browser/API response exposure |
| External diagnosis cost exhaustion | Availability/cost incident | One call per eligible assessment, no model retry loop, circuit breaker, Local ML and deployment egress controls |
| Hallucinated cause | Harmful intervention | Calibration, abstention, deterministic gate, approval |
| Permanent-looking diagnosis hides late capture | Duplicate collection | Immutable 120-second floor from trusted receive/database time, enforced by aggregate, both gate stages, and PostgreSQL |
| Incident poisoning | Traffic suppression | Minimum volume, confidence, provider corroboration, TTL |
| Stale downtime | Bad method recommendation | Freshness limit, hysteresis, safe fallback |
| Webhook storm | Queue collapse | Body/rate limits, backpressure, quotas, dead-letter queue |
| PII leakage | Privacy harm | Redaction, tokenised identity, retention, no PII to model |
| Worker crash around effect | Lost/repeated action | Transactional outbox and provider reconciliation |
| Operator mistake | Broad actions | Version-bound approval and global/merchant kill switches |
| Audit tampering | Unverifiable claims | Append-only ledger and per-case integrity hash chain |
| Overpayment race | Customer charged twice | Recheck, cancel, aggregate truth, duplicate review |
| Model/vendor outage | Recovery outage | Rules-only safe fallback or wait; never bypass gate |

## Required property tests

- Duplicating or permuting an event stream cannot create extra external effects.
- Reusing identical signed bytes under another event ID cannot create another case, decision, contact, or provider effect.
- Once paid truth is known, a later failure event cannot reopen collection.
- Every external effect has an earlier durable intent and successful gate record.
- No tenant can mutate another tenant's aggregate.
- Crashes at every outbox/action boundary converge after replay.
- Any model output outside the schema is non-executable.
- Amount and currency cannot be controlled by model output.
- Unknown provider states fail closed.
- An apparently permanent credential failure cannot execute before the 120-second late-capture floor.
- Provider-supplied timestamps and model output cannot start, shorten, or backdate that floor.
