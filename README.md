# RetryWise

**Recover more. Retry less.**

RetryWise is an incident-aware payment-recovery control plane for Razorpay merchants. It treats a failed payment as uncertain evidence, waits for late success, checks payment-rail health, and creates a bounded recovery path only when fresh provider truth and deterministic policy agree.

> The model proposes. Deterministic code authorizes. Razorpay Test Mode proves the effect.

## What is real and what is simulated

The repository has two deliberately isolated evidence planes:

- **Razorpay Test Mode:** signed webhooks, read-only payment/order reconciliation, Standard Payment Link create/fetch/cancel, PostgreSQL state, operator approvals, kill switches, and audit verification. No live key is accepted and no real money is claimed.
- **Replay:** seeded synthetic journeys used for repeatable comparison and adversarial testing. Replay totals can never be relabelled as provider results or authorize a provider effect.

The application does not ship a fake Razorpay effect adapter. Provider effects are disabled by default; the only runtime effect mode is explicitly named `razorpay_test`.

## Implemented vertical slice

1. The API verifies Razorpay HMAC over the exact raw request bytes, binds the endpoint to one enabled Test account, deduplicates the event, and commits inbox plus outbox state atomically.
2. The worker routes `payment.failed`. If the webhook does not contain enough trusted mapping data, it fetches the current Payment and Order from Razorpay before creating the canonical order, payment, and observing case.
3. PostgreSQL owns the non-shortenable late-capture deadline. The scheduler creates a version-bound assessment command when the case becomes eligible.
4. The assessment worker re-reads current Razorpay truth and method health, routes a redacted seven-field diagnosis through Local ML, bounded Gemini, or Shadow mode, and applies deterministic policy. Wait, block, approval, and create outcomes are durable and audited.
5. An approved collection action is materialized by a credential-isolated worker. Immediately before a provider call it rechecks the lease fence, case version, original payment, incident state, global kill switch, merchant kill switch, and one-active-instrument invariant.
6. Standard Payment Link creation reconciles ambiguous timeouts by stable `reference_id`; it never blindly retries an unknown write outcome.
7. Captured and Payment Link terminal events update monotonic money truth. If the original path becomes paid, obsolete collectable links are scheduled for protective cancellation. Paid/partially-paid races go to review.
8. Every assessment, approval, create, and cancellation authority transition appends canonical, tenant-bound hash-chain evidence; signed provider events remain immutable source evidence. The authenticated operator API recomputes and verifies the case chain.

## Safety model

- Test keys only; `rzp_live_...` is rejected at composition and adapter boundaries.
- Secrets live in owner-only mounted files, never command arguments, URLs, logs, browser state, environment variables, or database values.
- Enrollment first completes a read-only Razorpay Test API request, then writes `0600` files and only a key-ID digest plus versioned secret reference to PostgreSQL.
- Provider effects require both the deployment switch and merchant switch to be open. Either switch fails closed.
- All money values use integer minor units and exact currency/account/order binding.
- Transactional inbox/outbox, fenced leases, immutable idempotency keys, and post-write reconciliation make at-least-once delivery safe.
- The original payment is always re-read before collection; fresh provider truth dominates stale webhook or model output.
- Replay and Test Mode are database- and UI-separated. Live-money execution is intentionally unsupported.

## Runtime shape

```text
Razorpay Test webhooks -> API -> PostgreSQL inbox/outbox
                                  |
                                  v
                         scheduler + worker
                                  |
             fresh Razorpay Payment/Order/Link reads
                                  |
              deterministic gate -> Test Payment Link

Operator console -> authenticated API -> persisted cases, approvals,
                                        controls, incidents, audit proof
```

This is a modular monolith with separate API and worker roles and one PostgreSQL authority. Production can deploy the roles as separate processes. The free Render demonstration profile co-locates both roles in one web-service process, while preserving the same transactional outbox, leased worker, credential, and effect boundaries.

## How recovery is triggered

RetryWise is event-driven; an operator does not manually create a recovery case.

1. Razorpay sends `payment.failed` to the enrolled endpoint at `/api/v1/webhooks/razorpay/{endpoint_token}`.
2. The API verifies the signature over the raw body, resolves the endpoint to one Test account, deduplicates the provider event, and stores inbox and outbox records in one transaction.
3. The worker reads current Payment and Order state from Razorpay, creates the canonical recovery aggregate, and waits through the configured late-capture observation window.
4. The selected diagnosis engine classifies a closed, redacted feature vector and can abstain. Local ML is the reproducible default; Gemini can be authoritative only for classification, or run in shadow beside Local ML. Deterministic policy combines the result with money truth, incident state, timing, limits, and aggregate version.
5. Safe cases wait or stop. Uncertain cases require a version-bound operator decision. Authorized cases create at most one deterministic Standard Payment Link after a final provider recheck.
6. Captured-payment and Payment Link events reconcile the outcome. A case closes as recovered only from provider-confirmed money truth, with every authority transition recorded in the hash-chained audit ledger.

The console exposes this same sequence as an operating pipeline and keeps Test Mode evidence separate from offline replay results. In Test Mode it polls persisted evidence every five seconds, follows the newest case by default, preserves the selected case during background refresh, highlights the current operating stage, and renders a timestamped event stream. Operators can deliberately select an older case for investigation without the next refresh replacing it.

The Controls view persists one diagnosis mode per merchant:

- `LOCAL_ML`: pinned, offline, deterministic inference.
- `HYBRID_GEMINI`: stateless Gemini structured output with an eight-second bound, low thinking latency, semantic validation, a circuit breaker, and Local ML fallback. Every Hybrid recovery proposal requires an explicit operator approval or rejection, whether Gemini answers or the fallback takes over.
- `SHADOW`: Local ML remains authoritative while Gemini agreement is recorded for evaluation.

Gemini receives only payment method, normalized error source/step/reason, incident state, attempt bucket, and failure-age bucket. It receives no provider IDs, amount, customer identity, phone, email, UPI address, card data, or notes, and it has no credentials or execution tools. Requests set `store=false`. Every decision records requested mode, executed engine, latency, fallback reason, and shadow result.

## Local verification

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[api,dev]'
PYTHON=.venv/bin/python make quality
PYTHON=.venv/bin/python make coverage
PYTHON=.venv/bin/python make api-test
PYTHON=.venv/bin/python make eval-primary-verify
PYTHON=.venv/bin/python make eval-determinism
PYTHON=.venv/bin/python make package
```

Validate the container topology without starting services:

```sh
docker compose config --quiet
```

Default Compose starts the database, migrator, and effect-disabled API. The credentialed worker is behind the `razorpay-test` profile and starts only after enrollment:

```sh
docker compose up --build
docker compose --profile razorpay-test --env-file /absolute/path/retrywise-test.env up --build
```

See [the production runbook](docs/production-runbook.md) before using the second command.

## Reproducible offline evidence

The frozen primary run contains 2,000 paired synthetic journeys with 400 merchant-clustered bootstrap samples. It reports INR 20.11L simulated incremental value, INR 3.04L lift over the strongest safe rules baseline, a positive INR 0.38L–5.85L paired 95% interval, 318 incremental recoveries, 193 original-success suppressions, and zero hard safety violations.

The ten-seed stress run covers 20,000 synthetic journeys. All ten point estimates are positive, nine per-seed intervals support improvement, aggregate simulated lift over the strongest safe rules baseline is INR 39.82L, and hard safety violations remain zero. These numbers are engineering evidence, not observed merchant revenue.

## Deployment evidence and release boundary

The implementation is a production-grade **pre-production Test Mode candidate**, not a claim of completed production deployment. Before a production release, the following external checks remain mandatory:

- Move the worker role to continuously available managed compute and the database to a backed-up, non-expiring production plan.
- Repeat the late-original-success cancellation path and retain its provider reconciliation evidence.
- Add sustained load, restore, credential-rotation, and alert-delivery certification for the target production environment.
- Keep live-money credentials and live effects unsupported until a separately reviewed release introduces them deliberately.

Deployment validation includes public signed Razorpay Test webhooks, enrolled Test credentials, migrated PostgreSQL state, real Payment and Order reads, a real Standard Payment Link create, a captured Test recovery payment, deduplicated ingress, a terminal `RECOVERED` case, provider payment reconciliation, and a valid five-entry audit chain. These are Test Mode engineering facts, not live-money or production-reliability claims.

## Documentation

- [Production runbook and secure enrollment](docs/production-runbook.md)
- [System architecture](docs/architecture.md)
- [Razorpay integration](docs/razorpay-integration.md)
- [State machine](docs/state-machine.md)
- [Threat model](docs/threat-model.md)
- [Data model](docs/data-model.md)
- [Evaluation contract](docs/evaluation.md)
- [Development guide](docs/development.md)
- [HTTP API contract](contracts/openapi.yaml)

RetryWise is a working name and still requires normal trademark and domain clearance before commercial use.
