# Evaluation contract

## Objective

```text
Maximise simulated incremental recovered value
subject to zero hard safety violations.
```

Safety metrics are evaluated lexicographically before business metrics. A policy with more recovered value but a hard violation loses.

## Discrete-event simulator

The simulator uses a virtual clock; tests never depend on real sleeps.

### Generation pipeline

1. Generate merchant policy: contact caps, quiet hours, approval threshold, enabled methods, recovery horizon, and costs.
2. Generate latent incidents: UPI-wide, issuer/card-network, and bank-specific degradation with severity and reporting delay.
3. Generate logical orders: amount, currency, method, latent cause, natural-recovery time, response propensity, and consent.
4. Precompute potential outcomes for each permitted action using deterministic keyed randomness.
5. Emit canonical provider truth separately from the delivered webhook stream.
6. Mutate delivery with duplication, reordering, delay, loss, invalid signatures, wrong accounts, and schema evolution.
7. Inject provider/action faults independently.

The policy sees only delivered events and fetch responses. It never sees latent cause or potential-outcome truth. Grouped splits use merchant and incident episode or time; random row splits are prohibited because they leak incident context.

## Required scenario families

1. Ordinary recoverable failure, wrong UPI PIN, late authorisation, insufficient funds, expired credential, and unknown failure.
2. UPI-wide, issuer-specific, and bank-specific incidents with early, late, or absent provider downtime signals.
3. Duplicate, reordered, delayed, dropped, malformed, invalid-signature, and cross-tenant events.
4. Capture during observation, capture while link creation is in flight, and both collection paths capturing.
5. Partial payment, expiry, cancel-versus-paid race, opt-out, quiet hours, contact cap, and high-value approval.
6. Ambiguous mapping, currency mismatch, unknown enum, prompt-injection metadata, provider errors, worker crashes, and kill switch.

## Baselines

- `B0 Natural recovery`: no intervention.
- `B1 Blast all`: immediate generic link after every failure.
- `B2 Fixed safe rule`: fixed observation, one link, caps, no learned diagnosis.
- `B3 Incident-aware rules`: deterministic downtime/error routing with unknown failures sent to manual review.
- `RetryWise`: selective learned diagnosis, deterministic incident-aware fallback on in-distribution low confidence, expected-value selection, and the same safety gate.
- `Oracle ceiling`: sees latent truth; shown only as an unattainable upper bound.

All policies face identical potential outcomes.

## Metrics

### Safety, primary

- Unsafe executed action rate: zero.
- Stop-rule violations: zero.
- Stale-state actions: zero.
- Multiple active recovery instruments: zero.
- Invalid webhook acceptance: zero.
- Cross-tenant effects: zero.
- Unrecognised overpayment: zero.
- Synthetic outcome-field completeness: 100%. This checks expected fields in
  simulator outcomes; it does not prove PostgreSQL audit persistence or runtime
  hash-chain verification.
- Duplicate effects under replay/crash.
- Original-success actions suppressed.

### Business

```text
simulated_incremental_value =
  sum(amount * (chosen_action_outcome - no_action_outcome))
  - communication_cost
  - incentive_cost
  - duplicate_or_refund_penalty
  - configured_friction_penalty
```

Also report gross/net value, incremental recovered orders, contact efficiency, unnecessary-contact rate, median/p95 recovery time, abstention, regret versus oracle, and performance by cause.

### Model, incident, and reliability

- Incident precision/recall/F1, scope accuracy, and detection time are target production metrics; the current deterministic detector tests state/hysteresis behavior.
- The bundled diagnosis artifact reports a separate synthetic 18-row holdout: accuracy `1.0`, multiclass Brier `0.077490430499`, expected calibration error `0.140586225221`, and abstention rate `0.222222222222`. The sample is intentionally too small and synthetic for a merchant-performance claim.
- Duplicate suppression, event-to-decision latency, outbox reconciliation, unresolved uncertainty, dead-letter recovery, and deterministic replay equality.

Use paired bootstrap confidence intervals clustered by merchant or incident. Do not claim improvement when the interval does not support it.

## Honest labels

- `Razorpay test-mode collection executed`: real provider workflow, no real money.
- `Offline simulated recovered value`: synthetic counterfactual result.
- `Observed real merchant revenue`: never claimed without real deployment/experiment.

## Published runs

- Smoke: 200 cases under ten seconds.
- Primary: seed 42, 2,000 paired cases, 400 merchant-clustered bootstrap samples.
- Stress: 20,000 paired cases across 10 frozen seeds, each with its own merchant-clustered interval.
- Golden: fixed adversarial scenarios configured in CI on every commit.

Every manifest stores dataset hash, seed, code revision, policy/model version, and cost assumptions. Published local evidence uses a deterministic `source-sha256:` digest over all Python sources in `packages/simulator`, `packages/diagnosis`, and `packages/domain`; CI is configured to regenerate the 2,000-case primary report and require a byte-for-byte match. Downloadable JSON/CSV plus a human-readable report is a release artifact.

### Current frozen results

Primary seed 42:

- RetryWise offline simulated incremental value: ₹20.11L.
- Net point lift over B3: ₹3.04L.
- Merchant-clustered 95% paired interval: ₹0.38L to ₹5.85L.
- 318 incremental recoveries, 193 original-payment successes suppressed, zero hard violations, 100% synthetic outcome-field completeness.

Ten-seed stress summary:

- 20,000 synthetic journeys; all 10 lift point estimates are positive.
- 9 of 10 per-seed intervals support improvement; one is inconclusive, not relabelled as a win.
- Aggregate offline simulated lift over B3: ₹39.82L.
- Zero hard safety violations after a multi-seed regression exposed and fixed an overly short observation window for apparently expired credentials.

These results are synthetic counterfactual evidence. They do not claim observed real merchant revenue or real-money collection.
