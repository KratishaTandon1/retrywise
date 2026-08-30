# Razorpay integration contract

Verified against current official Razorpay India documentation on 29 August 2026.

## Critical sandbox facts

- A `payment.failed` event is not terminal. The same payment can later emit `payment.captured`, especially after UPI retry or late authorisation.
- Use a **Standard Payment Link** in test mode. UPI Payment Links are not supported in test mode.
- Test mode permits up to 30 Payment Links per business. Use the simulator for rehearsals and reserve real links for end-to-end validation.
- Cancelling a link is not an atomic guarantee against double payment. A paid/partially-paid result requires duplicate review.
- Razorpay documents no general idempotency key for Payment Link creation. RetryWise uses a stable unique `reference_id` and reconciles ambiguous creates by fetching with that reference. This is our strategy, not a documented exactly-once guarantee.

## Provider credentials and webhook secrets

- Versioned owner-only mounted-file material containing an `rzp_test_` key ID and its key secret.
- PostgreSQL enrollment containing the immutable secret-version reference, key-ID SHA-256, and binding generation.
- `RAZORPAY_WEBHOOK_SECRET_FILE` pointing to an owner-only mounted JSON file.
- Optional previous webhook secret and explicit `YYYY-MM-DDTHH:MM:SSZ` expiry inside that file during rotation.

API key/secret authenticate server APIs with HTTP Basic Auth. The webhook secret is separate. Test/live credentials, data, and webhook configuration remain isolated. Secrets never reach the browser.

Raw `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` environment variables are
rejected so there cannot be a second outbound credential authority. The
outbound worker uses a version-fenced, read-only mounted-file resolver. The
enrollment CLI performs one read-only Test API request before writing secrets,
and worker startup refuses a database generation/key-digest mismatch.

## Webhook subscriptions and current projection status

| Event | Target handling | Current runtime projection |
| --- | --- | --- |
| `payment.failed` | Open/observe recovery case | Worker-registered; enriches missing mapping through fresh Payment and Order reads |
| `payment.captured` | Reconcile original path; stop/cancel recovery | Worker-registered terminal projector |
| `payment.authorized` | Fail closed while funds may be captured | Normalized but deliberately not projected as collection authority |
| `order.paid` | Redundant paid signal | Not projected; fresh Order reads and payment truth remain authoritative |
| `payment.downtime.started/updated/resolved` | Maintain incident projection | Normalized ingress contract; method-health authority is currently PostgreSQL detector state |
| `payment_link.paid` | Confirm recovered path after reconciliation | Worker-registered terminal projector |
| `payment_link.partially_paid` | Defensive exception; partial payment is disabled | Worker-registered; routes to review |
| `payment_link.cancelled` | Confirm suppression/cancellation | Reconciled by the cancellation worker's fresh fetch |
| `payment_link.expired` | Reassess or exhaust case | Reconciled by current-link reads; webhook projection not registered |

## Webhook ingress

```text
POST /api/v1/webhooks/razorpay/{endpoint_token}
X-Razorpay-Signature: <hex HMAC>
x-razorpay-event-id: <provider event ID>
```

1. Select the expected merchant/provider account from the endpoint token.
2. Read exact raw bytes and apply body/content-type limits.
3. Verify HMAC-SHA256 using constant-time comparison.
4. Parse only after verification.
5. Verify payload `account_id` matches the endpoint's provider account.
6. In one transaction insert the inbox event and outbox work item.
7. Deduplicate on `(provider_account_id, provider_event_id)`.
8. Return 2xx within five seconds; all expensive work is asynchronous.

The HMAC authenticates the raw body, not the separately supplied event-ID
header. Inbox deduplication is therefore only the first layer: projection must
also detect identical body digests arriving under different IDs, record that as
suspicious evidence, and remain idempotent by provider resource and monotonic
payment/case state. A global unique digest constraint is intentionally avoided
because two legitimate provider deliveries could theoretically have identical
payload bytes.

Retries signed with a previous secret remain valid only before the explicit UTC
rotation deadline. The previous secret and deadline are an all-or-nothing pair;
an already-expired value prevents startup and a running process removes the old
secret from verification exactly at expiry. This bounds credential overlap
without using provider event age as an authenticity signal. Do not reject a
current-secret retry using an arbitrary short event-age cutoff; record anomalies
and fetch current truth.

## Provider reads

| Purpose | Endpoint |
| --- | --- |
| Current payment | `GET /v1/payments/:id` |
| Expanded card context | `GET /v1/payments/:id?expand[]=card` |
| Current original order | `GET /v1/orders/:id` |
| All attempts on order | `GET /v1/orders/:id/payments` |
| Current Payment Link | `GET /v1/payment_links/:id` |
| Find ambiguous create | `GET /v1/payment_links?reference_id=:reference` |
| Active downtimes | `GET /v1/payments/downtimes` |
| One downtime | `GET /v1/payments/downtimes/:id` |

Suppress new recovery when the original payment is captured, the original order is paid, or any payment on the original order is captured.

The HTTP adapter implements Payment fetch, Order fetch, Standard Payment Link
create/fetch/list-by-reference/cancel, and strict non-sensitive projections.
Order-attempt listing, expanded-card reads, and downtime API reads are not used
by the current vertical slice.

## Standard Payment Link creation

```json
{
  "amount": 129900,
  "currency": "INR",
  "accept_partial": false,
  "reference_id": "rtw_01J_caseShortId",
  "description": "Retry payment for order ORD-1042",
  "expire_by": 1788019200,
  "notify": {"sms": false, "email": false},
  "reminder_enable": false,
  "notes": {
    "recovery_case_id": "01J...",
    "merchant_order_id": "ORD-1042"
  }
}
```

Amount is in minor units; `reference_id` is stable, unique, and at most 40 characters; partial payment is always false; and the link is a separate Razorpay order correlated through the RetryWise case/reference. The durable command codec permits exactly the controller-owned `recovery_case_id` and `merchant_order_id` notes and derives the fixed description from the merchant order identifier; customer fields and free-form notes never enter the outbox. On an ambiguous timeout, fetch by `reference_id` before retrying.

## Cancellation and races

Before or after ambiguous cancellation, fetch the link:

- `cancelled`: the link-control action has converged, but later payment truth can still dominate.
- `expired`: no currently active link-control path; still reconcile payment truth.
- `paid` or `partially_paid`: cancellation was too late; aggregate both paths and open duplicate review if needed.
- transient concurrent-update error: back off, fetch, and reconcile.
- unknown: remain cancel-pending and alert; never claim duplicate prevention.

`amount_paid` is mandatory provider evidence. RetryWise rejects a missing,
non-integer, negative, or over-total value. `paid` requires the full amount;
`partially_paid` requires a value strictly between zero and the total; and this
no-partial-payment instrument requires zero for `created`, `cancelled`, and
`expired`. A cancel call is permitted only from exact fresh target truth with
`amount_paid == 0`.

The implemented cancellation foundation stores one closed, versioned
`CANCEL_PAYMENT_LINK` command. Its immutable target binds merchant, case,
action, instrument, provider account, Payment Link, controller-derived
`reference_id`, amount, and currency under canonical SHA-256 digests. The
executor requires an exact durable action/instrument-row projection, fetches
current provider truth, reloads that durable binding, and then performs a
second fresh effect-gate evaluation immediately before calling cancel. A
recovered/uncertain lease never calls cancel during its reconciliation-only
delivery. Exact fresh created/unpaid truth and a matching durable binding may
grant one `RETRY_SAME_EFFECT` delivery; that later delivery repeats every
fresh check and the final gate before one bounded cancel attempt.

Every cancel outcome—including a nominal 2xx/cancelled response, provider 4xx,
invalid response contracts, timeouts, and transport exceptions—forces another
provider fetch and durable-binding read before the job can transition. A
write-response success alone never completes the action. `paid` and
`partially_paid` always produce explicit review/reconciliation outcomes; they
are never converted into harmless cancellation success. Stable bounded machine
reason codes exclude provider free text, exception text, and credentials.

Cancellation therefore converges through fresh provider fetch and reconciliation
at the link-control layer; it does not claim endpoint-level idempotency and is
not proof that collection became impossible. Terminal original-payment,
Payment Link paid, or partial-payment truth always dominates and may open
duplicate review even after a cancelled response.

The PostgreSQL cancellation scheduler, binding reader, result/audit writer, and
outbox handler are registered in the executable worker. Deterministic tests use
injected transports; the credentialed Test Mode network proof remains a release
gate.

## Credentialed sandbox validation — external delivery pending

### A. Real recovery

Create a Razorpay test order, fail test checkout, verify the real webhook, observe/reconcile, create one real Standard Payment Link, complete its hosted test checkout, reconcile `payment_link.paid`, and mark `RECOVERED`.

### B. Real order-level suppression

Create a recovery link without paying it, succeed on the original order, reconcile original order truth, cancel the active link, and show verified suppression/cancellation evidence.

### C. Replay-only scenarios

No deterministic sandbox switch is documented for same-payment failed-to-captured or real downtime. Validate those exact sequences with clearly labelled Razorpay-compatible replay fixtures.

## Primary official sources

- [Payment webhook events](https://razorpay.com/docs/webhooks/payments/?preferred-country=IN)
- [Webhook validation](https://razorpay.com/docs/webhooks/validate-test/?preferred-country=IN)
- [Webhook best practices](https://razorpay.com/docs/webhooks/best-practices/?preferred-country=IN)
- [Create Standard Payment Link](https://razorpay.com/docs/api/payments/payment-links/create-standard/?preferred-country=IN)
- [Cancel Standard Payment Link](https://razorpay.com/docs/api/payments/payment-links/cancel-standard/?preferred-country=IN)
- [Payment Link webhook events](https://razorpay.com/docs/webhooks/payment-links/?preferred-country=IN)
- [Payment Downtime APIs](https://razorpay.com/docs/api/payments/downtime/?preferred-country=IN)
- [Fetch payment](https://razorpay.com/docs/api/payments/fetch-with-id/?preferred-country=IN)
- [Fetch order](https://razorpay.com/docs/api/orders/fetch-with-id/?preferred-country=IN)
- [Fetch order payments](https://razorpay.com/docs/api/orders/fetch-payments/?preferred-country=IN)
