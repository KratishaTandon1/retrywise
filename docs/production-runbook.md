# RetryWise Razorpay Test Mode runbook

This runbook is the release authority for the credentialed vertical slice. It keeps secrets out of chat and shell history, starts with every collection effect blocked, and opens one gate at a time.

## 1. Preconditions

- A Razorpay account with Test Mode access.
- A Test key ID beginning with `rzp_test_` and its key secret.
- The Razorpay account identifier beginning with `acc_`.
- A new webhook signing secret chosen in the Razorpay dashboard.
- A public HTTPS URL terminating at the RetryWise API.
- PostgreSQL with migrations `001` through `011` applied.
- An absolute private directory whose final `retrywise-secrets` child does not already exist.

Never paste the key secret or webhook secret into chat, source control, an issue, a command argument, or the console browser configuration.

## 2. Validate the non-credentialed build first

Run from the repository root:

```sh
PYTHON=.venv/bin/python make quality
PYTHON=.venv/bin/python make coverage
PYTHON=.venv/bin/python make api-test
PYTHON=.venv/bin/python make eval-primary-verify
PYTHON=.venv/bin/python make eval-determinism
PYTHON=.venv/bin/python make package
docker compose config --quiet
```

The console also requires `pnpm install --frozen-lockfile`, `pnpm lint`, and `pnpm build` in `apps/console` once its dependency lock is available. Do not substitute a syntax-only check for the production build in release evidence.

## 3. Start the database without the effect worker

The Compose worker is protected by the `razorpay-test` profile. Start and migrate PostgreSQL first:

```sh
docker compose up -d postgres
docker compose run --rm migrate
```

For the local Compose defaults, the host DSN is:

```text
postgresql://retrywise_dev:retrywise_local_only@127.0.0.1:5432/retrywise_dev
```

Use a non-default password for any shared or remotely reachable environment.

## 4. Secure enrollment

Enrollment uses hidden prompts. It first makes a read-only `GET /v1/payment_links` request with a random nonexistent reference, proving that the supplied Test credential can authenticate to the fixed Razorpay API origin. It then creates owner-only files and persists only binding metadata.

```sh
DATABASE_URL='postgresql://...' .venv/bin/retrywise-enroll-test \
  --secret-root /absolute/private/parent/retrywise-secrets \
  --display-name 'RetryWise Test Merchant' \
  --timezone Asia/Kolkata \
  --account-id acc_...
```

The command prompts, without echo, for:

1. Razorpay Test key ID.
2. Razorpay Test key secret.
3. Webhook signing secret.

It creates:

```text
retrywise-secrets/                         mode 0700
  razorpay/account.json                   mode 0600
  webhook/webhook.json                    mode 0600
  retrywise-test.env                      mode 0600
```

The generated environment starts with `RETRYWISE_EFFECTS_MODE=disabled` and `RETRYWISE_GLOBAL_KILL_SWITCH=true`. The merchant database kill switch also starts enabled. This is expected.

Enrollment proves credential usability, but Razorpay does not return the `acc_` owner in the Payment Link list response. The `acc_` association therefore remains operator-attested metadata, protected by a key-ID digest and monotonic credential generation.

Render's native runtime exposes dashboard secret files as root-controlled links
to root-owned `0640` targets. RetryWise accepts that managed boundary only when
the link and its non-writable parent are root-controlled, the running service
belongs to the target's group, group access is read-only, and no access is
granted to other users. Local and self-managed deployments continue to require
owner-only `0600`; ordinary links remain rejected.

On Windows, POSIX mode bits do not represent NTFS access control. Before a
local Windows worker reads the enrolled files, remove inherited access and grant
full control only to the current operator on the private root (run from the same
account that starts the worker):

```powershell
$retrywiseAclPrincipal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls "$env:USERPROFILE\retrywise-private" /inheritance:r /grant:r "${retrywiseAclPrincipal}:(OI)(CI)F" /T /C
```

The resolver continues to reject Windows reparse points. Linux and container
deployments still require exact owner-only POSIX file modes.

### Optional Gemini enrollment

Local ML requires no external key and remains the default. To enable Hybrid or Shadow mode, provision one owner-only JSON secret file outside the repository:

```json
{"api_key":"<Gemini API key>"}
```

Set file mode `0600`, then configure the same absolute mount path for API and worker as `RETRYWISE_GEMINI_API_KEY_FILE`. Optional non-secret controls are `RETRYWISE_GEMINI_MODEL` (default `gemini-2.5-flash`) and `RETRYWISE_GEMINI_TIMEOUT_SECONDS` (default `8`, maximum `10`). Requests are stateless (`store=false`), use low thinking latency, and cap output. Never configure `GEMINI_API_KEY`; raw Gemini credentials in environment configuration are rejected.

The API only reports whether a key file path is configured. Only the worker component opens the file and calls Gemini, including when that worker is co-located with the free-tier API process. Use the authenticated Controls view or `POST /api/v1/controls/diagnosis-engine` to select `LOCAL_ML`, `HYBRID_GEMINI`, or `SHADOW`; changes affect future assessments and append immutable operator evidence. Select the intended mode once before the demonstration. In Hybrid mode, every recovery proposal waits for an explicit operator approval or rejection before any Razorpay effect is eligible.

## 5. Configure signed webhooks

Take `RETRYWISE_WEBHOOK_ENDPOINT_TOKEN` from the protected environment file without copying it into public documentation. Register this HTTPS target in the Razorpay Test dashboard:

```text
https://<public-api-host>/api/v1/webhooks/razorpay/<endpoint-token>
```

Use the same signing secret entered during enrollment. Subscribe at minimum to:

- `payment.failed`
- `payment.captured`
- `payment_link.paid`
- `payment_link.partially_paid`

Do not use the dashboard's sample webhook for end-to-end validation. RetryWise enriches unknown failed payments with fresh Razorpay Payment and Order reads; a synthetic sample ID is not a fetchable provider resource. Produce a real Test Mode failure through the merchant's test Checkout or an original Test Payment Link.

## 6. Start in observe-only mode

Start the API with the protected environment while both kill switches remain armed:

```sh
docker compose --env-file /absolute/path/retrywise-test.env up --build -d api
```

Confirm:

- `/health/live` returns 200.
- `/health/ready` returns a safe configuration summary.
- an authenticated `GET /api/v1/controls/kill-switch` shows the merchant switch enabled.
- a real signed failed-payment event is accepted once and duplicates do not create another case.
- the worker has not been started and no provider write can occur.

## 7. Open the deployment gate, then the merchant gate

After observe-only ingress is proven, edit the protected environment file locally:

```text
RETRYWISE_EFFECTS_MODE=razorpay_test
RETRYWISE_GLOBAL_KILL_SWITCH=false
```

Start API and worker from the same code revision:

```sh
docker compose --profile razorpay-test \
  --env-file /absolute/path/retrywise-test.env \
  up --build -d api worker
```

The API readiness check now requires a fresh worker heartbeat with the exact code revision. Keep the merchant kill switch armed until the signed failed-payment case, enriched provider truth, observation deadline, and operator dossier are all correct.

Disarm the merchant switch through the authenticated console or `POST /api/v1/controls/kill-switch` with a fresh `Idempotency-Key`, `enabled: false`, and reason `enable_test_mode_effects`. The immutable control event and current state must commit atomically.

### Stable Render Free demonstration profile

Render does not provide a Free instance type for a standalone background worker.
For the no-cost demonstration only, run one API web-service instance with:

```text
RETRYWISE_EMBEDDED_WORKER=true
RETRYWISE_DATA_SOURCE=RAZORPAY_TEST_MODE
RETRYWISE_EFFECTS_MODE=razorpay_test
RETRYWISE_GLOBAL_KILL_SWITCH=false
```

Mount the versioned Razorpay Test credential and optional Gemini key as Render
secret files, and point `RETRYWISE_SECRET_ROOT` and
`RETRYWISE_GEMINI_API_KEY_FILE` at those mounted locations. Do not configure raw
key environment variables. Remove `RETRYWISE_CODE_REVISION` on Render: both roles
automatically use Render's immutable `RENDER_GIT_COMMIT` value, eliminating
manual revision edits on every deploy. Keep the Uvicorn instance count at one.

This configuration is stable across the demo. Normal payment operation does not
change environment variables. The authenticated merchant kill switch is the
runtime emergency control; changing it writes an audited database event and does
not redeploy the service. A production environment must move the worker to
continuously available managed compute and must not rely on a Free service's idle
sleep/wake behavior.

## 8. End-to-end validation

Run each path twice before recording.

### Recovery path

1. Produce a real failed Razorpay Test payment linked to a real Test order.
2. Confirm the signed webhook, enrichment read, one observing case, and the 120-second minimum deadline.
3. Wait for assessment. If the amount crosses the configured threshold, approve the exact case version.
4. Confirm a single Standard Payment Link in Razorpay with RetryWise's stable reference.
5. Complete that link in Test Mode.
6. Confirm `payment_link.paid`, monotonic amount truth, terminal case state, provider ID, and a valid runtime audit chain.

### Late-original-success path

1. Produce a failed Test payment and allow RetryWise to reach an actionable or active-link state.
2. Capture/pay the original provider path before using the recovery link.
3. Confirm fresh original truth suppresses further collection.
4. If a collectable recovery link exists, confirm protective cancellation is scheduled and reconciled.
5. Confirm paid/partially-paid races become review, never a false cancellation success.

### Ambiguous-create path

Inject or simulate a provider response loss only in a controlled test environment. Confirm the action becomes uncertain, reconciliation searches by the same reference, and exactly one provider link is adopted. A reclaimed lease must reconcile before it may repeat any write.

## 9. Emergency controls

Fastest merchant-scoped stop: set the merchant kill switch to `enabled: true` with reason `emergency_stop`.

Deployment-wide stop: restore `RETRYWISE_GLOBAL_KILL_SWITCH=true` and restart API/worker. Stopping the worker also prevents new provider effects:

```sh
docker compose --profile razorpay-test stop worker
```

Protective cancellation remains separately authorized because it reduces collection risk. Never delete provider or database evidence during an incident.

## 10. Console deployment contract

The console proxies the control plane server-side. Configure these as hosting secrets, not public variables:

- `RETRYWISE_API_URL=https://<public-api-host>`
- `RETRYWISE_OPERATOR_TOKEN=<merchant-scoped opaque bearer token>`

The browser must never receive the operator token. The console must show Replay and Razorpay Test as separate modes; an empty Test workspace is correct until persisted provider evidence exists.

## 11. Release evidence bundle

Capture all of the following without secrets or customer data:

- test, quality, coverage, contract, package, migration, console-build, and deployment results;
- Razorpay Test dashboard provider IDs and statuses;
- signed webhook acceptance and duplicate suppression counters;
- recovery case, decision, action, instrument, and immutable audit proof;
- both kill switches and exact worker code-revision readiness;
- one recovered Test path and one late-original-success suppression path;
- explicit labels stating Test Mode, no real money, and offline synthetic evidence where applicable.

Do not approve a production release until this evidence bundle exists.
