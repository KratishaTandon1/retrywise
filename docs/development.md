# Development workflow

## Purpose

The default RetryWise development and CI contract is dependency-free: Python's
standard library runs the domain, Razorpay-boundary, and simulator test suites.
Optional API and developer tools are isolated in `pyproject.toml` extras and are
not required to validate the financial-safety core.

Use Python 3.11 or newer and a POSIX-compatible `make`. Commands below can be
run from the RetryWise repository root. From its parent directory, prefix them
with `make -C retrywise`.

## Fast validation

```bash
make unit
```

This discovers every test under `tests/` with `unittest`. Tests must not call
Razorpay, read live credentials, sleep on wall time, or depend on execution
order.

The full local CI contract is:

```bash
make ci
```

It runs the unit tests and proves that the smoke and golden replay reports are
byte-for-byte deterministic.

## Evaluation commands

```bash
make eval-smoke
make eval-primary
make eval-golden
make eval-full
make eval-determinism
```

| Target | Contract |
| --- | --- |
| `eval-smoke` | 200 cases, seed 42, summary JSON |
| `eval-primary` | 2,000 cases, seed 42, 400 merchant-clustered bootstrap samples |
| `eval-golden` | 256 fixed adversarial cases, seed 20260829, case-level audit JSON |
| `eval-full` | 20,000 total cases across ten fixed seeds plus an aggregate summary |
| `eval-determinism` | Runs smoke and golden twice and compares exact JSON bytes |

Generated reports are written to `artifacts/evaluation/`. Git ignores generated
runs except the frozen primary and multi-seed manifests, which are explicit
repository evidence inputs. Every report contains the seed, dataset hash, policy
and model versions, code revision, cost assumptions, scenario coverage, and
explicit offline/synthetic labels.

Set `RETRYWISE_CODE_REVISION` to a commit SHA in automation. If it is absent, the
simulator records a deterministic hash of simulator, diagnosis, and domain Python
sources as the code revision. `make eval-primary-verify` regenerates the frozen
2,000-case report and byte-compares it with the committed artifact.

To invoke the simulator directly from the parent directory:

```bash
python3 -m retrywise.packages.simulator \
  --seed 42 \
  --cases 200 \
  --output retrywise/artifacts/evaluation/manual.json
```

## Python environment and HTTP API

The domain and simulator do not require installation. The implemented FastAPI
transport and PostgreSQL adapters use the optional `api` dependencies. Create an
isolated environment and install the API and developer extras with:

```bash
python3 -m venv .venv
python3 -m pip install --upgrade pip
python3 -m pip install -e '.[api,dev]'
```

The `api` extra contains FastAPI, Uvicorn, HTTP, settings, and PostgreSQL runtime
dependencies. The `dev` extra contains lint, type-check, coverage, and build
tooling. Dependency installation is never performed by the dependency-free CI
job.

Start the local API with Uvicorn's application factory. Uvicorn loads `.env`
explicitly; application code does not silently read dotenv files:

```bash
.venv/bin/uvicorn retrywise.services.control_plane.api:create_app \
  --factory \
  --env-file .env \
  --host 127.0.0.1 \
  --port 8000 \
  --workers 1
```

Use one process while an in-memory development adapter is selected. Multiple API
processes are safe only after every shared-state port is backed by PostgreSQL.
`GET /health/live` proves only that the process is running. Readiness must not be
interpreted as proof of durable webhook acceptance unless the runtime is composed
with the PostgreSQL inbox and its database probe is healthy.

## Containerised local stack

`Dockerfile` builds the control plane in a separate builder stage and runs it as
an unprivileged user from a minimal Python runtime. The API container has a
read-only root filesystem, dropped Linux capabilities, bounded process count, and
access logging disabled so the webhook endpoint token is not copied into default
request logs.

The Compose stack contains the implemented process roles:

- `postgres`: local PostgreSQL authority;
- `migrate`: a one-shot, fail-fast application of migrations `001` through `011`
  that safely skips an already-complete local schema and rejects a partial one;
- `api`: the FastAPI control plane, bound to loopback by default;
- `worker`: the full durable scheduler/handler graph, protected by the opt-in
  `razorpay-test` profile and secure credential mounts.

The zero-configuration Compose default is a replay-only API. It deliberately has
no operator credential and no webhook binding, so operator routes deny access and
the API makes no claim of durable provider ingress. Start that safe boundary with:

```bash
docker compose config --quiet
docker compose up --build -d
docker compose ps
docker compose logs migrate
```

The safe default remains Replay with provider effects disabled and the global
kill switch active. Operator endpoints deny access when
`RETRYWISE_OPERATOR_TOKEN` is empty. For an authenticated replay session, export a
fresh token and a replay-scoped merchant identifier before starting the stack:

```bash
export RETRYWISE_MERCHANT_ID=replay-local-merchant
export RETRYWISE_OPERATOR_TOKEN="$(openssl rand -hex 32)"
docker compose up --build -d
```

Webhook configuration is all-or-nothing: endpoint token, merchant, internal
provider-account ID, Razorpay account ID, and current webhook secret must either
all be set or all remain empty. Durable ingress additionally requires the merchant
and provider-account IDs to be ULIDs that already exist as an enabled binding in
PostgreSQL. Migration creates schema only; it never invents a tenant or credential
binding. The readiness endpoint returns `503` if a configured durable binding or
database dependency is unavailable.

Local Compose passes `DATABASE_REQUIRE_TLS` into the API and defaults it to
`false` only for the isolated development PostgreSQL network. Both `sandbox` and
`production` profiles fail during composition unless it is exactly `true`. Under
that policy, `DATABASE_URL` must be a single-host TCP `postgresql://` URI; the
built-in psycopg connector forces `sslmode=verify-full`, even if the URI omits
that query parameter. A conflicting `sslmode`, socket/service target override,
or unverifiable injected connector is rejected. Provision a trusted CA (system
trust or libpq `sslrootcert`) and a server certificate matching the URI hostname;
otherwise the readiness database connection fails closed. Keep the credential-
bearing URI in the deployment secret manager—validation errors and settings
diagnostics never render it.

For direct non-container development, `.env.example` collects non-secret
application and launcher fields plus webhook-secret fields in one place.
Outbound Razorpay API key/secret environment variables are rejected; provision
them only through the versioned database/managed-secret enrollment boundary.
Optional Gemini credentials use the separate owner-only
`RETRYWISE_GEMINI_API_KEY_FILE`; the authenticated merchant control selects
Local ML, Hybrid Gemini, or Shadow mode for future assessments. Browser-prefixed
configuration never carries either provider's credential.

Verify the process boundary after startup:

```bash
curl --fail --silent --show-error http://127.0.0.1:8000/health/live
curl --fail --silent --show-error http://127.0.0.1:8000/health/ready
```

## Operator console

The console keeps the operator token server-side. Its same-origin route handlers
proxy overview and replay requests to the control plane; no browser-prefixed
secret is supported.

```bash
cd apps/console
cp .env.example .env.local
# Put a freshly generated local operator token in .env.local.
pnpm install
pnpm dev
```

The visual shell contains an explicitly labelled bundled replay snapshot so the
UI can be reviewed offline. When the proxy reaches the API, the environment bar
reports `Replay API connected` and metrics/manifests come from the backend; this
does not assert database, worker, audit-chain, or provider readiness.
A failed API run preserves the snapshot and shows an error state; it never
relabels fixture evidence as a provider result. Razorpay Test Mode remains empty
until verified provider evidence exists.

Repository policy requires a committed `pnpm-lock.yaml` for console releases.
Generate it before the first release commit; CI must use
`pnpm install --frozen-lockfile` and run console lint/build as required gates.

Docker health uses `/health/ready`, not liveness, so a configured API is not marked
healthy until its durable ingress dependency and account binding pass the runtime
probe.

The local migration guard identifies complete initial `001`, fenced-outbox
`002`, provider-effect-boundary `003`, observation-deadline `004`,
provider-account-binding `005`, credential-generation `006`, provider-body
reuse index `007`, late-link truth `008`, worker heartbeat `009`, and immutable
merchant-control `010` schema states. It rejects partial installation.
The PostgreSQL CI job also seeds a legal pre-hardening database after `001`,
then applies `002`-`010` and proves that legacy cases are not backfilled with
invented observation evidence, cannot advance into collection, and that a new
default case receives a database-owned two-minute floor without a clock-latency
failure. Migration `005` stops with an actionable preflight error if append-only
legacy provider evidence is misbound. Migration `006` preserves legacy accounts
as ingress-only until explicit credential enrollment. Migration `007` runs
outside a transaction and must leave a valid, ready concurrent index.
This is not a replacement for a production migration ledger: deployed releases
must apply each forward-only numbered migration exactly once and record its
version and checksum in release automation.

Stop containers without deleting the database volume:

```bash
docker compose down
```

Use `docker compose down --volumes` only when intentionally discarding local
RetryWise database state.

## Environment boundary

Copy `.env.example` to an ignored `.env` only when a server process needs local
configuration. `ControlPlaneSettings` consumes application fields, while Uvicorn
or Compose consumes process fields such as ports. Stdlib tests and simulator
commands do not load the file automatically.

| Mode | Data | Provider effects | Credential boundary |
| --- | --- | --- | --- |
| Replay | Synthetic fixtures | Disabled | No Razorpay credentials required |
| Razorpay test mode | Test account only | Explicit `razorpay_test` opt-in | Versioned managed `rzp_test_` secret binding and isolated test webhooks/database |
| Live | Real merchant data | Unsupported locally | Deployment secret manager and separate infrastructure only |

Safe defaults in `.env.example` are deliberate:

- `RETRYWISE_EFFECTS_MODE=disabled`
- `RETRYWISE_GLOBAL_KILL_SWITCH=true`
- `RETRYWISE_DATA_SOURCE=REPLAY`
- optional webhook-secret fields are empty; outbound raw API credentials are unsupported

The configuration loader fails closed when environment facts conflict. In
particular, it rejects raw provider API credentials entirely, and a live provider mode
is never inferred from a key value alone. Live activation remains unsupported and
requires separate deployment configuration, credentials, data stores, webhook
endpoints, security review, and explicit authorization.

Never expose provider or database settings through browser-prefixed environment
variables. Webhook secrets are distinct from API key secrets. The previous
webhook secret is optional and exists only for bounded rotation. Configure
`RAZORPAY_WEBHOOK_SECRET_PREVIOUS` together with
`RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT` in canonical
`YYYY-MM-DDTHH:MM:SSZ` UTC form. Composition rejects an expired deadline, and
the verification boundary stops considering the previous secret at the deadline
even when the process remains running. Configure neither field outside an active
rotation window.

## Contribution boundaries

- Keep money as integer minor units with explicit ISO currency.
- Keep models non-authoritative; deterministic code gates every effect.
- Record intent and gate evidence before an external action.
- Treat duplicate and out-of-order delivery as normal.
- Label simulator results as offline synthetic counterfactuals, never real revenue.
- Add a deterministic regression case for every corrected financial-safety bug.
- Do not place real credentials, customer data, transient generated reports, or
  local database volumes in Git. The two explicitly allowlisted frozen
  source-bound manifests are the only evaluation-report exceptions.

CI uses Python 3.11, installs the declared API and developer extras, requires the
FastAPI transport tests, enforces Ruff, mypy, branch-aware coverage, and package
builds, and applies all PostgreSQL migrations to an ephemeral PostgreSQL 16
service. A separate Python 3.11 job retains deterministic simulator evidence.
Console installation and the standard Next.js production build remain required
release gates using the committed dependency lockfile.
