# Razorpay Test credential metadata binding

## Status

This is the fail-closed credential boundary used by the executable Test Mode
worker. It authorizes no live-money operation. Enrollment performs a read-only
Razorpay API authentication check; worker startup and each bounded adapter
construction re-attest the database generation and key-ID digest. One
credentialed end-to-end Test Mode proof remains external work.

## What the boundary proves

Before constructing the narrow Test Mode adapter, RetryWise requires agreement
among:

- the exact merchant and internal provider-account ULIDs;
- the immutable Razorpay `account_id` recorded for that row;
- Razorpay provider and `TEST` environment;
- current enabled state;
- an immutable managed-secret reference;
- a positive credential binding generation; and
- SHA-256 of the exact `rzp_test_` key id returned by the secret resolver.

Migration `006_version_credential_binding.sql` adds
`credential_key_id_sha256` and `credential_binding_version`. A material change
to the secret reference or key-id digest must advance the generation by exactly
one. The database rejects generation-only changes, skipped generations,
removing an enrolled digest, reuse of one digest across account rows in the same
provider environment, and any change to durable provider-account identity or
environment.

Version zero means ingress-only. Existing rows migrate to version zero with a
null key-id digest, so migration does not invent credential evidence. Such rows
can continue accepting correctly signed, account-matched Razorpay Test webhooks,
but the outbound binding repository rejects them before secret resolution.

## Two-phase resolution protocol

Adapter composition uses two bounded database transactions:

1. Read the enabled, enrolled account and close the transaction.
2. Resolve its managed-secret reference with no database transaction or row lock
   held.
3. Re-read the exact row under `FOR SHARE`.
4. Require every attested field, key-id digest, and generation to equal the
   initial snapshot and resolved material.
5. Construct the adapter and release the short lock. Enrollment has already made
   a separate read-only provider request; effect-time provider reads follow the
   normal workflow gate.

The generation prevents an ABA rotation from changing credentials and restoring
old-looking metadata while resolution is in progress. Secret-manager latency
does not hold a PostgreSQL lock or delay an emergency account update.

The secret reference is intentionally provider-agnostic opaque metadata, so code
cannot infer whether a vault alias is mutable. Deployment policy must resolve a
specific immutable secret version, not a moving alias such as `latest`.

The returned adapter remains a credential snapshot. Every create, cancel, or
provider-enrichment attempt performs this composition after claiming its bounded
command. The adapter is closed after the attempt and is never cached as permanent
authorization.

## What the boundary does not prove

Razorpay's ordinary Payment Gateway authentication documentation describes Test
API keys as Basic Auth credentials associated with a Merchant ID, but documents
no credential-introspection endpoint that returns the owning `account_id`.
Standard Payment Link responses likewise do not return that account identity.
Therefore matching secret-manager metadata and key-id SHA-256 to PostgreSQL is
an operational attestation, not cryptographic or provider-issued proof that the
key belongs to the recorded Razorpay account.

Razorpay Partner Auth is a separate operating model. It allows a partner to send
`X-Razorpay-Account` for a sub-merchant, and Razorpay validates that target. It
must not be implied for ordinary merchant Test keys or enabled without separate
product eligibility and design review.

Primary contracts:

- [Razorpay API authentication](https://razorpay.com/docs/api/authentication/)
- [Standard Payment Link fetch response](https://razorpay.com/docs/api/payments/payment-links/fetch-all-standard/)
- [Razorpay Partner Auth](https://razorpay.com/docs/partners/aggregators/partner-auth/)
- [Payment webhook payloads](https://razorpay.com/docs/webhooks/payments/)

## Remaining external provisioning proof

Before enabling an ordinary Test account for outbound effects, deployment must
implement and retain a reviewed provisioning proof:

1. Provision exactly one Test key set in the owner-only mounted credential file.
2. Record the exact key ID SHA-256, expected Razorpay `account_id`, file reference,
   reviewer, and enrollment generation.
3. Create and fetch a nonce-bound Test Payment Link with that key.
4. Complete a controlled Test payment and validate the raw webhook signature.
5. Require the correlated webhook's signed `account_id` to equal the enrolled
   account and retain non-sensitive proof digests and timestamps.
6. Keep the account disabled for effects when any step is missing, ambiguous, or
   mismatched.

This proof materially reduces provisioning error, but its guarantee must still
be described as secret-manager-attested and provider-smoke-proven. It is not a
general cryptographic key-to-account introspection mechanism.

## Secret handling

Key ids, key secrets, secret references, and stored key-id digests are excluded
from binding object representations. Resolver and adapter-construction failures
are normalized to stable reason codes. Credentials are never placed in durable
commands or frontend configuration. Database TLS remains a separate deployment
requirement and must be explicitly enabled through the validated connection
policy.
