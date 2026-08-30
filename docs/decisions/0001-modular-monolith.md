# ADR 0001: Start as a modular monolith with API and worker roles

- Status: accepted
- Date: 2026-08-29

## Context

RetryWise requires production-grade payment-event handling, probabilistic diagnosis, deterministic controls, external action execution, evaluation, and a clear operator experience without unnecessary operational complexity.

## Decision

Use one versioned Python codebase for the control plane, deployed in separate API and worker process roles, with PostgreSQL as the authority and a transactional outbox for asynchronous work. Keep the operator console as an independent web application.

## Why

- Domain invariants remain in one testable package.
- API and worker failures are isolated at runtime.
- The outbox gives durable at-least-once work without running a second data platform.
- Local development and incident reproduction remain practical.
- Internal module boundaries provide a migration path to services later.

## Rejected alternatives

### Independent microservices plus Kafka

Rejected for the first release because broker operations, schemas, deployment, and cross-service tracing would add cost without strengthening the required reliability guarantees.

### Serverless functions for every step

Rejected because observation timers, leased work, replay, and strict concurrency are clearer in a worker model. The API may later run serverlessly if the outbox and database contracts remain unchanged.

### Full event sourcing

Rejected because mutable operational projections are still required. RetryWise instead keeps ordinary transactional state plus an append-only hash-chained decision ledger.

## Consequences

- PostgreSQL is a critical dependency and must be operated as such.
- Worker concurrency requires leases and optimistic aggregate versions.
- Module boundaries must be enforced in tests and imports rather than by network calls.
- Future extraction requires preserving the domain event and command contracts.
