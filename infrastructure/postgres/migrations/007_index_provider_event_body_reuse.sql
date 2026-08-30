-- Deliberately not wrapped in a transaction: PostgreSQL requires this for a
-- concurrent index build. The migration runner checks pg_index.indisvalid and
-- refuses to treat a failed/invalid build as applied.
SET lock_timeout = '5s';
SET statement_timeout = '5min';

CREATE INDEX CONCURRENTLY provider_events_body_reuse_lookup_idx
    ON retrywise.provider_events (
        merchant_id,
        provider_account_id,
        body_sha256,
        received_at,
        id
    )
    INCLUDE (provider_event_id);

COMMENT ON INDEX retrywise.provider_events_body_reuse_lookup_idx IS
    'Supports ordered detection of an identical signed webhook body reused under another provider event id.';

RESET statement_timeout;
RESET lock_timeout;
