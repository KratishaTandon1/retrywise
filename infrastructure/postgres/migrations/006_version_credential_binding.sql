BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- Legacy rows deliberately remain at version zero with no key fingerprint.
-- They may continue to receive authenticated webhooks, but the outbound
-- credential repository refuses to authorize effects until an operator enrolls
-- an immutable secret version and the exact Test key-id digest as version one.
ALTER TABLE retrywise.provider_accounts
    ADD COLUMN credential_key_id_sha256 retrywise.sha256_digest,
    ADD COLUMN credential_binding_version bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT provider_accounts_credential_binding_pair_ck CHECK (
        (
            credential_binding_version = 0
            AND credential_key_id_sha256 IS NULL
        )
        OR
        (
            credential_binding_version > 0
            AND credential_key_id_sha256 IS NOT NULL
        )
    );

CREATE UNIQUE INDEX provider_accounts_credential_key_uidx
    ON retrywise.provider_accounts (
        provider,
        environment,
        credential_key_id_sha256
    )
    WHERE credential_key_id_sha256 IS NOT NULL;

CREATE FUNCTION retrywise.enforce_provider_account_credential_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, retrywise
AS $$
DECLARE
    material_changed boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.credential_key_id_sha256 IS NULL THEN
            IF NEW.credential_binding_version <> 0 THEN
                RAISE EXCEPTION
                    'unenrolled provider account must use credential binding version zero'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.credential_binding_version <> 1 THEN
            RAISE EXCEPTION
                'new credential binding must start at version one'
                USING ERRCODE = '23514';
        END IF;

        RETURN NEW;
    END IF;

    -- Keep this invariant local to the credential contract as defense in depth;
    -- migration 001 also protects the same durable account identity.
    IF ROW(
        NEW.id,
        NEW.merchant_id,
        NEW.provider,
        NEW.provider_account_identifier,
        NEW.environment,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.merchant_id,
        OLD.provider,
        OLD.provider_account_identifier,
        OLD.environment,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION
            'provider account identity and environment are immutable'
            USING ERRCODE = '55000';
    END IF;

    material_changed :=
        NEW.credential_secret_ref IS DISTINCT FROM OLD.credential_secret_ref
        OR NEW.credential_key_id_sha256 IS DISTINCT FROM
            OLD.credential_key_id_sha256;

    IF material_changed THEN
        IF NEW.credential_key_id_sha256 IS NULL THEN
            RAISE EXCEPTION
                'credential material requires an enrolled key-id digest'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.credential_binding_version <> OLD.credential_binding_version + 1 THEN
            RAISE EXCEPTION
                'credential binding version must increase by exactly one when material changes'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.credential_binding_version <> OLD.credential_binding_version THEN
        RAISE EXCEPTION
            'credential binding version cannot change without material rotation'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION retrywise.enforce_provider_account_credential_binding() IS
    'Fences outbound credential metadata with an exact monotonic generation while preserving immutable account identity.';

CREATE TRIGGER provider_accounts_20_enforce_credential_binding
BEFORE INSERT OR UPDATE ON retrywise.provider_accounts
FOR EACH ROW EXECUTE FUNCTION retrywise.enforce_provider_account_credential_binding();

COMMENT ON COLUMN retrywise.provider_accounts.credential_key_id_sha256 IS
    'SHA-256 of the exact Razorpay key id attested during credential enrollment; null means outbound effects are unauthorized.';

COMMENT ON COLUMN retrywise.provider_accounts.credential_binding_version IS
    'Monotonic credential metadata generation; zero is ingress-only and cannot authorize outbound effects.';

COMMIT;
