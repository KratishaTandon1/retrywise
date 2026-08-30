"""PostgreSQL-backed, transactional webhook inbox adapter.

The adapter commits three records as one transaction:

* immutable, verified provider evidence;
* the inbox processing record; and
* a normalized-provider-event outbox command.

It deliberately accepts a connection factory so the SQL boundary can be
tested without PostgreSQL and so production can supply either ``psycopg.connect``
or a pool's ``connection`` method.  Psycopg is imported only when the built-in
DSN connector is actually used.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Protocol, cast

from ...packages.razorpay import InboxConflictError, InboxRecord, InboxWriteResult
from .postgres_connection import PostgresConnectionPolicy

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_MAX_ULID_TIMESTAMP = (1 << 48) - 1
_MAX_ULID_RANDOMNESS = (1 << 80) - 1

_INSERT_PROVIDER_EVENT = """
INSERT INTO retrywise.provider_events (
    id,
    merchant_id,
    provider_account_id,
    provider_event_id,
    event_type,
    resource_type,
    resource_id,
    body_sha256,
    signature_version,
    signature_verified,
    account_verified,
    normalized_schema_version,
    canonical_event,
    provider_occurred_at,
    received_at
) VALUES (
    %(provider_event_record_id)s,
    %(merchant_id)s,
    %(provider_account_id)s,
    %(provider_event_id)s,
    %(event_type)s,
    %(resource_type)s,
    %(resource_id)s,
    %(body_sha256)s,
    1,
    TRUE,
    TRUE,
    %(normalized_schema_version)s,
    %(canonical_event)s::jsonb,
    %(provider_occurred_at)s,
    %(received_at)s
)
ON CONFLICT (provider_account_id, provider_event_id) DO NOTHING
RETURNING id
"""

_SELECT_EXISTING_DIGEST = """
SELECT body_sha256
FROM retrywise.provider_events
WHERE merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND provider_event_id = %(provider_event_id)s
"""

_INSERT_INBOX_EVENT = """
INSERT INTO retrywise.inbox_events (
    id,
    merchant_id,
    provider_account_id,
    provider_event_record_id,
    status,
    attempt_count,
    next_attempt_at,
    accepted_at,
    updated_at
) VALUES (
    %(inbox_event_id)s,
    %(merchant_id)s,
    %(provider_account_id)s,
    %(provider_event_record_id)s,
    'RECEIVED',
    0,
    %(received_at)s,
    %(received_at)s,
    %(received_at)s
)
"""

_INSERT_NORMALIZED_EVENT_JOB = """
INSERT INTO retrywise.outbox_jobs (
    id,
    merchant_id,
    aggregate_type,
    aggregate_id,
    command_type,
    command_schema_version,
    command_payload,
    idempotency_key,
    status,
    attempt_count,
    next_attempt_at,
    created_at,
    updated_at
) VALUES (
    %(outbox_job_id)s,
    %(merchant_id)s,
    'PROVIDER_EVENT',
    %(provider_event_record_id)s,
    'PROCESS_NORMALIZED_PROVIDER_EVENT',
    1,
    %(command_payload)s::jsonb,
    %(idempotency_key)s,
    'PENDING',
    0,
    %(received_at)s,
    %(received_at)s,
    %(received_at)s
)
"""

_CHECK_READY = """
SELECT
    to_regclass('retrywise.provider_events') IS NOT NULL
    AND to_regclass('retrywise.inbox_events') IS NOT NULL
    AND to_regclass('retrywise.outbox_jobs') IS NOT NULL
    AND EXISTS (
        SELECT 1
        FROM retrywise.provider_accounts
        WHERE merchant_id = %(merchant_id)s
          AND id = %(provider_account_id)s
          AND provider = 'RAZORPAY'
          AND provider_account_identifier = %(provider_account_identifier)s
          AND environment = 'TEST'
          AND enabled
    )
"""

_LOCK_ACCOUNT_BINDING = """
SELECT TRUE
FROM retrywise.provider_accounts
WHERE merchant_id = %(merchant_id)s
  AND id = %(provider_account_id)s
  AND provider = 'RAZORPAY'
  AND provider_account_identifier = %(provider_account_identifier)s
  AND environment = 'TEST'
  AND enabled
FOR SHARE
"""


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def __enter__(self) -> _Cursor: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class _Transaction(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...

    def transaction(self) -> _Transaction: ...


class _ConnectionContext(Protocol):
    def __enter__(self) -> _Connection: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


ConnectionFactory = Callable[[], _ConnectionContext]


class _MonotonicUlidFactory:
    """Generate process-local, lexicographically increasing standard ULIDs."""

    def __init__(
        self,
        *,
        clock_ms: Callable[[], int] | None = None,
        random_bits: Callable[[int], int] | None = None,
    ) -> None:
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._random_bits = random_bits or secrets.randbits
        self._last_timestamp_ms = -1
        self._last_randomness = -1
        self._lock = threading.Lock()

    def new(self) -> str:
        with self._lock:
            timestamp_ms = self._clock_ms()
            if type(timestamp_ms) is not int or timestamp_ms < 0:
                raise RuntimeError("ULID clock returned an invalid millisecond timestamp")
            timestamp_ms = max(timestamp_ms, self._last_timestamp_ms)
            if timestamp_ms > _MAX_ULID_TIMESTAMP:
                raise RuntimeError("ULID timestamp exceeds its 48-bit range")

            if timestamp_ms == self._last_timestamp_ms:
                if self._last_randomness == _MAX_ULID_RANDOMNESS:
                    timestamp_ms += 1
                    if timestamp_ms > _MAX_ULID_TIMESTAMP:
                        raise RuntimeError("ULID monotonic range is exhausted")
                    randomness = self._random_bits(80)
                else:
                    randomness = self._last_randomness + 1
            else:
                randomness = self._random_bits(80)

            if type(randomness) is not int or not 0 <= randomness <= _MAX_ULID_RANDOMNESS:
                raise RuntimeError("ULID entropy source returned an invalid value")

            self._last_timestamp_ms = timestamp_ms
            self._last_randomness = randomness
            return _encode_ulid((timestamp_ms << 80) | randomness)


def _encode_ulid(value: int) -> str:
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = _CROCKFORD_BASE32[value & 31]
        value >>= 5
    return "".join(characters)


def _require_internal_ulid(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _ULID_RE.fullmatch(value):
        raise ValueError(f"{field} must match the RetryWise ULID database domain")
    return value


def _utc_from_epoch(value: int, *, field: str) -> datetime:
    try:
        return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError(f"{field} is outside the supported timestamp range") from exc


def _database_digest(value: object) -> bytes:
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise RuntimeError("provider event digest returned by PostgreSQL is not binary")


def _first_column(row: Sequence[object] | None, *, query_name: str) -> object:
    if row is None or len(row) != 1:
        raise RuntimeError(f"{query_name} returned an unexpected row shape")
    return row[0]


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresWebhookInbox"),
        )

    return connect


class PostgresWebhookInbox:
    """Durable implementation of the Razorpay ``WebhookInbox`` protocol."""

    durable = True

    def __init__(
        self,
        *,
        merchant_id: str,
        provider_account_id: str,
        provider_account_identifier: str,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
    ) -> None:
        self._merchant_id = _require_internal_ulid(merchant_id, field="merchant_id")
        self._provider_account_id = _require_internal_ulid(
            provider_account_id, field="provider_account_id"
        )
        if (
            not isinstance(provider_account_identifier, str)
            or not provider_account_identifier
            or provider_account_identifier != provider_account_identifier.strip()
            or len(provider_account_identifier) > 128
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in provider_account_identifier
            )
        ):
            raise ValueError("provider_account_identifier must be clean, non-empty text")
        self._provider_account_identifier = provider_account_identifier
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if not isinstance(require_tls, bool):
            raise TypeError("require_tls must be boolean")
        if dsn is not None:
            self._connector = _dsn_factory(dsn, require_tls=require_tls)
        else:
            if require_tls:
                raise ValueError(
                    "require_tls needs the built-in DSN connector so its policy is verifiable"
                )
            if not callable(connector):
                raise TypeError("connector must be callable")
            self._connector = connector
        self._ulids = _MonotonicUlidFactory()

    def check_ready(self) -> bool:
        """Return whether the schema and configured enabled account are present."""

        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                _CHECK_READY,
                {
                    "merchant_id": self._merchant_id,
                    "provider_account_id": self._provider_account_id,
                    "provider_account_identifier": self._provider_account_identifier,
                },
            )
            ready = _first_column(cursor.fetchone(), query_name="readiness query")
        if type(ready) is not bool:
            raise RuntimeError("readiness query returned a non-boolean result")
        return ready

    def store_once(self, record: InboxRecord) -> InboxWriteResult:
        """Atomically persist verified evidence, inbox state, and worker command."""

        if not isinstance(record, InboxRecord):
            raise TypeError("record must be InboxRecord")
        event = record.event
        if not hmac.compare_digest(
            event.provider_account_id,
            self._provider_account_identifier,
        ):
            raise ValueError("record provider account does not match adapter binding")
        if not isinstance(event.raw_body_sha256, str) or not _SHA256_RE.fullmatch(
            event.raw_body_sha256
        ):
            raise ValueError("record body digest must be lowercase hexadecimal SHA-256")
        body_digest = bytes.fromhex(event.raw_body_sha256)

        occurred_at = _utc_from_epoch(event.occurred_at_epoch, field="occurred_at_epoch")
        received_at = _utc_from_epoch(record.received_at_epoch, field="received_at_epoch")
        canonical_event = json.dumps(
            event.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        provider_event_record_id = self._ulids.new()
        provider_params: dict[str, object] = {
            "provider_event_record_id": provider_event_record_id,
            "merchant_id": self._merchant_id,
            "provider_account_id": self._provider_account_id,
            "provider_event_id": event.event_id,
            "event_type": event.event_name,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "body_sha256": body_digest,
            "normalized_schema_version": event.schema_version,
            "canonical_event": canonical_event,
            "provider_occurred_at": occurred_at,
            "received_at": received_at,
        }

        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            binding_params = {
                "merchant_id": self._merchant_id,
                "provider_account_id": self._provider_account_id,
                "provider_account_identifier": self._provider_account_identifier,
            }
            cursor.execute(_LOCK_ACCOUNT_BINDING, binding_params)
            binding = cursor.fetchone()
            if binding is None or tuple(binding) != (True,):
                raise RuntimeError("configured provider account binding is unavailable")
            cursor.execute(_INSERT_PROVIDER_EVENT, provider_params)
            inserted = cursor.fetchone()
            if inserted is None:
                cursor.execute(
                    _SELECT_EXISTING_DIGEST,
                    {
                        "merchant_id": self._merchant_id,
                        "provider_account_id": self._provider_account_id,
                        "provider_event_id": event.event_id,
                    },
                )
                existing_digest = _database_digest(
                    _first_column(cursor.fetchone(), query_name="duplicate lookup")
                )
                if not hmac.compare_digest(existing_digest, body_digest):
                    raise InboxConflictError("provider event id was reused with different content")
                return InboxWriteResult.DUPLICATE

            inserted_id = _first_column(inserted, query_name="provider event insert")
            if inserted_id != provider_event_record_id:
                raise RuntimeError("provider event insert returned an unexpected id")

            inbox_event_id = self._ulids.new()
            inbox_params: dict[str, object] = {
                "inbox_event_id": inbox_event_id,
                "merchant_id": self._merchant_id,
                "provider_account_id": self._provider_account_id,
                "provider_event_record_id": provider_event_record_id,
                "received_at": received_at,
            }
            cursor.execute(_INSERT_INBOX_EVENT, inbox_params)

            outbox_job_id = self._ulids.new()
            command_payload = json.dumps(
                {
                    "event_type": event.event_name,
                    "inbox_event_id": inbox_event_id,
                    "merchant_id": self._merchant_id,
                    "provider_account_id": self._provider_account_id,
                    "provider_event_id": event.event_id,
                    "provider_event_record_id": provider_event_record_id,
                    "schema_version": 1,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            outbox_params: dict[str, object] = {
                "outbox_job_id": outbox_job_id,
                "merchant_id": self._merchant_id,
                "provider_event_record_id": provider_event_record_id,
                "command_payload": command_payload,
                "idempotency_key": f"normalized-provider-event:{provider_event_record_id}",
                "received_at": received_at,
            }
            cursor.execute(_INSERT_NORMALIZED_EVENT_JOB, outbox_params)

        return InboxWriteResult.STORED
