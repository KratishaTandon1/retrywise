"""Durable PostgreSQL outbox delivery with row-locking and fenced leases.

This module owns persistence mechanics only.  It does not infer what a command
means and it never calls a provider.  Callers must register explicit command
handlers at the worker composition boundary.

Migration ``002_fenced_outbox_delivery.sql`` is required.  The repository uses
``FOR UPDATE SKIP LOCKED`` to bound concurrent claims, and every settlement is
compare-and-swapped on job id, merchant, owner, lease token, delivery version,
and lease expiry.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast

from .outbox import BackoffPolicy, RetryMode
from .postgres_connection import PostgresConnectionPolicy

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_MAX_BATCH_SIZE = 100

_CLAIM_BATCH = """
WITH statement_clock AS MATERIALIZED (
    SELECT clock_timestamp() AS now
),
candidates AS MATERIALIZED (
    SELECT j.id
    FROM retrywise.outbox_jobs AS j
    CROSS JOIN statement_clock AS statement
    WHERE (
        j.status IN ('PENDING', 'RETRY_SCHEDULED')
        AND j.next_attempt_at <= statement.now
    )
    OR (
        j.status = 'IN_PROGRESS'
        AND j.lease_expires_at <= statement.now
    )
    ORDER BY
        CASE
            WHEN j.status = 'IN_PROGRESS' THEN j.lease_expires_at
            ELSE j.next_attempt_at
        END,
        j.id
    LIMIT %(batch_size)s
    FOR UPDATE OF j SKIP LOCKED
),
mutated AS (
    UPDATE retrywise.outbox_jobs AS j
    SET status = CASE
            WHEN j.attempt_count >= j.max_attempts
                THEN 'DEAD_LETTER'::retrywise.outbox_status
            ELSE 'IN_PROGRESS'::retrywise.outbox_status
        END,
        attempt_count = CASE
            WHEN j.attempt_count >= j.max_attempts THEN j.attempt_count
            ELSE j.attempt_count + 1
        END,
        delivery_version = j.delivery_version + 1,
        lease_owner = CASE
            WHEN j.attempt_count >= j.max_attempts THEN NULL
            ELSE %(worker_id)s
        END,
        lease_token = CASE
            WHEN j.attempt_count >= j.max_attempts THEN NULL
            ELSE %(lease_nonce)s || ':' || j.id::text || ':'
                || (j.delivery_version + 1)::text
        END,
        lease_expires_at = CASE
            WHEN j.attempt_count >= j.max_attempts THEN NULL
            ELSE statement.now + %(lease_duration)s
        END,
        retry_mode = CASE
            WHEN j.attempt_count >= j.max_attempts OR j.status = 'IN_PROGRESS'
                THEN 'RECONCILE_ONLY'::retrywise.outbox_retry_mode
            ELSE j.retry_mode
        END,
        last_error_code = CASE
            WHEN j.attempt_count >= j.max_attempts
                THEN 'max_attempts_exhausted_before_claim'
            ELSE j.last_error_code
        END,
        last_error_at = CASE
            WHEN j.attempt_count >= j.max_attempts THEN statement.now
            ELSE j.last_error_at
        END,
        dead_lettered_at = CASE
            WHEN j.attempt_count >= j.max_attempts THEN statement.now
            ELSE NULL
        END,
        dead_letter_reason = CASE
            WHEN j.attempt_count >= j.max_attempts
                THEN 'max_attempts_exhausted_before_claim'
            ELSE NULL
        END,
        updated_at = statement.now
    FROM candidates AS c
    CROSS JOIN statement_clock AS statement
    WHERE j.id = c.id
    RETURNING
        j.status::text,
        j.id::text,
        j.merchant_id::text,
        j.aggregate_type,
        j.aggregate_id,
        j.command_type,
        j.command_schema_version,
        j.command_payload,
        j.idempotency_key,
        j.attempt_count,
        j.max_attempts,
        j.lease_owner,
        j.lease_token,
        j.lease_expires_at,
        j.delivery_version,
        j.retry_mode::text,
        j.created_at,
        j.updated_at
)
SELECT *
FROM mutated
ORDER BY id
"""

_COMPLETE = """
WITH statement_clock AS MATERIALIZED (
    SELECT clock_timestamp() AS now
)
UPDATE retrywise.outbox_jobs
SET status = 'SUCCEEDED',
    delivery_version = delivery_version + 1,
    lease_owner = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    completion_reference = %(completion_reference)s,
    completed_at = statement.now,
    updated_at = statement.now
FROM statement_clock AS statement
WHERE id = %(job_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'IN_PROGRESS'
  AND delivery_version = %(expected_version)s
  AND lease_owner = %(worker_id)s
  AND lease_token = %(lease_token)s
  AND lease_expires_at > statement.now
RETURNING delivery_version
"""

_RETRY = """
WITH statement_clock AS MATERIALIZED (
    SELECT clock_timestamp() AS now
)
UPDATE retrywise.outbox_jobs
SET status = 'RETRY_SCHEDULED',
    delivery_version = delivery_version + 1,
    lease_owner = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    retry_mode = %(retry_mode)s::retrywise.outbox_retry_mode,
    next_attempt_at = statement.now + %(retry_delay)s,
    last_error_code = %(reason)s,
    last_error_at = statement.now,
    updated_at = statement.now
FROM statement_clock AS statement
WHERE id = %(job_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'IN_PROGRESS'
  AND delivery_version = %(expected_version)s
  AND lease_owner = %(worker_id)s
  AND lease_token = %(lease_token)s
  AND lease_expires_at > statement.now
RETURNING delivery_version
"""

_DEAD_LETTER = """
WITH statement_clock AS MATERIALIZED (
    SELECT clock_timestamp() AS now
)
UPDATE retrywise.outbox_jobs
SET status = 'DEAD_LETTER',
    delivery_version = delivery_version + 1,
    lease_owner = NULL,
    lease_token = NULL,
    lease_expires_at = NULL,
    retry_mode = 'RECONCILE_ONLY',
    last_error_code = %(reason)s,
    last_error_at = statement.now,
    dead_lettered_at = statement.now,
    dead_letter_reason = %(reason)s,
    updated_at = statement.now
FROM statement_clock AS statement
WHERE id = %(job_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'IN_PROGRESS'
  AND delivery_version = %(expected_version)s
  AND lease_owner = %(worker_id)s
  AND lease_token = %(lease_token)s
  AND lease_expires_at > statement.now
RETURNING delivery_version
"""

_CHECK_READY = """
SELECT
    to_regclass('retrywise.outbox_jobs') IS NOT NULL
    AND NOT current_setting('transaction_read_only')::boolean
    AND (
        SELECT count(*) = 4
        FROM pg_catalog.pg_attribute AS attribute
        WHERE attribute.attrelid = to_regclass('retrywise.outbox_jobs')
          AND attribute.attname IN (
              'delivery_version',
              'lease_token',
              'retry_mode',
              'completion_reference'
          )
          AND NOT attribute.attisdropped
    )
    AND EXISTS (
        SELECT 1
        FROM pg_catalog.pg_trigger AS trigger
        WHERE trigger.tgrelid = to_regclass('retrywise.outbox_jobs')
          AND trigger.tgname = 'outbox_jobs_10_enforce_lifecycle'
          AND trigger.tgenabled <> 'D'
    )
"""


class OutboxPersistenceError(RuntimeError):
    """Base class for durable outbox repository failures."""


class OutboxFenceLost(OutboxPersistenceError):
    """The persisted lease no longer matches or has expired."""


def _clean_text(value: str, *, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{field} must be clean, non-empty text of at most {maximum} characters")
    return value


def _internal_ulid(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _ULID_RE.fullmatch(value):
        raise ValueError(f"{field} must match the RetryWise ULID database domain")
    return value


def _utc(value: datetime, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field} must be a timezone-aware datetime")
    return value.astimezone(UTC)


def _positive_int(value: int, *, field: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _prefixed_reason(prefix: str, reason: str) -> str:
    """Keep operator evidence inside the persisted 500-character boundary."""

    available = 500 - len(prefix) - 1
    if available < 1:
        raise AssertionError("internal reason prefix exceeds its storage boundary")
    return f"{prefix}:{reason[:available]}"


def _payload(value: object) -> Mapping[str, object]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = bytes(value).decode("utf-8")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError("outbox command_payload is not valid JSON") from exc
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise RuntimeError("outbox command_payload must be a JSON object")
    return dict(value)


@dataclass(frozen=True, slots=True)
class ClaimedOutboxCommand:
    """One immutable command envelope under a current fenced lease."""

    job_id: str
    merchant_id: str
    aggregate_type: str
    aggregate_id: str
    command_type: str
    command_schema_version: int
    command_payload: Mapping[str, object]
    idempotency_key: str
    attempt_count: int
    max_attempts: int
    worker_id: str
    lease_token: str
    lease_expires_at: datetime
    delivery_version: int
    retry_mode: RetryMode
    created_at: datetime
    claimed_at: datetime

    def __post_init__(self) -> None:
        _internal_ulid(self.job_id, field="job_id")
        _internal_ulid(self.merchant_id, field="merchant_id")
        for field, maximum in (
            ("aggregate_type", 100),
            ("aggregate_id", 200),
            ("command_type", 100),
            ("idempotency_key", 300),
            ("worker_id", 128),
            ("lease_token", 200),
        ):
            _clean_text(getattr(self, field), field=field, maximum=maximum)
        _positive_int(self.command_schema_version, field="command_schema_version")
        _positive_int(self.attempt_count, field="attempt_count")
        _positive_int(self.max_attempts, field="max_attempts")
        _positive_int(self.delivery_version, field="delivery_version")
        if self.attempt_count > self.max_attempts:
            raise ValueError("attempt_count cannot exceed max_attempts")
        if not isinstance(self.retry_mode, RetryMode):
            raise TypeError("retry_mode must be RetryMode")
        object.__setattr__(self, "command_payload", _payload(self.command_payload))
        created_at = _utc(self.created_at, field="created_at")
        claimed_at = _utc(self.claimed_at, field="claimed_at")
        lease_expires_at = _utc(self.lease_expires_at, field="lease_expires_at")
        if claimed_at < created_at:
            raise ValueError("claimed_at cannot precede created_at")
        if lease_expires_at <= claimed_at:
            raise ValueError("lease_expires_at must be after claimed_at")
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "claimed_at", claimed_at)
        object.__setattr__(self, "lease_expires_at", lease_expires_at)


@dataclass(frozen=True, slots=True)
class OutboxClaimBatch:
    """Bounded claim result, including stale jobs closed without dispatch."""

    selected_count: int
    commands: tuple[ClaimedOutboxCommand, ...]
    expired_dead_lettered: int

    def __post_init__(self) -> None:
        if type(self.selected_count) is not int or self.selected_count < 0:
            raise ValueError("selected_count must be a non-negative integer")
        if type(self.expired_dead_lettered) is not int or self.expired_dead_lettered < 0:
            raise ValueError("expired_dead_lettered must be a non-negative integer")
        if self.selected_count != len(self.commands) + self.expired_dead_lettered:
            raise ValueError("selected_count must account for every claimed or expired row")


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def fetchall(self) -> Sequence[Sequence[object]]: ...

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


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresOutboxRepository"),
        )

    return connect


def _one_column(row: Sequence[object] | None, *, operation: str) -> object:
    if row is None:
        raise OutboxFenceLost(f"{operation} lost its fenced lease")
    if len(row) != 1:
        raise RuntimeError(f"{operation} returned an unexpected row shape")
    return row[0]


def _retry_mode(value: object) -> RetryMode:
    if not isinstance(value, str):
        raise RuntimeError("outbox retry_mode returned by PostgreSQL is not text")
    try:
        return RetryMode(value.lower())
    except ValueError as exc:
        raise RuntimeError(f"unsupported persisted outbox retry_mode: {value!r}") from exc


def _claimed_from_row(row: Sequence[object]) -> ClaimedOutboxCommand:
    if len(row) != 18:
        raise RuntimeError("outbox claim returned an unexpected row shape")
    if row[0] != "IN_PROGRESS":
        raise RuntimeError("only IN_PROGRESS rows can be converted to claimed commands")
    if not isinstance(row[1], str) or not isinstance(row[2], str):
        raise RuntimeError("outbox identifiers returned by PostgreSQL are not text")
    if not all(isinstance(row[index], str) for index in (3, 4, 5, 8, 11, 12)):
        raise RuntimeError("outbox claim returned a non-text command or lease field")
    if not all(type(row[index]) is int for index in (6, 9, 10, 14)):
        raise RuntimeError("outbox claim returned a non-integer counter or version")
    if not all(isinstance(row[index], datetime) for index in (13, 16, 17)):
        raise RuntimeError("outbox claim returned a non-datetime lease or audit field")
    return ClaimedOutboxCommand(
        job_id=row[1],
        merchant_id=row[2],
        aggregate_type=cast(str, row[3]),
        aggregate_id=cast(str, row[4]),
        command_type=cast(str, row[5]),
        command_schema_version=cast(int, row[6]),
        command_payload=_payload(row[7]),
        idempotency_key=cast(str, row[8]),
        attempt_count=cast(int, row[9]),
        max_attempts=cast(int, row[10]),
        worker_id=cast(str, row[11]),
        lease_token=cast(str, row[12]),
        lease_expires_at=cast(datetime, row[13]),
        delivery_version=cast(int, row[14]),
        retry_mode=_retry_mode(row[15]),
        created_at=cast(datetime, row[16]),
        claimed_at=cast(datetime, row[17]),
    )


class PostgresOutboxRepository:
    """Bounded PostgreSQL queue repository with fenced settlement methods."""

    durable = True

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        backoff: BackoffPolicy | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
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
        self._backoff = backoff or BackoffPolicy()
        if not isinstance(self._backoff, BackoffPolicy):
            raise TypeError("backoff must be BackoffPolicy")
        self._token_factory = token_factory or (lambda: secrets.token_hex(24))
        if not callable(self._token_factory):
            raise TypeError("token_factory must be callable")

    def check_ready(self) -> bool:
        """Check writable schema, fencing columns, and lifecycle trigger."""

        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_CHECK_READY, {})
            row = cursor.fetchone()
        if row is None or len(row) != 1 or type(row[0]) is not bool:
            raise RuntimeError("outbox readiness query returned an unexpected row")
        return row[0]

    def claim_batch(
        self,
        *,
        worker_id: str,
        batch_size: int = 25,
        lease_duration: timedelta = timedelta(seconds=30),
    ) -> OutboxClaimBatch:
        """Atomically claim at most ``batch_size`` due or expired jobs."""

        worker_id = _clean_text(worker_id, field="worker_id", maximum=128)
        if type(batch_size) is not int or not 1 <= batch_size <= _MAX_BATCH_SIZE:
            raise ValueError(f"batch_size must be between 1 and {_MAX_BATCH_SIZE}")
        if not isinstance(lease_duration, timedelta) or lease_duration <= timedelta(0):
            raise ValueError("lease_duration must be a positive timedelta")
        if lease_duration > timedelta(minutes=15):
            raise ValueError("lease_duration must not exceed 15 minutes")
        lease_nonce = _clean_text(self._token_factory(), field="token_factory result", maximum=96)
        params: dict[str, object] = {
            "batch_size": batch_size,
            "lease_duration": lease_duration,
            "lease_nonce": lease_nonce,
            "worker_id": worker_id,
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_CLAIM_BATCH, params)
            rows = cursor.fetchall()
        if len(rows) > batch_size:
            raise RuntimeError("outbox claim exceeded its requested batch bound")

        commands: list[ClaimedOutboxCommand] = []
        expired_dead_lettered = 0
        for row in rows:
            if not row:
                raise RuntimeError("outbox claim returned an empty row")
            if row[0] == "DEAD_LETTER":
                expired_dead_lettered += 1
            elif row[0] == "IN_PROGRESS":
                commands.append(_claimed_from_row(row))
            else:
                raise RuntimeError(f"outbox claim returned unexpected status: {row[0]!r}")
        return OutboxClaimBatch(len(rows), tuple(commands), expired_dead_lettered)

    def complete(self, command: ClaimedOutboxCommand, *, completion_reference: str) -> int:
        """Persist successful delivery if and only if the lease remains current."""

        completion_reference = _clean_text(
            completion_reference, field="completion_reference", maximum=500
        )
        return self._settle(
            _COMPLETE,
            command,
            operation="complete",
            extra={"completion_reference": completion_reference},
        )

    def retry(
        self,
        command: ClaimedOutboxCommand,
        *,
        reason: str,
        retry_mode: RetryMode = RetryMode.RECONCILE_ONLY,
    ) -> int:
        """Schedule bounded backoff, or dead-letter the exhausted final attempt."""

        reason = _clean_text(reason, field="reason", maximum=500)
        if not isinstance(retry_mode, RetryMode):
            raise TypeError("retry_mode must be RetryMode")
        if command.attempt_count >= command.max_attempts:
            return self.dead_letter(
                command,
                reason=_prefixed_reason("max_attempts_exhausted", reason),
            )
        return self._settle(
            _RETRY,
            command,
            operation="retry",
            extra={
                "retry_delay": self._backoff.delay_after(command.attempt_count),
                "reason": reason,
                "retry_mode": retry_mode.value.upper(),
            },
        )

    def dead_letter(self, command: ClaimedOutboxCommand, *, reason: str) -> int:
        """Persist terminal operator evidence behind the current fence."""

        reason = _clean_text(reason, field="reason", maximum=500)
        return self._settle(
            _DEAD_LETTER,
            command,
            operation="dead_letter",
            extra={"reason": reason},
        )

    def _settle(
        self,
        query: str,
        command: ClaimedOutboxCommand,
        *,
        operation: str,
        extra: Mapping[str, object],
    ) -> int:
        if not isinstance(command, ClaimedOutboxCommand):
            raise TypeError("command must be ClaimedOutboxCommand")
        params: dict[str, object] = {
            "expected_version": command.delivery_version,
            "job_id": command.job_id,
            "lease_token": command.lease_token,
            "merchant_id": command.merchant_id,
            "worker_id": command.worker_id,
            **extra,
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(query, params)
            version = _one_column(cursor.fetchone(), operation=operation)
        if type(version) is not int or version != command.delivery_version + 1:
            raise RuntimeError(f"{operation} returned an invalid delivery version")
        return version


__all__ = [
    "ClaimedOutboxCommand",
    "ConnectionFactory",
    "OutboxClaimBatch",
    "OutboxFenceLost",
    "OutboxPersistenceError",
    "PostgresOutboxRepository",
]
