"""Strict, transactional projection of canonical provider events.

This module implements only the first worker-owned business slice:
``PROCESS_NORMALIZED_PROVIDER_EVENT`` for ``payment.failed``.  It never calls a
provider, a model, or an effect executor.  A current outbox lease is checked and
locked before the immutable provider evidence is loaded.  Payment projection,
creation (or reuse) of one open recovery case, and inbox settlement then commit
as one PostgreSQL transaction.

The outbox row is deliberately settled by :class:`OutboxWorker` after this
handler returns.  If the process dies in that narrow gap, redelivery observes
the already-terminal inbox row and returns the same successful disposition.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Protocol, cast

from ...packages.razorpay import CanonicalEventType
from .outbox import RetryMode
from .outbox_worker import HandlerResult
from .payment_enrichment import (
    ENRICH_FAILED_PAYMENT_COMMAND_TYPE,
    ENRICH_FAILED_PAYMENT_SCHEMA_VERSION,
    EnrichFailedPaymentCommand,
    canonical_enrichment_payload,
    encode_enrich_failed_payment_command,
)
from .postgres_connection import PostgresConnectionPolicy
from .postgres_outbox import ClaimedOutboxCommand

PROCESS_NORMALIZED_PROVIDER_EVENT: Final = "PROCESS_NORMALIZED_PROVIDER_EVENT"
PROCESS_NORMALIZED_PROVIDER_EVENT_SCHEMA_VERSION: Final = 1
MAX_NORMALIZED_EVENT_COMMAND_BYTES: Final = 4 * 1024

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_OPERATIONAL_FACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
_PAYMENT_METHOD_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_PII_NUMBER_RE = re.compile(r"(?<!\d)\d{10,19}(?!\d)")
_CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_MAX_SIGNED_BIGINT = (1 << 63) - 1
_MINIMUM_OBSERVATION = timedelta(minutes=2)

_COMMAND_FIELDS = frozenset(
    {
        "event_type",
        "inbox_event_id",
        "merchant_id",
        "provider_account_id",
        "provider_event_id",
        "provider_event_record_id",
        "schema_version",
    }
)
_CANONICAL_FIELDS = frozenset(
    {
        "event_id",
        "event_name",
        "event_type",
        "occurred_at_epoch",
        "provider_account_id",
        "raw_body_sha256",
        "related_resources",
        "resource",
        "resource_id",
        "resource_type",
        "schema_version",
    }
)
_PAYMENT_FIELDS = frozenset(
    {
        "amount",
        "amount_refunded",
        "captured",
        "created_at",
        "currency",
        "entity",
        "error_code",
        "error_reason",
        "error_source",
        "error_step",
        "id",
        "invoice_id",
        "method",
        "order_id",
        "refund_status",
        "status",
    }
)
_REQUIRED_PAYMENT_FIELDS = frozenset({"amount", "currency", "id", "order_id", "status"})
_OPEN_CASE_STATES = frozenset(
    {
        "OBSERVING",
        "ASSESSING",
        "WAITING",
        "APPROVAL_REQUIRED",
        "ACTION_QUEUED",
        "EXECUTING",
        "ACTION_UNCERTAIN",
        "ACTIVE",
    }
)
_SAFE_PRE_FAILURE_PAYMENT_STATES = frozenset({"UNKNOWN", "CREATED", "FAILED"})
_SAFE_RECOVERY_TRUTHS = frozenset({"UNKNOWN", "UNPAID"})
_KNOWN_CANONICAL_EVENT_TYPES = frozenset(
    event_type.value
    for event_type in CanonicalEventType
    if event_type is not CanonicalEventType.UNKNOWN
)

_LOCK_OUTBOX_FENCE = """
SELECT TRUE
FROM retrywise.outbox_jobs AS job
WHERE job.id = %(job_id)s
  AND job.merchant_id = %(merchant_id)s
  AND job.aggregate_type = 'PROVIDER_EVENT'
  AND job.aggregate_id = %(provider_event_record_id)s
  AND job.command_type = 'PROCESS_NORMALIZED_PROVIDER_EVENT'
  AND job.command_schema_version = 1
  AND job.command_payload = %(command_payload)s::jsonb
  AND job.idempotency_key = %(idempotency_key)s
  AND job.status = 'IN_PROGRESS'
  AND job.delivery_version = %(delivery_version)s
  AND job.lease_owner = %(worker_id)s
  AND job.lease_token = %(lease_token)s
  AND job.lease_expires_at > clock_timestamp()
FOR UPDATE OF job
"""

_LOAD_EVENT_AND_INBOX = """
SELECT
    inbox.id::text,
    inbox.status::text,
    inbox.attempt_count,
    inbox.max_attempts,
    CASE
        WHEN inbox.status = 'PROCESSING'
            THEN inbox.lease_expires_at <= clock_timestamp()
        ELSE FALSE
    END AS processing_lease_expired,
    event.merchant_id::text,
    event.provider_account_id::text,
    account.provider_account_identifier,
    event.id::text,
    event.provider_event_id,
    event.event_type,
    event.resource_type,
    event.resource_id,
    event.body_sha256,
    event.signature_verified,
    event.account_verified,
    event.normalized_schema_version,
    event.canonical_event,
    event.provider_occurred_at,
    event.received_at
FROM retrywise.inbox_events AS inbox
JOIN retrywise.provider_events AS event
  ON event.merchant_id = inbox.merchant_id
 AND event.provider_account_id = inbox.provider_account_id
 AND event.id = inbox.provider_event_record_id
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = event.merchant_id
 AND account.id = event.provider_account_id
 AND account.provider = 'RAZORPAY'
 AND account.environment = 'TEST'
 AND account.enabled
WHERE inbox.id = %(inbox_event_id)s
  AND inbox.merchant_id = %(merchant_id)s
  AND inbox.provider_account_id = %(provider_account_id)s
  AND inbox.provider_event_record_id = %(provider_event_record_id)s
FOR UPDATE OF inbox
FOR SHARE OF account
"""

_FIND_REUSED_BODY = """
SELECT provider_event_id
FROM retrywise.provider_events
WHERE merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND body_sha256 = %(body_sha256)s
  AND (received_at, id) < (
      %(received_at)s,
      %(provider_event_record_id)s::retrywise.ulid
  )
ORDER BY received_at, id
LIMIT 1
"""

_LOAD_PAYMENT_AND_ORDER = """
SELECT
    payment.id::text,
    payment.logical_order_id::text,
    payment.provider_payment_id,
    payment.provider_order_id,
    payment.status::text,
    payment.amount_minor,
    payment.currency::text,
    payment.payment_method,
    payment.error_facts,
    payment.provider_snapshot_at,
    logical_order.original_provider_order_id,
    logical_order.amount_due_minor,
    logical_order.currency::text,
    logical_order.canonical_truth::text,
    logical_order.mapping_status::text
FROM retrywise.provider_payments AS payment
JOIN retrywise.logical_orders AS logical_order
  ON logical_order.merchant_id = payment.merchant_id
 AND logical_order.id = payment.logical_order_id
 AND logical_order.provider_account_id = payment.provider_account_id
 AND logical_order.currency = payment.currency
WHERE payment.merchant_id = %(merchant_id)s
  AND payment.provider_account_id = %(provider_account_id)s
  AND payment.provider_payment_id = %(provider_payment_id)s
FOR UPDATE OF payment, logical_order
"""

_START_INBOX_PROCESSING = """
UPDATE retrywise.inbox_events
SET status = 'PROCESSING',
    attempt_count = attempt_count + 1,
    lease_owner = %(processor_id)s,
    lease_expires_at = %(lease_expires_at)s,
    last_error_code = NULL,
    last_error_at = NULL
WHERE id = %(inbox_event_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND provider_event_record_id = %(provider_event_record_id)s
  AND attempt_count < max_attempts
  AND (
      (status IN ('RECEIVED', 'RETRY_SCHEDULED')
       AND next_attempt_at <= clock_timestamp())
      OR (status = 'PROCESSING' AND lease_expires_at <= clock_timestamp())
  )
RETURNING status::text, attempt_count
"""

_DEAD_LETTER_EXHAUSTED_INBOX = """
UPDATE retrywise.inbox_events
SET status = 'DEAD_LETTER',
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error_code = 'normalized_event_attempts_exhausted',
    last_error_at = clock_timestamp(),
    dead_lettered_at = clock_timestamp(),
    dead_letter_reason = 'normalized_event_attempts_exhausted'
WHERE id = %(inbox_event_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND provider_event_record_id = %(provider_event_record_id)s
  AND status IN ('RECEIVED', 'PROCESSING', 'RETRY_SCHEDULED')
  AND attempt_count >= max_attempts
RETURNING status::text
"""

_PROJECT_PAYMENT_FAILED = """
UPDATE retrywise.provider_payments
SET status = 'FAILED',
    payment_method = COALESCE(payment_method, %(payment_method)s),
    error_facts = %(error_facts)s::jsonb,
    provider_snapshot_at = GREATEST(provider_snapshot_at, %(provider_occurred_at)s),
    updated_at = clock_timestamp()
WHERE id = %(payment_record_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND logical_order_id = %(logical_order_id)s
  AND provider_payment_id = %(provider_payment_id)s
  AND status IN ('UNKNOWN', 'CREATED', 'FAILED')
RETURNING status::text
"""

_INSERT_OBSERVING_CASE = """
INSERT INTO retrywise.recovery_cases (
    id,
    merchant_id,
    logical_order_id,
    provider_account_id,
    currency,
    amount_due_snapshot_minor,
    state
) VALUES (
    %(recovery_case_id)s,
    %(merchant_id)s,
    %(logical_order_id)s,
    %(provider_account_id)s,
    %(currency)s,
    %(amount_due_minor)s,
    'OBSERVING'
)
ON CONFLICT (merchant_id, logical_order_id, currency)
WHERE state IN (
    'OBSERVING',
    'ASSESSING',
    'WAITING',
    'APPROVAL_REQUIRED',
    'ACTION_QUEUED',
    'EXECUTING',
    'ACTION_UNCERTAIN',
    'ACTIVE'
)
DO NOTHING
RETURNING
    id::text,
    state::text,
    observation_contract_version,
    observation_started_at,
    observation_deadline_at
"""

_LOAD_OPEN_CASE = """
SELECT
    id::text,
    state::text,
    observation_contract_version,
    observation_started_at,
    observation_deadline_at
FROM retrywise.recovery_cases
WHERE merchant_id = %(merchant_id)s
  AND logical_order_id = %(logical_order_id)s
  AND provider_account_id = %(provider_account_id)s
  AND currency = %(currency)s
  AND state IN (
      'OBSERVING',
      'ASSESSING',
      'WAITING',
      'APPROVAL_REQUIRED',
      'ACTION_QUEUED',
      'EXECUTING',
      'ACTION_UNCERTAIN',
      'ACTIVE'
  )
FOR UPDATE
"""

_RECHECK_OUTBOX_FENCE = """
SELECT lease_expires_at > clock_timestamp()
FROM retrywise.outbox_jobs
WHERE id = %(job_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'IN_PROGRESS'
  AND delivery_version = %(delivery_version)s
  AND lease_owner = %(worker_id)s
  AND lease_token = %(lease_token)s
"""

_SETTLE_INBOX = """
UPDATE retrywise.inbox_events
SET status = %(inbox_status)s::retrywise.inbox_status,
    lease_owner = NULL,
    lease_expires_at = NULL,
    processed_at = clock_timestamp(),
    last_error_code = %(reason_code)s::text,
    last_error_at = CASE
        WHEN %(reason_code)s::text IS NULL THEN NULL
        ELSE clock_timestamp()
    END
WHERE id = %(inbox_event_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND provider_event_record_id = %(provider_event_record_id)s
  AND status = 'PROCESSING'
  AND lease_owner = %(processor_id)s
RETURNING status::text
"""

_DEFER_INBOX = """
UPDATE retrywise.inbox_events
SET status = 'RETRY_SCHEDULED',
    next_attempt_at = clock_timestamp() + interval '5 seconds',
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error_code = %(reason_code)s,
    last_error_at = clock_timestamp()
WHERE id = %(inbox_event_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND provider_event_record_id = %(provider_event_record_id)s
  AND status = 'PROCESSING'
  AND lease_owner = %(processor_id)s
RETURNING status::text
"""

_INSERT_PAYMENT_ENRICHMENT = """
INSERT INTO retrywise.outbox_jobs (
    id, merchant_id, aggregate_type, aggregate_id, command_type,
    command_schema_version, command_payload, idempotency_key, status,
    attempt_count, max_attempts, next_attempt_at
) VALUES (
    %(enrichment_job_id)s, %(merchant_id)s, 'PROVIDER_PAYMENT',
    %(enrichment_provider_payment_id)s, %(enrichment_command_type)s,
    %(enrichment_schema_version)s, %(enrichment_payload)s::jsonb,
    %(enrichment_idempotency_key)s, 'PENDING', 0, 8, clock_timestamp()
)
ON CONFLICT (merchant_id, idempotency_key) DO NOTHING
RETURNING id::text
"""


class NormalizedEventCommandError(ValueError):
    """The outbox command is not the one closed, versioned schema."""


class NormalizedEventBindingError(RuntimeError):
    """Persisted evidence disagrees with the authenticated command binding."""


class NormalizedEventEvidenceError(RuntimeError):
    """Canonical evidence is malformed or internally inconsistent."""


class NormalizedEventFenceLost(RuntimeError):
    """The handler no longer owns the durable outbox delivery fence."""


class NormalizedEventBusy(RuntimeError):
    """Another non-expired inbox processing lease is present."""


def _clean_text(value: object, *, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise NormalizedEventCommandError(
            f"{field} must be clean, non-empty text of at most {maximum} characters"
        )
    return value


def _ulid(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _ULID_RE.fullmatch(value):
        raise NormalizedEventCommandError(f"{field} must match the RetryWise ULID domain")
    return value


def _exact_mapping(
    value: object,
    *,
    fields: frozenset[str],
    field: str,
    error_type: type[RuntimeError] | type[ValueError],
) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise error_type(f"{field} must be a JSON object")
    copied = dict(value)
    present = frozenset(copied)
    if present != fields:
        missing = ",".join(sorted(fields - present))
        unknown = ",".join(sorted(present - fields))
        raise error_type(f"{field} fields disagree (missing={missing}; unknown={unknown})")
    return copied


def _canonical_payload_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            dict(payload),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NormalizedEventCommandError("command payload must contain only JSON values") from exc
    if len(encoded) > MAX_NORMALIZED_EVENT_COMMAND_BYTES:
        raise NormalizedEventCommandError("command payload exceeds its 4 KiB boundary")
    return encoded


@dataclass(frozen=True, slots=True)
class ProcessNormalizedProviderEventCommand:
    """Validated business binding reconstructed from an outbox delivery."""

    merchant_id: str
    provider_account_id: str
    provider_event_record_id: str
    provider_event_id: str
    inbox_event_id: str
    event_type: str
    schema_version: int = PROCESS_NORMALIZED_PROVIDER_EVENT_SCHEMA_VERSION


def decode_process_normalized_provider_event_command(
    claimed: ClaimedOutboxCommand,
) -> ProcessNormalizedProviderEventCommand:
    """Decode one exact v1 command and bind it to its durable outbox envelope."""

    if not isinstance(claimed, ClaimedOutboxCommand):
        raise TypeError("claimed must be ClaimedOutboxCommand")
    if claimed.command_type != PROCESS_NORMALIZED_PROVIDER_EVENT:
        raise NormalizedEventCommandError("unexpected command type")
    if claimed.command_schema_version != PROCESS_NORMALIZED_PROVIDER_EVENT_SCHEMA_VERSION:
        raise NormalizedEventCommandError("unsupported command schema version")
    if claimed.aggregate_type != "PROVIDER_EVENT":
        raise NormalizedEventCommandError("command aggregate type must be PROVIDER_EVENT")

    payload = _exact_mapping(
        claimed.command_payload,
        fields=_COMMAND_FIELDS,
        field="command_payload",
        error_type=NormalizedEventCommandError,
    )
    _canonical_payload_bytes(payload)
    schema_version = payload["schema_version"]
    if type(schema_version) is not int or schema_version != 1:
        raise NormalizedEventCommandError("payload schema_version must be integer 1")
    merchant_id = _ulid(payload["merchant_id"], field="merchant_id")
    provider_account_id = _ulid(payload["provider_account_id"], field="provider_account_id")
    provider_event_record_id = _ulid(
        payload["provider_event_record_id"], field="provider_event_record_id"
    )
    inbox_event_id = _ulid(payload["inbox_event_id"], field="inbox_event_id")
    provider_event_id = _clean_text(
        payload["provider_event_id"], field="provider_event_id", maximum=256
    )
    event_type = _clean_text(payload["event_type"], field="event_type", maximum=200)

    if merchant_id != claimed.merchant_id:
        raise NormalizedEventCommandError("payload merchant does not match outbox tenant")
    if provider_event_record_id != claimed.aggregate_id:
        raise NormalizedEventCommandError("payload event record does not match aggregate id")
    expected_key = f"normalized-provider-event:{provider_event_record_id}"
    if claimed.idempotency_key != expected_key:
        raise NormalizedEventCommandError("outbox idempotency key does not match event record")

    return ProcessNormalizedProviderEventCommand(
        merchant_id=merchant_id,
        provider_account_id=provider_account_id,
        provider_event_record_id=provider_event_record_id,
        provider_event_id=provider_event_id,
        inbox_event_id=inbox_event_id,
        event_type=event_type,
    )


class ProjectionDisposition(StrEnum):
    PROCESSED = "PROCESSED"
    IGNORED = "IGNORED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    DEAD_LETTER = "DEAD_LETTER"


@dataclass(frozen=True, slots=True)
class NormalizedEventProjectionResult:
    disposition: ProjectionDisposition
    provider_event_record_id: str
    recovery_case_id: str | None = None
    recovery_case_created: bool = False
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, ProjectionDisposition):
            raise TypeError("disposition must be ProjectionDisposition")
        _ulid(self.provider_event_record_id, field="provider_event_record_id")
        if self.recovery_case_id is not None:
            _ulid(self.recovery_case_id, field="recovery_case_id")
        if type(self.recovery_case_created) is not bool:
            raise TypeError("recovery_case_created must be boolean")
        if self.recovery_case_created and self.recovery_case_id is None:
            raise ValueError("a created recovery case requires its id")
        if self.disposition is not ProjectionDisposition.PROCESSED and self.recovery_case_id:
            raise ValueError("only processed events can reference a recovery case")
        if (
            self.disposition
            in {
                ProjectionDisposition.IGNORED,
                ProjectionDisposition.RETRY_SCHEDULED,
            }
            and self.reason_code is None
        ):
            raise ValueError("ignored or deferred results require a reason code")
        if self.reason_code is not None:
            _clean_text(self.reason_code, field="reason_code", maximum=200)

    @property
    def completion_reference(self) -> str:
        suffix = self.disposition.value.lower()
        if self.recovery_case_id is not None:
            suffix = f"{suffix}:case:{self.recovery_case_id}"
        return f"normalized-provider-event:{self.provider_event_record_id}:{suffix}"


@dataclass(frozen=True, slots=True)
class _PersistedEvent:
    inbox_event_id: str
    inbox_status: str
    attempt_count: int
    max_attempts: int
    processing_lease_expired: bool
    merchant_id: str
    provider_account_id: str
    provider_account_identifier: str
    provider_event_record_id: str
    provider_event_id: str
    event_type: str
    resource_type: str
    resource_id: str | None
    body_sha256: bytes
    signature_verified: bool
    account_verified: bool
    normalized_schema_version: int
    canonical_event: Mapping[str, object]
    provider_occurred_at: datetime
    received_at: datetime


@dataclass(frozen=True, slots=True)
class _FailedPayment:
    provider_payment_id: str
    provider_order_id: str | None
    amount_minor: int
    currency: str
    payment_method: str | None
    error_facts: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _PaymentProjectionTarget:
    payment_record_id: str
    logical_order_id: str
    provider_payment_id: str
    provider_order_id: str | None
    status: str
    amount_minor: int
    currency: str
    payment_method: str | None
    error_facts: Mapping[str, object]
    provider_snapshot_at: datetime
    original_provider_order_id: str | None
    amount_due_minor: int
    order_currency: str
    canonical_truth: str
    mapping_status: str


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


class NormalizedEventRepository(Protocol):
    def project(
        self,
        command: ProcessNormalizedProviderEventCommand,
        *,
        claim: ClaimedOutboxCommand,
    ) -> NormalizedEventProjectionResult: ...


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresNormalizedEventRepository"),
        )

    return connect


def _first_column(row: Sequence[object] | None, *, operation: str) -> object:
    if row is None or len(row) != 1:
        raise RuntimeError(f"{operation} returned an unexpected row shape")
    return row[0]


def _binary_digest(value: object) -> bytes:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if not isinstance(value, bytes) or len(value) != 32:
        raise NormalizedEventEvidenceError("provider event body digest is not SHA-256")
    return value


def _aware_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise NormalizedEventEvidenceError(f"{field} must be a timezone-aware timestamp")
    return value.astimezone(UTC)


def _persisted_event(row: Sequence[object] | None) -> _PersistedEvent:
    if row is None:
        raise NormalizedEventBindingError("bound provider event and inbox row were not found")
    if len(row) != 20:
        raise RuntimeError("provider event lookup returned an unexpected row shape")
    if not all(isinstance(row[index], str) for index in (0, 1, 5, 6, 7, 8, 9, 10, 11)):
        raise NormalizedEventEvidenceError("provider event lookup returned non-text identifiers")
    if not all(type(row[index]) is int for index in (2, 3, 16)):
        raise NormalizedEventEvidenceError("provider event counters or schema are not integers")
    if type(row[4]) is not bool or type(row[14]) is not bool or type(row[15]) is not bool:
        raise NormalizedEventEvidenceError("provider event verification evidence is not boolean")
    if row[12] is not None and not isinstance(row[12], str):
        raise NormalizedEventEvidenceError("provider event resource id is not text")
    canonical = row[17]
    if not isinstance(canonical, Mapping) or not all(isinstance(key, str) for key in canonical):
        raise NormalizedEventEvidenceError("canonical provider event is not a JSON object")
    return _PersistedEvent(
        inbox_event_id=cast(str, row[0]),
        inbox_status=cast(str, row[1]),
        attempt_count=cast(int, row[2]),
        max_attempts=cast(int, row[3]),
        processing_lease_expired=row[4],
        merchant_id=cast(str, row[5]),
        provider_account_id=cast(str, row[6]),
        provider_account_identifier=cast(str, row[7]),
        provider_event_record_id=cast(str, row[8]),
        provider_event_id=cast(str, row[9]),
        event_type=cast(str, row[10]),
        resource_type=cast(str, row[11]),
        resource_id=row[12],
        body_sha256=_binary_digest(row[13]),
        signature_verified=row[14],
        account_verified=row[15],
        normalized_schema_version=cast(int, row[16]),
        canonical_event=dict(cast(Mapping[str, object], canonical)),
        provider_occurred_at=_aware_utc(row[18], field="provider_occurred_at"),
        received_at=_aware_utc(row[19], field="received_at"),
    )


def _validate_event_binding(
    event: _PersistedEvent,
    command: ProcessNormalizedProviderEventCommand,
) -> None:
    expected = (
        command.inbox_event_id,
        command.merchant_id,
        command.provider_account_id,
        command.provider_event_record_id,
        command.provider_event_id,
        command.event_type,
    )
    actual = (
        event.inbox_event_id,
        event.merchant_id,
        event.provider_account_id,
        event.provider_event_record_id,
        event.provider_event_id,
        event.event_type,
    )
    if actual != expected:
        raise NormalizedEventBindingError("persisted event binding disagrees with command")
    if not event.signature_verified or not event.account_verified:
        raise NormalizedEventBindingError("provider event is not authenticated and account-bound")
    _canonical_text(
        event.provider_account_identifier,
        field="provider_account_identifier",
        maximum=128,
    )
    if event.normalized_schema_version != command.schema_version:
        raise NormalizedEventBindingError("provider event schema disagrees with command schema")


def _canonical_integer(value: object, *, field: str, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= _MAX_SIGNED_BIGINT:
        raise NormalizedEventEvidenceError(f"{field} must be a bounded JSON integer")
    return value


def _canonical_text(value: object, *, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise NormalizedEventEvidenceError(f"{field} is not bounded clean text")
    return value


def _optional_canonical_text(value: object, *, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    return _canonical_text(value, field=field, maximum=maximum)


def _validate_canonical_envelope(event: _PersistedEvent) -> Mapping[str, object]:
    canonical = _exact_mapping(
        event.canonical_event,
        fields=_CANONICAL_FIELDS,
        field="canonical_event",
        error_type=NormalizedEventEvidenceError,
    )
    schema_version = _canonical_integer(
        canonical["schema_version"], field="canonical_event.schema_version", minimum=1
    )
    occurred_at_epoch = _canonical_integer(
        canonical["occurred_at_epoch"], field="canonical_event.occurred_at_epoch"
    )
    digest = _canonical_text(
        canonical["raw_body_sha256"],
        field="canonical_event.raw_body_sha256",
        maximum=64,
    )
    if not _SHA256_RE.fullmatch(digest):
        raise NormalizedEventEvidenceError("canonical event digest is not lowercase SHA-256")
    try:
        occurred_at = datetime.fromtimestamp(occurred_at_epoch, UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise NormalizedEventEvidenceError("canonical event timestamp is outside range") from exc

    resource_id = canonical["resource_id"]
    if resource_id is not None:
        resource_id = _canonical_text(resource_id, field="canonical_event.resource_id", maximum=128)
    related = canonical["related_resources"]
    if not isinstance(related, Mapping) or not all(isinstance(key, str) for key in related):
        raise NormalizedEventEvidenceError("canonical related_resources must be an object")
    resource = canonical["resource"]
    if not isinstance(resource, Mapping) or not all(isinstance(key, str) for key in resource):
        raise NormalizedEventEvidenceError("canonical resource must be an object")

    bindings = (
        schema_version == event.normalized_schema_version,
        canonical["event_id"] == event.provider_event_id,
        canonical["provider_account_id"] == event.provider_account_identifier,
        canonical["event_name"] == event.event_type,
        canonical["resource_type"] == event.resource_type,
        resource_id == event.resource_id,
        hmac_compare_digest(digest, event.body_sha256.hex()),
        occurred_at == event.provider_occurred_at,
    )
    if not all(bindings):
        raise NormalizedEventBindingError("canonical event disagrees with immutable columns")
    canonical_event_type = _canonical_text(
        canonical["event_type"], field="canonical_event.event_type", maximum=200
    )
    expected_event_type = (
        event.event_type if event.event_type in _KNOWN_CANONICAL_EVENT_TYPES else "unknown"
    )
    if canonical_event_type != expected_event_type:
        raise NormalizedEventBindingError(
            "canonical event_name and canonical event_type are inconsistent"
        )
    return canonical


def hmac_compare_digest(left: str, right: str) -> bool:
    """Compare public digests without introducing accidental short-circuit code."""

    return secrets.compare_digest(left, right)


def _failed_payment(canonical: Mapping[str, object]) -> _FailedPayment:
    if canonical["event_name"] != "payment.failed":
        raise NormalizedEventEvidenceError("payment failure decoder received another event")
    if canonical["event_type"] != "payment.failed":
        raise NormalizedEventEvidenceError("canonical payment failure type is inconsistent")
    if canonical["resource_type"] != "payment":
        raise NormalizedEventEvidenceError("payment failure resource type must be payment")
    resource = cast(Mapping[str, object], canonical["resource"])
    present = frozenset(resource)
    if not present >= _REQUIRED_PAYMENT_FIELDS or not present <= _PAYMENT_FIELDS:
        raise NormalizedEventEvidenceError("canonical payment resource fields are not allowed")
    payment_id = _canonical_text(resource["id"], field="payment.id", maximum=128)
    provider_order_id = _optional_canonical_text(
        resource["order_id"], field="payment.order_id", maximum=128
    )
    status = _canonical_text(resource["status"], field="payment.status", maximum=50)
    if status != "failed":
        raise NormalizedEventEvidenceError("payment.failed resource status must be failed")
    amount_minor = _canonical_integer(resource["amount"], field="payment.amount", minimum=1)
    currency = _canonical_text(resource["currency"], field="payment.currency", maximum=3)
    if not _CURRENCY_RE.fullmatch(currency):
        raise NormalizedEventEvidenceError("payment currency must be uppercase ISO text")
    entity = resource.get("entity")
    if entity is not None and entity != "payment":
        raise NormalizedEventEvidenceError("payment entity discriminator is inconsistent")
    captured = resource.get("captured")
    if captured is not None and captured is not False:
        raise NormalizedEventEvidenceError("failed payment cannot be marked captured")
    amount_refunded = resource.get("amount_refunded")
    if (
        amount_refunded is not None
        and _canonical_integer(amount_refunded, field="payment.amount_refunded") != 0
    ):
        raise NormalizedEventEvidenceError("failed payment cannot carry a refund amount")
    created_at = resource.get("created_at")
    if created_at is not None:
        _canonical_integer(created_at, field="payment.created_at")

    payment_method = _optional_canonical_text(
        resource.get("method"), field="payment.method", maximum=50
    )
    if payment_method is not None and not _PAYMENT_METHOD_RE.fullmatch(payment_method):
        raise NormalizedEventEvidenceError("payment method is not a canonical identifier")
    _optional_canonical_text(resource.get("invoice_id"), field="payment.invoice_id", maximum=128)
    _optional_canonical_text(
        resource.get("refund_status"), field="payment.refund_status", maximum=50
    )
    error_facts: dict[str, str] = {}
    for key in ("error_code", "error_reason", "error_source", "error_step"):
        value = _optional_canonical_text(resource.get(key), field=f"payment.{key}", maximum=200)
        if value is not None:
            if not _OPERATIONAL_FACT_RE.fullmatch(value) or _PII_NUMBER_RE.search(value):
                raise NormalizedEventEvidenceError(
                    f"payment.{key} is not a non-sensitive operational identifier"
                )
            error_facts[key] = value

    related = cast(Mapping[str, object], canonical["related_resources"])
    if frozenset(related) - {"payment", "order"}:
        raise NormalizedEventEvidenceError("payment failure has unexpected related resources")
    related_payment = related.get("payment")
    if related_payment is not None and related_payment != resource:
        raise NormalizedEventEvidenceError("related payment disagrees with primary resource")

    return _FailedPayment(
        provider_payment_id=payment_id,
        provider_order_id=provider_order_id,
        amount_minor=amount_minor,
        currency=currency,
        payment_method=payment_method,
        error_facts=error_facts,
    )


def _payment_target(row: Sequence[object] | None) -> _PaymentProjectionTarget | None:
    if row is None:
        return None
    if len(row) != 15:
        raise RuntimeError("payment mapping lookup returned an unexpected row shape")
    if not all(isinstance(row[index], str) for index in (0, 1, 2, 4, 6, 12, 13, 14)):
        raise NormalizedEventEvidenceError("payment mapping contains non-text state or identity")
    if row[3] is not None and not isinstance(row[3], str):
        raise NormalizedEventEvidenceError("provider payment order id is not text")
    if row[7] is not None and not isinstance(row[7], str):
        raise NormalizedEventEvidenceError("persisted payment method is not text")
    if row[10] is not None and not isinstance(row[10], str):
        raise NormalizedEventEvidenceError("logical order provider id is not text")
    if type(row[5]) is not int or type(row[11]) is not int:
        raise NormalizedEventEvidenceError("payment mapping money is not integer minor units")
    error_facts = row[8]
    if not isinstance(error_facts, Mapping) or not all(isinstance(key, str) for key in error_facts):
        raise NormalizedEventEvidenceError("persisted payment error facts are not an object")
    return _PaymentProjectionTarget(
        payment_record_id=cast(str, row[0]),
        logical_order_id=cast(str, row[1]),
        provider_payment_id=cast(str, row[2]),
        provider_order_id=row[3],
        status=cast(str, row[4]),
        amount_minor=row[5],
        currency=cast(str, row[6]),
        payment_method=row[7],
        error_facts=dict(cast(Mapping[str, object], error_facts)),
        provider_snapshot_at=_aware_utc(row[9], field="provider_snapshot_at"),
        original_provider_order_id=row[10],
        amount_due_minor=row[11],
        order_currency=cast(str, row[12]),
        canonical_truth=cast(str, row[13]),
        mapping_status=cast(str, row[14]),
    )


def _mapping_is_exact(target: _PaymentProjectionTarget, payment: _FailedPayment) -> bool:
    return (
        target.provider_payment_id == payment.provider_payment_id
        and target.provider_order_id == payment.provider_order_id
        and target.original_provider_order_id == payment.provider_order_id
        and target.mapping_status == "MAPPED"
        and target.amount_minor == payment.amount_minor
        and target.amount_due_minor == payment.amount_minor
        and target.currency == payment.currency
        and target.order_currency == payment.currency
        and (
            target.payment_method is None
            or payment.payment_method is None
            or target.payment_method == payment.payment_method
        )
    )


def _new_ulid() -> str:
    timestamp_ms = time.time_ns() // 1_000_000
    if not 0 <= timestamp_ms < 1 << 48:
        raise RuntimeError("system clock is outside the ULID timestamp range")
    value = (timestamp_ms << 80) | secrets.randbits(80)
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = _CROCKFORD_BASE32[value & 31]
        value >>= 5
    return "".join(characters)


def _case_row(
    row: Sequence[object] | None,
    *,
    created: bool,
) -> tuple[str, bool]:
    if row is None or len(row) != 5:
        raise RuntimeError("recovery case lookup returned an unexpected row shape")
    case_id, state, contract_version, started_at, deadline_at = row
    if not isinstance(case_id, str) or not _ULID_RE.fullmatch(case_id):
        raise NormalizedEventEvidenceError("recovery case id is not a RetryWise ULID")
    if not isinstance(state, str) or state not in _OPEN_CASE_STATES:
        raise NormalizedEventEvidenceError("recovery case is not open")
    if type(contract_version) is not int or contract_version != 1:
        raise NormalizedEventEvidenceError("recovery case lacks trusted observation contract")
    started = _aware_utc(started_at, field="observation_started_at")
    deadline = _aware_utc(deadline_at, field="observation_deadline_at")
    if deadline - started < _MINIMUM_OBSERVATION:
        raise NormalizedEventEvidenceError("recovery observation deadline is below safety floor")
    if created and state != "OBSERVING":
        raise NormalizedEventEvidenceError("a new recovery case did not start OBSERVING")
    return case_id, created


class PostgresNormalizedEventRepository:
    """PostgreSQL repository for one idempotent normalized-event projection."""

    durable = True

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        case_id_factory: Callable[[], str] = _new_ulid,
        enrichment_job_id_factory: Callable[[], str] = _new_ulid,
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
        if not callable(case_id_factory):
            raise TypeError("case_id_factory must be callable")
        if not callable(enrichment_job_id_factory):
            raise TypeError("enrichment_job_id_factory must be callable")
        self._case_id_factory = case_id_factory
        self._enrichment_job_id_factory = enrichment_job_id_factory

    def project(
        self,
        command: ProcessNormalizedProviderEventCommand,
        *,
        claim: ClaimedOutboxCommand,
    ) -> NormalizedEventProjectionResult:
        if not isinstance(command, ProcessNormalizedProviderEventCommand):
            raise TypeError("command must be ProcessNormalizedProviderEventCommand")
        if not isinstance(claim, ClaimedOutboxCommand):
            raise TypeError("claim must be ClaimedOutboxCommand")
        processor_id = f"normalized:{claim.job_id}"
        base_params: dict[str, object] = {
            "job_id": claim.job_id,
            "merchant_id": command.merchant_id,
            "provider_account_id": command.provider_account_id,
            "provider_event_record_id": command.provider_event_record_id,
            "provider_event_id": command.provider_event_id,
            "inbox_event_id": command.inbox_event_id,
            "command_payload": _canonical_payload_bytes(claim.command_payload).decode("utf-8"),
            "idempotency_key": claim.idempotency_key,
            "delivery_version": claim.delivery_version,
            "worker_id": claim.worker_id,
            "lease_token": claim.lease_token,
            "lease_expires_at": claim.lease_expires_at,
            "processor_id": processor_id,
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_LOCK_OUTBOX_FENCE, base_params)
            if cursor.fetchone() != (True,):
                raise NormalizedEventFenceLost("normalized event outbox fence is absent or expired")

            cursor.execute(_LOAD_EVENT_AND_INBOX, base_params)
            event = _persisted_event(cursor.fetchone())
            _validate_event_binding(event, command)

            if event.inbox_status in {"PROCESSED", "IGNORED", "DEAD_LETTER"}:
                self._recheck_fence(cursor, base_params)
                disposition = ProjectionDisposition(event.inbox_status)
                return NormalizedEventProjectionResult(
                    disposition=disposition,
                    provider_event_record_id=command.provider_event_record_id,
                    reason_code=(
                        "previously_ignored"
                        if disposition is ProjectionDisposition.IGNORED
                        else None
                    ),
                )
            if event.inbox_status == "PROCESSING" and not event.processing_lease_expired:
                raise NormalizedEventBusy("normalized event inbox lease is still active")
            if event.inbox_status not in {"RECEIVED", "RETRY_SCHEDULED", "PROCESSING"}:
                raise NormalizedEventEvidenceError("inbox is in an unsupported lifecycle state")

            canonical = _validate_canonical_envelope(event)
            cursor.execute(
                _FIND_REUSED_BODY,
                {
                    **base_params,
                    "body_sha256": event.body_sha256,
                    "received_at": event.received_at,
                },
            )
            reused_body = cursor.fetchone() is not None

            disposition = ProjectionDisposition.PROCESSED
            reason_code: str | None = None
            recovery_case_id: str | None = None
            recovery_case_created = False
            payment: _FailedPayment | None = None
            target: _PaymentProjectionTarget | None = None
            enrichment: EnrichFailedPaymentCommand | None = None

            if reused_body:
                disposition = ProjectionDisposition.IGNORED
                reason_code = "suspicious_body_reused_across_event_ids"
            elif event.event_type != "payment.failed":
                disposition = ProjectionDisposition.IGNORED
                reason_code = "unsupported_event_type"
            else:
                payment = _failed_payment(canonical)
                if payment.provider_order_id is None:
                    disposition = ProjectionDisposition.IGNORED
                    reason_code = "payment_missing_order_binding"
                else:
                    cursor.execute(
                        _LOAD_PAYMENT_AND_ORDER,
                        {**base_params, "provider_payment_id": payment.provider_payment_id},
                    )
                    target = _payment_target(cursor.fetchone())
                    if target is None:
                        disposition = ProjectionDisposition.RETRY_SCHEDULED
                        reason_code = "provider_payment_projection_not_ready"
                        enrichment = EnrichFailedPaymentCommand(
                            merchant_id=command.merchant_id,
                            provider_account_id=command.provider_account_id,
                            provider_payment_id=payment.provider_payment_id,
                            provider_order_id=payment.provider_order_id,
                            amount_minor=payment.amount_minor,
                            currency=payment.currency,
                        )
                    elif not _mapping_is_exact(target, payment):
                        disposition = ProjectionDisposition.IGNORED
                        reason_code = "payment_mapping_conflict"
                    elif target.status not in _SAFE_PRE_FAILURE_PAYMENT_STATES:
                        disposition = ProjectionDisposition.IGNORED
                        reason_code = "capture_capable_payment_state_dominates_failure"
                    elif (
                        target.status != "FAILED"
                        and target.provider_snapshot_at > event.provider_occurred_at
                    ):
                        disposition = ProjectionDisposition.IGNORED
                        reason_code = "stale_provider_snapshot_dominates_failure"

            if not self._start_inbox(cursor, event, base_params):
                self._recheck_fence(cursor, base_params)
                return NormalizedEventProjectionResult(
                    disposition=ProjectionDisposition.DEAD_LETTER,
                    provider_event_record_id=command.provider_event_record_id,
                    reason_code="normalized_event_attempts_exhausted",
                )

            if (
                disposition is ProjectionDisposition.PROCESSED
                and payment is not None
                and target is not None
            ):
                prior_projection = target.error_facts.get("retrywise_provider_event_record_id")
                if prior_projection is not None and (
                    not isinstance(prior_projection, str)
                    or not _ULID_RE.fullmatch(prior_projection)
                ):
                    raise NormalizedEventEvidenceError(
                        "persisted payment projection marker is malformed"
                    )
                should_project = target.status != "FAILED" or prior_projection is None
                if should_project:
                    safe_facts = {
                        **payment.error_facts,
                        "projection_contract": "payment-failed/v1",
                        "retrywise_provider_event_record_id": command.provider_event_record_id,
                    }
                    cursor.execute(
                        _PROJECT_PAYMENT_FAILED,
                        {
                            **base_params,
                            "payment_record_id": target.payment_record_id,
                            "logical_order_id": target.logical_order_id,
                            "provider_payment_id": payment.provider_payment_id,
                            "payment_method": payment.payment_method,
                            "error_facts": json.dumps(
                                safe_facts,
                                ensure_ascii=False,
                                separators=(",", ":"),
                                sort_keys=True,
                            ),
                            "provider_occurred_at": event.provider_occurred_at,
                        },
                    )
                    if (
                        _first_column(cursor.fetchone(), operation="payment failure projection")
                        != "FAILED"
                    ):
                        raise RuntimeError("payment failure projection returned another state")

                if target.canonical_truth in _SAFE_RECOVERY_TRUTHS:
                    if target.status == "FAILED" and prior_projection not in {
                        None,
                        command.provider_event_record_id,
                    }:
                        cursor.execute(
                            _LOAD_OPEN_CASE,
                            {
                                **base_params,
                                "logical_order_id": target.logical_order_id,
                                "currency": target.currency,
                            },
                        )
                        existing = cursor.fetchone()
                        if existing is not None:
                            recovery_case_id, recovery_case_created = _case_row(
                                existing, created=False
                            )
                    else:
                        generated_case_id = self._case_id_factory()
                        try:
                            generated_case_id = _ulid(
                                generated_case_id, field="case_id_factory result"
                            )
                        except NormalizedEventCommandError as exc:
                            raise RuntimeError("case_id_factory returned an invalid ULID") from exc
                        case_params = {
                            **base_params,
                            "recovery_case_id": generated_case_id,
                            "logical_order_id": target.logical_order_id,
                            "currency": target.currency,
                            "amount_due_minor": target.amount_due_minor,
                        }
                        cursor.execute(_INSERT_OBSERVING_CASE, case_params)
                        inserted_case = cursor.fetchone()
                        if inserted_case is not None:
                            recovery_case_id, recovery_case_created = _case_row(
                                inserted_case, created=True
                            )
                        else:
                            cursor.execute(_LOAD_OPEN_CASE, case_params)
                            recovery_case_id, recovery_case_created = _case_row(
                                cursor.fetchone(), created=False
                            )

            if enrichment is not None:
                enrichment_payload = encode_enrich_failed_payment_command(enrichment)
                cursor.execute(
                    _INSERT_PAYMENT_ENRICHMENT,
                    {
                        **base_params,
                        "enrichment_job_id": _ulid(
                            self._enrichment_job_id_factory(),
                            field="enrichment_job_id_factory result",
                        ),
                        "enrichment_provider_payment_id": enrichment.provider_payment_id,
                        "enrichment_command_type": ENRICH_FAILED_PAYMENT_COMMAND_TYPE,
                        "enrichment_schema_version": ENRICH_FAILED_PAYMENT_SCHEMA_VERSION,
                        "enrichment_payload": canonical_enrichment_payload(enrichment_payload),
                        "enrichment_idempotency_key": enrichment.idempotency_key,
                    },
                )
                inserted = cursor.fetchone()
                if inserted is not None and (
                    len(inserted) != 1
                    or not isinstance(inserted[0], str)
                    or not _ULID_RE.fullmatch(inserted[0])
                ):
                    raise RuntimeError("payment enrichment enqueue returned an invalid id")

            self._recheck_fence(cursor, base_params)
            if disposition is ProjectionDisposition.RETRY_SCHEDULED:
                self._defer_inbox(cursor, base_params, reason_code=reason_code)
            else:
                self._settle_inbox(
                    cursor,
                    base_params,
                    disposition=disposition,
                    reason_code=reason_code,
                )
            return NormalizedEventProjectionResult(
                disposition=disposition,
                provider_event_record_id=command.provider_event_record_id,
                recovery_case_id=recovery_case_id,
                recovery_case_created=recovery_case_created,
                reason_code=reason_code,
            )

    @staticmethod
    def _start_inbox(
        cursor: _Cursor,
        event: _PersistedEvent,
        params: Mapping[str, object],
    ) -> bool:
        cursor.execute(_START_INBOX_PROCESSING, params)
        started = cursor.fetchone()
        if started is not None:
            if len(started) != 2 or started[0] != "PROCESSING" or type(started[1]) is not int:
                raise RuntimeError("inbox processing claim returned an unexpected row")
            return True
        if event.attempt_count < event.max_attempts:
            raise NormalizedEventBusy("inbox processing claim was not acquired")
        cursor.execute(_DEAD_LETTER_EXHAUSTED_INBOX, params)
        dead_lettered = _first_column(cursor.fetchone(), operation="exhausted inbox settlement")
        if dead_lettered != "DEAD_LETTER":
            raise RuntimeError("exhausted inbox did not enter DEAD_LETTER")
        return False

    @staticmethod
    def _recheck_fence(cursor: _Cursor, params: Mapping[str, object]) -> None:
        cursor.execute(_RECHECK_OUTBOX_FENCE, params)
        if _first_column(cursor.fetchone(), operation="outbox fence recheck") is not True:
            raise NormalizedEventFenceLost("normalized event outbox lease expired before commit")

    @staticmethod
    def _settle_inbox(
        cursor: _Cursor,
        params: Mapping[str, object],
        *,
        disposition: ProjectionDisposition,
        reason_code: str | None,
    ) -> None:
        if disposition not in {
            ProjectionDisposition.PROCESSED,
            ProjectionDisposition.IGNORED,
        }:
            raise ValueError("only processed or ignored inbox rows use normal settlement")
        cursor.execute(
            _SETTLE_INBOX,
            {
                **params,
                "inbox_status": disposition.value,
                "reason_code": reason_code,
            },
        )
        if _first_column(cursor.fetchone(), operation="inbox settlement") != disposition.value:
            raise RuntimeError("inbox settlement returned an unexpected status")

    @staticmethod
    def _defer_inbox(
        cursor: _Cursor,
        params: Mapping[str, object],
        *,
        reason_code: str | None,
    ) -> None:
        if reason_code is None:
            raise ValueError("deferred inbox rows require a reason code")
        cursor.execute(_DEFER_INBOX, {**params, "reason_code": reason_code})
        if (
            _first_column(cursor.fetchone(), operation="inbox deferral")
            != ProjectionDisposition.RETRY_SCHEDULED.value
        ):
            raise RuntimeError("inbox deferral returned an unexpected status")


class ProcessNormalizedProviderEventHandler:
    """OutboxWorker-compatible, fail-closed normalized-event handler."""

    def __init__(self, repository: NormalizedEventRepository) -> None:
        if not callable(getattr(repository, "project", None)):
            raise TypeError("repository must provide project(command, claim=...)")
        self._repository = repository

    def __call__(self, claimed: ClaimedOutboxCommand) -> HandlerResult:
        try:
            command = decode_process_normalized_provider_event_command(claimed)
        except NormalizedEventCommandError:
            return HandlerResult.dead_letter("invalid_normalized_event_command")
        try:
            result = self._repository.project(command, claim=claimed)
        except (NormalizedEventBindingError, NormalizedEventEvidenceError):
            return HandlerResult.dead_letter("invalid_normalized_event_evidence")
        except NormalizedEventFenceLost:
            return HandlerResult.retry_safely(
                "normalized_event_fence_lost",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        except NormalizedEventBusy:
            return HandlerResult.retry_safely(
                "normalized_event_inbox_busy",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        if not isinstance(result, NormalizedEventProjectionResult):
            return HandlerResult.dead_letter("invalid_normalized_event_projection_result")
        if result.disposition is ProjectionDisposition.DEAD_LETTER:
            return HandlerResult.dead_letter(
                result.reason_code or "normalized_event_inbox_dead_lettered"
            )
        if result.disposition is ProjectionDisposition.RETRY_SCHEDULED:
            return HandlerResult.retry_safely(
                result.reason_code or "normalized_event_projection_deferred",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        return HandlerResult.succeeded(result.completion_reference)


__all__ = [
    "MAX_NORMALIZED_EVENT_COMMAND_BYTES",
    "PROCESS_NORMALIZED_PROVIDER_EVENT",
    "PROCESS_NORMALIZED_PROVIDER_EVENT_SCHEMA_VERSION",
    "NormalizedEventBindingError",
    "NormalizedEventBusy",
    "NormalizedEventCommandError",
    "NormalizedEventEvidenceError",
    "NormalizedEventFenceLost",
    "NormalizedEventProjectionResult",
    "NormalizedEventRepository",
    "PostgresNormalizedEventRepository",
    "ProcessNormalizedProviderEventCommand",
    "ProcessNormalizedProviderEventHandler",
    "ProjectionDisposition",
    "decode_process_normalized_provider_event_command",
]
