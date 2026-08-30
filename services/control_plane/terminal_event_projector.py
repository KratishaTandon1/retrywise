"""Strict terminal-money projection for canonical Razorpay webhook evidence.

This is a deliberately separate foundation for the shared
``PROCESS_NORMALIZED_PROVIDER_EVENT`` command.  It handles only three signals
whose signed canonical payload can prove money movement without a provider
read: an exactly mapped original ``payment.captured`` and an exactly bound
recovery ``payment_link.paid`` or ``payment_link.partially_paid``.

The module is not a runtime router.  A future worker composition must dispatch
``payment.failed`` to :mod:`normalized_event_projector` and the supported
terminal types here.  Payment-Link cancellation and expiry stay as immutable
provider evidence until case-policy and late-paid lifecycle support exists.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Protocol, cast

from ...packages.razorpay import make_recovery_reference_id
from .normalized_event_projector import (
    _DEAD_LETTER_EXHAUSTED_INBOX,
    _FIND_REUSED_BODY,
    _LOAD_EVENT_AND_INBOX,
    _LOCK_OUTBOX_FENCE,
    _RECHECK_OUTBOX_FENCE,
    _SETTLE_INBOX,
    _START_INBOX_PROCESSING,
    NormalizedEventBindingError,
    NormalizedEventBusy,
    NormalizedEventCommandError,
    NormalizedEventEvidenceError,
    NormalizedEventFenceLost,
    NormalizedEventProjectionResult,
    ProcessNormalizedProviderEventCommand,
    ProjectionDisposition,
    _canonical_integer,
    _canonical_payload_bytes,
    _canonical_text,
    _new_ulid,
    _optional_canonical_text,
    _persisted_event,
    _PersistedEvent,
    _validate_canonical_envelope,
    _validate_event_binding,
    decode_process_normalized_provider_event_command,
)
from .outbox import RetryMode
from .outbox_worker import HandlerResult
from .postgres_connection import PostgresConnectionPolicy
from .postgres_outbox import ClaimedOutboxCommand

SUPPORTED_TERMINAL_EVENT_TYPES: Final = frozenset(
    {
        "payment.captured",
        "payment_link.paid",
        "payment_link.partially_paid",
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
_PAYMENT_LINK_FIELDS = frozenset(
    {
        "accept_partial",
        "amount",
        "amount_paid",
        "cancelled_at",
        "created_at",
        "currency",
        "entity",
        "expire_by",
        "expired_at",
        "id",
        "order_id",
        "reference_id",
        "status",
        "upi_link",
    }
)
_ORDER_FIELDS = frozenset(
    {
        "amount",
        "amount_due",
        "amount_paid",
        "attempts",
        "created_at",
        "currency",
        "entity",
        "id",
        "status",
    }
)
_REQUIRED_CAPTURE_FIELDS = frozenset({"amount", "captured", "currency", "id", "order_id", "status"})
_REQUIRED_LINK_FIELDS = frozenset(
    {
        "accept_partial",
        "amount",
        "amount_paid",
        "currency",
        "id",
        "order_id",
        "reference_id",
        "status",
    }
)
_REQUIRED_RELATED_PAYMENT_FIELDS = frozenset(
    {"amount", "captured", "currency", "id", "order_id", "status"}
)
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_PAYMENT_METHOD_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_MAX_SIGNED_BIGINT = (1 << 63) - 1
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
_CAPTURE_ACCEPTING_PAYMENT_STATES = frozenset(
    {"UNKNOWN", "CREATED", "AUTHORIZED", "FAILED", "CAPTURED"}
)
_LINK_PAID_ACCEPTING_STATES = frozenset(
    {
        "ISSUED",
        "ACTIVE",
        "CANCEL_PENDING",
        "PARTIALLY_PAID",
        "PAID",
        "CANCELLED",
        "EXPIRED",
    }
)
_LINK_PARTIAL_ACCEPTING_STATES = frozenset(
    {"ISSUED", "ACTIVE", "CANCEL_PENDING", "PARTIALLY_PAID", "CANCELLED", "EXPIRED"}
)

_LOAD_CAPTURE_TARGET = """
SELECT
    payment.id::text,
    payment.logical_order_id::text,
    payment.provider_payment_id,
    payment.provider_order_id,
    payment.status::text,
    payment.amount_minor,
    payment.currency::text,
    payment.captured_minor,
    payment.refunded_minor,
    payment.payment_method,
    payment.provider_snapshot_at,
    logical_order.original_provider_order_id,
    logical_order.amount_due_minor,
    logical_order.currency::text,
    logical_order.canonical_truth::text,
    logical_order.captured_total_minor,
    logical_order.refunded_total_minor,
    logical_order.provider_snapshot_at,
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

_LOAD_CAPTURE_ORDER = """
SELECT
    logical_order.id::text,
    logical_order.original_provider_order_id,
    logical_order.amount_due_minor,
    logical_order.currency::text,
    logical_order.canonical_truth::text,
    logical_order.mapping_status::text
FROM retrywise.logical_orders AS logical_order
WHERE logical_order.merchant_id = %(merchant_id)s
  AND logical_order.provider_account_id = %(provider_account_id)s
  AND logical_order.original_provider_order_id = %(provider_order_id)s
FOR UPDATE OF logical_order
"""

_INSERT_DISCOVERED_CAPTURE_PAYMENT = """
INSERT INTO retrywise.provider_payments (
    id,
    merchant_id,
    provider_account_id,
    logical_order_id,
    provider_payment_id,
    provider_order_id,
    status,
    amount_minor,
    currency,
    captured_minor,
    refunded_minor,
    payment_method,
    instrument_context,
    error_facts,
    provider_snapshot_at,
    created_at,
    updated_at
) VALUES (
    %(payment_record_id)s,
    %(merchant_id)s,
    %(provider_account_id)s,
    %(logical_order_id)s,
    %(provider_payment_id)s,
    %(provider_order_id)s,
    'UNKNOWN',
    %(amount_minor)s,
    %(currency)s,
    0,
    0,
    %(payment_method)s,
    '{}'::jsonb,
    %(discovery_facts)s::jsonb,
    %(provider_occurred_at)s,
    clock_timestamp(),
    clock_timestamp()
)
ON CONFLICT (provider_account_id, provider_payment_id) DO NOTHING
RETURNING id::text
"""

_LOAD_LINK_TARGET = """
SELECT
    instrument.id::text,
    instrument.recovery_case_id::text,
    instrument.logical_order_id::text,
    instrument.provider_account_id::text,
    instrument.provider_payment_link_id,
    instrument.provider_order_id,
    instrument.provider_payment_id,
    instrument.reference_id,
    instrument.amount_minor,
    instrument.currency::text,
    instrument.status::text,
    instrument.accept_partial,
    instrument.collected_minor,
    instrument.refunded_minor,
    instrument.last_reconciled_at,
    recovery_case.state::text,
    recovery_case.version,
    logical_order.original_provider_order_id,
    logical_order.amount_due_minor,
    logical_order.currency::text,
    logical_order.canonical_truth::text,
    logical_order.captured_total_minor,
    logical_order.refunded_total_minor,
    logical_order.provider_snapshot_at,
    logical_order.mapping_status::text
FROM retrywise.recovery_instruments AS instrument
JOIN retrywise.recovery_cases AS recovery_case
  ON recovery_case.merchant_id = instrument.merchant_id
 AND recovery_case.id = instrument.recovery_case_id
 AND recovery_case.logical_order_id = instrument.logical_order_id
 AND recovery_case.provider_account_id = instrument.provider_account_id
 AND recovery_case.currency = instrument.currency
 AND recovery_case.amount_due_snapshot_minor = instrument.amount_minor
JOIN retrywise.logical_orders AS logical_order
  ON logical_order.merchant_id = instrument.merchant_id
 AND logical_order.id = instrument.logical_order_id
 AND logical_order.provider_account_id = instrument.provider_account_id
 AND logical_order.currency = instrument.currency
 AND logical_order.amount_due_minor = instrument.amount_minor
WHERE instrument.merchant_id = %(merchant_id)s
  AND instrument.provider_account_id = %(provider_account_id)s
  AND instrument.provider_payment_link_id = %(provider_payment_link_id)s
FOR UPDATE OF instrument, recovery_case, logical_order
"""

_LOCK_ORIGINAL_PATH_PAYMENTS = """
SELECT
    payment.id::text,
    payment.provider_payment_id,
    payment.provider_order_id,
    payment.status::text,
    payment.amount_minor,
    payment.currency::text,
    payment.captured_minor,
    payment.refunded_minor
FROM retrywise.provider_payments AS payment
WHERE payment.merchant_id = %(merchant_id)s
  AND payment.provider_account_id = %(provider_account_id)s
  AND payment.logical_order_id = %(logical_order_id)s
  AND payment.provider_order_id = %(original_provider_order_id)s
ORDER BY payment.id
FOR UPDATE OF payment
"""

_LOCK_ORDER_INSTRUMENTS = """
SELECT
    instrument.id::text,
    instrument.recovery_case_id::text,
    instrument.status::text,
    instrument.amount_minor,
    instrument.currency::text,
    instrument.collected_minor,
    instrument.refunded_minor,
    instrument.provider_payment_link_id,
    instrument.provider_order_id,
    instrument.provider_payment_id,
    instrument.reference_id,
    instrument.accept_partial,
    instrument.last_reconciled_at
FROM retrywise.recovery_instruments AS instrument
WHERE instrument.merchant_id = %(merchant_id)s
  AND instrument.provider_account_id = %(provider_account_id)s
  AND instrument.logical_order_id = %(logical_order_id)s
  AND instrument.currency = %(currency)s
ORDER BY instrument.id
FOR UPDATE OF instrument
"""

_LOCK_ORDER_CASES = """
SELECT
    recovery_case.id::text,
    recovery_case.state::text,
    recovery_case.version,
    recovery_case.terminal_reason_code,
    recovery_case.terminal_at
FROM retrywise.recovery_cases AS recovery_case
WHERE recovery_case.merchant_id = %(merchant_id)s
  AND recovery_case.provider_account_id = %(provider_account_id)s
  AND recovery_case.logical_order_id = %(logical_order_id)s
  AND recovery_case.currency = %(currency)s
ORDER BY recovery_case.id
FOR UPDATE OF recovery_case
"""

_PROJECT_CAPTURED_PAYMENT = """
UPDATE retrywise.provider_payments
SET status = 'CAPTURED',
    captured_minor = %(captured_minor)s,
    payment_method = COALESCE(payment_method, %(payment_method)s),
    error_facts = error_facts || %(projection_facts)s::jsonb,
    provider_snapshot_at = GREATEST(provider_snapshot_at, %(provider_occurred_at)s),
    updated_at = clock_timestamp()
WHERE id = %(payment_record_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND logical_order_id = %(logical_order_id)s
  AND provider_payment_id = %(provider_payment_id)s
  AND provider_order_id = %(provider_order_id)s
  AND amount_minor = %(amount_minor)s
  AND currency = %(currency)s::retrywise.currency_code
  AND status = %(expected_payment_status)s::retrywise.provider_payment_status
  AND captured_minor = %(expected_captured_minor)s
  AND refunded_minor = 0
RETURNING status::text
"""

_PROJECT_RECOVERY_INSTRUMENT = """
UPDATE retrywise.recovery_instruments
SET status = %(new_instrument_status)s::retrywise.recovery_instrument_status,
    provider_order_id = COALESCE(provider_order_id, %(provider_order_id)s),
    provider_payment_id = COALESCE(provider_payment_id, %(provider_payment_id)s),
    collected_minor = %(collected_minor)s,
    last_provider_status = %(provider_status)s,
    reconciliation_status = 'CONFIRMED',
    last_reconciled_at = clock_timestamp(),
    updated_at = clock_timestamp()
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND recovery_case_id = %(recovery_case_id)s
  AND logical_order_id = %(logical_order_id)s
  AND provider_payment_link_id = %(provider_payment_link_id)s
  AND reference_id = %(reference_id)s
  AND amount_minor = %(amount_minor)s
  AND currency = %(currency)s::retrywise.currency_code
  AND status = %(expected_instrument_status)s::retrywise.recovery_instrument_status
  AND collected_minor = %(expected_collected_minor)s
  AND refunded_minor = %(expected_refunded_minor)s
  AND accept_partial = FALSE
  AND (provider_order_id IS NULL OR provider_order_id = %(provider_order_id)s)
  AND (provider_payment_id IS NULL OR provider_payment_id = %(provider_payment_id)s)
RETURNING status::text
"""

_PROJECT_ORDER_TRUTH = """
UPDATE retrywise.logical_orders
SET captured_total_minor = %(captured_total_minor)s,
    canonical_truth = %(canonical_truth)s::retrywise.canonical_payment_truth,
    truth_version = truth_version + 1,
    provider_snapshot_at = GREATEST(
        COALESCE(provider_snapshot_at, %(provider_occurred_at)s),
        %(provider_occurred_at)s
    ),
    updated_at = clock_timestamp()
WHERE id = %(logical_order_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND amount_due_minor = %(amount_due_minor)s
  AND currency = %(currency)s::retrywise.currency_code
  AND canonical_truth = %(expected_canonical_truth)s::retrywise.canonical_payment_truth
  AND captured_total_minor = %(expected_captured_total_minor)s
  AND refunded_total_minor = %(expected_refunded_total_minor)s
RETURNING canonical_truth::text
"""

_PROJECT_CASE_TERMINAL = """
UPDATE retrywise.recovery_cases
SET state = %(new_case_state)s::retrywise.recovery_case_state,
    version = version + 1,
    terminal_reason_code = %(terminal_reason_code)s,
    terminal_at = clock_timestamp(),
    updated_at = clock_timestamp()
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND logical_order_id = %(logical_order_id)s
  AND currency = %(currency)s::retrywise.currency_code
  AND state = %(expected_case_state)s::retrywise.recovery_case_state
  AND version = %(expected_case_version)s
RETURNING state::text
"""


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


@dataclass(frozen=True, slots=True)
class _CapturedPayment:
    provider_payment_id: str
    provider_order_id: str
    amount_minor: int
    currency: str
    payment_method: str | None


@dataclass(frozen=True, slots=True)
class _PaymentLinkCollection:
    event_type: str
    provider_payment_link_id: str
    provider_order_id: str
    provider_payment_id: str
    reference_id: str
    amount_minor: int
    amount_paid_minor: int
    currency: str

    @property
    def instrument_status(self) -> str:
        return "PAID" if self.event_type == "payment_link.paid" else "PARTIALLY_PAID"


@dataclass(frozen=True, slots=True)
class _CaptureTarget:
    payment_record_id: str
    logical_order_id: str
    provider_payment_id: str
    provider_order_id: str | None
    payment_status: str
    amount_minor: int
    currency: str
    captured_minor: int
    refunded_minor: int
    payment_method: str | None
    payment_snapshot_at: datetime
    original_provider_order_id: str | None
    amount_due_minor: int
    order_currency: str
    canonical_truth: str
    captured_total_minor: int
    refunded_total_minor: int
    order_snapshot_at: datetime | None
    mapping_status: str


@dataclass(frozen=True, slots=True)
class _LinkTarget:
    instrument_id: str
    recovery_case_id: str
    logical_order_id: str
    provider_account_id: str
    provider_payment_link_id: str | None
    provider_order_id: str | None
    provider_payment_id: str | None
    reference_id: str
    amount_minor: int
    currency: str
    instrument_status: str
    accept_partial: bool
    collected_minor: int
    refunded_minor: int
    last_reconciled_at: datetime | None
    case_state: str
    case_version: int
    original_provider_order_id: str | None
    amount_due_minor: int
    order_currency: str
    canonical_truth: str
    captured_total_minor: int
    refunded_total_minor: int
    order_snapshot_at: datetime | None
    mapping_status: str


@dataclass(frozen=True, slots=True)
class _PathPayment:
    payment_record_id: str
    provider_payment_id: str
    provider_order_id: str | None
    status: str
    amount_minor: int
    currency: str
    captured_minor: int
    refunded_minor: int


@dataclass(frozen=True, slots=True)
class _PathInstrument:
    instrument_id: str
    recovery_case_id: str
    status: str
    amount_minor: int
    currency: str
    collected_minor: int
    refunded_minor: int
    provider_payment_link_id: str | None
    provider_order_id: str | None
    provider_payment_id: str | None
    reference_id: str
    accept_partial: bool
    last_reconciled_at: datetime | None


@dataclass(frozen=True, slots=True)
class _Case:
    recovery_case_id: str
    state: str
    version: int
    terminal_reason_code: str | None
    terminal_at: datetime | None


@dataclass(frozen=True, slots=True)
class _CaseTransition:
    recovery_case_id: str
    expected_state: str
    expected_version: int
    new_state: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class _CapturePlan:
    target: _CaptureTarget
    payment: _CapturedPayment
    captured_total_minor: int
    canonical_truth: str
    case_transitions: tuple[_CaseTransition, ...]


@dataclass(frozen=True, slots=True)
class _LinkPlan:
    target: _LinkTarget
    collection: _PaymentLinkCollection
    captured_total_minor: int
    canonical_truth: str
    case_transition: _CaseTransition | None


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresTerminalEventRepository"),
        )

    return connect


def _first_column(row: Sequence[object] | None, *, operation: str) -> object:
    if row is None or len(row) != 1:
        raise RuntimeError(f"{operation} returned an unexpected row shape")
    return row[0]


def _optional_timestamp(value: object, *, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise NormalizedEventEvidenceError(f"{field} must be a timezone-aware timestamp")
    return value


def _bounded_money(value: object, *, field: str, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    return _canonical_integer(value, field=field, minimum=minimum)


def _currency(value: object, *, field: str) -> str:
    text = _canonical_text(value, field=field, maximum=3)
    if not _CURRENCY_RE.fullmatch(text):
        raise NormalizedEventEvidenceError(f"{field} must be uppercase ISO currency text")
    return text


def _allowed_resource(
    resource: Mapping[str, object],
    *,
    required: frozenset[str],
    allowed: frozenset[str],
    field: str,
) -> None:
    present = frozenset(resource)
    if not present >= required or not present <= allowed:
        raise NormalizedEventEvidenceError(f"{field} fields are not allowed")


def _validate_optional_entity(resource: Mapping[str, object], *, expected: str, field: str) -> None:
    entity = resource.get("entity")
    if entity is not None and entity != expected:
        raise NormalizedEventEvidenceError(f"{field} entity discriminator is inconsistent")


def _validate_optional_epoch(resource: Mapping[str, object], key: str, *, field: str) -> None:
    value = resource.get(key)
    if value is not None:
        _canonical_integer(value, field=f"{field}.{key}")


def _captured_payment(canonical: Mapping[str, object]) -> _CapturedPayment:
    if (
        canonical["event_name"] != "payment.captured"
        or canonical["event_type"] != "payment.captured"
        or canonical["resource_type"] != "payment"
    ):
        raise NormalizedEventEvidenceError("capture decoder received another event type")
    resource = cast(Mapping[str, object], canonical["resource"])
    _allowed_resource(
        resource,
        required=_REQUIRED_CAPTURE_FIELDS,
        allowed=_PAYMENT_FIELDS,
        field="payment",
    )
    _validate_optional_entity(resource, expected="payment", field="payment")
    payment_id = _canonical_text(resource["id"], field="payment.id", maximum=128)
    order_id = _canonical_text(resource["order_id"], field="payment.order_id", maximum=128)
    if resource["status"] != "captured" or resource["captured"] is not True:
        raise NormalizedEventEvidenceError("payment.captured requires captured status and flag")
    amount = _bounded_money(resource["amount"], field="payment.amount", positive=True)
    currency = _currency(resource["currency"], field="payment.currency")
    amount_refunded = resource.get("amount_refunded")
    if (
        amount_refunded is not None
        and _bounded_money(amount_refunded, field="payment.amount_refunded") != 0
    ):
        raise NormalizedEventEvidenceError("refunded money is outside capture projection v1")
    _validate_optional_epoch(resource, "created_at", field="payment")
    method = _optional_canonical_text(resource.get("method"), field="payment.method", maximum=50)
    if method is not None and not _PAYMENT_METHOD_RE.fullmatch(method):
        raise NormalizedEventEvidenceError("payment method is not a canonical identifier")
    _optional_canonical_text(resource.get("invoice_id"), field="payment.invoice_id", maximum=128)
    _optional_canonical_text(
        resource.get("refund_status"), field="payment.refund_status", maximum=50
    )
    related = cast(Mapping[str, object], canonical["related_resources"])
    if frozenset(related) - {"payment", "order"}:
        raise NormalizedEventEvidenceError("payment capture has unexpected related resources")
    if related.get("payment") != resource:
        raise NormalizedEventEvidenceError("related payment disagrees with primary resource")
    return _CapturedPayment(
        provider_payment_id=payment_id,
        provider_order_id=order_id,
        amount_minor=amount,
        currency=currency,
        payment_method=method,
    )


def _payment_link_collection(canonical: Mapping[str, object]) -> _PaymentLinkCollection:
    event_type = canonical["event_type"]
    if event_type not in {"payment_link.paid", "payment_link.partially_paid"}:
        raise NormalizedEventEvidenceError("payment-link decoder received another event type")
    if canonical["event_name"] != event_type or canonical["resource_type"] != "payment_link":
        raise NormalizedEventEvidenceError("canonical payment-link event binding is inconsistent")
    resource = cast(Mapping[str, object], canonical["resource"])
    _allowed_resource(
        resource,
        required=_REQUIRED_LINK_FIELDS,
        allowed=_PAYMENT_LINK_FIELDS,
        field="payment_link",
    )
    _validate_optional_entity(resource, expected="payment_link", field="payment_link")
    expected_status = "paid" if event_type == "payment_link.paid" else "partially_paid"
    if resource["status"] != expected_status:
        raise NormalizedEventEvidenceError("payment-link status disagrees with event type")
    if resource["accept_partial"] is not False:
        raise NormalizedEventEvidenceError("RetryWise recovery links must disable partial payment")
    upi_link = resource.get("upi_link")
    if upi_link not in {None, False}:
        raise NormalizedEventEvidenceError("UPI Payment Links are outside the Test Mode contract")
    link_id = _canonical_text(resource["id"], field="payment_link.id", maximum=128)
    order_id = _canonical_text(resource["order_id"], field="payment_link.order_id", maximum=128)
    reference_id = _canonical_text(
        resource["reference_id"], field="payment_link.reference_id", maximum=40
    )
    amount = _bounded_money(resource["amount"], field="payment_link.amount", positive=True)
    amount_paid = _bounded_money(resource["amount_paid"], field="payment_link.amount_paid")
    currency = _currency(resource["currency"], field="payment_link.currency")
    if event_type == "payment_link.paid" and amount_paid != amount:
        raise NormalizedEventEvidenceError("paid Payment Link must carry the full amount_paid")
    if event_type == "payment_link.partially_paid" and not 0 < amount_paid < amount:
        raise NormalizedEventEvidenceError("partial Payment Link money must be strictly bounded")
    for key in ("created_at", "expire_by", "cancelled_at", "expired_at"):
        _validate_optional_epoch(resource, key, field="payment_link")

    related = cast(Mapping[str, object], canonical["related_resources"])
    if frozenset(related) - {"payment_link", "payment", "order"}:
        raise NormalizedEventEvidenceError("payment-link event has unexpected related resources")
    if related.get("payment_link") != resource:
        raise NormalizedEventEvidenceError("related Payment Link disagrees with primary resource")
    payment_resource = related.get("payment")
    if not isinstance(payment_resource, Mapping):
        raise NormalizedEventEvidenceError("payment-link money event requires related payment")
    _allowed_resource(
        payment_resource,
        required=_REQUIRED_RELATED_PAYMENT_FIELDS,
        allowed=_PAYMENT_FIELDS,
        field="related payment",
    )
    _validate_optional_entity(payment_resource, expected="payment", field="related payment")
    payment_id = _canonical_text(payment_resource["id"], field="related_payment.id", maximum=128)
    if payment_resource["status"] != "captured" or payment_resource["captured"] is not True:
        raise NormalizedEventEvidenceError("related recovery payment must be captured")
    if payment_resource["order_id"] != order_id:
        raise NormalizedEventEvidenceError("related recovery payment order is inconsistent")
    if _currency(payment_resource["currency"], field="related_payment.currency") != currency:
        raise NormalizedEventEvidenceError("related recovery payment currency is inconsistent")
    related_amount = _bounded_money(
        payment_resource["amount"], field="related_payment.amount", positive=True
    )
    if related_amount > amount_paid:
        raise NormalizedEventEvidenceError("related payment exceeds cumulative link collection")
    related_refunded = payment_resource.get("amount_refunded")
    if (
        related_refunded is not None
        and _bounded_money(related_refunded, field="related_payment.amount_refunded") != 0
    ):
        raise NormalizedEventEvidenceError("refunded recovery money is outside projection v1")

    order_resource_value = related.get("order")
    if order_resource_value is not None:
        if not isinstance(order_resource_value, Mapping) or not all(
            isinstance(key, str) for key in order_resource_value
        ):
            raise NormalizedEventEvidenceError("related order must be an object")
        order_resource = cast(Mapping[str, object], order_resource_value)
        _allowed_resource(
            order_resource,
            required=frozenset({"amount", "amount_paid", "currency", "id"}),
            allowed=_ORDER_FIELDS,
            field="related order",
        )
        _validate_optional_entity(order_resource, expected="order", field="related order")
        if (
            order_resource["id"] != order_id
            or _bounded_money(order_resource["amount"], field="related_order.amount") != amount
            or _bounded_money(order_resource["amount_paid"], field="related_order.amount_paid")
            != amount_paid
            or _currency(order_resource["currency"], field="related_order.currency") != currency
        ):
            raise NormalizedEventEvidenceError("related recovery order money is inconsistent")

    return _PaymentLinkCollection(
        event_type=event_type,
        provider_payment_link_id=link_id,
        provider_order_id=order_id,
        provider_payment_id=payment_id,
        reference_id=reference_id,
        amount_minor=amount,
        amount_paid_minor=amount_paid,
        currency=currency,
    )


def _capture_target(row: Sequence[object] | None) -> _CaptureTarget | None:
    if row is None:
        return None
    if len(row) != 19:
        raise RuntimeError("capture mapping lookup returned an unexpected row shape")
    if not all(isinstance(row[index], str) for index in (0, 1, 2, 4, 6, 13, 14, 18)):
        raise NormalizedEventEvidenceError("capture mapping contains non-text identity or state")
    for index in (3, 9, 11):
        if row[index] is not None and not isinstance(row[index], str):
            raise NormalizedEventEvidenceError("capture mapping contains malformed optional text")
    if not all(type(row[index]) is int for index in (5, 7, 8, 12, 15, 16)):
        raise NormalizedEventEvidenceError("capture mapping contains non-integer money")
    payment_snapshot = _optional_timestamp(row[10], field="payment snapshot")
    if payment_snapshot is None:
        raise NormalizedEventEvidenceError("payment snapshot is required")
    return _CaptureTarget(
        payment_record_id=cast(str, row[0]),
        logical_order_id=cast(str, row[1]),
        provider_payment_id=cast(str, row[2]),
        provider_order_id=cast(str | None, row[3]),
        payment_status=cast(str, row[4]),
        amount_minor=cast(int, row[5]),
        currency=cast(str, row[6]),
        captured_minor=cast(int, row[7]),
        refunded_minor=cast(int, row[8]),
        payment_method=cast(str | None, row[9]),
        payment_snapshot_at=payment_snapshot,
        original_provider_order_id=cast(str | None, row[11]),
        amount_due_minor=cast(int, row[12]),
        order_currency=cast(str, row[13]),
        canonical_truth=cast(str, row[14]),
        captured_total_minor=cast(int, row[15]),
        refunded_total_minor=cast(int, row[16]),
        order_snapshot_at=_optional_timestamp(row[17], field="order snapshot"),
        mapping_status=cast(str, row[18]),
    )


def _link_target(row: Sequence[object] | None) -> _LinkTarget | None:
    if row is None:
        return None
    if len(row) != 25:
        raise RuntimeError("Payment Link mapping lookup returned an unexpected row shape")
    if not all(isinstance(row[index], str) for index in (0, 1, 2, 3, 7, 9, 10, 15, 19, 20, 24)):
        raise NormalizedEventEvidenceError(
            "Payment Link mapping contains non-text identity or state"
        )
    for index in (4, 5, 6, 17):
        if row[index] is not None and not isinstance(row[index], str):
            raise NormalizedEventEvidenceError("Payment Link mapping has malformed optional text")
    if not all(type(row[index]) is int for index in (8, 12, 13, 16, 18, 21, 22)):
        raise NormalizedEventEvidenceError("Payment Link mapping contains non-integer state")
    if type(row[11]) is not bool:
        raise NormalizedEventEvidenceError("Payment Link accept_partial is not boolean")
    return _LinkTarget(
        instrument_id=cast(str, row[0]),
        recovery_case_id=cast(str, row[1]),
        logical_order_id=cast(str, row[2]),
        provider_account_id=cast(str, row[3]),
        provider_payment_link_id=cast(str | None, row[4]),
        provider_order_id=cast(str | None, row[5]),
        provider_payment_id=cast(str | None, row[6]),
        reference_id=cast(str, row[7]),
        amount_minor=cast(int, row[8]),
        currency=cast(str, row[9]),
        instrument_status=cast(str, row[10]),
        accept_partial=row[11],
        collected_minor=cast(int, row[12]),
        refunded_minor=cast(int, row[13]),
        last_reconciled_at=_optional_timestamp(row[14], field="instrument reconciliation"),
        case_state=cast(str, row[15]),
        case_version=cast(int, row[16]),
        original_provider_order_id=cast(str | None, row[17]),
        amount_due_minor=cast(int, row[18]),
        order_currency=cast(str, row[19]),
        canonical_truth=cast(str, row[20]),
        captured_total_minor=cast(int, row[21]),
        refunded_total_minor=cast(int, row[22]),
        order_snapshot_at=_optional_timestamp(row[23], field="order snapshot"),
        mapping_status=cast(str, row[24]),
    )


def _path_payment(row: Sequence[object]) -> _PathPayment:
    if len(row) != 8 or not all(isinstance(row[index], str) for index in (0, 1, 3, 5)):
        raise NormalizedEventEvidenceError("original path payment row is malformed")
    if row[2] is not None and not isinstance(row[2], str):
        raise NormalizedEventEvidenceError("original path order id is malformed")
    if not all(type(row[index]) is int for index in (4, 6, 7)):
        raise NormalizedEventEvidenceError("original path payment money is malformed")
    return _PathPayment(
        payment_record_id=cast(str, row[0]),
        provider_payment_id=cast(str, row[1]),
        provider_order_id=row[2],
        status=cast(str, row[3]),
        amount_minor=cast(int, row[4]),
        currency=cast(str, row[5]),
        captured_minor=cast(int, row[6]),
        refunded_minor=cast(int, row[7]),
    )


def _path_instrument(row: Sequence[object]) -> _PathInstrument:
    if len(row) != 13 or not all(isinstance(row[index], str) for index in (0, 1, 2, 4, 10)):
        raise NormalizedEventEvidenceError("recovery path instrument row is malformed")
    if not all(type(row[index]) is int for index in (3, 5, 6)) or type(row[11]) is not bool:
        raise NormalizedEventEvidenceError("recovery path instrument money is malformed")
    for index in (7, 8, 9):
        if row[index] is not None and not isinstance(row[index], str):
            raise NormalizedEventEvidenceError("recovery path provider id is malformed")
    return _PathInstrument(
        instrument_id=cast(str, row[0]),
        recovery_case_id=cast(str, row[1]),
        status=cast(str, row[2]),
        amount_minor=cast(int, row[3]),
        currency=cast(str, row[4]),
        collected_minor=cast(int, row[5]),
        refunded_minor=cast(int, row[6]),
        provider_payment_link_id=cast(str | None, row[7]),
        provider_order_id=cast(str | None, row[8]),
        provider_payment_id=cast(str | None, row[9]),
        reference_id=cast(str, row[10]),
        accept_partial=row[11],
        last_reconciled_at=_optional_timestamp(row[12], field="instrument reconciliation"),
    )


def _case(row: Sequence[object]) -> _Case:
    if len(row) != 5 or not isinstance(row[0], str) or not isinstance(row[1], str):
        raise NormalizedEventEvidenceError("recovery case row is malformed")
    if type(row[2]) is not int:
        raise NormalizedEventEvidenceError("recovery case version is malformed")
    if row[3] is not None and not isinstance(row[3], str):
        raise NormalizedEventEvidenceError("recovery case terminal reason is malformed")
    return _Case(
        recovery_case_id=row[0],
        state=row[1],
        version=row[2],
        terminal_reason_code=row[3],
        terminal_at=_optional_timestamp(row[4], field="case terminal time"),
    )


def _checked_sum(values: Sequence[int], *, field: str) -> int:
    total = 0
    for value in values:
        if type(value) is not int or value < 0 or total > _MAX_SIGNED_BIGINT - value:
            raise NormalizedEventEvidenceError(f"{field} exceeds PostgreSQL bigint money bounds")
        total += value
    return total


def _original_total(
    payments: Sequence[_PathPayment],
    *,
    currency: str,
    capture_override: _CapturedPayment | None = None,
    capture_record_id: str | None = None,
) -> int:
    captured: list[int] = []
    override_seen = capture_override is None
    for payment in payments:
        if (
            payment.currency != currency
            or not 0 <= payment.refunded_minor <= payment.captured_minor
        ):
            raise NormalizedEventEvidenceError("original payment path money is inconsistent")
        if payment.amount_minor <= 0 or payment.captured_minor > payment.amount_minor:
            raise NormalizedEventEvidenceError("original payment path amount is inconsistent")
        if payment.payment_record_id == capture_record_id and capture_override is not None:
            if (
                payment.provider_payment_id != capture_override.provider_payment_id
                or payment.amount_minor != capture_override.amount_minor
            ):
                raise NormalizedEventEvidenceError("capture override disagrees with locked payment")
            captured.append(capture_override.amount_minor)
            override_seen = True
        elif payment.status in {"CAPTURED", "REFUNDED"}:
            captured.append(payment.captured_minor)
        elif payment.captured_minor != 0:
            raise NormalizedEventEvidenceError("non-captured original payment carries money")
    if not override_seen:
        raise NormalizedEventEvidenceError("captured payment is absent from locked original path")
    return _checked_sum(captured, field="original captured total")


def _recovery_total(
    instruments: Sequence[_PathInstrument],
    *,
    currency: str,
    link_override: _PaymentLinkCollection | None = None,
    instrument_id: str | None = None,
) -> int:
    collected: list[int] = []
    override_seen = link_override is None
    for instrument in instruments:
        if (
            instrument.currency != currency
            or not 0 <= instrument.refunded_minor <= instrument.collected_minor
        ):
            raise NormalizedEventEvidenceError("recovery instrument money is inconsistent")
        if instrument.amount_minor <= 0 or instrument.collected_minor > instrument.amount_minor:
            raise NormalizedEventEvidenceError("recovery instrument amount is inconsistent")
        if instrument.instrument_id == instrument_id and link_override is not None:
            if (
                instrument.provider_payment_link_id != link_override.provider_payment_link_id
                or instrument.amount_minor != link_override.amount_minor
                or instrument.reference_id != link_override.reference_id
            ):
                raise NormalizedEventEvidenceError("link override disagrees with locked instrument")
            collected.append(link_override.amount_paid_minor)
            override_seen = True
        elif instrument.status in {"PAID", "PARTIALLY_PAID"}:
            collected.append(instrument.collected_minor)
        elif instrument.collected_minor != 0:
            raise NormalizedEventEvidenceError("non-collected recovery instrument carries money")
    if not override_seen:
        raise NormalizedEventEvidenceError("target Payment Link is absent from locked path")
    return _checked_sum(collected, field="recovery captured total")


def _truth_for_total(total: int, amount_due: int) -> str:
    if total <= 0 or amount_due <= 0:
        raise NormalizedEventEvidenceError("terminal projection requires positive collected money")
    if total < amount_due:
        return "PARTIALLY_PAID"
    if total == amount_due:
        return "PAID"
    return "OVERPAID"


def _money_is_monotonic(
    *,
    current_total: int,
    projected_total: int,
    refunded_total: int,
    current_truth: str,
    projected_truth: str,
) -> bool:
    if not 0 <= refunded_total <= current_total <= projected_total:
        return False
    if current_truth == "EXCEPTION":
        return False
    ranks = {
        "UNKNOWN": 0,
        "UNPAID": 0,
        "AUTHORIZED": 0,
        "PARTIALLY_PAID": 1,
        "PAID": 2,
        "OVERPAID": 3,
    }
    return current_truth in ranks and ranks[projected_truth] >= ranks[current_truth]


class TerminalEventRepository(Protocol):
    def project(
        self,
        command: ProcessNormalizedProviderEventCommand,
        *,
        claim: ClaimedOutboxCommand,
    ) -> NormalizedEventProjectionResult: ...


class PostgresTerminalEventRepository:
    """Project authenticated terminal money and settle its inbox atomically."""

    durable = True

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        payment_id_factory: Callable[[], str] = _new_ulid,
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
        if not callable(payment_id_factory):
            raise TypeError("payment_id_factory must be callable")
        self._payment_id_factory = payment_id_factory

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
        processor_id = f"terminal:{claim.job_id}"
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
                raise NormalizedEventFenceLost("terminal event outbox fence is absent or expired")

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
                raise NormalizedEventBusy("terminal event inbox lease is still active")
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
            plan: _CapturePlan | _LinkPlan | None = None
            if reused_body:
                disposition = ProjectionDisposition.IGNORED
                reason_code = "suspicious_body_reused_across_event_ids"
            elif event.event_type == "payment.captured":
                plan, reason_code = self._prepare_capture(
                    cursor,
                    base_params,
                    event,
                    canonical,
                    payment_id_factory=self._payment_id_factory,
                )
            elif event.event_type in {"payment_link.paid", "payment_link.partially_paid"}:
                plan, reason_code = self._prepare_link(cursor, base_params, event, canonical)
            elif event.event_type in {"payment_link.cancelled", "payment_link.expired"}:
                disposition = ProjectionDisposition.IGNORED
                reason_code = "terminal_link_event_requires_case_policy_projection"
            else:
                disposition = ProjectionDisposition.IGNORED
                reason_code = "unsupported_terminal_event_type"
            if plan is None and reason_code is not None:
                disposition = ProjectionDisposition.IGNORED

            if not self._start_inbox(cursor, event, base_params):
                self._recheck_fence(cursor, base_params)
                return NormalizedEventProjectionResult(
                    disposition=ProjectionDisposition.DEAD_LETTER,
                    provider_event_record_id=command.provider_event_record_id,
                    reason_code="terminal_event_attempts_exhausted",
                )

            if disposition is ProjectionDisposition.PROCESSED:
                if isinstance(plan, _CapturePlan):
                    self._apply_capture(cursor, base_params, event, plan)
                elif isinstance(plan, _LinkPlan):
                    self._apply_link(cursor, base_params, event, plan)
                else:
                    raise RuntimeError("processed terminal event has no projection plan")

            self._recheck_fence(cursor, base_params)
            self._settle_inbox(
                cursor,
                base_params,
                disposition=disposition,
                reason_code=reason_code,
            )
            return NormalizedEventProjectionResult(
                disposition=disposition,
                provider_event_record_id=command.provider_event_record_id,
                reason_code=reason_code,
            )

    @staticmethod
    def _prepare_capture(
        cursor: _Cursor,
        params: Mapping[str, object],
        event: _PersistedEvent,
        canonical: Mapping[str, object],
        *,
        payment_id_factory: Callable[[], str],
    ) -> tuple[_CapturePlan | None, str | None]:
        payment = _captured_payment(canonical)
        cursor.execute(
            _LOAD_CAPTURE_TARGET,
            {**params, "provider_payment_id": payment.provider_payment_id},
        )
        target = _capture_target(cursor.fetchone())
        if target is None:
            cursor.execute(
                _LOAD_CAPTURE_ORDER,
                {**params, "provider_order_id": payment.provider_order_id},
            )
            order = cursor.fetchone()
            if order is None:
                return None, "unmapped_captured_payment"
            if (
                len(order) != 6
                or not isinstance(order[0], str)
                or order[1] != payment.provider_order_id
                or order[2] != payment.amount_minor
                or order[3] != payment.currency
                or order[4] == "EXCEPTION"
                or order[5] != "MAPPED"
            ):
                return None, "captured_payment_order_mapping_conflict"
            payment_record_id = payment_id_factory()
            if not isinstance(payment_record_id, str) or not re.fullmatch(
                r"[0-9A-HJKMNP-TV-Z]{26}", payment_record_id
            ):
                raise RuntimeError("payment_id_factory returned an invalid ULID")
            cursor.execute(
                _INSERT_DISCOVERED_CAPTURE_PAYMENT,
                {
                    **params,
                    "payment_record_id": payment_record_id,
                    "logical_order_id": order[0],
                    "provider_payment_id": payment.provider_payment_id,
                    "provider_order_id": payment.provider_order_id,
                    "amount_minor": payment.amount_minor,
                    "currency": payment.currency,
                    "payment_method": payment.payment_method,
                    "provider_occurred_at": event.provider_occurred_at,
                    "discovery_facts": json.dumps(
                        {
                            "projection_contract": "payment-captured-discovery/v1",
                            "retrywise_provider_event_record_id": (event.provider_event_record_id),
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                },
            )
            inserted = cursor.fetchone()
            if inserted is not None and inserted != (payment_record_id,):
                raise RuntimeError("captured payment discovery returned another id")
            cursor.execute(
                _LOAD_CAPTURE_TARGET,
                {**params, "provider_payment_id": payment.provider_payment_id},
            )
            target = _capture_target(cursor.fetchone())
            if target is None:
                raise NormalizedEventBusy("captured payment discovery did not converge")
        exact = (
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
        if not exact:
            return None, "captured_payment_mapping_conflict"
        if target.payment_status not in _CAPTURE_ACCEPTING_PAYMENT_STATES:
            return None, "refunded_payment_state_dominates_capture"
        if target.refunded_minor != 0:
            return None, "refunded_payment_money_dominates_capture"
        if (
            target.payment_status == "CAPTURED"
            and target.payment_snapshot_at > event.provider_occurred_at
        ):
            return None, "newer_capture_snapshot_already_projected"

        path_params = {
            **params,
            "logical_order_id": target.logical_order_id,
            "original_provider_order_id": target.original_provider_order_id,
            "currency": target.currency,
        }
        cursor.execute(_LOCK_ORIGINAL_PATH_PAYMENTS, path_params)
        payments = tuple(_path_payment(row) for row in cursor.fetchall())
        cursor.execute(_LOCK_ORDER_INSTRUMENTS, path_params)
        instruments = tuple(_path_instrument(row) for row in cursor.fetchall())
        cursor.execute(_LOCK_ORDER_CASES, path_params)
        cases = tuple(_case(row) for row in cursor.fetchall())

        original_total = _original_total(
            payments,
            currency=target.currency,
            capture_override=payment,
            capture_record_id=target.payment_record_id,
        )
        recovery_total = _recovery_total(instruments, currency=target.currency)
        total = _checked_sum((original_total, recovery_total), field="combined captured total")
        truth = _truth_for_total(total, target.amount_due_minor)
        if not _money_is_monotonic(
            current_total=target.captured_total_minor,
            projected_total=total,
            refunded_total=target.refunded_total_minor,
            current_truth=target.canonical_truth,
            projected_truth=truth,
        ):
            return None, "captured_order_truth_conflict"

        collected_case_ids = {
            instrument.recovery_case_id
            for instrument in instruments
            if instrument.status in {"PAID", "PARTIALLY_PAID"} and instrument.collected_minor > 0
        }
        transitions: list[_CaseTransition] = []
        for recovery_case in cases:
            if recovery_case.recovery_case_id in collected_case_ids:
                if recovery_case.state != "DUPLICATE_REVIEW":
                    transitions.append(
                        _CaseTransition(
                            recovery_case_id=recovery_case.recovery_case_id,
                            expected_state=recovery_case.state,
                            expected_version=recovery_case.version,
                            new_state="DUPLICATE_REVIEW",
                            reason_code="both_original_and_recovery_paths_collected",
                        )
                    )
            elif recovery_case.state in _OPEN_CASE_STATES:
                transitions.append(
                    _CaseTransition(
                        recovery_case_id=recovery_case.recovery_case_id,
                        expected_state=recovery_case.state,
                        expected_version=recovery_case.version,
                        new_state="SUPPRESSED_PAID",
                        reason_code="original_payment_captured",
                    )
                )
        return (
            _CapturePlan(
                target=target,
                payment=payment,
                captured_total_minor=total,
                canonical_truth=truth,
                case_transitions=tuple(transitions),
            ),
            None,
        )

    @staticmethod
    def _prepare_link(
        cursor: _Cursor,
        params: Mapping[str, object],
        event: _PersistedEvent,
        canonical: Mapping[str, object],
    ) -> tuple[_LinkPlan | None, str | None]:
        collection = _payment_link_collection(canonical)
        cursor.execute(
            _LOAD_LINK_TARGET,
            {**params, "provider_payment_link_id": collection.provider_payment_link_id},
        )
        target = _link_target(cursor.fetchone())
        if target is None:
            return None, "unmapped_recovery_payment_link"
        expected_reference_id = make_recovery_reference_id(
            target.recovery_case_id,
            provider_account_id=target.provider_account_id,
        )
        exact = (
            target.provider_account_id == params["provider_account_id"]
            and target.provider_payment_link_id == collection.provider_payment_link_id
            and target.reference_id == expected_reference_id
            and collection.reference_id == expected_reference_id
            and target.amount_minor == collection.amount_minor
            and target.amount_due_minor == collection.amount_minor
            and target.currency == collection.currency
            and target.order_currency == collection.currency
            and target.mapping_status == "MAPPED"
            and target.accept_partial is False
            and target.provider_order_id in {None, collection.provider_order_id}
            and target.provider_payment_id in {None, collection.provider_payment_id}
        )
        if not exact:
            return None, "recovery_payment_link_mapping_conflict"
        accepting = (
            _LINK_PAID_ACCEPTING_STATES
            if collection.event_type == "payment_link.paid"
            else _LINK_PARTIAL_ACCEPTING_STATES
        )
        if target.instrument_status not in accepting:
            return None, "recovery_instrument_state_dominates_link_event"
        if collection.amount_paid_minor < target.collected_minor:
            return None, "newer_recovery_collection_money_dominates_event"
        if target.refunded_minor != 0:
            return None, "refunded_recovery_money_dominates_link_event"

        path_params = {
            **params,
            "logical_order_id": target.logical_order_id,
            "original_provider_order_id": target.original_provider_order_id,
            "currency": target.currency,
        }
        if target.original_provider_order_id is None:
            return None, "recovery_case_missing_original_order_binding"
        cursor.execute(_LOCK_ORIGINAL_PATH_PAYMENTS, path_params)
        payments = tuple(_path_payment(row) for row in cursor.fetchall())
        cursor.execute(_LOCK_ORDER_INSTRUMENTS, path_params)
        instruments = tuple(_path_instrument(row) for row in cursor.fetchall())
        original_total = _original_total(payments, currency=target.currency)
        recovery_total = _recovery_total(
            instruments,
            currency=target.currency,
            link_override=collection,
            instrument_id=target.instrument_id,
        )
        total = _checked_sum((original_total, recovery_total), field="combined captured total")
        truth = _truth_for_total(total, target.amount_due_minor)
        if not _money_is_monotonic(
            current_total=target.captured_total_minor,
            projected_total=total,
            refunded_total=target.refunded_total_minor,
            current_truth=target.canonical_truth,
            projected_truth=truth,
        ):
            return None, "recovery_order_truth_conflict"

        transition: _CaseTransition | None
        is_partial = collection.event_type == "payment_link.partially_paid"
        duplicate = is_partial or original_total > 0 or total > target.amount_due_minor
        if duplicate:
            transition = (
                None
                if target.case_state == "DUPLICATE_REVIEW"
                else _CaseTransition(
                    recovery_case_id=target.recovery_case_id,
                    expected_state=target.case_state,
                    expected_version=target.case_version,
                    new_state="DUPLICATE_REVIEW",
                    reason_code=(
                        "partial_collection_violated_link_contract"
                        if is_partial and original_total == 0
                        else "both_original_and_recovery_paths_collected"
                    ),
                )
            )
        elif target.case_state == "ACTIVE":
            transition = _CaseTransition(
                recovery_case_id=target.recovery_case_id,
                expected_state=target.case_state,
                expected_version=target.case_version,
                new_state="RECOVERED",
                reason_code="recovery_payment_link_paid",
            )
        elif target.case_state == "RECOVERED" and target.instrument_status == "PAID":
            transition = None
        else:
            transition = _CaseTransition(
                recovery_case_id=target.recovery_case_id,
                expected_state=target.case_state,
                expected_version=target.case_version,
                new_state="DUPLICATE_REVIEW",
                reason_code="recovery_collected_outside_active_case",
            )
        return (
            _LinkPlan(
                target=target,
                collection=collection,
                captured_total_minor=total,
                canonical_truth=truth,
                case_transition=transition,
            ),
            None,
        )

    @staticmethod
    def _apply_capture(
        cursor: _Cursor,
        params: Mapping[str, object],
        event: _PersistedEvent,
        plan: _CapturePlan,
    ) -> None:
        target = plan.target
        payment = plan.payment
        cursor.execute(
            _PROJECT_CAPTURED_PAYMENT,
            {
                **params,
                "payment_record_id": target.payment_record_id,
                "logical_order_id": target.logical_order_id,
                "provider_payment_id": payment.provider_payment_id,
                "provider_order_id": payment.provider_order_id,
                "amount_minor": payment.amount_minor,
                "currency": payment.currency,
                "captured_minor": payment.amount_minor,
                "payment_method": payment.payment_method,
                "expected_payment_status": target.payment_status,
                "expected_captured_minor": target.captured_minor,
                "projection_facts": json.dumps(
                    {
                        "projection_contract": "payment-captured/v1",
                        "retrywise_provider_event_record_id": event.provider_event_record_id,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                "provider_occurred_at": event.provider_occurred_at,
            },
        )
        if _first_column(cursor.fetchone(), operation="captured payment projection") != "CAPTURED":
            raise RuntimeError("captured payment projection returned another state")
        PostgresTerminalEventRepository._apply_order(cursor, params, event, plan)
        for transition in plan.case_transitions:
            PostgresTerminalEventRepository._apply_case(
                cursor,
                params,
                logical_order_id=target.logical_order_id,
                currency=target.currency,
                transition=transition,
            )

    @staticmethod
    def _apply_link(
        cursor: _Cursor,
        params: Mapping[str, object],
        event: _PersistedEvent,
        plan: _LinkPlan,
    ) -> None:
        target = plan.target
        collection = plan.collection
        cursor.execute(
            _PROJECT_RECOVERY_INSTRUMENT,
            {
                **params,
                "instrument_id": target.instrument_id,
                "recovery_case_id": target.recovery_case_id,
                "logical_order_id": target.logical_order_id,
                "provider_payment_link_id": collection.provider_payment_link_id,
                "provider_order_id": collection.provider_order_id,
                "provider_payment_id": collection.provider_payment_id,
                "reference_id": collection.reference_id,
                "amount_minor": collection.amount_minor,
                "currency": collection.currency,
                "new_instrument_status": collection.instrument_status,
                "expected_instrument_status": target.instrument_status,
                "expected_collected_minor": target.collected_minor,
                "expected_refunded_minor": target.refunded_minor,
                "collected_minor": collection.amount_paid_minor,
                "provider_status": collection.instrument_status.lower(),
            },
        )
        if (
            _first_column(cursor.fetchone(), operation="recovery instrument projection")
            != collection.instrument_status
        ):
            raise RuntimeError("recovery instrument projection returned another state")
        PostgresTerminalEventRepository._apply_order(cursor, params, event, plan)
        if plan.case_transition is not None:
            PostgresTerminalEventRepository._apply_case(
                cursor,
                params,
                logical_order_id=target.logical_order_id,
                currency=target.currency,
                transition=plan.case_transition,
            )

    @staticmethod
    def _apply_order(
        cursor: _Cursor,
        params: Mapping[str, object],
        event: _PersistedEvent,
        plan: _CapturePlan | _LinkPlan,
    ) -> None:
        target = plan.target
        cursor.execute(
            _PROJECT_ORDER_TRUTH,
            {
                **params,
                "logical_order_id": target.logical_order_id,
                "amount_due_minor": target.amount_due_minor,
                "currency": target.currency,
                "captured_total_minor": plan.captured_total_minor,
                "canonical_truth": plan.canonical_truth,
                "expected_canonical_truth": target.canonical_truth,
                "expected_captured_total_minor": target.captured_total_minor,
                "expected_refunded_total_minor": target.refunded_total_minor,
                "provider_occurred_at": event.provider_occurred_at,
            },
        )
        if (
            _first_column(cursor.fetchone(), operation="logical order truth projection")
            != plan.canonical_truth
        ):
            raise RuntimeError("logical order truth projection returned another state")

    @staticmethod
    def _apply_case(
        cursor: _Cursor,
        params: Mapping[str, object],
        *,
        logical_order_id: str,
        currency: str,
        transition: _CaseTransition,
    ) -> None:
        cursor.execute(
            _PROJECT_CASE_TERMINAL,
            {
                **params,
                "recovery_case_id": transition.recovery_case_id,
                "logical_order_id": logical_order_id,
                "currency": currency,
                "expected_case_state": transition.expected_state,
                "expected_case_version": transition.expected_version,
                "new_case_state": transition.new_state,
                "terminal_reason_code": transition.reason_code,
            },
        )
        if (
            _first_column(cursor.fetchone(), operation="recovery case projection")
            != transition.new_state
        ):
            raise RuntimeError("recovery case projection returned another state")

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
            raise NormalizedEventBusy("terminal event inbox processing claim was not acquired")
        cursor.execute(_DEAD_LETTER_EXHAUSTED_INBOX, params)
        if (
            _first_column(cursor.fetchone(), operation="exhausted inbox settlement")
            != "DEAD_LETTER"
        ):
            raise RuntimeError("exhausted terminal inbox did not enter DEAD_LETTER")
        return False

    @staticmethod
    def _recheck_fence(cursor: _Cursor, params: Mapping[str, object]) -> None:
        cursor.execute(_RECHECK_OUTBOX_FENCE, params)
        if _first_column(cursor.fetchone(), operation="outbox fence recheck") is not True:
            raise NormalizedEventFenceLost("terminal event outbox lease expired before commit")

    @staticmethod
    def _settle_inbox(
        cursor: _Cursor,
        params: Mapping[str, object],
        *,
        disposition: ProjectionDisposition,
        reason_code: str | None,
    ) -> None:
        if disposition not in {ProjectionDisposition.PROCESSED, ProjectionDisposition.IGNORED}:
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


class ProcessTerminalProviderEventHandler:
    """OutboxWorker-compatible handler for the explicit terminal subset only."""

    def __init__(self, repository: TerminalEventRepository) -> None:
        if not callable(getattr(repository, "project", None)):
            raise TypeError("repository must provide project(command, claim=...)")
        self._repository = repository

    def __call__(self, claimed: ClaimedOutboxCommand) -> HandlerResult:
        try:
            command = decode_process_normalized_provider_event_command(claimed)
        except NormalizedEventCommandError:
            return HandlerResult.dead_letter("invalid_terminal_event_command")
        if command.event_type not in SUPPORTED_TERMINAL_EVENT_TYPES:
            return HandlerResult.dead_letter("unsupported_terminal_event_command")
        try:
            result = self._repository.project(command, claim=claimed)
        except (NormalizedEventBindingError, NormalizedEventEvidenceError):
            return HandlerResult.dead_letter("invalid_terminal_event_evidence")
        except NormalizedEventFenceLost:
            return HandlerResult.retry_safely(
                "terminal_event_fence_lost",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        except NormalizedEventBusy:
            return HandlerResult.retry_safely(
                "terminal_event_inbox_busy",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        if not isinstance(result, NormalizedEventProjectionResult):
            return HandlerResult.dead_letter("invalid_terminal_event_projection_result")
        if result.disposition is ProjectionDisposition.DEAD_LETTER:
            return HandlerResult.dead_letter(
                result.reason_code or "terminal_event_inbox_dead_lettered"
            )
        return HandlerResult.succeeded(result.completion_reference)


__all__ = [
    "SUPPORTED_TERMINAL_EVENT_TYPES",
    "PostgresTerminalEventRepository",
    "ProcessTerminalProviderEventHandler",
    "TerminalEventRepository",
]
