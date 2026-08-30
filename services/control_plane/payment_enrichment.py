"""Durable provider enrichment for a failed payment that is not mapped locally.

The webhook projector never invents an order from event data.  It schedules this
read-only provider command, which fetches current Payment and Order truth from a
credential-bound Razorpay Test account.  Persistence is fenced by the claimed
outbox lease and stores only operational fields; receipts, notes, contact data,
and payment-instrument details are deliberately discarded.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Protocol, cast

from .outbox import RetryMode
from .outbox_worker import HandlerResult
from .postgres_connection import PostgresConnectionPolicy
from .postgres_outbox import ClaimedOutboxCommand
from .razorpay_test_adapter import OrderRecord, PaymentRecord, RazorpayReadError

ENRICH_FAILED_PAYMENT_COMMAND_TYPE: Final = "ENRICH_FAILED_PAYMENT"
ENRICH_FAILED_PAYMENT_SCHEMA_VERSION: Final = 1
MAX_ENRICHMENT_COMMAND_BYTES: Final = 4 * 1024

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_PAYMENT_ID_RE = re.compile(r"^pay_[A-Za-z0-9_-]{1,124}$")
_ORDER_ID_RE = re.compile(r"^order_[A-Za-z0-9_-]{1,122}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_FIELDS = frozenset(
    {
        "amount_minor",
        "currency",
        "merchant_id",
        "provider_account_id",
        "provider_order_id",
        "provider_payment_id",
        "schema_version",
    }
)


class PaymentEnrichmentCommandError(ValueError):
    """The delivery is not the exact closed enrichment command."""


class PaymentEnrichmentBindingError(RuntimeError):
    """Fresh provider truth conflicts with the immutable webhook binding."""


class PaymentEnrichmentPersistenceError(RuntimeError):
    """The enrichment transaction could not be proven durable and fenced."""


def _clean(value: object, *, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PaymentEnrichmentCommandError(f"{field} is invalid")
    return value


def _ulid(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _ULID_RE.fullmatch(value):
        raise PaymentEnrichmentCommandError(f"{field} is not a RetryWise ULID")
    return value


@dataclass(frozen=True, slots=True)
class EnrichFailedPaymentCommand:
    merchant_id: str
    provider_account_id: str
    provider_payment_id: str
    provider_order_id: str
    amount_minor: int
    currency: str

    def __post_init__(self) -> None:
        _ulid(self.merchant_id, field="merchant_id")
        _ulid(self.provider_account_id, field="provider_account_id")
        if not _PAYMENT_ID_RE.fullmatch(self.provider_payment_id):
            raise PaymentEnrichmentCommandError("provider_payment_id is invalid")
        if not _ORDER_ID_RE.fullmatch(self.provider_order_id):
            raise PaymentEnrichmentCommandError("provider_order_id is invalid")
        if type(self.amount_minor) is not int or self.amount_minor <= 0:
            raise PaymentEnrichmentCommandError("amount_minor must be positive")
        if not _CURRENCY_RE.fullmatch(self.currency):
            raise PaymentEnrichmentCommandError("currency is invalid")

    @property
    def idempotency_key(self) -> str:
        return f"enrich-provider-payment:{self.provider_account_id}:{self.provider_payment_id}"


def encode_enrich_failed_payment_command(
    command: EnrichFailedPaymentCommand,
) -> dict[str, object]:
    if not isinstance(command, EnrichFailedPaymentCommand):
        raise TypeError("command must be EnrichFailedPaymentCommand")
    return {
        "amount_minor": command.amount_minor,
        "currency": command.currency,
        "merchant_id": command.merchant_id,
        "provider_account_id": command.provider_account_id,
        "provider_order_id": command.provider_order_id,
        "provider_payment_id": command.provider_payment_id,
        "schema_version": ENRICH_FAILED_PAYMENT_SCHEMA_VERSION,
    }


def canonical_enrichment_payload(payload: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise PaymentEnrichmentCommandError("enrichment payload is not canonical JSON") from exc
    if len(encoded) > MAX_ENRICHMENT_COMMAND_BYTES:
        raise PaymentEnrichmentCommandError("enrichment payload exceeds its boundary")
    return encoded.decode("ascii")


def decode_enrich_failed_payment_command(
    claimed: ClaimedOutboxCommand,
) -> EnrichFailedPaymentCommand:
    if not isinstance(claimed, ClaimedOutboxCommand):
        raise TypeError("claimed must be ClaimedOutboxCommand")
    if (
        claimed.command_type != ENRICH_FAILED_PAYMENT_COMMAND_TYPE
        or claimed.command_schema_version != ENRICH_FAILED_PAYMENT_SCHEMA_VERSION
        or claimed.aggregate_type != "PROVIDER_PAYMENT"
    ):
        raise PaymentEnrichmentCommandError("unexpected enrichment envelope")
    payload = claimed.command_payload
    if not isinstance(payload, Mapping) or frozenset(payload) != _FIELDS:
        raise PaymentEnrichmentCommandError("enrichment payload fields disagree")
    canonical_enrichment_payload(payload)
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise PaymentEnrichmentCommandError("enrichment schema version is invalid")
    command = EnrichFailedPaymentCommand(
        merchant_id=cast(str, payload["merchant_id"]),
        provider_account_id=cast(str, payload["provider_account_id"]),
        provider_payment_id=cast(str, payload["provider_payment_id"]),
        provider_order_id=cast(str, payload["provider_order_id"]),
        amount_minor=cast(int, payload["amount_minor"]),
        currency=cast(str, payload["currency"]),
    )
    if (
        command.merchant_id != claimed.merchant_id
        or command.provider_payment_id != claimed.aggregate_id
        or command.idempotency_key != claimed.idempotency_key
    ):
        raise PaymentEnrichmentCommandError("enrichment envelope binding mismatch")
    return command


class PaymentEnrichmentAdapter(Protocol):
    def fetch_payment(self, *, payment_id: str, provider_account_id: str) -> PaymentRecord: ...

    def fetch_order(self, *, order_id: str, provider_account_id: str) -> OrderRecord: ...

    def close(self) -> None: ...


PaymentEnrichmentAdapterFactory = Callable[[str, str], PaymentEnrichmentAdapter]


@dataclass(frozen=True, slots=True)
class PaymentEnrichmentResult:
    logical_order_id: str
    payment_record_id: str

    def __post_init__(self) -> None:
        _ulid(self.logical_order_id, field="logical_order_id")
        _ulid(self.payment_record_id, field="payment_record_id")

    @property
    def completion_reference(self) -> str:
        return f"enriched-provider-payment:{self.payment_record_id}"


_LOCK_FENCE = """
SELECT TRUE
FROM retrywise.outbox_jobs AS job
WHERE job.id = %(job_id)s
  AND job.merchant_id = %(merchant_id)s
  AND job.aggregate_type = 'PROVIDER_PAYMENT'
  AND job.aggregate_id = %(provider_payment_id)s
  AND job.command_type = 'ENRICH_FAILED_PAYMENT'
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

_LOCK_ACCOUNT = """
SELECT TRUE
FROM retrywise.provider_accounts AS account
JOIN retrywise.merchants AS merchant ON merchant.id = account.merchant_id
WHERE account.merchant_id = %(merchant_id)s
  AND account.id = %(provider_account_id)s
  AND account.provider = 'RAZORPAY'
  AND account.environment = 'TEST'
  AND account.enabled
  AND merchant.status = 'ACTIVE'
FOR SHARE OF account, merchant
"""

_INSERT_ORDER = """
INSERT INTO retrywise.logical_orders (
    id, merchant_id, provider_account_id, merchant_order_reference,
    original_provider_order_id, amount_due_minor, currency,
    captured_total_minor, refunded_total_minor, canonical_truth, truth_version,
    provider_snapshot_at, mapping_status, mapping_reason_code
) VALUES (
    %(logical_order_id)s, %(merchant_id)s, %(provider_account_id)s,
    %(merchant_order_reference)s, %(provider_order_id)s, %(order_amount_minor)s,
    %(currency)s, %(order_amount_paid_minor)s, 0,
    %(canonical_truth)s::retrywise.canonical_payment_truth,
    1, %(observed_at)s, 'MAPPED', 'provider_api_enrichment_v1'
)
ON CONFLICT DO NOTHING
RETURNING id::text
"""

_LOAD_ORDER = """
SELECT id::text, original_provider_order_id, amount_due_minor, currency::text,
       mapping_status::text, captured_total_minor, provider_snapshot_at
FROM retrywise.logical_orders
WHERE merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND original_provider_order_id = %(provider_order_id)s
FOR UPDATE
"""

_UPDATE_ORDER = """
UPDATE retrywise.logical_orders
SET captured_total_minor = GREATEST(captured_total_minor, %(order_amount_paid_minor)s),
    canonical_truth = CASE
        WHEN GREATEST(captured_total_minor, %(order_amount_paid_minor)s) = 0 THEN 'UNPAID'
        WHEN GREATEST(captured_total_minor, %(order_amount_paid_minor)s) < amount_due_minor
            THEN 'PARTIALLY_PAID'
        WHEN GREATEST(captured_total_minor, %(order_amount_paid_minor)s) = amount_due_minor
            THEN 'PAID'
        ELSE 'OVERPAID'
    END::retrywise.canonical_payment_truth,
    truth_version = truth_version + 1,
    provider_snapshot_at = %(observed_at)s,
    mapping_status = 'MAPPED',
    mapping_reason_code = 'provider_api_enrichment_v1',
    updated_at = clock_timestamp()
WHERE id = %(persisted_logical_order_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND (provider_snapshot_at IS NULL OR provider_snapshot_at <= %(observed_at)s)
RETURNING id::text
"""

_INSERT_PAYMENT = """
INSERT INTO retrywise.provider_payments (
    id, merchant_id, provider_account_id, logical_order_id,
    provider_payment_id, provider_order_id, status, amount_minor, currency,
    captured_minor, refunded_minor, payment_method, error_facts,
    provider_created_at, provider_snapshot_at
) VALUES (
    %(payment_record_id)s, %(merchant_id)s, %(provider_account_id)s,
    %(persisted_logical_order_id)s, %(provider_payment_id)s, %(provider_order_id)s,
    %(payment_status)s::retrywise.provider_payment_status,
    %(payment_amount_minor)s, %(currency)s,
    %(captured_minor)s, %(refunded_minor)s, %(payment_method)s,
    %(error_facts)s::jsonb, %(payment_created_at)s, %(observed_at)s
)
ON CONFLICT DO NOTHING
RETURNING id::text
"""

_LOAD_PAYMENT = """
SELECT id::text, logical_order_id::text, provider_order_id, amount_minor,
       currency::text, provider_snapshot_at
FROM retrywise.provider_payments
WHERE merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND provider_payment_id = %(provider_payment_id)s
FOR UPDATE
"""

_UPDATE_PAYMENT = """
UPDATE retrywise.provider_payments
SET status = %(payment_status)s::retrywise.provider_payment_status,
    captured_minor = %(captured_minor)s,
    refunded_minor = %(refunded_minor)s,
    payment_method = %(payment_method)s,
    error_facts = %(error_facts)s::jsonb,
    provider_created_at = COALESCE(provider_created_at, %(payment_created_at)s),
    provider_snapshot_at = %(observed_at)s,
    updated_at = clock_timestamp()
WHERE id = %(persisted_payment_record_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND provider_snapshot_at <= %(observed_at)s
RETURNING id::text
"""

_RECHECK_FENCE = """
SELECT lease_expires_at > clock_timestamp()
FROM retrywise.outbox_jobs
WHERE id = %(job_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'IN_PROGRESS'
  AND delivery_version = %(delivery_version)s
  AND lease_owner = %(worker_id)s
  AND lease_token = %(lease_token)s
"""


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def __enter__(self) -> _Cursor: ...

    def __exit__(self, *args: object) -> bool | None: ...


class _Transaction(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(self, *args: object) -> bool | None: ...


class _Connection(Protocol):
    def transaction(self) -> _Transaction: ...

    def cursor(self) -> _Cursor: ...


class _ConnectionContext(Protocol):
    def __enter__(self) -> _Connection: ...

    def __exit__(self, *args: object) -> bool | None: ...


ConnectionFactory = Callable[[], _ConnectionContext]


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresFailedPaymentEnrichmentRepository"),
        )

    return connect


def _utc(value: datetime, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _one(row: Sequence[object] | None, expected: object, reason: str) -> None:
    if row != (expected,):
        raise PaymentEnrichmentPersistenceError(reason)


class PostgresFailedPaymentEnrichmentRepository:
    """Fenced, idempotent storage of one provider Payment/Order snapshot."""

    def __init__(
        self,
        *,
        id_factory: Callable[[], str],
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if not callable(id_factory):
            raise TypeError("id_factory must be callable")
        self._id_factory = id_factory
        self._connector = (
            _dsn_factory(dsn, require_tls=require_tls)
            if dsn is not None
            else cast(ConnectionFactory, connector)
        )

    def persist(
        self,
        *,
        command: EnrichFailedPaymentCommand,
        payment: PaymentRecord,
        order: OrderRecord,
        observed_at: datetime,
        claim: ClaimedOutboxCommand,
    ) -> PaymentEnrichmentResult:
        if not isinstance(command, EnrichFailedPaymentCommand):
            raise TypeError("command must be EnrichFailedPaymentCommand")
        if not isinstance(payment, PaymentRecord) or not isinstance(order, OrderRecord):
            raise TypeError("payment and order must be strict provider records")
        if not isinstance(claim, ClaimedOutboxCommand):
            raise TypeError("claim must be ClaimedOutboxCommand")
        observed_at = _utc(observed_at, field="observed_at")
        self._validate_binding(command, payment, order)
        logical_order_id = _ulid(self._id_factory(), field="id_factory result")
        payment_record_id = _ulid(self._id_factory(), field="id_factory result")
        payment_created_at = (
            datetime.fromtimestamp(payment.created_at_epoch, UTC)
            if payment.created_at_epoch is not None
            else observed_at
        )
        error_facts = {}
        if payment.error_source is not None:
            error_facts = {
                "error_reason": payment.error_reason,
                "error_source": payment.error_source,
                "error_step": payment.error_step,
                "projection_contract": "provider-api-enrichment/v1",
            }
        canonical_truth = (
            "UNPAID"
            if order.amount_paid_minor == 0
            else "PAID"
            if order.amount_paid_minor == order.amount_minor
            else "PARTIALLY_PAID"
        )
        params: dict[str, object] = {
            "job_id": claim.job_id,
            "merchant_id": command.merchant_id,
            "provider_account_id": command.provider_account_id,
            "provider_payment_id": command.provider_payment_id,
            "provider_order_id": command.provider_order_id,
            "command_payload": canonical_enrichment_payload(claim.command_payload),
            "idempotency_key": claim.idempotency_key,
            "delivery_version": claim.delivery_version,
            "worker_id": claim.worker_id,
            "lease_token": claim.lease_token,
            "logical_order_id": logical_order_id,
            "payment_record_id": payment_record_id,
            "merchant_order_reference": f"razorpay:{order.order_id}",
            "order_amount_minor": order.amount_minor,
            "order_amount_paid_minor": order.amount_paid_minor,
            "currency": order.currency,
            "canonical_truth": canonical_truth,
            "payment_status": payment.status.value.upper(),
            "payment_amount_minor": payment.amount_minor,
            "captured_minor": payment.captured_minor,
            "refunded_minor": payment.refunded_minor,
            "payment_method": payment.payment_method,
            "error_facts": json.dumps(error_facts, sort_keys=True, separators=(",", ":")),
            "payment_created_at": payment_created_at,
            "observed_at": observed_at,
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_LOCK_FENCE, params)
            _one(cursor.fetchone(), True, "payment_enrichment_fence_lost")
            cursor.execute(_LOCK_ACCOUNT, params)
            _one(cursor.fetchone(), True, "payment_enrichment_account_unavailable")

            cursor.execute(_INSERT_ORDER, params)
            cursor.fetchone()
            cursor.execute(_LOAD_ORDER, params)
            order_row = cursor.fetchone()
            persisted_logical_order_id = self._validated_order_row(order_row, command, order)
            params["persisted_logical_order_id"] = persisted_logical_order_id
            cursor.execute(_UPDATE_ORDER, params)
            cursor.fetchone()

            cursor.execute(_INSERT_PAYMENT, params)
            cursor.fetchone()
            cursor.execute(_LOAD_PAYMENT, params)
            payment_row = cursor.fetchone()
            persisted_payment_record_id = self._validated_payment_row(
                payment_row, command, persisted_logical_order_id
            )
            params["persisted_payment_record_id"] = persisted_payment_record_id
            cursor.execute(_UPDATE_PAYMENT, params)
            cursor.fetchone()

            cursor.execute(_RECHECK_FENCE, params)
            _one(cursor.fetchone(), True, "payment_enrichment_fence_lost")
        return PaymentEnrichmentResult(
            logical_order_id=persisted_logical_order_id,
            payment_record_id=persisted_payment_record_id,
        )

    @staticmethod
    def _validate_binding(
        command: EnrichFailedPaymentCommand,
        payment: PaymentRecord,
        order: OrderRecord,
    ) -> None:
        if (
            payment.payment_id != command.provider_payment_id
            or payment.order_id != command.provider_order_id
            or order.order_id != command.provider_order_id
            or payment.amount_minor != command.amount_minor
            or payment.currency != command.currency
            or order.amount_minor != payment.amount_minor
            or order.currency != payment.currency
        ):
            raise PaymentEnrichmentBindingError("provider_enrichment_binding_conflict")

    @staticmethod
    def _validated_order_row(
        row: Sequence[object] | None,
        command: EnrichFailedPaymentCommand,
        order: OrderRecord,
    ) -> str:
        if row is None or len(row) != 7:
            raise PaymentEnrichmentPersistenceError("provider_order_mapping_missing")
        identifier, provider_order_id, amount, currency, mapping, captured, snapshot = row
        if (
            not isinstance(identifier, str)
            or not _ULID_RE.fullmatch(identifier)
            or provider_order_id != command.provider_order_id
            or amount != order.amount_minor
            or currency != order.currency
            or mapping not in {"UNMAPPED", "MAPPED"}
            or type(captured) is not int
            or captured < 0
            or (snapshot is not None and not isinstance(snapshot, datetime))
        ):
            raise PaymentEnrichmentBindingError("provider_order_mapping_conflict")
        return identifier

    @staticmethod
    def _validated_payment_row(
        row: Sequence[object] | None,
        command: EnrichFailedPaymentCommand,
        logical_order_id: str,
    ) -> str:
        if row is None or len(row) != 6:
            raise PaymentEnrichmentPersistenceError("provider_payment_mapping_missing")
        identifier, persisted_order_id, provider_order_id, amount, currency, snapshot = row
        if (
            not isinstance(identifier, str)
            or not _ULID_RE.fullmatch(identifier)
            or persisted_order_id != logical_order_id
            or provider_order_id != command.provider_order_id
            or amount != command.amount_minor
            or currency != command.currency
            or not isinstance(snapshot, datetime)
        ):
            raise PaymentEnrichmentBindingError("provider_payment_mapping_conflict")
        return identifier


class EnrichFailedPaymentHandler:
    """Read current Razorpay truth and persist a verified local mapping."""

    def __init__(
        self,
        *,
        repository: PostgresFailedPaymentEnrichmentRepository,
        adapter_factory: PaymentEnrichmentAdapterFactory,
        clock: Callable[[], datetime],
    ) -> None:
        if not callable(adapter_factory) or not callable(clock):
            raise TypeError("adapter_factory and clock must be callable")
        self._repository = repository
        self._adapter_factory = adapter_factory
        self._clock = clock

    def __call__(self, claimed: ClaimedOutboxCommand) -> HandlerResult:
        try:
            command = decode_enrich_failed_payment_command(claimed)
        except (PaymentEnrichmentCommandError, TypeError, ValueError):
            return HandlerResult.dead_letter("invalid_payment_enrichment_command")
        adapter: PaymentEnrichmentAdapter | None = None
        try:
            adapter = self._adapter_factory(command.merchant_id, command.provider_account_id)
            payment = adapter.fetch_payment(
                payment_id=command.provider_payment_id,
                provider_account_id=command.provider_account_id,
            )
            order = adapter.fetch_order(
                order_id=command.provider_order_id,
                provider_account_id=command.provider_account_id,
            )
            result = self._repository.persist(
                command=command,
                payment=payment,
                order=order,
                observed_at=self._clock(),
                claim=claimed,
            )
        except RazorpayReadError:
            return HandlerResult.retry_safely(
                "provider_enrichment_read_unavailable",
                retry_mode=RetryMode.RETRY_SAME_EFFECT,
            )
        except PaymentEnrichmentBindingError:
            return HandlerResult.dead_letter("provider_enrichment_binding_conflict")
        except PaymentEnrichmentPersistenceError:
            return HandlerResult.retry_safely(
                "provider_enrichment_persistence_unavailable",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        except Exception:
            return HandlerResult.retry_safely(
                "provider_enrichment_unavailable",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        finally:
            if adapter is not None:
                with suppress(Exception):
                    adapter.close()
        return HandlerResult.succeeded(result.completion_reference)


__all__ = [
    "ENRICH_FAILED_PAYMENT_COMMAND_TYPE",
    "ENRICH_FAILED_PAYMENT_SCHEMA_VERSION",
    "EnrichFailedPaymentCommand",
    "EnrichFailedPaymentHandler",
    "PaymentEnrichmentBindingError",
    "PaymentEnrichmentCommandError",
    "PaymentEnrichmentResult",
    "PostgresFailedPaymentEnrichmentRepository",
    "canonical_enrichment_payload",
    "decode_enrich_failed_payment_command",
    "encode_enrich_failed_payment_command",
]
