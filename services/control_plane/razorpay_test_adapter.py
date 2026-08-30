"""Razorpay Test Mode HTTP adapter for Standard Payment Links.

The adapter is deliberately narrow. It pins one test credential snapshot to one
internal provider-account identifier, talks only to Razorpay's fixed HTTPS API
origin, disables redirects and transport retries, and exposes only a
non-sensitive Payment Link projection. It does not infer the Razorpay account
that owns the key; that relationship is metadata-attested by composition. It
never turns an uncertain create response into a blind retry:
timeouts, transport failures, duplicate-reference responses, and malformed
success bodies are classified as ambiguous so the executor reconciles by the
stable ``reference_id`` first.

Cancellation remains a protective best-effort action.  Even a confirmed
``cancelled`` response does not prove that a concurrent payment was impossible;
the caller must continue to consume payment truth from provider fetches and
webhooks and must never infer that a refund is required.
"""

from __future__ import annotations

import hmac
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import TracebackType
from typing import Any, Self

import httpx

from ...packages.razorpay import (
    PaymentLinkLookupResult,
    PaymentLinkValidationError,
    StandardPaymentLinkRequest,
)
from .executor import ProviderCreateOutcome

_API_ORIGIN = "https://api.razorpay.com"
_PAYMENT_LINKS_PATH = "/v1/payment_links"
_PAYMENTS_PATH = "/v1/payments"
_ORDERS_PATH = "/v1/orders"
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_LOOKUP_CANDIDATES = 100
_PAYMENT_LINK_ID_RE = re.compile(r"^plink_[A-Za-z0-9]{1,120}$")
_PAYMENT_ID_RE = re.compile(r"^pay_[A-Za-z0-9_-]{1,124}$")
_ORDER_ID_RE = re.compile(r"^order_[A-Za-z0-9_-]{1,122}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_PAYMENT_METHOD_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_MACHINE_FACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_KNOWN_STATUSES = frozenset({"created", "partially_paid", "expired", "cancelled", "paid"})
_CERTAIN_REJECT_STATUSES = frozenset({400, 401, 402, 403, 404, 405, 406, 410, 413, 415, 422})


class RazorpayAdapterError(RuntimeError):
    """A sanitized provider-boundary failure safe to persist or emit as a metric."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = _clean_text(reason_code, field="reason_code", maximum=128)
        super().__init__(self.reason_code)


class RazorpayReadError(RazorpayAdapterError):
    """Provider truth could not be read and therefore must not be assumed."""


class ProviderAccountMismatchError(RazorpayAdapterError):
    """A command attempted to use credentials bound to a different account."""


class PaymentLinkStatus(StrEnum):
    CREATED = "created"
    PARTIALLY_PAID = "partially_paid"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    PAID = "paid"


class PaymentStatus(StrEnum):
    CREATED = "created"
    AUTHORIZED = "authorized"
    CAPTURED = "captured"
    REFUNDED = "refunded"
    FAILED = "failed"


class OrderStatus(StrEnum):
    CREATED = "created"
    ATTEMPTED = "attempted"
    PAID = "paid"


class ProviderCancelStatus(StrEnum):
    CERTAIN_SUCCESS = "certain_success"
    CERTAIN_FAILURE = "certain_failure"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class PaymentRecord:
    """Strict non-sensitive projection of one Razorpay payment read."""

    payment_id: str
    order_id: str
    status: PaymentStatus
    amount_minor: int
    currency: str
    captured_minor: int
    refunded_minor: int
    payment_method: str
    error_source: str | None
    error_step: str | None
    error_reason: str | None
    created_at_epoch: int | None = None

    def __post_init__(self) -> None:
        if not _PAYMENT_ID_RE.fullmatch(self.payment_id):
            raise RazorpayReadError("provider_payment_response_invalid")
        if not _ORDER_ID_RE.fullmatch(self.order_id):
            raise RazorpayReadError("provider_payment_response_invalid")
        if not isinstance(self.status, PaymentStatus):
            raise RazorpayReadError("provider_payment_response_invalid")
        if type(self.amount_minor) is not int or self.amount_minor <= 0:
            raise RazorpayReadError("provider_payment_response_invalid")
        if not _CURRENCY_RE.fullmatch(self.currency):
            raise RazorpayReadError("provider_payment_response_invalid")
        if (
            type(self.captured_minor) is not int
            or type(self.refunded_minor) is not int
            or not 0 <= self.refunded_minor <= self.captured_minor <= self.amount_minor
        ):
            raise RazorpayReadError("provider_payment_response_invalid")
        if not _PAYMENT_METHOD_RE.fullmatch(self.payment_method):
            raise RazorpayReadError("provider_payment_response_invalid")
        failure_facts = (self.error_source, self.error_step, self.error_reason)
        if self.status is PaymentStatus.FAILED:
            if any(
                value is None or not _MACHINE_FACT_RE.fullmatch(value) for value in failure_facts
            ):
                raise RazorpayReadError("provider_payment_response_invalid")
            if self.captured_minor or self.refunded_minor:
                raise RazorpayReadError("provider_payment_response_invalid")
        elif any(value is not None for value in failure_facts):
            raise RazorpayReadError("provider_payment_response_invalid")
        if self.created_at_epoch is not None and (
            type(self.created_at_epoch) is not int or self.created_at_epoch <= 0
        ):
            raise RazorpayReadError("provider_payment_response_invalid")
        if self.status in {PaymentStatus.CREATED, PaymentStatus.AUTHORIZED} and (
            self.captured_minor or self.refunded_minor
        ):
            raise RazorpayReadError("provider_payment_response_invalid")
        if (
            self.status in {PaymentStatus.CAPTURED, PaymentStatus.REFUNDED}
            and not self.captured_minor
        ):
            raise RazorpayReadError("provider_payment_response_invalid")
        if self.status is PaymentStatus.REFUNDED and not self.refunded_minor:
            raise RazorpayReadError("provider_payment_response_invalid")

    @classmethod
    def from_provider(cls, value: object) -> PaymentRecord:
        if not isinstance(value, Mapping):
            raise RazorpayReadError("provider_payment_response_invalid")
        try:
            payment_id = value["id"]
            order_id = value["order_id"]
            raw_status = value["status"]
            amount = value["amount"]
            currency = value["currency"]
            amount_refunded = value.get("amount_refunded", 0)
            captured = value.get("captured", False)
            method = value["method"]
            created_at = value.get("created_at")
            if (
                type(payment_id) is not str
                or type(order_id) is not str
                or type(raw_status) is not str
                or type(amount) is not int
                or type(currency) is not str
                or type(amount_refunded) is not int
                or type(captured) is not bool
                or type(method) is not str
                or (created_at is not None and type(created_at) is not int)
            ):
                raise ValueError
            status = PaymentStatus(raw_status)
            if captured is not (status in {PaymentStatus.CAPTURED, PaymentStatus.REFUNDED}):
                raise ValueError
            captured_minor = (
                amount
                if captured or status in {PaymentStatus.CAPTURED, PaymentStatus.REFUNDED}
                else 0
            )
            facts: tuple[str | None, str | None, str | None]
            if status is PaymentStatus.FAILED:
                parsed_facts = tuple(
                    _provider_machine_fact(value.get(name))
                    for name in ("error_source", "error_step", "error_reason")
                )
                facts = (parsed_facts[0], parsed_facts[1], parsed_facts[2])
            else:
                facts = (None, None, None)
            return cls(
                payment_id=payment_id,
                order_id=order_id,
                status=status,
                amount_minor=amount,
                currency=currency,
                captured_minor=captured_minor,
                refunded_minor=amount_refunded,
                payment_method=method,
                error_source=facts[0],
                error_step=facts[1],
                error_reason=facts[2],
                created_at_epoch=created_at,
            )
        except (KeyError, TypeError, ValueError, RazorpayReadError):
            raise RazorpayReadError("provider_payment_response_invalid") from None


@dataclass(frozen=True, slots=True)
class OrderRecord:
    """Strict non-sensitive projection of one Razorpay Order read."""

    order_id: str
    amount_minor: int
    amount_paid_minor: int
    amount_due_minor: int
    currency: str
    status: OrderStatus
    attempts: int
    created_at_epoch: int

    def __post_init__(self) -> None:
        if not _ORDER_ID_RE.fullmatch(self.order_id):
            raise RazorpayReadError("provider_order_response_invalid")
        if type(self.amount_minor) is not int or self.amount_minor <= 0:
            raise RazorpayReadError("provider_order_response_invalid")
        if (
            type(self.amount_paid_minor) is not int
            or type(self.amount_due_minor) is not int
            or not 0 <= self.amount_paid_minor <= self.amount_minor
            or not 0 <= self.amount_due_minor <= self.amount_minor
            or self.amount_paid_minor + self.amount_due_minor != self.amount_minor
        ):
            raise RazorpayReadError("provider_order_response_invalid")
        if not _CURRENCY_RE.fullmatch(self.currency):
            raise RazorpayReadError("provider_order_response_invalid")
        if not isinstance(self.status, OrderStatus):
            raise RazorpayReadError("provider_order_response_invalid")
        if type(self.attempts) is not int or self.attempts < 0:
            raise RazorpayReadError("provider_order_response_invalid")
        if type(self.created_at_epoch) is not int or self.created_at_epoch <= 0:
            raise RazorpayReadError("provider_order_response_invalid")
        if self.status is OrderStatus.PAID and (
            self.amount_paid_minor != self.amount_minor or self.amount_due_minor != 0
        ):
            raise RazorpayReadError("provider_order_response_invalid")
        if self.status is OrderStatus.CREATED and self.attempts != 0:
            raise RazorpayReadError("provider_order_response_invalid")

    @classmethod
    def from_provider(cls, value: object) -> OrderRecord:
        if not isinstance(value, Mapping):
            raise RazorpayReadError("provider_order_response_invalid")
        try:
            entity = value.get("entity")
            if entity is not None and entity != "order":
                raise ValueError
            order_id = value["id"]
            amount = value["amount"]
            amount_paid = value["amount_paid"]
            amount_due = value["amount_due"]
            currency = value["currency"]
            raw_status = value["status"]
            attempts = value["attempts"]
            created_at = value["created_at"]
            if (
                type(order_id) is not str
                or type(amount) is not int
                or type(amount_paid) is not int
                or type(amount_due) is not int
                or type(currency) is not str
                or type(raw_status) is not str
                or type(attempts) is not int
                or type(created_at) is not int
            ):
                raise ValueError
            return cls(
                order_id=order_id,
                amount_minor=amount,
                amount_paid_minor=amount_paid,
                amount_due_minor=amount_due,
                currency=currency,
                status=OrderStatus(raw_status),
                attempts=attempts,
                created_at_epoch=created_at,
            )
        except (KeyError, TypeError, ValueError, RazorpayReadError):
            raise RazorpayReadError("provider_order_response_invalid") from None


@dataclass(frozen=True, slots=True)
class PaymentLinkRecord:
    """Strict, non-sensitive projection of a Standard Payment Link response."""

    payment_link_id: str
    reference_id: str
    amount_minor: int
    amount_paid_minor: int
    currency: str
    accept_partial: bool
    upi_link: bool
    status: PaymentLinkStatus
    short_url: str | None = None

    def __post_init__(self) -> None:
        _validate_payment_link_id(self.payment_link_id)
        try:
            _clean_text(self.reference_id, field="reference_id", maximum=40)
        except ValueError as exc:
            raise PaymentLinkValidationError("reference_id is invalid") from exc
        if type(self.amount_minor) is not int or self.amount_minor <= 0:
            raise PaymentLinkValidationError("amount must be a positive integer")
        if (
            type(self.amount_paid_minor) is not int
            or self.amount_paid_minor < 0
            or self.amount_paid_minor > self.amount_minor
        ):
            raise PaymentLinkValidationError("amount_paid must be between zero and amount")
        if not isinstance(self.currency, str) or not _CURRENCY_RE.fullmatch(self.currency):
            raise PaymentLinkValidationError("currency must be an uppercase three-letter code")
        if type(self.accept_partial) is not bool or type(self.upi_link) is not bool:
            raise PaymentLinkValidationError("link-mode flags must be booleans")
        if not isinstance(self.status, PaymentLinkStatus):
            raise PaymentLinkValidationError("status is invalid")
        if self.status is PaymentLinkStatus.PAID:
            if self.amount_paid_minor != self.amount_minor:
                raise PaymentLinkValidationError("paid link must have its full amount paid")
        elif self.status is PaymentLinkStatus.PARTIALLY_PAID:
            if not 0 < self.amount_paid_minor < self.amount_minor:
                raise PaymentLinkValidationError(
                    "partially paid link must have a proper partial amount"
                )
        elif self.amount_paid_minor != 0:
            raise PaymentLinkValidationError(
                "created, cancelled, or expired no-partial link cannot have an amount paid"
            )
        if self.short_url is not None:
            _validate_short_url(self.short_url)

    @classmethod
    def from_provider(cls, value: object) -> PaymentLinkRecord:
        if not isinstance(value, Mapping):
            raise PaymentLinkValidationError("provider Payment Link must be an object")
        status = value.get("status")
        if not isinstance(status, str) or status not in _KNOWN_STATUSES:
            raise PaymentLinkValidationError("provider Payment Link status is invalid")
        try:
            parsed_status = PaymentLinkStatus(status)
        except ValueError as exc:  # pragma: no cover - guarded by the closed set
            raise PaymentLinkValidationError("provider Payment Link status is invalid") from exc
        short_url = value.get("short_url")
        if short_url is not None and not isinstance(short_url, str):
            raise PaymentLinkValidationError("provider Payment Link short_url is invalid")
        payment_link_id = value.get("id")
        reference_id = value.get("reference_id")
        amount_minor = value.get("amount")
        amount_paid_minor = value.get("amount_paid")
        currency = value.get("currency")
        accept_partial = value.get("accept_partial")
        upi_link = value.get("upi_link")
        if not isinstance(payment_link_id, str):
            raise PaymentLinkValidationError("provider Payment Link id is invalid")
        if not isinstance(reference_id, str):
            raise PaymentLinkValidationError("provider Payment Link reference_id is invalid")
        if type(amount_minor) is not int:
            raise PaymentLinkValidationError("provider Payment Link amount is invalid")
        if type(amount_paid_minor) is not int:
            raise PaymentLinkValidationError("provider Payment Link amount_paid is invalid")
        if not isinstance(currency, str):
            raise PaymentLinkValidationError("provider Payment Link currency is invalid")
        if type(accept_partial) is not bool or type(upi_link) is not bool:
            raise PaymentLinkValidationError("provider Payment Link mode is invalid")
        return cls(
            payment_link_id=payment_link_id,
            reference_id=reference_id,
            amount_minor=amount_minor,
            amount_paid_minor=amount_paid_minor,
            currency=currency,
            accept_partial=accept_partial,
            upi_link=upi_link,
            status=parsed_status,
            short_url=short_url,
        )

    def matches_create(self, request: StandardPaymentLinkRequest) -> bool:
        if not isinstance(request, StandardPaymentLinkRequest):
            raise TypeError("request must be StandardPaymentLinkRequest")
        return (
            self.reference_id == request.reference_id
            and self.amount_minor == request.amount_minor
            and self.currency == request.currency
            and self.accept_partial is False
            and self.upi_link is False
        )

    def to_reconciliation_candidate(self) -> dict[str, object]:
        """Return only fields required by ``decide_ambiguous_create``."""

        return {
            "id": self.payment_link_id,
            "reference_id": self.reference_id,
            "amount": self.amount_minor,
            "currency": self.currency,
            "accept_partial": self.accept_partial,
            "upi_link": self.upi_link,
            "status": self.status.value,
        }


@dataclass(frozen=True, slots=True)
class ProviderCancelOutcome:
    status: ProviderCancelStatus
    reason_code: str
    payment_link: PaymentLinkRecord | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ProviderCancelStatus):
            raise TypeError("status must be ProviderCancelStatus")
        _clean_text(self.reason_code, field="reason_code", maximum=128)
        if self.status is ProviderCancelStatus.CERTAIN_SUCCESS:
            if not isinstance(self.payment_link, PaymentLinkRecord):
                raise ValueError("certain cancellation success requires a Payment Link")
            if self.payment_link.status is not PaymentLinkStatus.CANCELLED:
                raise ValueError("certain cancellation success requires cancelled provider state")
        elif self.payment_link is not None:
            raise ValueError("only certain cancellation success may contain a Payment Link")


class _MalformedProviderResponse(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _BufferedResponse:
    """Bounded response copy that deliberately drops the authenticated request."""

    status_code: int
    headers: Mapping[str, str]
    content: bytes


def _clean_text(value: object, *, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or _CONTROL_RE.search(value)
    ):
        raise ValueError(f"{field} must be clean, non-empty text")
    return value


def _validate_payment_link_id(value: object) -> str:
    if not isinstance(value, str) or not _PAYMENT_LINK_ID_RE.fullmatch(value):
        raise PaymentLinkValidationError("payment_link_id is invalid")
    return value


def _validate_reference_id(value: object) -> str:
    try:
        return _clean_text(value, field="reference_id", maximum=40)
    except ValueError as exc:
        raise PaymentLinkValidationError("reference_id is invalid") from exc


def _validate_short_url(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or not value.startswith("https://rzp.io/")
        or _CONTROL_RE.search(value)
    ):
        raise PaymentLinkValidationError("short_url is not a trusted Razorpay HTTPS URL")


def _decode_object(response: _BufferedResponse) -> Mapping[str, Any]:
    content = response.content
    if len(content) > _MAX_RESPONSE_BYTES:
        raise _MalformedProviderResponse("response_too_large")
    content_type = response.headers.get("content-type", "").lower().split(";", 1)[0].strip()
    if content_type != "application/json" and not content_type.endswith("+json"):
        raise _MalformedProviderResponse("response_content_type_invalid")
    try:
        decoded = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _MalformedProviderResponse("response_json_invalid") from exc
    if not isinstance(decoded, Mapping):
        raise _MalformedProviderResponse("response_shape_invalid")
    return decoded


def _error_description(response: _BufferedResponse) -> str:
    """Read an error description for classification only; never return or log it."""

    try:
        decoded = _decode_object(response)
    except _MalformedProviderResponse:
        return ""
    error = decoded.get("error")
    if not isinstance(error, Mapping):
        return ""
    description = error.get("description")
    if not isinstance(description, str):
        return ""
    return description.casefold()


def _is_duplicate_reference(response: _BufferedResponse) -> bool:
    if response.status_code != 400:
        return False
    description = _error_description(response)
    return "reference" in description and (
        "already exists" in description or "given reference_id" in description
    )


def _is_update_in_progress(response: _BufferedResponse) -> bool:
    description = _error_description(response)
    return "update" in description and "progress" in description


def _transport_reason(exc: httpx.TransportError) -> str:
    if isinstance(exc, httpx.ConnectTimeout):
        return "provider_connect_timeout_unknown_outcome"
    if isinstance(exc, httpx.ReadTimeout):
        return "provider_read_timeout_unknown_outcome"
    if isinstance(exc, httpx.WriteTimeout):
        return "provider_write_timeout_unknown_outcome"
    if isinstance(exc, httpx.PoolTimeout):
        return "provider_pool_timeout_before_request"
    if isinstance(exc, httpx.TimeoutException):
        return "provider_timeout_unknown_outcome"
    return "provider_transport_unknown_outcome"


def _provider_machine_fact(value: object) -> str:
    if type(value) is str and _MACHINE_FACT_RE.fullmatch(value):
        return value
    return "unknown"


class RazorpayTestModePaymentLinkAdapter:
    """Synchronous, executor-compatible Standard Payment Link adapter.

    ``transport`` exists for deterministic tests and controlled network stacks;
    request URLs remain pinned to ``https://api.razorpay.com`` regardless of the
    injected transport.  The adapter owns and closes its internal HTTP client.
    """

    def __init__(
        self,
        *,
        key_id: str,
        key_secret: str,
        provider_account_id: str,
        transport: httpx.BaseTransport | None = None,
        epoch_clock: Callable[[], int] | None = None,
    ) -> None:
        _clean_text(key_id, field="key_id", maximum=128)
        if key_id.startswith("rzp_live_"):
            raise ValueError("live Razorpay credentials are out of scope")
        if not key_id.startswith("rzp_test_"):
            raise ValueError("Razorpay key id must be a test key")
        _clean_text(key_secret, field="key_secret", maximum=256)
        self._provider_account_id = _clean_text(
            provider_account_id,
            field="provider_account_id",
            maximum=128,
        )
        if epoch_clock is not None and not callable(epoch_clock):
            raise TypeError("epoch_clock must be callable")
        self._epoch_clock = epoch_clock or (lambda: int(time.time()))
        if transport is None:
            transport = httpx.HTTPTransport(
                retries=0,
                limits=httpx.Limits(
                    max_connections=20,
                    max_keepalive_connections=10,
                    keepalive_expiry=15.0,
                ),
            )
        self._client = httpx.Client(
            base_url=_API_ORIGIN,
            auth=httpx.BasicAuth(key_id, key_secret),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "RetryWise/0.1 Razorpay-Test-Mode",
            },
            timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=1.0),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )
        self._closed = False

    def __repr__(self) -> str:
        return (
            "RazorpayTestModePaymentLinkAdapter("
            f"test_mode=True, internal_account_pinned=True, closed={self._closed})"
        )

    def __enter__(self) -> Self:
        self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._client.close()
            self._closed = True

    def create_standard_payment_link(
        self,
        request: StandardPaymentLinkRequest,
        *,
        provider_account_id: str,
    ) -> ProviderCreateOutcome:
        self._assert_account(provider_account_id)
        if not isinstance(request, StandardPaymentLinkRequest):
            raise TypeError("request must be StandardPaymentLinkRequest")
        now_epoch = self._now_epoch()
        payload = request.to_payload(now_epoch=now_epoch)
        try:
            response = self._request("POST", _PAYMENT_LINKS_PATH, json_body=payload)
        except _MalformedProviderResponse:
            return ProviderCreateOutcome.ambiguous("provider_create_response_invalid")
        except httpx.PoolTimeout as exc:
            return ProviderCreateOutcome.failed_safely(_transport_reason(exc))
        except httpx.TransportError as exc:
            return ProviderCreateOutcome.ambiguous(_transport_reason(exc))

        if response.status_code == 200:
            try:
                record = PaymentLinkRecord.from_provider(_decode_object(response))
            except (PaymentLinkValidationError, _MalformedProviderResponse):
                return ProviderCreateOutcome.ambiguous("provider_create_response_invalid")
            if not record.matches_create(request):
                return ProviderCreateOutcome.ambiguous("provider_create_response_conflicts")
            return ProviderCreateOutcome.succeeded(record.payment_link_id)

        if _is_duplicate_reference(response):
            return ProviderCreateOutcome.ambiguous("provider_reference_exists_requires_lookup")
        if response.status_code in _CERTAIN_REJECT_STATUSES:
            return ProviderCreateOutcome.failed_safely(
                f"provider_rejected_create_http_{response.status_code}"
            )
        return ProviderCreateOutcome.ambiguous(
            f"provider_create_http_{response.status_code}_unknown_outcome"
        )

    def lookup_payment_links(
        self,
        *,
        reference_id: str,
        provider_account_id: str,
    ) -> PaymentLinkLookupResult:
        """Executor port: any failed or malformed read is explicitly incomplete."""

        try:
            records = self.list_payment_links_by_reference(
                reference_id=reference_id,
                provider_account_id=provider_account_id,
            )
        except RazorpayReadError:
            return PaymentLinkLookupResult(completed=False)
        return PaymentLinkLookupResult(
            completed=True,
            candidates=tuple(record.to_reconciliation_candidate() for record in records),
        )

    def list_payment_links_by_reference(
        self,
        *,
        reference_id: str,
        provider_account_id: str,
    ) -> tuple[PaymentLinkRecord, ...]:
        self._assert_account(provider_account_id)
        reference_id = _validate_reference_id(reference_id)
        response = self._read(
            _PAYMENT_LINKS_PATH,
            params={"reference_id": reference_id},
        )
        try:
            decoded = _decode_object(response)
        except _MalformedProviderResponse:
            raise RazorpayReadError("provider_lookup_response_invalid") from None
        raw_links = decoded.get("payment_links")
        if not isinstance(raw_links, list) or len(raw_links) > _MAX_LOOKUP_CANDIDATES:
            raise RazorpayReadError("provider_lookup_response_invalid")
        try:
            records = tuple(PaymentLinkRecord.from_provider(item) for item in raw_links)
        except PaymentLinkValidationError:
            raise RazorpayReadError("provider_lookup_candidate_invalid") from None
        if any(record.reference_id != reference_id for record in records):
            raise RazorpayReadError("provider_lookup_reference_mismatch")
        return records

    def fetch_payment_link(
        self,
        *,
        payment_link_id: str,
        provider_account_id: str,
    ) -> PaymentLinkRecord:
        self._assert_account(provider_account_id)
        payment_link_id = _validate_payment_link_id(payment_link_id)
        response = self._read(f"{_PAYMENT_LINKS_PATH}/{payment_link_id}")
        try:
            record = PaymentLinkRecord.from_provider(_decode_object(response))
        except (PaymentLinkValidationError, _MalformedProviderResponse):
            raise RazorpayReadError("provider_fetch_response_invalid") from None
        if not hmac.compare_digest(record.payment_link_id, payment_link_id):
            raise RazorpayReadError("provider_fetch_id_mismatch")
        return record

    def fetch_payment(
        self,
        *,
        payment_id: str,
        provider_account_id: str,
    ) -> PaymentRecord:
        """Fetch current payment truth while discarding customer/provider free text."""

        self._assert_account(provider_account_id)
        if type(payment_id) is not str or not _PAYMENT_ID_RE.fullmatch(payment_id):
            raise RazorpayReadError("provider_payment_id_invalid")
        response = self._read(f"{_PAYMENTS_PATH}/{payment_id}")
        try:
            record = PaymentRecord.from_provider(_decode_object(response))
        except RazorpayReadError:
            raise
        except Exception:
            raise RazorpayReadError("provider_payment_response_invalid") from None
        if not hmac.compare_digest(record.payment_id, payment_id):
            raise RazorpayReadError("provider_payment_id_mismatch")
        return record

    def fetch_order(
        self,
        *,
        order_id: str,
        provider_account_id: str,
    ) -> OrderRecord:
        """Fetch current order totals without retaining receipt, notes, or customer data."""

        self._assert_account(provider_account_id)
        if type(order_id) is not str or not _ORDER_ID_RE.fullmatch(order_id):
            raise RazorpayReadError("provider_order_id_invalid")
        response = self._read(f"{_ORDERS_PATH}/{order_id}")
        try:
            record = OrderRecord.from_provider(_decode_object(response))
        except RazorpayReadError:
            raise
        except Exception:
            raise RazorpayReadError("provider_order_response_invalid") from None
        if not hmac.compare_digest(record.order_id, order_id):
            raise RazorpayReadError("provider_order_id_mismatch")
        return record

    def cancel_payment_link(
        self,
        *,
        payment_link_id: str,
        provider_account_id: str,
    ) -> ProviderCancelOutcome:
        self._assert_account(provider_account_id)
        payment_link_id = _validate_payment_link_id(payment_link_id)
        try:
            response = self._request(
                "POST",
                f"{_PAYMENT_LINKS_PATH}/{payment_link_id}/cancel",
            )
        except _MalformedProviderResponse:
            return ProviderCancelOutcome(
                ProviderCancelStatus.AMBIGUOUS,
                "provider_cancel_response_invalid",
            )
        except httpx.PoolTimeout as exc:
            return ProviderCancelOutcome(
                ProviderCancelStatus.CERTAIN_FAILURE,
                _transport_reason(exc),
            )
        except httpx.TransportError as exc:
            return ProviderCancelOutcome(
                ProviderCancelStatus.AMBIGUOUS,
                _transport_reason(exc),
            )

        if response.status_code == 200:
            try:
                record = PaymentLinkRecord.from_provider(_decode_object(response))
            except (PaymentLinkValidationError, _MalformedProviderResponse):
                return ProviderCancelOutcome(
                    ProviderCancelStatus.AMBIGUOUS,
                    "provider_cancel_response_invalid",
                )
            if (
                not hmac.compare_digest(record.payment_link_id, payment_link_id)
                or record.status is not PaymentLinkStatus.CANCELLED
            ):
                return ProviderCancelOutcome(
                    ProviderCancelStatus.AMBIGUOUS,
                    "provider_cancel_response_conflicts",
                )
            return ProviderCancelOutcome(
                ProviderCancelStatus.CERTAIN_SUCCESS,
                "provider_confirmed_cancel",
                record,
            )

        if _is_update_in_progress(response):
            return ProviderCancelOutcome(
                ProviderCancelStatus.AMBIGUOUS,
                "provider_cancel_update_in_progress",
            )
        if response.status_code in _CERTAIN_REJECT_STATUSES:
            return ProviderCancelOutcome(
                ProviderCancelStatus.CERTAIN_FAILURE,
                f"provider_rejected_cancel_http_{response.status_code}",
            )
        return ProviderCancelOutcome(
            ProviderCancelStatus.AMBIGUOUS,
            f"provider_cancel_http_{response.status_code}_unknown_outcome",
        )

    def _read(
        self,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> _BufferedResponse:
        try:
            response = self._request("GET", path, params=params)
        except _MalformedProviderResponse:
            raise RazorpayReadError("provider_read_response_too_large") from None
        except httpx.TransportError as exc:
            reason = _transport_reason(exc).replace("_unknown_outcome", "")
            raise RazorpayReadError(reason) from None
        if response.status_code != 200:
            raise RazorpayReadError(f"provider_read_http_{response.status_code}")
        return response

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> _BufferedResponse:
        """Read at most the configured cap and discard request/auth metadata."""

        with self._client.stream(
            method,
            path,
            json=json_body,
            params=params,
        ) as response:
            raw_length = response.headers.get("content-length")
            if raw_length is not None:
                try:
                    declared_length = int(raw_length)
                except ValueError as exc:
                    raise _MalformedProviderResponse("response_content_length_invalid") from exc
                if declared_length < 0 or declared_length > _MAX_RESPONSE_BYTES:
                    raise _MalformedProviderResponse("response_too_large")
            content = bytearray()
            for chunk in response.iter_bytes():
                content.extend(chunk)
                if len(content) > _MAX_RESPONSE_BYTES:
                    raise _MalformedProviderResponse("response_too_large")
            return _BufferedResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                content=bytes(content),
            )

    def _assert_account(self, provider_account_id: str) -> None:
        self._ensure_open()
        try:
            candidate = _clean_text(
                provider_account_id,
                field="provider_account_id",
                maximum=128,
            )
        except ValueError as exc:
            raise ProviderAccountMismatchError("provider_account_binding_mismatch") from exc
        if not hmac.compare_digest(candidate, self._provider_account_id):
            raise ProviderAccountMismatchError("provider_account_binding_mismatch")

    def _ensure_open(self) -> None:
        if self._closed:
            raise RazorpayAdapterError("provider_adapter_closed")

    def _now_epoch(self) -> int:
        value = self._epoch_clock()
        if type(value) is not int or value < 0:
            raise ValueError("epoch_clock must return a non-negative integer")
        return value


__all__ = [
    "OrderRecord",
    "OrderStatus",
    "PaymentLinkRecord",
    "PaymentLinkStatus",
    "PaymentRecord",
    "PaymentStatus",
    "ProviderAccountMismatchError",
    "ProviderCancelOutcome",
    "ProviderCancelStatus",
    "RazorpayAdapterError",
    "RazorpayReadError",
    "RazorpayTestModePaymentLinkAdapter",
]
