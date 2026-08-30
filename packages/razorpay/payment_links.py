"""Validated Standard Payment Link commands and create reconciliation."""

from __future__ import annotations

import calendar
import copy
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_LINK_STATUSES = {"created", "partially_paid", "expired", "cancelled", "paid"}
_MIN_EXPIRY_LEAD_SECONDS = 15 * 60


class PaymentLinkValidationError(ValueError):
    """A command or provider candidate violates the Payment Link contract."""


def _strict_positive_int(value: Any, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise PaymentLinkValidationError(f"{field_name} must be a positive integer in minor units")
    return value


def _clean_text(value: Any, field_name: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PaymentLinkValidationError(f"{field_name} must be a non-empty string")
    if len(value) > maximum:
        raise PaymentLinkValidationError(f"{field_name} exceeds {maximum} characters")
    if _CONTROL_RE.search(value):
        raise PaymentLinkValidationError(f"{field_name} contains control characters")
    return value


def _six_calendar_months_after(epoch: int) -> int:
    now = datetime.fromtimestamp(epoch, tz=UTC)
    month_index = (now.month - 1) + 6
    target_year = now.year + month_index // 12
    target_month = month_index % 12 + 1
    target_day = min(now.day, calendar.monthrange(target_year, target_month)[1])
    return int(now.replace(year=target_year, month=target_month, day=target_day).timestamp())


@dataclass(frozen=True)
class PaymentLinkCustomer:
    name: str
    contact: str | None = None
    email: str | None = None

    def __post_init__(self) -> None:
        _clean_text(self.name, "customer.name", maximum=256)
        if self.contact is not None:
            _clean_text(self.contact, "customer.contact", maximum=64)
        if self.email is not None:
            _clean_text(self.email, "customer.email", maximum=254)

    def to_payload(self) -> dict[str, str]:
        payload = {"name": self.name}
        if self.contact is not None:
            payload["contact"] = self.contact
        if self.email is not None:
            payload["email"] = self.email
        return payload


@dataclass(frozen=True)
class StandardPaymentLinkRequest:
    """Only the safe RetryWise subset of Razorpay's create request."""

    amount_minor: int
    currency: str
    reference_id: str
    description: str
    expire_by_epoch: int
    notes: Mapping[str, str] = field(default_factory=dict)
    customer: PaymentLinkCustomer | None = None

    def __post_init__(self) -> None:
        _strict_positive_int(self.amount_minor, "amount_minor")
        if not isinstance(self.currency, str) or not _CURRENCY_RE.fullmatch(self.currency):
            raise PaymentLinkValidationError("currency must be an uppercase three-letter ISO code")
        _clean_text(self.reference_id, "reference_id", maximum=40)
        _clean_text(self.description, "description", maximum=2048)
        if type(self.expire_by_epoch) is not int or self.expire_by_epoch <= 0:
            raise PaymentLinkValidationError("expire_by_epoch must be a positive integer epoch")
        if not isinstance(self.notes, Mapping):
            raise PaymentLinkValidationError("notes must be a mapping")
        if len(self.notes) > 15:
            raise PaymentLinkValidationError("notes cannot contain more than 15 items")
        copied_notes: dict[str, str] = {}
        for key, value in self.notes.items():
            clean_key = _clean_text(key, "notes key", maximum=256)
            clean_value = _clean_text(value, f"notes[{clean_key}]", maximum=256)
            copied_notes[clean_key] = clean_value
        object.__setattr__(self, "notes", MappingProxyType(copied_notes))
        if self.customer is not None and not isinstance(self.customer, PaymentLinkCustomer):
            raise PaymentLinkValidationError("customer must be PaymentLinkCustomer when supplied")

    def validate_expiry(self, *, now_epoch: int) -> None:
        if type(now_epoch) is not int or now_epoch < 0:
            raise PaymentLinkValidationError("now_epoch must be a non-negative integer epoch")
        if self.expire_by_epoch < now_epoch + _MIN_EXPIRY_LEAD_SECONDS:
            raise PaymentLinkValidationError(
                "expire_by_epoch must be at least 15 minutes in the future"
            )
        if self.expire_by_epoch > _six_calendar_months_after(now_epoch):
            raise PaymentLinkValidationError(
                "expire_by_epoch cannot be more than six calendar months ahead"
            )

    def to_payload(self, *, now_epoch: int | None = None) -> dict[str, Any]:
        if now_epoch is not None:
            self.validate_expiry(now_epoch=now_epoch)
        payload: dict[str, Any] = {
            "amount": self.amount_minor,
            "currency": self.currency,
            "accept_partial": False,
            "upi_link": False,
            "reference_id": self.reference_id,
            "description": self.description,
            "expire_by": self.expire_by_epoch,
            "notify": {"sms": False, "email": False},
            "reminder_enable": False,
            "notes": dict(self.notes),
        }
        if self.customer is not None:
            payload["customer"] = self.customer.to_payload()
        return payload

    def to_json_bytes(self, *, now_epoch: int | None = None) -> bytes:
        return json.dumps(
            self.to_payload(now_epoch=now_epoch),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


@dataclass(frozen=True)
class PaymentLinkLookupResult:
    """Result of fetching Payment Links by the stable reference id."""

    completed: bool
    candidates: Sequence[Mapping[str, Any]] = ()

    def __post_init__(self) -> None:
        if type(self.completed) is not bool:
            raise TypeError("completed must be bool")
        if not self.completed and self.candidates:
            raise ValueError("an incomplete lookup cannot contain candidates")
        copied_candidates = tuple(copy.deepcopy(candidate) for candidate in self.candidates)
        object.__setattr__(self, "candidates", copied_candidates)


class AmbiguousCreateAction(StrEnum):
    ADOPT_EXISTING = "adopt_existing"
    RETRY_CREATE_SAME_REFERENCE = "retry_create_same_reference"
    REQUERY = "requery"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class AmbiguousCreateDecision:
    action: AmbiguousCreateAction
    reason_code: str
    payment_link_id: str | None = None


@dataclass(frozen=True)
class _PaymentLinkSnapshot:
    payment_link_id: str
    reference_id: str
    amount_minor: int
    currency: str
    accept_partial: bool
    upi_link: bool
    status: str

    @classmethod
    def from_mapping(cls, candidate: Mapping[str, Any]) -> _PaymentLinkSnapshot:
        if not isinstance(candidate, Mapping):
            raise PaymentLinkValidationError("provider candidate must be an object")
        payment_link_id = _clean_text(candidate.get("id"), "candidate.id", maximum=128)
        reference_id = _clean_text(
            candidate.get("reference_id"), "candidate.reference_id", maximum=40
        )
        amount_minor = _strict_positive_int(candidate.get("amount"), "candidate.amount")
        currency = candidate.get("currency")
        if not isinstance(currency, str) or not _CURRENCY_RE.fullmatch(currency):
            raise PaymentLinkValidationError("candidate.currency is invalid")
        accept_partial = candidate.get("accept_partial")
        upi_link = candidate.get("upi_link")
        if type(accept_partial) is not bool or type(upi_link) is not bool:
            raise PaymentLinkValidationError("candidate link-mode flags must be booleans")
        status = candidate.get("status")
        if not isinstance(status, str) or status not in _LINK_STATUSES:
            raise PaymentLinkValidationError("candidate.status is invalid")
        return cls(
            payment_link_id=payment_link_id,
            reference_id=reference_id,
            amount_minor=amount_minor,
            currency=currency,
            accept_partial=accept_partial,
            upi_link=upi_link,
            status=status,
        )

    def matches(self, request: StandardPaymentLinkRequest) -> bool:
        return (
            self.reference_id == request.reference_id
            and self.amount_minor == request.amount_minor
            and self.currency == request.currency
            and self.accept_partial is False
            and self.upi_link is False
        )


def decide_ambiguous_create(
    request: StandardPaymentLinkRequest,
    lookup: PaymentLinkLookupResult,
) -> AmbiguousCreateDecision:
    """Fail-safe decision after a create timeout or indeterminate response.

    A new create is permitted only after a *completed* lookup proves that no
    link exists for the same stable reference.  Conflicting or duplicate
    candidates require human/operator investigation.
    """

    if not isinstance(request, StandardPaymentLinkRequest):
        raise TypeError("request must be StandardPaymentLinkRequest")
    if not isinstance(lookup, PaymentLinkLookupResult):
        raise TypeError("lookup must be PaymentLinkLookupResult")
    if not lookup.completed:
        return AmbiguousCreateDecision(AmbiguousCreateAction.REQUERY, "lookup_not_completed")
    if not lookup.candidates:
        return AmbiguousCreateDecision(
            AmbiguousCreateAction.RETRY_CREATE_SAME_REFERENCE,
            "completed_lookup_found_no_link",
        )
    if len(lookup.candidates) != 1:
        return AmbiguousCreateDecision(
            AmbiguousCreateAction.ESCALATE,
            "multiple_links_found_for_unique_reference",
        )
    try:
        snapshot = _PaymentLinkSnapshot.from_mapping(lookup.candidates[0])
    except PaymentLinkValidationError:
        return AmbiguousCreateDecision(
            AmbiguousCreateAction.ESCALATE, "malformed_provider_candidate"
        )
    if not snapshot.matches(request):
        return AmbiguousCreateDecision(
            AmbiguousCreateAction.ESCALATE,
            "provider_candidate_conflicts_with_command",
            payment_link_id=snapshot.payment_link_id,
        )
    return AmbiguousCreateDecision(
        AmbiguousCreateAction.ADOPT_EXISTING,
        "matching_link_proves_create_succeeded",
        payment_link_id=snapshot.payment_link_id,
    )
