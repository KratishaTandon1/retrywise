"""Signature verification and canonical Razorpay webhook normalisation."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

_SIGNATURE_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_BASE_ENTITY_FIELDS = frozenset({"id", "entity", "status", "created_at"})
_ENTITY_FIELD_ALLOWLIST = {
    "payment": _BASE_ENTITY_FIELDS
    | {
        "amount",
        "amount_refunded",
        "captured",
        "currency",
        "error_code",
        "error_reason",
        "error_source",
        "error_step",
        "invoice_id",
        "method",
        "order_id",
        "refund_status",
    },
    "order": _BASE_ENTITY_FIELDS
    | {
        "amount",
        "amount_due",
        "amount_paid",
        "attempts",
        "currency",
    },
    "payment_link": _BASE_ENTITY_FIELDS
    | {
        "accept_partial",
        "amount",
        "amount_paid",
        "cancelled_at",
        "currency",
        "expire_by",
        "expired_at",
        "order_id",
        "reference_id",
        "upi_link",
    },
    "payment.downtime": _BASE_ENTITY_FIELDS
    | {
        "bank",
        "issuer",
        "method",
        "network",
        "resolved_at",
        "scheduled",
        "severity",
    },
}


class WebhookVerificationError(ValueError):
    """The webhook authenticity check failed."""


class WebhookDecodeError(ValueError):
    """A verified webhook does not satisfy the provider contract."""


class AccountMismatchError(WebhookDecodeError):
    """The signed payload belongs to a different provider account."""


class CanonicalEventType(StrEnum):
    PAYMENT_FAILED = "payment.failed"
    PAYMENT_CAPTURED = "payment.captured"
    PAYMENT_AUTHORIZED = "payment.authorized"
    ORDER_PAID = "order.paid"
    PAYMENT_DOWNTIME_STARTED = "payment.downtime.started"
    PAYMENT_DOWNTIME_UPDATED = "payment.downtime.updated"
    PAYMENT_DOWNTIME_RESOLVED = "payment.downtime.resolved"
    PAYMENT_LINK_PAID = "payment_link.paid"
    PAYMENT_LINK_PARTIALLY_PAID = "payment_link.partially_paid"
    PAYMENT_LINK_CANCELLED = "payment_link.cancelled"
    PAYMENT_LINK_EXPIRED = "payment_link.expired"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class _EventSpec:
    canonical_type: CanonicalEventType
    payload_key: str
    resource_type: str


_EVENT_SPECS = {
    "payment.failed": _EventSpec(CanonicalEventType.PAYMENT_FAILED, "payment", "payment"),
    "payment.captured": _EventSpec(CanonicalEventType.PAYMENT_CAPTURED, "payment", "payment"),
    "payment.authorized": _EventSpec(CanonicalEventType.PAYMENT_AUTHORIZED, "payment", "payment"),
    "order.paid": _EventSpec(CanonicalEventType.ORDER_PAID, "order", "order"),
    "payment.downtime.started": _EventSpec(
        CanonicalEventType.PAYMENT_DOWNTIME_STARTED,
        "payment.downtime",
        "payment.downtime",
    ),
    "payment.downtime.updated": _EventSpec(
        CanonicalEventType.PAYMENT_DOWNTIME_UPDATED,
        "payment.downtime",
        "payment.downtime",
    ),
    "payment.downtime.resolved": _EventSpec(
        CanonicalEventType.PAYMENT_DOWNTIME_RESOLVED,
        "payment.downtime",
        "payment.downtime",
    ),
    "payment_link.paid": _EventSpec(
        CanonicalEventType.PAYMENT_LINK_PAID, "payment_link", "payment_link"
    ),
    "payment_link.partially_paid": _EventSpec(
        CanonicalEventType.PAYMENT_LINK_PARTIALLY_PAID,
        "payment_link",
        "payment_link",
    ),
    "payment_link.cancelled": _EventSpec(
        CanonicalEventType.PAYMENT_LINK_CANCELLED,
        "payment_link",
        "payment_link",
    ),
    "payment_link.expired": _EventSpec(
        CanonicalEventType.PAYMENT_LINK_EXPIRED,
        "payment_link",
        "payment_link",
    ),
}


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise WebhookDecodeError("webhook JSON contains a duplicate object key")
        decoded[key] = value
    return decoded


@dataclass(frozen=True)
class WebhookHeaders:
    """Security-relevant Razorpay request headers."""

    signature: str
    event_id: str

    @classmethod
    def from_mapping(cls, headers: Mapping[str, str]) -> WebhookHeaders:
        lowered = {str(key).lower(): value for key, value in headers.items()}
        signature = lowered.get("x-razorpay-signature")
        event_id = lowered.get("x-razorpay-event-id")
        if not isinstance(signature, str) or not signature.strip():
            raise WebhookVerificationError("missing X-Razorpay-Signature header")
        if not isinstance(event_id, str) or not event_id.strip():
            raise WebhookDecodeError("missing x-razorpay-event-id header")
        if event_id != event_id.strip() or len(event_id) > 256:
            raise WebhookDecodeError("invalid x-razorpay-event-id header")
        return cls(signature=signature, event_id=event_id)


@dataclass(frozen=True)
class CanonicalWebhookEvent:
    """Versioned, immutable representation consumed by RetryWise.

    ``resource`` and ``related_resources`` are deeply read-only.  ``to_dict``
    returns ordinary JSON-compatible containers for persistence.
    """

    event_id: str
    provider_account_id: str
    event_name: str
    event_type: CanonicalEventType
    occurred_at_epoch: int
    resource_type: str
    resource_id: str | None
    resource: Mapping[str, Any]
    related_resources: Mapping[str, Mapping[str, Any]]
    raw_body_sha256: str
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "provider_account_id": self.provider_account_id,
            "event_name": self.event_name,
            "event_type": self.event_type.value,
            "occurred_at_epoch": self.occurred_at_epoch,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource": _thaw_json(self.resource),
            "related_resources": _thaw_json(self.related_resources),
            "raw_body_sha256": self.raw_body_sha256,
        }


def _require_raw_bytes(raw_body: bytes) -> None:
    if not isinstance(raw_body, bytes):
        raise TypeError("raw_body must be exact bytes received from Razorpay")


def _normalise_secret(secret: bytes) -> bytes:
    if not isinstance(secret, bytes):
        raise TypeError("webhook secrets must be supplied as bytes")
    if not secret:
        raise ValueError("webhook secret cannot be empty")
    return secret


def calculate_webhook_signature(raw_body: bytes, secret: bytes) -> str:
    """Return Razorpay's lowercase HMAC-SHA256 hexadecimal signature."""

    _require_raw_bytes(raw_body)
    key = _normalise_secret(secret)
    return hmac.new(key, raw_body, hashlib.sha256).hexdigest()


def is_valid_webhook_signature(raw_body: bytes, signature: str, secrets: Iterable[bytes]) -> bool:
    """Verify against current/previous secrets without re-encoding the body.

    All configured secrets are evaluated, even after a match, so rotation does
    not introduce a match-position timing shortcut.
    """

    _require_raw_bytes(raw_body)
    configured = tuple(_normalise_secret(secret) for secret in secrets)
    if not configured:
        raise ValueError("at least one webhook secret is required")

    signature_has_valid_shape = isinstance(signature, str) and bool(
        _SIGNATURE_RE.fullmatch(signature)
    )
    candidate = signature.lower() if signature_has_valid_shape else "0" * 64
    matched = False
    for secret in configured:
        expected = calculate_webhook_signature(raw_body, secret)
        matched = hmac.compare_digest(expected, candidate) | matched
    return bool(signature_has_valid_shape and matched)


def verify_webhook_signature(raw_body: bytes, signature: str, secrets: Iterable[bytes]) -> None:
    """Raise when an exact raw-body signature does not validate."""

    if not is_valid_webhook_signature(raw_body, signature, secrets):
        raise WebhookVerificationError("invalid Razorpay webhook signature")


def _required_string(container: Mapping[str, Any], field: str) -> str:
    value = container.get(field)
    if not isinstance(value, str) or not value or value != value.strip():
        raise WebhookDecodeError(f"{field} must be a non-empty string")
    return value


def _required_epoch(container: Mapping[str, Any], field: str) -> int:
    value = container.get(field)
    if type(value) is not int or value < 0:
        raise WebhookDecodeError(f"{field} must be a non-negative integer epoch")
    return value


def _extract_entity(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    wrapper = payload.get(key)
    if not isinstance(wrapper, Mapping):
        raise WebhookDecodeError(f"payload.{key} must be an object")
    entity = wrapper.get("entity")
    if not isinstance(entity, Mapping):
        raise WebhookDecodeError(f"payload.{key}.entity must be an object")
    return entity


def _sanitize_entity(resource_type: str, entity: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only structured operational fields; discard contact/credential data."""

    allowed = _ENTITY_FIELD_ALLOWLIST.get(resource_type, _BASE_ENTITY_FIELDS)
    sanitized: dict[str, Any] = {}
    for key in allowed:
        if key not in entity:
            continue
        value = entity.get(key)
        if value is None or type(value) in {bool, int, str}:
            sanitized[key] = value
    return sanitized


def _related_entities(payload: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    related: dict[str, Mapping[str, Any]] = {}
    for key, wrapper in payload.items():
        if not isinstance(key, str) or not isinstance(wrapper, Mapping):
            continue
        entity = wrapper.get("entity")
        if isinstance(entity, Mapping):
            related[key] = _sanitize_entity(key, entity)
    return related


def normalize_verified_webhook(
    raw_body: bytes,
    *,
    event_id: str,
    expected_account_id: str | None = None,
) -> CanonicalWebhookEvent:
    """Normalise a body only after the caller has verified its signature."""

    _require_raw_bytes(raw_body)
    if not isinstance(event_id, str) or not event_id or event_id != event_id.strip():
        raise WebhookDecodeError("event_id must be a non-empty string")
    if len(event_id) > 256:
        raise WebhookDecodeError("event_id exceeds 256 characters")

    try:
        decoded = json.loads(
            raw_body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookDecodeError("webhook body is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, Mapping):
        raise WebhookDecodeError("webhook JSON root must be an object")

    account_id = _required_string(decoded, "account_id")
    if expected_account_id is not None and account_id != expected_account_id:
        raise AccountMismatchError("webhook account_id does not match endpoint account")
    event_name = _required_string(decoded, "event")
    occurred_at = _required_epoch(decoded, "created_at")
    payload = decoded.get("payload")
    if not isinstance(payload, Mapping):
        raise WebhookDecodeError("payload must be an object")

    spec = _EVENT_SPECS.get(event_name)
    related = _related_entities(payload)
    if spec is None:
        event_type = CanonicalEventType.UNKNOWN
        resource_type = "unknown"
        resource: Mapping[str, Any] = {}
        resource_id: str | None = None
        for candidate_type, candidate in related.items():
            candidate_id = candidate.get("id")
            if isinstance(candidate_id, str) and candidate_id:
                resource_type = candidate_type
                resource = candidate
                resource_id = candidate_id
                break
    else:
        event_type = spec.canonical_type
        resource_type = spec.resource_type
        resource = _sanitize_entity(
            spec.payload_key,
            _extract_entity(payload, spec.payload_key),
        )
        resource_id = resource.get("id")
        if not isinstance(resource_id, str) or not resource_id:
            raise WebhookDecodeError(
                f"payload.{spec.payload_key}.entity.id must be a non-empty string"
            )

    frozen_related = {key: _freeze_json(entity) for key, entity in related.items()}
    return CanonicalWebhookEvent(
        event_id=event_id,
        provider_account_id=account_id,
        event_name=event_name,
        event_type=event_type,
        occurred_at_epoch=occurred_at,
        resource_type=resource_type,
        resource_id=resource_id,
        resource=_freeze_json(dict(resource)),
        related_resources=MappingProxyType(frozen_related),
        raw_body_sha256=hashlib.sha256(raw_body).hexdigest(),
    )


def verify_and_normalize_webhook(
    raw_body: bytes,
    *,
    headers: WebhookHeaders,
    secrets: Sequence[bytes],
    expected_account_id: str | None = None,
) -> CanonicalWebhookEvent:
    """Authenticate then normalise one Razorpay webhook request."""

    verify_webhook_signature(raw_body, headers.signature, secrets)
    return normalize_verified_webhook(
        raw_body,
        event_id=headers.event_id,
        expected_account_id=expected_account_id,
    )
