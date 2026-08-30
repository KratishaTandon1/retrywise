"""Fast, authenticated webhook ingress application service."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from ...packages.razorpay import (
    InboxRecord,
    InboxWriteResult,
    WebhookHeaders,
    WebhookInbox,
    verify_and_normalize_webhook,
)
from ...packages.razorpay.webhooks import CanonicalWebhookEvent

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{24,128}$")


class IngressError(ValueError):
    """Webhook request cannot be accepted."""


class EndpointNotFound(IngressError):
    """Endpoint token does not resolve to a provider account."""


class PayloadTooLarge(IngressError):
    """Webhook body exceeded the configured ingress limit."""


class UnsupportedMediaType(IngressError):
    """Webhook was not sent as JSON."""


@dataclass(frozen=True, slots=True)
class EndpointBinding:
    endpoint_token: str
    merchant_id: str
    provider_account_id: str
    provider_account_identifier: str
    webhook_secrets: tuple[bytes, ...] = field(repr=False)
    previous_secret_expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not _TOKEN_RE.fullmatch(self.endpoint_token):
            raise ValueError("endpoint_token must be 24-128 URL-safe characters")
        for name in ("merchant_id", "provider_account_id", "provider_account_identifier"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        secrets = tuple(self.webhook_secrets)
        if not secrets or any(not isinstance(item, bytes) or not item for item in secrets):
            raise ValueError("at least one non-empty byte webhook secret is required")
        expiry = self.previous_secret_expires_at
        if len(secrets) == 1 and expiry is not None:
            raise ValueError("a previous-secret expiry requires exactly two webhook secrets")
        if len(secrets) > 1:
            if len(secrets) != 2 or expiry is None:
                raise ValueError("exactly one previous webhook secret requires a UTC expiry")
            if (
                not isinstance(expiry, datetime)
                or expiry.tzinfo is None
                or expiry.utcoffset() != UTC.utcoffset(expiry)
            ):
                raise ValueError("previous-secret expiry must be an aware UTC datetime")
            if hmac.compare_digest(secrets[0], secrets[1]):
                raise ValueError("current and previous webhook secrets must be different")
        object.__setattr__(self, "webhook_secrets", secrets)

    def active_webhook_secrets(self, *, now: datetime) -> tuple[bytes, ...]:
        """Return current plus still-valid rotation secret for one verification attempt."""

        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != UTC.utcoffset(now)
        ):
            raise ValueError("webhook verification clock must be an aware UTC datetime")
        expiry = self.previous_secret_expires_at
        if expiry is not None and now >= expiry:
            return self.webhook_secrets[:1]
        return self.webhook_secrets


class EndpointRegistry(Protocol):
    def find(self, endpoint_token: str) -> EndpointBinding | None: ...


class StaticEndpointRegistry:
    """Immutable local/test registry; production resolves secret-manager references."""

    def __init__(self, bindings: tuple[EndpointBinding, ...]) -> None:
        indexed: dict[str, EndpointBinding] = {}
        for binding in bindings:
            if binding.endpoint_token in indexed:
                raise ValueError("duplicate endpoint token")
            indexed[binding.endpoint_token] = binding
        self._bindings = MappingProxyType(indexed)

    def find(self, endpoint_token: str) -> EndpointBinding | None:
        return self._bindings.get(endpoint_token)


class IngressStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    DUPLICATE = "DUPLICATE"


@dataclass(frozen=True, slots=True)
class IngressReceipt:
    status: IngressStatus
    merchant_id: str
    provider_account_id: str
    provider_event_id: str
    event_name: str
    body_sha256: str
    canonical_event: CanonicalWebhookEvent

    @property
    def enqueued(self) -> bool:
        return self.status is IngressStatus.ACCEPTED


class WebhookIngress:
    """Authenticate, normalize, and durably deduplicate one request.

    The injected production inbox must atomically insert the inbox row and the
    normalized-event outbox job. The in-memory inbox is suitable only for tests.
    """

    def __init__(
        self,
        *,
        registry: EndpointRegistry,
        inbox: WebhookInbox,
        max_body_bytes: int = 262_144,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1_024 <= max_body_bytes <= 1_048_576:
            raise ValueError("max_body_bytes must be between 1 KiB and 1 MiB")
        self._registry = registry
        self._inbox = inbox
        self._max_body_bytes = max_body_bytes
        self._clock = clock or (lambda: datetime.now(UTC))
        if not callable(self._clock):
            raise TypeError("clock must be callable")

    @property
    def durable(self) -> bool:
        """Whether acceptance survives process loss after the HTTP response."""

        return getattr(self._inbox, "durable", False) is True

    def check_ready(self) -> bool:
        """Probe the durable persistence boundary without weakening fail-closed behavior."""

        if not self.durable:
            return False
        check = getattr(self._inbox, "check_ready", None)
        if not callable(check):
            return False
        return check() is True

    def accept(
        self,
        *,
        endpoint_token: str,
        raw_body: bytes,
        headers: Mapping[str, str],
        content_type: str,
        received_at_epoch: int,
    ) -> IngressReceipt:
        if not isinstance(raw_body, bytes):
            raise TypeError("raw_body must be exact request bytes")
        if not raw_body:
            raise IngressError("webhook body cannot be empty")
        if len(raw_body) > self._max_body_bytes:
            raise PayloadTooLarge("webhook body exceeds configured limit")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            raise UnsupportedMediaType("webhook content type must be application/json")
        if type(received_at_epoch) is not int or received_at_epoch < 0:
            raise ValueError("received_at_epoch must be a non-negative integer")

        binding = self._registry.find(endpoint_token)
        if binding is None:
            raise EndpointNotFound("unknown webhook endpoint")
        security_headers = WebhookHeaders.from_mapping(headers)
        event = verify_and_normalize_webhook(
            raw_body,
            headers=security_headers,
            secrets=binding.active_webhook_secrets(now=self._clock()),
            expected_account_id=binding.provider_account_identifier,
        )
        write_result = self._inbox.store_once(
            InboxRecord(event=event, received_at_epoch=received_at_epoch)
        )
        status = (
            IngressStatus.ACCEPTED
            if write_result is InboxWriteResult.STORED
            else IngressStatus.DUPLICATE
        )
        return IngressReceipt(
            status=status,
            merchant_id=binding.merchant_id,
            provider_account_id=binding.provider_account_id,
            provider_event_id=event.event_id,
            event_name=event.event_name,
            body_sha256=hashlib.sha256(raw_body).hexdigest(),
            canonical_event=event,
        )
