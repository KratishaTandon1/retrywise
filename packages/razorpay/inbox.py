"""Provider-event inbox contract and a test/reference implementation."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from .webhooks import CanonicalWebhookEvent


class InboxConflictError(RuntimeError):
    """A provider reused an event id with different signed content."""


class InboxWriteResult(StrEnum):
    STORED = "stored"
    DUPLICATE = "duplicate"


@dataclass(frozen=True)
class InboxRecord:
    """Durable evidence accepted at the provider boundary."""

    event: CanonicalWebhookEvent
    received_at_epoch: int

    def __post_init__(self) -> None:
        if type(self.received_at_epoch) is not int or self.received_at_epoch < 0:
            raise ValueError("received_at_epoch must be a non-negative integer")

    @property
    def dedupe_key(self) -> tuple[str, str]:
        return self.event.provider_account_id, self.event.event_id


@runtime_checkable
class WebhookInbox(Protocol):
    """Persistence port for at-least-once webhook delivery.

    A production adapter MUST make ``store_once`` atomic with creation of the
    corresponding asynchronous work/outbox item.  It must enforce uniqueness
    on ``(provider_account_id, event_id)`` and surface different-content reuse
    as ``InboxConflictError`` rather than silently dropping it.
    """

    def store_once(self, record: InboxRecord) -> InboxWriteResult: ...


class InMemoryWebhookInbox:
    """Thread-safe reference adapter for tests and local simulations only."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], InboxRecord] = {}
        self._lock = threading.Lock()

    def store_once(self, record: InboxRecord) -> InboxWriteResult:
        key = record.dedupe_key
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                self._records[key] = record
                return InboxWriteResult.STORED
            if (
                existing.event.raw_body_sha256 != record.event.raw_body_sha256
                or existing.event.event_name != record.event.event_name
            ):
                raise InboxConflictError("provider event id was reused with different content")
            return InboxWriteResult.DUPLICATE

    def get(self, provider_account_id: str, event_id: str) -> InboxRecord | None:
        with self._lock:
            return self._records.get((provider_account_id, event_id))

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
