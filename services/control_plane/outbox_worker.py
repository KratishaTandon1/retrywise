"""Fail-closed command dispatch around the durable PostgreSQL outbox.

There is deliberately no executable entry point in this module: production
composition must provide real, registered handlers.  ``poll_once`` is the
smallest safe orchestration unit for tests, supervisors, and framework-owned
lifecycles.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Protocol

from .outbox import RetryMode
from .postgres_outbox import ClaimedOutboxCommand, OutboxClaimBatch, OutboxFenceLost


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


class OutboxRepository(Protocol):
    def claim_batch(
        self,
        *,
        worker_id: str,
        batch_size: int,
        lease_duration: timedelta,
    ) -> OutboxClaimBatch: ...

    def complete(self, command: ClaimedOutboxCommand, *, completion_reference: str) -> int: ...

    def retry(
        self,
        command: ClaimedOutboxCommand,
        *,
        reason: str,
        retry_mode: RetryMode,
    ) -> int: ...

    def dead_letter(self, command: ClaimedOutboxCommand, *, reason: str) -> int: ...


class HandlerDisposition(StrEnum):
    SUCCEEDED = "succeeded"
    RETRY = "retry"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True, slots=True)
class HandlerResult:
    """A handler's explicit persistence instruction; handlers do not settle rows."""

    disposition: HandlerDisposition
    completion_reference: str | None = None
    reason: str | None = None
    retry_mode: RetryMode | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, HandlerDisposition):
            raise TypeError("disposition must be HandlerDisposition")
        if self.disposition is HandlerDisposition.SUCCEEDED:
            if self.completion_reference is None:
                raise ValueError("successful handler results require completion_reference")
            _clean_text(
                self.completion_reference,
                field="completion_reference",
                maximum=500,
            )
            if self.reason is not None or self.retry_mode is not None:
                raise ValueError("successful handler results cannot include retry metadata")
            return
        if self.reason is None:
            raise ValueError("non-success handler results require reason")
        _clean_text(self.reason, field="reason", maximum=500)
        if self.disposition is HandlerDisposition.RETRY:
            if self.retry_mode not in {
                RetryMode.RECONCILE_ONLY,
                RetryMode.RETRY_SAME_EFFECT,
            }:
                raise ValueError("retry results require an explicit safe retry mode")
            if self.completion_reference is not None:
                raise ValueError("retry results cannot include completion_reference")
        elif self.retry_mode is not None or self.completion_reference is not None:
            raise ValueError("dead-letter results can only include a reason")

    @classmethod
    def succeeded(cls, completion_reference: str) -> HandlerResult:
        return cls(HandlerDisposition.SUCCEEDED, completion_reference=completion_reference)

    @classmethod
    def retry_safely(
        cls,
        reason: str,
        *,
        retry_mode: RetryMode = RetryMode.RECONCILE_ONLY,
    ) -> HandlerResult:
        return cls(HandlerDisposition.RETRY, reason=reason, retry_mode=retry_mode)

    @classmethod
    def dead_letter(cls, reason: str) -> HandlerResult:
        return cls(HandlerDisposition.DEAD_LETTER, reason=reason)


CommandHandler = Callable[[ClaimedOutboxCommand], HandlerResult]


@dataclass(frozen=True, slots=True)
class PollResult:
    selected: int
    claimed: int
    succeeded: int
    retried: int
    dead_lettered: int
    fence_lost: int

    def __post_init__(self) -> None:
        for field in (
            "selected",
            "claimed",
            "succeeded",
            "retried",
            "dead_lettered",
            "fence_lost",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")
        if self.claimed > self.selected:
            raise ValueError("claimed cannot exceed selected")
        if self.succeeded + self.retried + self.dead_lettered + self.fence_lost != self.selected:
            raise ValueError("every selected row must have exactly one poll outcome")


@dataclass(frozen=True, slots=True)
class RunSummary:
    polls: int = 0
    selected: int = 0
    claimed: int = 0
    succeeded: int = 0
    retried: int = 0
    dead_lettered: int = 0
    fence_lost: int = 0

    def add(self, result: PollResult) -> RunSummary:
        return RunSummary(
            polls=self.polls + 1,
            selected=self.selected + result.selected,
            claimed=self.claimed + result.claimed,
            succeeded=self.succeeded + result.succeeded,
            retried=self.retried + result.retried,
            dead_lettered=self.dead_lettered + result.dead_lettered,
            fence_lost=self.fence_lost + result.fence_lost,
        )


class OutboxWorker:
    """Bounded synchronous poller that dispatches only registered commands."""

    def __init__(
        self,
        *,
        repository: OutboxRepository,
        worker_id: str,
        handlers: Mapping[str, CommandHandler],
        batch_size: int = 25,
        lease_duration: timedelta = timedelta(seconds=30),
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._repository = repository
        self._worker_id = _clean_text(worker_id, field="worker_id", maximum=128)
        if type(batch_size) is not int or not 1 <= batch_size <= 100:
            raise ValueError("batch_size must be between 1 and 100")
        if not isinstance(lease_duration, timedelta) or lease_duration <= timedelta(0):
            raise ValueError("lease_duration must be a positive timedelta")
        if lease_duration > timedelta(minutes=15):
            raise ValueError("lease_duration must not exceed 15 minutes")
        if not isinstance(handlers, Mapping):
            raise TypeError("handlers must be a mapping")
        copied_handlers: dict[str, CommandHandler] = {}
        for command_type, handler in handlers.items():
            command_type = _clean_text(command_type, field="command_type", maximum=100)
            if not callable(handler):
                raise TypeError(f"handler for {command_type!r} must be callable")
            copied_handlers[command_type] = handler
        if not callable(sleeper):
            raise TypeError("sleeper must be callable")
        self._handlers = copied_handlers
        self._batch_size = batch_size
        self._lease_duration = lease_duration
        self._sleeper = sleeper

    def poll_once(self) -> PollResult:
        """Claim one bounded batch and settle every selected row before returning."""

        batch = self._repository.claim_batch(
            worker_id=self._worker_id,
            batch_size=self._batch_size,
            lease_duration=self._lease_duration,
        )
        if not isinstance(batch, OutboxClaimBatch):
            raise TypeError("repository must return OutboxClaimBatch")

        succeeded = 0
        retried = 0
        dead_lettered = batch.expired_dead_lettered
        fence_lost = 0
        for command in batch.commands:
            handler = self._handlers.get(command.command_type)
            if handler is None:
                result = HandlerResult.dead_letter(
                    f"unregistered_command_type:{command.command_type}"
                )
            else:
                try:
                    result = handler(command)
                except Exception as exc:  # handler errors must not escape with a live lease
                    result = HandlerResult.retry_safely(
                        f"handler_exception:{type(exc).__name__}",
                        retry_mode=RetryMode.RECONCILE_ONLY,
                    )
                if not isinstance(result, HandlerResult):
                    result = HandlerResult.dead_letter("invalid_handler_result")

            try:
                if result.disposition is HandlerDisposition.SUCCEEDED:
                    reference = result.completion_reference
                    if reference is None:  # guarded by HandlerResult
                        raise AssertionError("successful handler result has no reference")
                    self._repository.complete(command, completion_reference=reference)
                    succeeded += 1
                elif result.disposition is HandlerDisposition.RETRY:
                    reason = result.reason
                    retry_mode = result.retry_mode
                    if reason is None or retry_mode is None:  # guarded by HandlerResult
                        raise AssertionError("retry handler result lacks retry metadata")
                    self._repository.retry(
                        command,
                        reason=reason,
                        retry_mode=retry_mode,
                    )
                    retried += 1
                else:
                    reason = result.reason
                    if reason is None:  # guarded by HandlerResult
                        raise AssertionError("dead-letter handler result has no reason")
                    self._repository.dead_letter(command, reason=reason)
                    dead_lettered += 1
            except OutboxFenceLost:
                fence_lost += 1

        return PollResult(
            selected=batch.selected_count,
            claimed=len(batch.commands),
            succeeded=succeeded,
            retried=retried,
            dead_lettered=dead_lettered,
            fence_lost=fence_lost,
        )

    def run_until_stopped(
        self,
        *,
        stop_requested: Callable[[], bool],
        idle_delay_seconds: float = 1.0,
    ) -> RunSummary:
        """Poll until asked to stop, finishing every already-claimed bounded batch."""

        if not callable(stop_requested):
            raise TypeError("stop_requested must be callable")
        if (
            not isinstance(idle_delay_seconds, (int, float))
            or isinstance(idle_delay_seconds, bool)
            or not 0 < idle_delay_seconds <= 60
        ):
            raise ValueError("idle_delay_seconds must be in (0, 60]")
        summary = RunSummary()
        while not stop_requested():
            result = self.poll_once()
            summary = summary.add(result)
            if result.selected == 0 and not stop_requested():
                self._sleeper(float(idle_delay_seconds))
        return summary


__all__ = [
    "CommandHandler",
    "HandlerDisposition",
    "HandlerResult",
    "OutboxRepository",
    "OutboxWorker",
    "PollResult",
    "RunSummary",
]
