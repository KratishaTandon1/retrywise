"""Closed router for the shared normalized-provider-event command family."""

from __future__ import annotations

from .normalized_event_projector import (
    NormalizedEventCommandError,
    decode_process_normalized_provider_event_command,
)
from .outbox_worker import CommandHandler, HandlerResult
from .postgres_outbox import ClaimedOutboxCommand
from .terminal_event_projector import SUPPORTED_TERMINAL_EVENT_TYPES


class ProcessNormalizedProviderEventRouter:
    """Dispatch signed event evidence by its command-bound canonical event type."""

    def __init__(
        self,
        *,
        failure_handler: CommandHandler,
        terminal_handler: CommandHandler,
    ) -> None:
        if not callable(failure_handler) or not callable(terminal_handler):
            raise TypeError("normalized event handlers must be callable")
        self._failure_handler = failure_handler
        self._terminal_handler = terminal_handler

    def __call__(self, claimed: ClaimedOutboxCommand) -> HandlerResult:
        try:
            command = decode_process_normalized_provider_event_command(claimed)
        except (NormalizedEventCommandError, TypeError):
            return HandlerResult.dead_letter("invalid_normalized_event_command")
        if command.event_type in SUPPORTED_TERMINAL_EVENT_TYPES:
            return self._terminal_handler(claimed)
        return self._failure_handler(claimed)


__all__ = ["ProcessNormalizedProviderEventRouter"]
