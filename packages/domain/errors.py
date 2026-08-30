"""Domain-specific failures with stable, inspectable attributes."""

from __future__ import annotations


class DomainError(ValueError):
    """Base class for deterministic domain validation failures."""


class InvalidValue(DomainError):
    """Raised when a value object cannot be constructed safely."""


class VersionConflict(DomainError):
    """Raised when an optimistic aggregate version check fails."""

    def __init__(self, *, expected: int, actual: int) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"aggregate version conflict: expected {expected}, actual {actual}")


class InvalidTransition(DomainError):
    """Raised when a state-machine transition is not in the closed graph."""

    def __init__(self, *, machine: str, current: str, target: str) -> None:
        self.machine = machine
        self.current = current
        self.target = target
        super().__init__(f"invalid {machine} transition: {current} -> {target}")


class AuthorizationBindingError(DomainError):
    """Raised when a gate decision or approval is bound to other evidence."""


class LedgerIntegrityError(DomainError):
    """Raised when an append would violate ledger integrity rules."""
