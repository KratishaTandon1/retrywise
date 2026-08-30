"""Closed state vocabularies and transition graphs."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import TypeVar

from .errors import InvalidTransition


class CanonicalPaymentState(StrEnum):
    UNKNOWN = "unknown"
    UNPAID = "unpaid"
    AUTHORIZED = "authorized"
    PARTIALLY_PAID = "partially_paid"
    PAID = "paid"
    OVERPAID = "overpaid"
    EXCEPTION = "exception"


class RecoveryState(StrEnum):
    DORMANT = "dormant"
    OBSERVING = "observing"
    ASSESSING = "assessing"
    WAITING = "waiting"
    APPROVAL_REQUIRED = "approval_required"
    ACTION_QUEUED = "action_queued"
    EXECUTING = "executing"
    ACTION_UNCERTAIN = "action_uncertain"
    ACTIVE = "active"
    RECOVERED = "recovered"
    SUPPRESSED_PAID = "suppressed_paid"
    SUPPRESSED_POLICY = "suppressed_policy"
    EXHAUSTED = "exhausted"
    FAILED_SAFE = "failed_safe"
    ESCALATED = "escalated"
    DUPLICATE_REVIEW = "duplicate_review"


class IncidentState(StrEnum):
    NORMAL = "normal"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    COOLING = "cooling"


COLLECTION_TERMINAL_STATES = frozenset(
    {
        RecoveryState.RECOVERED,
        RecoveryState.SUPPRESSED_PAID,
        RecoveryState.SUPPRESSED_POLICY,
        RecoveryState.EXHAUSTED,
        RecoveryState.FAILED_SAFE,
        RecoveryState.ESCALATED,
        RecoveryState.DUPLICATE_REVIEW,
    }
)


NONTERMINAL_RECOVERY_STATES = frozenset(set(RecoveryState) - COLLECTION_TERMINAL_STATES)


_PAYMENT_TRANSITIONS = {
    CanonicalPaymentState.UNKNOWN: frozenset(
        {
            CanonicalPaymentState.UNPAID,
            CanonicalPaymentState.AUTHORIZED,
            CanonicalPaymentState.PARTIALLY_PAID,
            CanonicalPaymentState.PAID,
            CanonicalPaymentState.OVERPAID,
            CanonicalPaymentState.EXCEPTION,
        }
    ),
    CanonicalPaymentState.UNPAID: frozenset(
        {
            CanonicalPaymentState.AUTHORIZED,
            CanonicalPaymentState.PARTIALLY_PAID,
            CanonicalPaymentState.PAID,
            CanonicalPaymentState.OVERPAID,
            CanonicalPaymentState.EXCEPTION,
        }
    ),
    CanonicalPaymentState.AUTHORIZED: frozenset(
        {
            CanonicalPaymentState.PARTIALLY_PAID,
            CanonicalPaymentState.PAID,
            CanonicalPaymentState.OVERPAID,
            CanonicalPaymentState.EXCEPTION,
        }
    ),
    CanonicalPaymentState.PARTIALLY_PAID: frozenset(
        {
            CanonicalPaymentState.PAID,
            CanonicalPaymentState.OVERPAID,
            CanonicalPaymentState.EXCEPTION,
        }
    ),
    CanonicalPaymentState.PAID: frozenset(
        {CanonicalPaymentState.OVERPAID, CanonicalPaymentState.EXCEPTION}
    ),
    CanonicalPaymentState.OVERPAID: frozenset({CanonicalPaymentState.EXCEPTION}),
    CanonicalPaymentState.EXCEPTION: frozenset(),
}


_RECOVERY_TRANSITIONS = {
    RecoveryState.DORMANT: frozenset({RecoveryState.OBSERVING}),
    RecoveryState.OBSERVING: frozenset({RecoveryState.ASSESSING, RecoveryState.SUPPRESSED_PAID}),
    RecoveryState.ASSESSING: frozenset(
        {
            RecoveryState.WAITING,
            RecoveryState.APPROVAL_REQUIRED,
            RecoveryState.ACTION_QUEUED,
            RecoveryState.EXHAUSTED,
            RecoveryState.SUPPRESSED_POLICY,
            RecoveryState.SUPPRESSED_PAID,
            RecoveryState.ESCALATED,
        }
    ),
    RecoveryState.WAITING: frozenset(
        {
            RecoveryState.ASSESSING,
            RecoveryState.SUPPRESSED_PAID,
            RecoveryState.SUPPRESSED_POLICY,
            RecoveryState.EXHAUSTED,
        }
    ),
    RecoveryState.APPROVAL_REQUIRED: frozenset(
        {
            RecoveryState.ACTION_QUEUED,
            RecoveryState.SUPPRESSED_POLICY,
            RecoveryState.SUPPRESSED_PAID,
        }
    ),
    RecoveryState.ACTION_QUEUED: frozenset(
        {
            RecoveryState.EXECUTING,
            RecoveryState.SUPPRESSED_PAID,
            RecoveryState.SUPPRESSED_POLICY,
        }
    ),
    RecoveryState.EXECUTING: frozenset(
        {
            RecoveryState.ACTIVE,
            RecoveryState.ACTION_UNCERTAIN,
            RecoveryState.FAILED_SAFE,
            RecoveryState.SUPPRESSED_PAID,
        }
    ),
    RecoveryState.ACTION_UNCERTAIN: frozenset(
        {
            RecoveryState.ACTIVE,
            RecoveryState.ACTION_QUEUED,
            RecoveryState.ESCALATED,
            RecoveryState.SUPPRESSED_PAID,
        }
    ),
    RecoveryState.ACTIVE: frozenset(
        {
            RecoveryState.RECOVERED,
            RecoveryState.SUPPRESSED_PAID,
            RecoveryState.ASSESSING,
            RecoveryState.EXHAUSTED,
        }
    ),
    RecoveryState.RECOVERED: frozenset(),
    RecoveryState.SUPPRESSED_PAID: frozenset(),
    RecoveryState.SUPPRESSED_POLICY: frozenset(),
    RecoveryState.EXHAUSTED: frozenset(),
    RecoveryState.FAILED_SAFE: frozenset(),
    RecoveryState.ESCALATED: frozenset(),
    RecoveryState.DUPLICATE_REVIEW: frozenset(),
}


_INCIDENT_TRANSITIONS = {
    IncidentState.NORMAL: frozenset({IncidentState.SUSPECTED}),
    IncidentState.SUSPECTED: frozenset({IncidentState.CONFIRMED, IncidentState.NORMAL}),
    IncidentState.CONFIRMED: frozenset({IncidentState.COOLING}),
    IncidentState.COOLING: frozenset({IncidentState.CONFIRMED, IncidentState.NORMAL}),
}


StateT = TypeVar("StateT", bound=StrEnum)


def _validate_transition(
    *,
    machine: str,
    current: StateT,
    target: StateT,
    graph: Mapping[StateT, frozenset[StateT]],
) -> bool:
    if current == target:
        return False
    if target not in graph[current]:
        raise InvalidTransition(
            machine=machine, current=str(current.value), target=str(target.value)
        )
    return True


def validate_payment_transition(
    current: CanonicalPaymentState, target: CanonicalPaymentState
) -> bool:
    return _validate_transition(
        machine="payment", current=current, target=target, graph=_PAYMENT_TRANSITIONS
    )


def validate_recovery_transition(current: RecoveryState, target: RecoveryState) -> bool:
    if current == target:
        return False
    if target is RecoveryState.DUPLICATE_REVIEW and current is not RecoveryState.DORMANT:
        return True
    return _validate_transition(
        machine="recovery", current=current, target=target, graph=_RECOVERY_TRANSITIONS
    )


def validate_incident_transition(current: IncidentState, target: IncidentState) -> bool:
    return _validate_transition(
        machine="incident", current=current, target=target, graph=_INCIDENT_TRANSITIONS
    )
