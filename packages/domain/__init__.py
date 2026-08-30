"""Pure deterministic domain core for RetryWise.

The package deliberately has no framework, database, network, or secret
dependencies. Application layers translate provider/API facts into these value
objects and persist returned events and gate evidence transactionally.
"""

from .actions import ActionProposal, ActionType, Approval
from .aggregate import AggregateChange, AggregateEvent, RecoveryAggregate
from .errors import (
    AuthorizationBindingError,
    DomainError,
    InvalidTransition,
    InvalidValue,
    LedgerIntegrityError,
    VersionConflict,
)
from .gate import (
    APPROVAL_BLOCKING_REASONS,
    DeterministicGate,
    GateContext,
    GateDecision,
    GatePolicy,
    GateReason,
    GateStage,
    ProviderSnapshot,
)
from .ledger import (
    GENESIS_HASH,
    DecisionLedger,
    LedgerEntry,
    LedgerVerification,
    LedgerVerificationReason,
    verify_ledger,
)
from .states import CanonicalPaymentState, IncidentState, RecoveryState
from .values import (
    MINIMUM_LATE_CAPTURE_WINDOW,
    LateCapturePolicy,
    Money,
    Probability,
)

__all__ = [
    "APPROVAL_BLOCKING_REASONS",
    "GENESIS_HASH",
    "MINIMUM_LATE_CAPTURE_WINDOW",
    "ActionProposal",
    "ActionType",
    "AggregateChange",
    "AggregateEvent",
    "Approval",
    "AuthorizationBindingError",
    "CanonicalPaymentState",
    "DecisionLedger",
    "DeterministicGate",
    "DomainError",
    "GateContext",
    "GateDecision",
    "GatePolicy",
    "GateReason",
    "GateStage",
    "IncidentState",
    "InvalidTransition",
    "InvalidValue",
    "LateCapturePolicy",
    "LedgerEntry",
    "LedgerIntegrityError",
    "LedgerVerification",
    "LedgerVerificationReason",
    "Money",
    "Probability",
    "ProviderSnapshot",
    "RecoveryAggregate",
    "RecoveryState",
    "VersionConflict",
    "verify_ledger",
]
