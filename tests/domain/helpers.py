from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from retrywise.packages.domain import (
    ActionProposal,
    ActionType,
    CanonicalPaymentState,
    DeterministicGate,
    GateContext,
    GatePolicy,
    IncidentState,
    Money,
    Probability,
    ProviderSnapshot,
    RecoveryState,
)

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def policy(**changes: object) -> GatePolicy:
    base = GatePolicy(
        version="policy-v1",
        allowed_actions=frozenset(ActionType),
        provider_snapshot_max_age=timedelta(seconds=30),
        incident_health_max_age=timedelta(seconds=60),
        max_attempts=3,
        max_contacts_in_window=2,
        approval_threshold=Money(500_000, "INR"),
        min_confidence=Probability("0.75"),
    )
    return replace(base, **changes)


def proposal(**changes: object) -> ActionProposal:
    base = ActionProposal(
        proposal_id="proposal_1",
        merchant_id="merchant_1",
        case_id="case_1",
        decision_version=1,
        action_type=ActionType.CREATE_STANDARD_PAYMENT_LINK,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        amount=Money(129_900, "INR"),
        payment_method="upi",
        expected_value_minor=30_000,
        model_confidence=Probability("0.90"),
    )
    return replace(base, **changes)


def snapshot(**changes: object) -> ProviderSnapshot:
    base = ProviderSnapshot(
        payment_state=CanonicalPaymentState.UNPAID,
        amount_due=Money(129_900, "INR"),
        payment_method="upi",
        observed_at=NOW - timedelta(seconds=5),
        active_instrument_count=0,
        incident_state=IncidentState.NORMAL,
        method_health_observed_at=NOW - timedelta(seconds=5),
    )
    return replace(base, **changes)


def context(**changes: object) -> GateContext:
    base = GateContext(
        merchant_id="merchant_1",
        case_id="case_1",
        evaluated_at=NOW,
        aggregate_version=3,
        expected_aggregate_version=3,
        recovery_state=RecoveryState.ASSESSING,
        snapshot=snapshot(),
        environment_effects_enabled=True,
        observation_deadline=NOW - timedelta(seconds=1),
    )
    return replace(base, **changes)


def gate(**policy_changes: object) -> DeterministicGate:
    return DeterministicGate(policy(**policy_changes))
