"""Pinned policy composition shared by API, worker, and evidence tooling."""

from __future__ import annotations

from datetime import timedelta

from ...packages.domain import ActionType, DeterministicGate, GatePolicy, Money, Probability

PINNED_POLICY_VERSION = "policy-v1"


def production_gate() -> DeterministicGate:
    """Return the immutable policy used by this release.

    Merchant rows are required to carry the same version. Policy changes are
    therefore deployments with explicit data enrollment, never silent runtime
    configuration drift.
    """

    return DeterministicGate(
        GatePolicy(
            version=PINNED_POLICY_VERSION,
            allowed_actions=frozenset(ActionType),
            provider_snapshot_max_age=timedelta(seconds=30),
            incident_health_max_age=timedelta(minutes=2),
            max_attempts=3,
            max_contacts_in_window=2,
            approval_threshold=Money(500_000, "INR"),
            min_confidence=Probability("0.75"),
            allowed_clock_skew=timedelta(seconds=5),
        )
    )


__all__ = ["PINNED_POLICY_VERSION", "production_gate"]
