"""Deterministic synthetic scenario generation using keyed randomness."""

from __future__ import annotations

import hashlib

from .models import (
    POLICY_VERSION_DEFAULT,
    ActionKind,
    CostAssumptions,
    EventKind,
    FailureCause,
    MerchantPolicy,
    PotentialOutcome,
    Scenario,
    ScenarioDataset,
    ScenarioEvent,
    stable_hash,
)

CAUSES = tuple(FailureCause)
METHOD_BY_CAUSE = {
    FailureCause.ORDINARY_RECOVERABLE: "card",
    FailureCause.WRONG_UPI_PIN: "upi",
    FailureCause.LATE_AUTHORIZATION: "upi",
    FailureCause.INSUFFICIENT_FUNDS: "card",
    FailureCause.EXPIRED_CREDENTIAL: "card",
    FailureCause.UNKNOWN: "upi",
    FailureCause.UPI_INCIDENT: "upi",
    FailureCause.ISSUER_INCIDENT: "card",
    FailureCause.BANK_INCIDENT: "netbanking",
}
ERROR_BY_CAUSE = {
    FailureCause.ORDINARY_RECOVERABLE: "temporary_processing_error",
    FailureCause.WRONG_UPI_PIN: "incorrect_upi_pin",
    FailureCause.LATE_AUTHORIZATION: "payment_timed_out",
    FailureCause.INSUFFICIENT_FUNDS: "insufficient_balance",
    FailureCause.EXPIRED_CREDENTIAL: "expired_card",
    FailureCause.UNKNOWN: "unknown_error",
    FailureCause.UPI_INCIDENT: "upi_service_unavailable",
    FailureCause.ISSUER_INCIDENT: "issuer_unavailable",
    FailureCause.BANK_INCIDENT: "bank_unavailable",
}
NATURAL_RECOVERY_PROBABILITY = {
    FailureCause.ORDINARY_RECOVERABLE: 0.20,
    FailureCause.WRONG_UPI_PIN: 0.65,
    FailureCause.LATE_AUTHORIZATION: 0.82,
    FailureCause.INSUFFICIENT_FUNDS: 0.08,
    FailureCause.EXPIRED_CREDENTIAL: 0.01,
    FailureCause.UNKNOWN: 0.18,
    FailureCause.UPI_INCIDENT: 0.25,
    FailureCause.ISSUER_INCIDENT: 0.18,
    FailureCause.BANK_INCIDENT: 0.20,
}
ACTION_RECOVERY_PROBABILITY = {
    FailureCause.ORDINARY_RECOVERABLE: (0.62, 0.56),
    FailureCause.WRONG_UPI_PIN: (0.58, 0.72),
    FailureCause.LATE_AUTHORIZATION: (0.35, 0.48),
    FailureCause.INSUFFICIENT_FUNDS: (0.24, 0.33),
    FailureCause.EXPIRED_CREDENTIAL: (0.18, 0.82),
    FailureCause.UNKNOWN: (0.36, 0.48),
    FailureCause.UPI_INCIDENT: (0.12, 0.78),
    FailureCause.ISSUER_INCIDENT: (0.16, 0.76),
    FailureCause.BANK_INCIDENT: (0.15, 0.74),
}


def keyed_u64(seed: int, *parts: object) -> int:
    material = "|".join((str(seed), *(str(part) for part in parts)))
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def keyed_unit(seed: int, *parts: object) -> float:
    return keyed_u64(seed, *parts) / float(1 << 64)


def keyed_int(seed: int, low: int, high: int, *parts: object) -> int:
    if low > high:
        raise ValueError("low must not exceed high")
    return low + keyed_u64(seed, *parts) % (high - low + 1)


def generate_dataset(
    seed: int,
    case_count: int,
    *,
    policy_version: str = POLICY_VERSION_DEFAULT,
    costs: CostAssumptions | None = None,
) -> ScenarioDataset:
    """Generate a reproducible paired-evaluation dataset.

    Keyed hashes, instead of a shared random-number stream, ensure that adding a
    policy or changing evaluation order cannot change potential outcomes.
    """

    if case_count <= 0:
        raise ValueError("case_count must be positive")
    costs = costs or CostAssumptions()
    merchant_count = min(12, max(4, (case_count + 24) // 25))
    merchants = tuple(
        _generate_merchant(seed, index, policy_version) for index in range(merchant_count)
    )
    scenarios = tuple(
        _generate_scenario(seed, index, merchants[index % merchant_count])
        for index in range(case_count)
    )
    hash_payload = {
        "seed": seed,
        "merchant_policies": merchants,
        "scenarios": scenarios,
        "costs": costs,
    }
    return ScenarioDataset(
        seed=seed,
        scenarios=scenarios,
        merchant_policies=merchants,
        costs=costs,
        dataset_hash=stable_hash(hash_payload),
    )


def _generate_merchant(
    seed: int,
    index: int,
    policy_version: str,
) -> MerchantPolicy:
    merchant_id = f"merchant-{index:02d}"
    return MerchantPolicy(
        merchant_id=merchant_id,
        provider_account_id=f"acc_sim_{index:02d}",
        contact_cap=1 + int(keyed_unit(seed, "merchant", index, "cap") > 0.82),
        quiet_hours_start=22,
        quiet_hours_end=8,
        approval_threshold_minor=keyed_int(seed, 800_000, 1_600_000, "merchant", index, "approval"),
        enabled_methods=("upi", "card", "netbanking"),
        recovery_horizon_ms=8 * 60 * 60 * 1_000,
        version=policy_version,
    )


def _generate_scenario(
    seed: int,
    index: int,
    merchant: MerchantPolicy,
) -> Scenario:
    scenario_id = f"case-{index:05d}"
    cause = CAUSES[(index + seed) % len(CAUSES)]
    method = METHOD_BY_CAUSE[cause]
    amount_minor = keyed_int(seed, 40_000, 2_000_000, scenario_id, "amount")
    natural_recovery = (
        keyed_unit(seed, scenario_id, "natural") < NATURAL_RECOVERY_PROBABILITY[cause]
    )
    natural_recovery_at_ms = None
    if natural_recovery:
        natural_recovery_at_ms = keyed_int(seed, 25_000, 105_000, scenario_id, "natural-delay")

    incident_scope = None
    if cause is FailureCause.UPI_INCIDENT:
        incident_scope = "upi:all"
    elif cause is FailureCause.ISSUER_INCIDENT:
        incident_scope = "card:issuer:HDFC"
    elif cause is FailureCause.BANK_INCIDENT:
        incident_scope = "netbanking:bank:HDFC"

    generic_probability, alternative_probability = ACTION_RECOVERY_PROBABILITY[cause]
    response_score = round(keyed_unit(seed, scenario_id, "response-score"), 6)
    generic_probability *= 0.65 + 0.7 * response_score
    alternative_probability *= 0.65 + 0.7 * response_score
    potential_outcomes = (
        PotentialOutcome(
            action=ActionKind.GENERIC_LINK,
            would_recover=(
                keyed_unit(seed, scenario_id, ActionKind.GENERIC_LINK.value)
                < min(generic_probability, 0.97)
            ),
            recovery_delay_ms=keyed_int(seed, 20_000, 95_000, scenario_id, "generic-delay"),
        ),
        PotentialOutcome(
            action=ActionKind.ALTERNATIVE_LINK,
            would_recover=(
                keyed_unit(seed, scenario_id, ActionKind.ALTERNATIVE_LINK.value)
                < min(alternative_probability, 0.97)
            ),
            recovery_delay_ms=keyed_int(seed, 20_000, 90_000, scenario_id, "alternative-delay"),
        ),
    )

    delivery_mutations: list[str] = []
    adversarial_flags: list[str] = []
    events: list[ScenarioEvent] = []

    failed_event_id = f"evt-{scenario_id}-failed"
    events.append(
        ScenarioEvent(
            event_id=failed_event_id,
            scenario_id=scenario_id,
            kind=EventKind.PAYMENT_FAILED,
            occurs_at_ms=0,
            delivered_at_ms=0,
            provider_account_id=merchant.provider_account_id,
            signature_valid=True,
            schema_version="2026-08-01",
            currency="INR",
            metadata=(("error_reason", ERROR_BY_CAUSE[cause]),),
        )
    )

    if index % 5 == 0:
        delivery_mutations.append("duplicate")
        events.append(
            ScenarioEvent(
                event_id=failed_event_id,
                scenario_id=scenario_id,
                kind=EventKind.PAYMENT_FAILED,
                occurs_at_ms=0,
                delivered_at_ms=keyed_int(seed, 1, 5_000, scenario_id, "duplicate-delay"),
                provider_account_id=merchant.provider_account_id,
                signature_valid=True,
                schema_version="2026-08-01",
                currency="INR",
                delivery_attempt=2,
            )
        )
    if index % 7 == 0:
        delivery_mutations.append("invalid_signature")
        events.append(
            ScenarioEvent(
                event_id=f"evt-{scenario_id}-forged",
                scenario_id=scenario_id,
                kind=EventKind.PAYMENT_FAILED,
                occurs_at_ms=0,
                delivered_at_ms=0,
                provider_account_id=merchant.provider_account_id,
                signature_valid=False,
                schema_version="2026-08-01",
                currency="INR",
            )
        )
    if index % 11 == 0:
        delivery_mutations.append("cross_tenant")
        events.append(
            ScenarioEvent(
                event_id=f"evt-{scenario_id}-cross-tenant",
                scenario_id=scenario_id,
                kind=EventKind.PAYMENT_FAILED,
                occurs_at_ms=0,
                delivered_at_ms=1,
                provider_account_id="acc_wrong_tenant",
                signature_valid=True,
                schema_version="2026-08-01",
                currency="INR",
            )
        )
    if index % 13 == 0:
        delivery_mutations.append("schema_evolution")
        adversarial_flags.append("unknown_enum")
    if index % 17 == 0:
        adversarial_flags.append("prompt_injection_metadata")
    if index % 19 == 0:
        adversarial_flags.append("currency_mismatch")
    if index % 23 == 0:
        adversarial_flags.append("kill_switch")
    if index % 31 == 0:
        adversarial_flags.append("partial_payment")
    if index % 37 == 0:
        adversarial_flags.append("expired_order")
    if index % 41 == 0:
        adversarial_flags.append("cancel_paid_race")
    if index % 43 == 0:
        adversarial_flags.append("ambiguous_mapping")
    if index % 47 == 0:
        adversarial_flags.append("provider_error")
    if index % 53 == 0:
        adversarial_flags.append("worker_crash")
    if index % 59 == 0:
        adversarial_flags.append("contact_cap_exhausted")
    if index % 61 == 0:
        adversarial_flags.append("capture_while_link_creation_in_flight")
    if index % 71 == 0:
        delivery_mutations.append("malformed")
        events.append(
            ScenarioEvent(
                event_id=f"evt-{scenario_id}-malformed",
                scenario_id=scenario_id,
                kind=EventKind.MALFORMED,
                occurs_at_ms=0,
                delivered_at_ms=2,
                provider_account_id=merchant.provider_account_id,
                signature_valid=True,
                schema_version="2026-08-01",
                currency="INR",
            )
        )

    if natural_recovery_at_ms is not None:
        adversarial_flags.append("capture_during_observation")
        capture_delivery: int | None = natural_recovery_at_ms
        if index % 6 == 0:
            capture_delivery = natural_recovery_at_ms + keyed_int(
                seed, 1_000, 30_000, scenario_id, "capture-delay"
            )
            delivery_mutations.append("delayed_capture")
        if index % 29 == 0:
            capture_delivery = None
            delivery_mutations.append("dropped_capture")
        events.append(
            ScenarioEvent(
                event_id=f"evt-{scenario_id}-captured",
                scenario_id=scenario_id,
                kind=EventKind.PAYMENT_CAPTURED,
                occurs_at_ms=natural_recovery_at_ms,
                delivered_at_ms=capture_delivery,
                provider_account_id=merchant.provider_account_id,
                signature_valid=True,
                schema_version="2026-08-01",
                currency="INR",
            )
        )
        if any(outcome.would_recover for outcome in potential_outcomes):
            adversarial_flags.append("both_collection_paths_can_capture")

    if incident_scope is not None:
        signal_mode = index % 3
        signal_delivery: int | None
        if signal_mode == 0:
            signal_delivery = 20_000
            delivery_mutations.append("early_downtime_signal")
        elif signal_mode == 1:
            signal_delivery = 180_000
            delivery_mutations.append("late_downtime_signal")
        else:
            signal_delivery = None
            delivery_mutations.append("missing_downtime_signal")
        events.append(
            ScenarioEvent(
                event_id=f"evt-{scenario_id}-downtime",
                scenario_id=scenario_id,
                kind=EventKind.DOWNTIME_STARTED,
                occurs_at_ms=10_000,
                delivered_at_ms=signal_delivery,
                provider_account_id=merchant.provider_account_id,
                signature_valid=True,
                schema_version="2026-08-01",
                currency="INR",
                metadata=(("scope", incident_scope),),
            )
        )

    return Scenario(
        scenario_id=scenario_id,
        family=cause.value,
        merchant_id=merchant.merchant_id,
        order_id=f"order-sim-{index:05d}",
        amount_minor=amount_minor,
        currency="INR",
        method=method,
        observable_error=ERROR_BY_CAUSE[cause],
        customer_response_score=response_score,
        consent_to_contact=(keyed_unit(seed, scenario_id, "consent") > 0.08),
        failure_local_hour=keyed_int(seed, 0, 23, scenario_id, "hour"),
        latent_cause=cause,
        natural_recovery_at_ms=natural_recovery_at_ms,
        incident_scope=incident_scope,
        anomaly_score=(
            round(0.82 + 0.17 * keyed_unit(seed, scenario_id, "anomaly"), 6)
            if incident_scope
            else round(0.05 + 0.55 * keyed_unit(seed, scenario_id, "anomaly"), 6)
        ),
        events=tuple(
            sorted(
                events,
                key=lambda event: (
                    event.delivered_at_ms is None,
                    event.delivered_at_ms or 0,
                    event.event_id,
                    event.delivery_attempt,
                ),
            )
        ),
        potential_outcomes=potential_outcomes,
        delivery_mutations=tuple(sorted(delivery_mutations)),
        adversarial_flags=tuple(sorted(adversarial_flags)),
    )
