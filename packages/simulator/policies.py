"""Reference policies and required baselines for paired evaluation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from decimal import ROUND_FLOOR, Decimal
from typing import ClassVar

from ..diagnosis import (
    BUNDLED_REGISTRY,
    PINNED_BUNDLED_VERSION,
    DiagnosisModel,
    FailureClass,
)
from .models import (
    ActionKind,
    CostAssumptions,
    MerchantPolicy,
    ObservedCase,
    PolicyDecision,
    Scenario,
)

POLICY_DISPLAY_NAMES = {
    "B0": "B0 Natural recovery",
    "B1": "B1 Blast all",
    "B2": "B2 Fixed safe rule",
    "B3": "B3 Incident-aware rules",
    "RetryWise": "RetryWise",
    "oracle": "Oracle ceiling",
}


class EvaluationPolicy(ABC):
    key: str
    deployable: bool = True
    use_safety_gate: bool = True
    revalidate_before_action: bool = True
    sees_latent_truth: bool = False

    @property
    def display_name(self) -> str:
        return POLICY_DISPLAY_NAMES[self.key]

    @abstractmethod
    def observation_delay_ms(self, observed: ObservedCase) -> int:
        raise NotImplementedError

    @abstractmethod
    def choose_action(
        self,
        observed: ObservedCase,
        merchant_policy: MerchantPolicy,
        costs: CostAssumptions,
    ) -> tuple[ActionKind, tuple[str, ...]]:
        raise NotImplementedError

    def decide(
        self,
        observed: ObservedCase,
        merchant_policy: MerchantPolicy,
        costs: CostAssumptions,
    ) -> PolicyDecision:
        action, reasons = self.choose_action(observed, merchant_policy, costs)
        return PolicyDecision(
            action=action,
            observation_delay_ms=self.observation_delay_ms(observed),
            reason_codes=reasons,
            use_safety_gate=self.use_safety_gate,
            revalidate_before_action=self.revalidate_before_action,
        )


class NaturalRecoveryPolicy(EvaluationPolicy):
    key = "B0"

    def observation_delay_ms(self, observed: ObservedCase) -> int:
        return 0

    def choose_action(
        self,
        observed: ObservedCase,
        merchant_policy: MerchantPolicy,
        costs: CostAssumptions,
    ) -> tuple[ActionKind, tuple[str, ...]]:
        return ActionKind.NO_ACTION, ("baseline_no_intervention",)


class BlastAllPolicy(EvaluationPolicy):
    key = "B1"
    use_safety_gate = False
    revalidate_before_action = False

    def observation_delay_ms(self, observed: ObservedCase) -> int:
        return 0

    def choose_action(
        self,
        observed: ObservedCase,
        merchant_policy: MerchantPolicy,
        costs: CostAssumptions,
    ) -> tuple[ActionKind, tuple[str, ...]]:
        return ActionKind.GENERIC_LINK, ("immediate_generic_link",)


class FixedSafePolicy(EvaluationPolicy):
    key = "B2"

    def observation_delay_ms(self, observed: ObservedCase) -> int:
        return 120_000

    def choose_action(
        self,
        observed: ObservedCase,
        merchant_policy: MerchantPolicy,
        costs: CostAssumptions,
    ) -> tuple[ActionKind, tuple[str, ...]]:
        return ActionKind.GENERIC_LINK, ("fixed_observation_complete",)


class IncidentAwarePolicy(EvaluationPolicy):
    key = "B3"

    def observation_delay_ms(self, observed: ObservedCase) -> int:
        return 120_000

    def choose_action(
        self,
        observed: ObservedCase,
        merchant_policy: MerchantPolicy,
        costs: CostAssumptions,
    ) -> tuple[ActionKind, tuple[str, ...]]:
        if observed.observable_error == "unknown_error":
            return ActionKind.NO_ACTION, ("unknown_failure_manual_review",)
        if observed.provider_incident_signal or observed.anomaly_score >= 0.80:
            return ActionKind.ALTERNATIVE_LINK, ("incident_aware_routing",)
        return ActionKind.GENERIC_LINK, ("healthy_instrument_fixed_route",)


class RetryWisePolicy(EvaluationPolicy):
    key = "RetryWise"

    _ERROR_FEATURES: ClassVar[dict[str, tuple[str, str, str]]] = {
        "temporary_processing_error": ("provider", "processing", "gateway_timeout"),
        "incorrect_upi_pin": ("customer", "authentication", "incorrect_pin"),
        "payment_timed_out": ("network", "processing", "network_timeout"),
        "insufficient_balance": ("issuer", "authorization", "insufficient_funds"),
        "expired_card": ("issuer", "authentication", "credential_expired"),
        "unknown_error": ("unknown", "unknown", "unknown"),
        "upi_service_unavailable": ("provider", "processing", "provider_unavailable"),
        "issuer_unavailable": ("issuer", "authorization", "issuer_unavailable"),
        "bank_unavailable": ("network", "authorization", "network_timeout"),
    }

    _ACTION_PROBABILITIES: ClassVar[dict[FailureClass, tuple[Decimal, Decimal]]] = {
        FailureClass.PROVIDER_INCIDENT: (Decimal("0.12"), Decimal("0.72")),
        FailureClass.CUSTOMER_CORRECTABLE: (Decimal("0.50"), Decimal("0.66")),
        FailureClass.CREDENTIAL_PERMANENT: (Decimal("0.15"), Decimal("0.78")),
        FailureClass.FUNDS_TEMPORARY: (Decimal("0.20"), Decimal("0.30")),
    }

    _OBSERVATION_BY_ERROR: ClassVar[dict[str, int]] = {
        "incorrect_upi_pin": 120_000,
        "payment_timed_out": 130_000,
        "insufficient_balance": 15 * 60_000,
        # A permanent-looking diagnosis does not prove the original attempt can
        # no longer capture. Keep the same minimum late-capture observation
        # window before any replacement collection path becomes eligible.
        "expired_card": 120_000,
        "unknown_error": 180_000,
        "upi_service_unavailable": 150_000,
        "issuer_unavailable": 150_000,
        "bank_unavailable": 150_000,
    }

    def __init__(self, *, model_version: str = PINNED_BUNDLED_VERSION) -> None:
        self._model = DiagnosisModel.from_registry(BUNDLED_REGISTRY, model_version)

    def observation_delay_ms(self, observed: ObservedCase) -> int:
        return self._OBSERVATION_BY_ERROR.get(observed.observable_error, 120_000)

    def choose_action(
        self,
        observed: ObservedCase,
        merchant_policy: MerchantPolicy,
        costs: CostAssumptions,
    ) -> tuple[ActionKind, tuple[str, ...]]:
        incident = observed.provider_incident_signal or observed.anomaly_score >= 0.80
        diagnosis = self._model.infer(self._diagnosis_features(observed, incident=incident))
        model_reason = f"diagnosis_{diagnosis.predicted_class.value}"
        if diagnosis.abstained:
            if diagnosis.out_of_distribution or observed.observable_error == "unknown_error":
                return ActionKind.NO_ACTION, (
                    "model_abstained",
                    "manual_review_required",
                    model_reason,
                )
            fallback_action = ActionKind.ALTERNATIVE_LINK if incident else ActionKind.GENERIC_LINK
            return fallback_action, (
                "model_abstained",
                "deterministic_incident_aware_fallback",
                model_reason,
            )
        if diagnosis.predicted_class in {
            FailureClass.MERCHANT_INTEGRATION,
            FailureClass.UNKNOWN,
        }:
            return ActionKind.NO_ACTION, ("diagnosis_not_recoverable", model_reason)

        generic_probability, alternative_probability = self._ACTION_PROBABILITIES[
            diagnosis.predicted_class
        ]
        propensity_factor = Decimal("0.55") + Decimal("0.75") * Decimal(
            str(observed.customer_response_score)
        )
        generic_probability *= propensity_factor
        alternative_probability *= propensity_factor
        fixed_cost = costs.communication_cost_minor + costs.action_cost_minor
        probability_cap = Decimal("0.95")
        generic_value = (
            int(
                (
                    Decimal(observed.amount_minor) * min(generic_probability, probability_cap)
                ).to_integral_value(rounding=ROUND_FLOOR)
            )
            - fixed_cost
        )
        alternative_value = int(
            (
                Decimal(observed.amount_minor) * min(alternative_probability, probability_cap)
            ).to_integral_value(rounding=ROUND_FLOOR)
        )
        if max(generic_value, alternative_value) <= 0:
            return ActionKind.NO_ACTION, ("non_positive_expected_value", model_reason)
        if alternative_value > generic_value:
            reason = "incident_alternative_method" if incident else "alternative_expected_value"
            return ActionKind.ALTERNATIVE_LINK, (
                reason,
                "positive_expected_value",
                model_reason,
            )
        return ActionKind.GENERIC_LINK, (
            "generic_link_expected_value",
            "positive_expected_value",
            model_reason,
        )

    def _diagnosis_features(self, observed: ObservedCase, *, incident: bool) -> dict[str, object]:
        error_source, error_step, error_reason = self._ERROR_FEATURES.get(
            observed.observable_error,
            ("unknown", "unknown", "unknown"),
        )
        delay = self.observation_delay_ms(observed)
        age_bucket = "stale" if delay >= 10 * 60_000 else "recent" if delay >= 180_000 else "fresh"
        incident_state = (
            "confirmed"
            if observed.provider_incident_signal
            else "suspected"
            if observed.anomaly_score >= 0.80
            else "normal"
        )
        return {
            "payment_method": observed.method,
            "error_source": error_source,
            "error_step": error_step,
            "error_reason": error_reason,
            "incident_state": incident_state if incident else "normal",
            "attempt_bucket": "first",
            "failure_age_bucket": age_bucket,
        }


class OraclePolicy(EvaluationPolicy):
    key = "oracle"
    deployable = False
    sees_latent_truth = True

    def observation_delay_ms(self, observed: ObservedCase) -> int:
        return 0

    def choose_action(
        self,
        observed: ObservedCase,
        merchant_policy: MerchantPolicy,
        costs: CostAssumptions,
    ) -> tuple[ActionKind, tuple[str, ...]]:
        raise RuntimeError("Oracle selection requires latent scenario truth")

    def decide_with_truth(
        self,
        scenario: Scenario,
        observed: ObservedCase,
        merchant_policy: MerchantPolicy,
        costs: CostAssumptions,
    ) -> PolicyDecision:
        if scenario.natural_recovery_at_ms is not None:
            action = ActionKind.NO_ACTION
            reasons = ("oracle_sees_natural_recovery",)
        else:
            successful = tuple(
                outcome for outcome in scenario.potential_outcomes if outcome.would_recover
            )
            if successful:
                best = min(successful, key=lambda outcome: outcome.recovery_delay_ms)
                action = best.action
                reasons = ("oracle_best_potential_outcome",)
            else:
                action = ActionKind.NO_ACTION
                reasons = ("oracle_sees_no_recoverable_action",)
        return PolicyDecision(
            action=action,
            observation_delay_ms=0,
            reason_codes=reasons,
            use_safety_gate=True,
            revalidate_before_action=True,
        )


def policy_catalog(*, model_version: str = PINNED_BUNDLED_VERSION) -> tuple[EvaluationPolicy, ...]:
    return (
        NaturalRecoveryPolicy(),
        BlastAllPolicy(),
        FixedSafePolicy(),
        IncidentAwarePolicy(),
        RetryWisePolicy(model_version=model_version),
        OraclePolicy(),
    )
