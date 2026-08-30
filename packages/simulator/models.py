"""Immutable models shared by the RetryWise offline simulator.

All monetary values use the currency's smallest unit.  The simulator only emits
synthetic, offline counterfactual results; the labels below make that boundary a
machine-readable part of every report.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum, StrEnum
from typing import Any

from ..diagnosis import PINNED_BUNDLED_VERSION

SCHEMA_VERSION = "retrywise.evaluation.v1"
SIMULATOR_VERSION = "simulator-v1"
POLICY_VERSION_DEFAULT = "recovery-policy-v1"
MODEL_VERSION_DEFAULT = PINNED_BUNDLED_VERSION


class FailureCause(StrEnum):
    ORDINARY_RECOVERABLE = "ordinary_recoverable"
    WRONG_UPI_PIN = "wrong_upi_pin"
    LATE_AUTHORIZATION = "late_authorization"
    INSUFFICIENT_FUNDS = "insufficient_funds"
    EXPIRED_CREDENTIAL = "expired_credential"
    UNKNOWN = "unknown_failure"
    UPI_INCIDENT = "upi_wide_incident"
    ISSUER_INCIDENT = "issuer_specific_incident"
    BANK_INCIDENT = "bank_specific_incident"


class EventKind(StrEnum):
    PAYMENT_FAILED = "payment.failed"
    PAYMENT_CAPTURED = "payment.captured"
    DOWNTIME_STARTED = "payment.downtime.started"
    DOWNTIME_RESOLVED = "payment.downtime.resolved"
    MALFORMED = "malformed"


class ActionKind(StrEnum):
    NO_ACTION = "no_action"
    GENERIC_LINK = "generic_payment_link"
    ALTERNATIVE_LINK = "alternative_method_link"


@dataclass(frozen=True, slots=True)
class CostAssumptions:
    communication_cost_minor: int = 200
    action_cost_minor: int = 100
    incentive_cost_minor: int = 0
    friction_penalty_minor: int = 1_000
    duplicate_penalty_minor: int = 50_000


@dataclass(frozen=True, slots=True)
class MerchantPolicy:
    merchant_id: str
    provider_account_id: str
    contact_cap: int
    quiet_hours_start: int
    quiet_hours_end: int
    approval_threshold_minor: int
    enabled_methods: tuple[str, ...]
    recovery_horizon_ms: int
    version: str


@dataclass(frozen=True, slots=True)
class ScenarioEvent:
    event_id: str
    scenario_id: str
    kind: EventKind
    occurs_at_ms: int
    delivered_at_ms: int | None
    provider_account_id: str
    signature_valid: bool
    schema_version: str
    currency: str
    delivery_attempt: int = 1
    metadata: tuple[tuple[str, str], ...] = ()

    @property
    def delivered(self) -> bool:
        return self.delivered_at_ms is not None


@dataclass(frozen=True, slots=True)
class PotentialOutcome:
    action: ActionKind
    would_recover: bool
    recovery_delay_ms: int


@dataclass(frozen=True, slots=True)
class Scenario:
    scenario_id: str
    family: str
    merchant_id: str
    order_id: str
    amount_minor: int
    currency: str
    method: str
    observable_error: str
    customer_response_score: float
    consent_to_contact: bool
    failure_local_hour: int
    latent_cause: FailureCause
    natural_recovery_at_ms: int | None
    incident_scope: str | None
    anomaly_score: float
    events: tuple[ScenarioEvent, ...]
    potential_outcomes: tuple[PotentialOutcome, ...]
    delivery_mutations: tuple[str, ...]
    adversarial_flags: tuple[str, ...]

    def outcome_for(self, action: ActionKind) -> PotentialOutcome:
        for outcome in self.potential_outcomes:
            if outcome.action is action:
                return outcome
        raise KeyError(f"No potential outcome for {action.value}")


@dataclass(frozen=True, slots=True)
class ScenarioDataset:
    seed: int
    scenarios: tuple[Scenario, ...]
    merchant_policies: tuple[MerchantPolicy, ...]
    costs: CostAssumptions
    dataset_hash: str


@dataclass(frozen=True, slots=True)
class ObservedCase:
    scenario_id: str
    merchant_id: str
    amount_minor: int
    currency: str
    method: str
    observable_error: str
    customer_response_score: float
    consent_to_contact: bool
    failure_local_hour: int
    anomaly_score: float
    provider_incident_signal: bool


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: ActionKind
    observation_delay_ms: int
    reason_codes: tuple[str, ...]
    use_safety_gate: bool
    revalidate_before_action: bool


@dataclass(frozen=True, slots=True)
class AuditEntry:
    timestamp_ms: int
    actor: str
    event_type: str
    scenario_id: str
    policy_key: str
    reason_code: str
    trace_id: str
    policy_version: str
    decision_id: str
    details: tuple[tuple[str, str], ...] = ()

    def present_field_count(self) -> int:
        required = (
            self.actor,
            self.event_type,
            self.scenario_id,
            self.policy_key,
            self.reason_code,
            self.trace_id,
            self.policy_version,
            self.decision_id,
        )
        return 1 + sum(bool(value) for value in required)

    @staticmethod
    def expected_field_count() -> int:
        return 9


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    scenario_id: str
    merchant_id: str
    policy_key: str
    action: ActionKind
    action_executed: bool
    contact_sent: bool
    natural_recovered: bool
    action_recovered: bool
    incremental_recovered: bool
    natural_recovered_value_minor: int
    action_recovered_value_minor: int
    incremental_recovered_value_minor: int
    communication_cost_minor: int
    action_cost_minor: int
    incentive_cost_minor: int
    friction_penalty_minor: int
    duplicate_penalty_minor: int
    net_incremental_value_minor: int
    recovery_time_ms: int | None
    unnecessary_contact: bool
    duplicate_risk: bool
    original_success_action_suppressed: bool
    abstained: bool
    safety_violations: tuple[str, ...]
    duplicate_events_suppressed: int
    invalid_events_rejected: int
    audit_entries: tuple[AuditEntry, ...]


@dataclass(frozen=True, slots=True)
class PolicyMetrics:
    total_cases: int
    gross_action_recovered_value_minor: int
    natural_recovered_value_minor: int
    simulated_incremental_recovered_value_minor: int
    net_simulated_incremental_value_minor: int
    natural_recovered_orders: int
    action_recovered_orders: int
    incremental_recovered_orders: int
    contacts_sent: int
    actions_executed: int
    communication_cost_minor: int
    action_cost_minor: int
    incentive_cost_minor: int
    friction_penalty_minor: int
    duplicate_penalty_minor: int
    unnecessary_contacts: int
    unnecessary_contact_rate: float
    contact_efficiency: float
    duplicate_risk_events: int
    unsafe_executed_action_rate: float
    hard_safety_violations: int
    stop_rule_violations: int
    stale_state_actions: int
    multiple_active_recovery_instruments: int
    invalid_webhook_acceptances: int
    cross_tenant_effects: int
    recognized_overpayments: int
    unrecognized_overpayments: int
    safety_violation_breakdown: tuple[tuple[str, int], ...]
    audit_completeness_pct: float
    duplicate_events_suppressed: int
    invalid_events_rejected: int
    duplicate_effects_under_replay: int
    original_success_actions_suppressed: int
    abstentions: int
    abstention_rate: float
    median_recovery_time_ms: int | None
    p95_recovery_time_ms: int | None


@dataclass(frozen=True, slots=True)
class PolicyResult:
    policy_key: str
    display_name: str
    deployable: bool
    metrics: PolicyMetrics
    case_outcomes: tuple[CaseOutcome, ...]


@dataclass(frozen=True, slots=True)
class ConfidenceInterval:
    low_minor: int
    high_minor: int
    confidence: float
    bootstrap_samples: int
    cluster_unit: str


@dataclass(frozen=True, slots=True)
class PairedComparison:
    candidate: str
    reference: str
    paired_on: str
    delta_net_value_minor: int
    delta_incremental_recovered_orders: int
    delta_hard_safety_violations: int
    wins: int
    losses: int
    ties: int
    confidence_interval: ConfidenceInterval
    supports_improvement: bool
    conclusion: str


@dataclass(frozen=True, slots=True)
class HonestLabels:
    execution_context: str = "offline_replay"
    dataset_label: str = "Synthetic counterfactual scenarios"
    value_label: str = "Offline simulated recovered value"
    real_money: bool = False
    observed_real_merchant_revenue_claimed: bool = False
    test_mode_collection_label: str = (
        "Razorpay test-mode collection executed: not measured by this offline run"
    )


@dataclass(frozen=True, slots=True)
class RunManifest:
    seed: int
    case_count: int
    dataset_hash: str
    policy_version: str
    model_version: str
    code_revision: str
    simulator_version: str
    bootstrap_samples: int
    cost_assumptions: CostAssumptions
    scenario_family_counts: tuple[tuple[str, int], ...]
    delivery_mutation_counts: tuple[tuple[str, int], ...]
    adversarial_flag_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    schema_version: str
    labels: HonestLabels
    manifest: RunManifest
    results: tuple[PolicyResult, ...]
    comparisons: tuple[PairedComparison, ...]
    deployable_ranking: tuple[str, ...]

    def to_dict(self, include_case_outcomes: bool = False) -> dict[str, Any]:
        result_payload: dict[str, Any] = {}
        for result in self.results:
            payload = {
                "display_name": result.display_name,
                "deployable": result.deployable,
                "metrics": to_primitive(result.metrics),
            }
            if include_case_outcomes:
                payload["case_outcomes"] = to_primitive(result.case_outcomes)
            result_payload[result.policy_key] = payload
        return {
            "schema_version": self.schema_version,
            "labels": to_primitive(self.labels),
            "manifest": to_primitive(self.manifest),
            "results": result_payload,
            "comparisons": to_primitive(self.comparisons),
            "deployable_ranking": list(self.deployable_ranking),
        }


def to_primitive(value: Any) -> Any:
    """Convert simulator models into stable JSON-compatible primitives."""

    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {field.name: to_primitive(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, dict):
        return {
            str(key): to_primitive(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [to_primitive(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        to_primitive(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def stable_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
