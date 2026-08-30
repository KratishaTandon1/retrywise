"""Virtual-clock execution engine for paired policy replay."""

from __future__ import annotations

import heapq
import math
import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .models import (
    ActionKind,
    AuditEntry,
    CaseOutcome,
    EventKind,
    MerchantPolicy,
    ObservedCase,
    PolicyMetrics,
    PolicyResult,
    Scenario,
    ScenarioDataset,
    ScenarioEvent,
)
from .policies import EvaluationPolicy, OraclePolicy


@dataclass(order=True, slots=True)
class _QueueItem:
    at_ms: int
    sequence: int
    kind: str = field(compare=False)
    payload: Any = field(compare=False)


@dataclass(frozen=True, slots=True)
class ClockItem:
    at_ms: int
    kind: str
    payload: Any


class VirtualClock:
    """Small deterministic event queue; it never reads or sleeps on wall time."""

    def __init__(self) -> None:
        self.now_ms = 0
        self._sequence = 0
        self._queue: list[_QueueItem] = []

    def schedule(self, at_ms: int, kind: str, payload: Any) -> None:
        if at_ms < self.now_ms:
            raise ValueError("cannot schedule an event in the virtual past")
        self._sequence += 1
        heapq.heappush(
            self._queue,
            _QueueItem(at_ms=at_ms, sequence=self._sequence, kind=kind, payload=payload),
        )

    def run_until(self, target_ms: int) -> tuple[ClockItem, ...]:
        if target_ms < self.now_ms:
            raise ValueError("virtual time is monotonic")
        emitted: list[ClockItem] = []
        while self._queue and self._queue[0].at_ms <= target_ms:
            queued = heapq.heappop(self._queue)
            self.now_ms = queued.at_ms
            emitted.append(ClockItem(queued.at_ms, queued.kind, queued.payload))
        self.now_ms = target_ms
        return tuple(emitted)

    def drain(self) -> tuple[ClockItem, ...]:
        if not self._queue:
            return ()
        return self.run_until(max(item.at_ms for item in self._queue))


def run_policy(dataset: ScenarioDataset, policy: EvaluationPolicy) -> PolicyResult:
    merchant_policies = {item.merchant_id: item for item in dataset.merchant_policies}
    outcomes = tuple(
        _run_case(dataset, scenario, merchant_policies[scenario.merchant_id], policy)
        for scenario in dataset.scenarios
    )
    return PolicyResult(
        policy_key=policy.key,
        display_name=policy.display_name,
        deployable=policy.deployable,
        metrics=_aggregate_metrics(outcomes),
        case_outcomes=outcomes,
    )


def _run_case(
    dataset: ScenarioDataset,
    scenario: Scenario,
    merchant_policy: MerchantPolicy,
    policy: EvaluationPolicy,
) -> CaseOutcome:
    trace_id = f"trace-{scenario.scenario_id}-{policy.key}"
    decision_id = f"decision-{scenario.scenario_id}-{policy.key}"
    audit: list[AuditEntry] = []
    valid_events, duplicate_count, invalid_count = _accepted_events(
        scenario.events,
        merchant_policy,
    )
    failures = tuple(event for event in valid_events if event.kind is EventKind.PAYMENT_FAILED)
    if not failures:
        audit.append(
            _audit(
                0,
                "gateway",
                "case_not_opened",
                scenario,
                policy,
                "no_verified_failure",
                trace_id,
                decision_id,
                merchant_policy,
            )
        )
        return _no_action_outcome(
            scenario,
            policy,
            audit,
            duplicate_count,
            invalid_count,
        )

    failure_at = min(event.delivered_at_ms or 0 for event in failures)
    initial = _observed_case(scenario, valid_events, failure_at)
    observation_delay = policy.observation_delay_ms(initial)
    decision_at = failure_at + observation_delay
    observed = _observed_case(scenario, valid_events, decision_at)
    if isinstance(policy, OraclePolicy):
        decision = policy.decide_with_truth(
            scenario,
            observed,
            merchant_policy,
            dataset.costs,
        )
    else:
        decision = policy.decide(observed, merchant_policy, dataset.costs)
    # The policy owns the delay; this assignment keeps a single immutable decision.
    decision_at = failure_at + decision.observation_delay_ms

    clock = VirtualClock()
    for event in valid_events:
        if event.delivered_at_ms is not None:
            clock.schedule(event.delivered_at_ms, "provider_event", event)
    clock.run_until(decision_at)

    audit.append(
        _audit(
            failure_at,
            "gateway",
            "verified_failure_accepted",
            scenario,
            policy,
            "signature_account_and_event_verified",
            trace_id,
            decision_id,
            merchant_policy,
        )
    )
    audit.append(
        _audit(
            decision_at,
            "decision_engine",
            "decision_recorded",
            scenario,
            policy,
            "+".join(decision.reason_codes),
            trace_id,
            decision_id,
            merchant_policy,
            (("action", decision.action.value),),
        )
    )

    natural_recovered = (
        scenario.natural_recovery_at_ms is not None
        and scenario.natural_recovery_at_ms <= merchant_policy.recovery_horizon_ms
    )
    if decision.action is ActionKind.NO_ACTION:
        audit.append(
            _audit(
                decision_at,
                "policy",
                "action_abstained",
                scenario,
                policy,
                decision.reason_codes[0],
                trace_id,
                decision_id,
                merchant_policy,
            )
        )
        return _make_outcome(
            scenario=scenario,
            policy=policy,
            action=ActionKind.NO_ACTION,
            action_executed=False,
            contact_sent=False,
            natural_recovered=natural_recovered,
            action_recovered=False,
            execution_at_ms=None,
            recovery_time_ms=scenario.natural_recovery_at_ms,
            unnecessary_contact=False,
            duplicate_risk=False,
            original_success_action_suppressed=False,
            abstained=True,
            safety_violations=(),
            duplicate_events_suppressed=duplicate_count,
            invalid_events_rejected=invalid_count,
            audit=tuple(audit),
            dataset=dataset,
        )

    execution_at = decision_at
    suppression_reason: str | None = None
    original_success_suppressed = False
    if decision.use_safety_gate:
        execution_at, suppression_reason = _apply_guardrails(
            scenario,
            merchant_policy,
            execution_at,
        )
        if (
            suppression_reason is None
            and decision.revalidate_before_action
            and scenario.natural_recovery_at_ms is not None
            and scenario.natural_recovery_at_ms <= execution_at
        ):
            suppression_reason = "original_payment_already_captured"
            original_success_suppressed = True

    if suppression_reason is not None:
        audit.append(
            _audit(
                execution_at,
                "safety_gate",
                "action_suppressed",
                scenario,
                policy,
                suppression_reason,
                trace_id,
                decision_id,
                merchant_policy,
            )
        )
        return _make_outcome(
            scenario=scenario,
            policy=policy,
            action=decision.action,
            action_executed=False,
            contact_sent=False,
            natural_recovered=natural_recovered,
            action_recovered=False,
            execution_at_ms=execution_at,
            recovery_time_ms=scenario.natural_recovery_at_ms,
            unnecessary_contact=False,
            duplicate_risk=False,
            original_success_action_suppressed=original_success_suppressed,
            abstained=True,
            safety_violations=(),
            duplicate_events_suppressed=duplicate_count,
            invalid_events_rejected=invalid_count,
            audit=tuple(audit),
            dataset=dataset,
        )

    safety_violations = _unsafe_policy_violations(
        scenario,
        merchant_policy,
        execution_at,
        decision.use_safety_gate,
    )
    potential = scenario.outcome_for(decision.action)
    recovery_at = execution_at + potential.recovery_delay_ms
    action_recovered = (
        potential.would_recover and recovery_at <= merchant_policy.recovery_horizon_ms
    )
    duplicate_risk = bool(action_recovered and natural_recovered)
    if duplicate_risk:
        safety_violations = tuple(
            sorted((*safety_violations, "multiple_collection_paths_captured"))
        )
    incremental_recovered = bool(action_recovered and not natural_recovered)
    recovery_time_candidates = tuple(
        value
        for value in (
            scenario.natural_recovery_at_ms if natural_recovered else None,
            recovery_at if action_recovered else None,
        )
        if value is not None
    )
    recovery_time = min(recovery_time_candidates) if recovery_time_candidates else None

    audit.append(
        _audit(
            execution_at,
            "executor",
            "action_executed",
            scenario,
            policy,
            "provider_action_completed",
            trace_id,
            decision_id,
            merchant_policy,
            (("action", decision.action.value),),
        )
    )
    audit.append(
        _audit(
            recovery_time or merchant_policy.recovery_horizon_ms,
            "outcome_attribution",
            "outcome_recorded",
            scenario,
            policy,
            (
                "incremental_recovery"
                if incremental_recovered
                else "duplicate_risk"
                if duplicate_risk
                else "no_incremental_recovery"
            ),
            trace_id,
            decision_id,
            merchant_policy,
        )
    )
    return _make_outcome(
        scenario=scenario,
        policy=policy,
        action=decision.action,
        action_executed=True,
        contact_sent=True,
        natural_recovered=natural_recovered,
        action_recovered=action_recovered,
        execution_at_ms=execution_at,
        recovery_time_ms=recovery_time,
        unnecessary_contact=not incremental_recovered,
        duplicate_risk=duplicate_risk,
        original_success_action_suppressed=False,
        abstained=False,
        safety_violations=safety_violations,
        duplicate_events_suppressed=duplicate_count,
        invalid_events_rejected=invalid_count,
        audit=tuple(audit),
        dataset=dataset,
    )


def _accepted_events(
    events: tuple[ScenarioEvent, ...],
    merchant_policy: MerchantPolicy,
) -> tuple[tuple[ScenarioEvent, ...], int, int]:
    accepted: list[ScenarioEvent] = []
    seen: set[str] = set()
    duplicates = 0
    invalid = 0
    for event in events:
        if not event.delivered:
            continue
        if (
            not event.signature_valid
            or event.provider_account_id != merchant_policy.provider_account_id
            or event.kind is EventKind.MALFORMED
        ):
            invalid += 1
            continue
        if event.event_id in seen:
            duplicates += 1
            continue
        seen.add(event.event_id)
        accepted.append(event)
    return tuple(accepted), duplicates, invalid


def _observed_case(
    scenario: Scenario,
    events: tuple[ScenarioEvent, ...],
    at_ms: int,
) -> ObservedCase:
    provider_signal = any(
        event.kind is EventKind.DOWNTIME_STARTED
        and event.delivered_at_ms is not None
        and event.delivered_at_ms <= at_ms
        for event in events
    )
    return ObservedCase(
        scenario_id=scenario.scenario_id,
        merchant_id=scenario.merchant_id,
        amount_minor=scenario.amount_minor,
        currency=scenario.currency,
        method=scenario.method,
        observable_error=scenario.observable_error,
        customer_response_score=scenario.customer_response_score,
        consent_to_contact=scenario.consent_to_contact,
        failure_local_hour=scenario.failure_local_hour,
        anomaly_score=scenario.anomaly_score,
        provider_incident_signal=provider_signal,
    )


def _apply_guardrails(
    scenario: Scenario,
    merchant_policy: MerchantPolicy,
    execution_at: int,
) -> tuple[int, str | None]:
    if "kill_switch" in scenario.adversarial_flags:
        return execution_at, "merchant_kill_switch"
    if "partial_payment" in scenario.adversarial_flags:
        return execution_at, "canonical_truth_partially_paid"
    if "expired_order" in scenario.adversarial_flags:
        return execution_at, "order_expired"
    if "ambiguous_mapping" in scenario.adversarial_flags:
        return execution_at, "ambiguous_order_mapping"
    if "provider_error" in scenario.adversarial_flags:
        return execution_at, "provider_state_unavailable"
    if "contact_cap_exhausted" in scenario.adversarial_flags:
        return execution_at, "contact_cap_exhausted"
    if "currency_mismatch" in scenario.adversarial_flags:
        return execution_at, "currency_mismatch"
    if not scenario.consent_to_contact:
        return execution_at, "contact_consent_missing"
    if merchant_policy.contact_cap < 1:
        return execution_at, "contact_cap_exhausted"
    if scenario.amount_minor >= merchant_policy.approval_threshold_minor:
        return execution_at, "high_value_approval_required"
    quiet_delay = _quiet_hours_delay_ms(
        scenario.failure_local_hour,
        merchant_policy.quiet_hours_start,
        merchant_policy.quiet_hours_end,
    )
    execution_at = max(execution_at, quiet_delay)
    if execution_at > merchant_policy.recovery_horizon_ms:
        return execution_at, "recovery_horizon_exhausted"
    return execution_at, None


def _unsafe_policy_violations(
    scenario: Scenario,
    merchant_policy: MerchantPolicy,
    execution_at: int,
    safety_gate_used: bool,
) -> tuple[str, ...]:
    if safety_gate_used:
        return ()
    violations: list[str] = []
    if not scenario.consent_to_contact:
        violations.append("contact_without_consent")
    if _is_quiet_hour(
        scenario.failure_local_hour,
        merchant_policy.quiet_hours_start,
        merchant_policy.quiet_hours_end,
    ):
        violations.append("quiet_hours_contact")
    if scenario.amount_minor >= merchant_policy.approval_threshold_minor:
        violations.append("approval_bypass")
    if "currency_mismatch" in scenario.adversarial_flags:
        violations.append("currency_mismatch_action")
    if "kill_switch" in scenario.adversarial_flags:
        violations.append("kill_switch_bypass")
    if "partial_payment" in scenario.adversarial_flags:
        violations.append("partial_payment_collection")
    if "expired_order" in scenario.adversarial_flags:
        violations.append("expired_order_action")
    if "ambiguous_mapping" in scenario.adversarial_flags:
        violations.append("ambiguous_mapping_action")
    if "provider_error" in scenario.adversarial_flags:
        violations.append("provider_uncertainty_action")
    if "contact_cap_exhausted" in scenario.adversarial_flags:
        violations.append("contact_cap_violation")
    if (
        scenario.natural_recovery_at_ms is not None
        and scenario.natural_recovery_at_ms <= execution_at
    ):
        violations.append("stale_state_action")
    return tuple(sorted(violations))


def _is_quiet_hour(hour: int, start: int, end: int) -> bool:
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _quiet_hours_delay_ms(hour: int, start: int, end: int) -> int:
    if not _is_quiet_hour(hour, start, end):
        return 0
    hours_until_end = (end - hour) % 24
    return hours_until_end * 60 * 60 * 1_000


def _audit(
    timestamp_ms: int,
    actor: str,
    event_type: str,
    scenario: Scenario,
    policy: EvaluationPolicy,
    reason_code: str,
    trace_id: str,
    decision_id: str,
    merchant_policy: MerchantPolicy,
    details: tuple[tuple[str, str], ...] = (),
) -> AuditEntry:
    return AuditEntry(
        timestamp_ms=timestamp_ms,
        actor=actor,
        event_type=event_type,
        scenario_id=scenario.scenario_id,
        policy_key=policy.key,
        reason_code=reason_code,
        trace_id=trace_id,
        policy_version=merchant_policy.version,
        decision_id=decision_id,
        details=details,
    )


def _no_action_outcome(
    scenario: Scenario,
    policy: EvaluationPolicy,
    audit: list[AuditEntry],
    duplicate_count: int,
    invalid_count: int,
) -> CaseOutcome:
    natural_recovered = scenario.natural_recovery_at_ms is not None
    amount = scenario.amount_minor if natural_recovered else 0
    return CaseOutcome(
        scenario_id=scenario.scenario_id,
        merchant_id=scenario.merchant_id,
        policy_key=policy.key,
        action=ActionKind.NO_ACTION,
        action_executed=False,
        contact_sent=False,
        natural_recovered=natural_recovered,
        action_recovered=False,
        incremental_recovered=False,
        natural_recovered_value_minor=amount,
        action_recovered_value_minor=0,
        incremental_recovered_value_minor=0,
        communication_cost_minor=0,
        action_cost_minor=0,
        incentive_cost_minor=0,
        friction_penalty_minor=0,
        duplicate_penalty_minor=0,
        net_incremental_value_minor=0,
        recovery_time_ms=scenario.natural_recovery_at_ms,
        unnecessary_contact=False,
        duplicate_risk=False,
        original_success_action_suppressed=False,
        abstained=True,
        safety_violations=(),
        duplicate_events_suppressed=duplicate_count,
        invalid_events_rejected=invalid_count,
        audit_entries=tuple(audit),
    )


def _make_outcome(
    *,
    scenario: Scenario,
    policy: EvaluationPolicy,
    action: ActionKind,
    action_executed: bool,
    contact_sent: bool,
    natural_recovered: bool,
    action_recovered: bool,
    execution_at_ms: int | None,
    recovery_time_ms: int | None,
    unnecessary_contact: bool,
    duplicate_risk: bool,
    original_success_action_suppressed: bool,
    abstained: bool,
    safety_violations: tuple[str, ...],
    duplicate_events_suppressed: int,
    invalid_events_rejected: int,
    audit: tuple[AuditEntry, ...],
    dataset: ScenarioDataset,
) -> CaseOutcome:
    natural_value = scenario.amount_minor if natural_recovered else 0
    action_value = scenario.amount_minor if action_recovered else 0
    incremental = bool(action_recovered and not natural_recovered)
    incremental_value = scenario.amount_minor if incremental else 0
    communication_cost = dataset.costs.communication_cost_minor if contact_sent else 0
    action_cost = dataset.costs.action_cost_minor if action_executed else 0
    incentive_cost = dataset.costs.incentive_cost_minor if action_executed else 0
    friction_penalty = dataset.costs.friction_penalty_minor if unnecessary_contact else 0
    duplicate_penalty = (
        scenario.amount_minor + dataset.costs.duplicate_penalty_minor if duplicate_risk else 0
    )
    net_value = (
        incremental_value
        - communication_cost
        - action_cost
        - incentive_cost
        - friction_penalty
        - duplicate_penalty
    )
    return CaseOutcome(
        scenario_id=scenario.scenario_id,
        merchant_id=scenario.merchant_id,
        policy_key=policy.key,
        action=action,
        action_executed=action_executed,
        contact_sent=contact_sent,
        natural_recovered=natural_recovered,
        action_recovered=action_recovered,
        incremental_recovered=incremental,
        natural_recovered_value_minor=natural_value,
        action_recovered_value_minor=action_value,
        incremental_recovered_value_minor=incremental_value,
        communication_cost_minor=communication_cost,
        action_cost_minor=action_cost,
        incentive_cost_minor=incentive_cost,
        friction_penalty_minor=friction_penalty,
        duplicate_penalty_minor=duplicate_penalty,
        net_incremental_value_minor=net_value,
        recovery_time_ms=recovery_time_ms,
        unnecessary_contact=unnecessary_contact,
        duplicate_risk=duplicate_risk,
        original_success_action_suppressed=original_success_action_suppressed,
        abstained=abstained,
        safety_violations=safety_violations,
        duplicate_events_suppressed=duplicate_events_suppressed,
        invalid_events_rejected=invalid_events_rejected,
        audit_entries=audit,
    )


def _aggregate_metrics(outcomes: tuple[CaseOutcome, ...]) -> PolicyMetrics:
    violations = Counter(
        violation for outcome in outcomes for violation in outcome.safety_violations
    )
    actions_with_violations = sum(
        outcome.action_executed and bool(outcome.safety_violations) for outcome in outcomes
    )
    actions = sum(outcome.action_executed for outcome in outcomes)
    contacts = sum(outcome.contact_sent for outcome in outcomes)
    unnecessary = sum(outcome.unnecessary_contact for outcome in outcomes)
    incremental_orders = sum(outcome.incremental_recovered for outcome in outcomes)
    audit_present = sum(
        entry.present_field_count() for outcome in outcomes for entry in outcome.audit_entries
    )
    audit_expected = sum(
        entry.expected_field_count() for outcome in outcomes for entry in outcome.audit_entries
    )
    recovery_times = sorted(
        outcome.recovery_time_ms for outcome in outcomes if outcome.recovery_time_ms is not None
    )
    return PolicyMetrics(
        total_cases=len(outcomes),
        gross_action_recovered_value_minor=sum(
            outcome.action_recovered_value_minor for outcome in outcomes
        ),
        natural_recovered_value_minor=sum(
            outcome.natural_recovered_value_minor for outcome in outcomes
        ),
        simulated_incremental_recovered_value_minor=sum(
            outcome.incremental_recovered_value_minor for outcome in outcomes
        ),
        net_simulated_incremental_value_minor=sum(
            outcome.net_incremental_value_minor for outcome in outcomes
        ),
        natural_recovered_orders=sum(outcome.natural_recovered for outcome in outcomes),
        action_recovered_orders=sum(outcome.action_recovered for outcome in outcomes),
        incremental_recovered_orders=incremental_orders,
        contacts_sent=contacts,
        actions_executed=actions,
        communication_cost_minor=sum(outcome.communication_cost_minor for outcome in outcomes),
        action_cost_minor=sum(outcome.action_cost_minor for outcome in outcomes),
        incentive_cost_minor=sum(outcome.incentive_cost_minor for outcome in outcomes),
        friction_penalty_minor=sum(outcome.friction_penalty_minor for outcome in outcomes),
        duplicate_penalty_minor=sum(outcome.duplicate_penalty_minor for outcome in outcomes),
        unnecessary_contacts=unnecessary,
        unnecessary_contact_rate=(unnecessary / contacts if contacts else 0.0),
        contact_efficiency=(incremental_orders / contacts if contacts else 0.0),
        duplicate_risk_events=sum(outcome.duplicate_risk for outcome in outcomes),
        unsafe_executed_action_rate=(actions_with_violations / actions if actions else 0.0),
        hard_safety_violations=sum(violations.values()),
        stop_rule_violations=sum(
            count
            for violation, count in violations.items()
            if violation
            in {
                "contact_without_consent",
                "quiet_hours_contact",
                "approval_bypass",
                "currency_mismatch_action",
                "kill_switch_bypass",
                "partial_payment_collection",
                "expired_order_action",
                "ambiguous_mapping_action",
                "provider_uncertainty_action",
                "contact_cap_violation",
            }
        ),
        stale_state_actions=violations.get("stale_state_action", 0),
        multiple_active_recovery_instruments=0,
        invalid_webhook_acceptances=0,
        cross_tenant_effects=0,
        recognized_overpayments=sum(outcome.duplicate_risk for outcome in outcomes),
        unrecognized_overpayments=0,
        safety_violation_breakdown=tuple(sorted(violations.items())),
        audit_completeness_pct=(
            round(100.0 * audit_present / audit_expected, 6) if audit_expected else 100.0
        ),
        duplicate_events_suppressed=sum(
            outcome.duplicate_events_suppressed for outcome in outcomes
        ),
        invalid_events_rejected=sum(outcome.invalid_events_rejected for outcome in outcomes),
        duplicate_effects_under_replay=0,
        original_success_actions_suppressed=sum(
            outcome.original_success_action_suppressed for outcome in outcomes
        ),
        abstentions=sum(outcome.abstained for outcome in outcomes),
        abstention_rate=(
            sum(outcome.abstained for outcome in outcomes) / len(outcomes) if outcomes else 0.0
        ),
        median_recovery_time_ms=(
            int(statistics.median(recovery_times)) if recovery_times else None
        ),
        p95_recovery_time_ms=_nearest_rank_percentile(recovery_times, 0.95),
    )


def _nearest_rank_percentile(values: list[int], quantile: float) -> int | None:
    if not values:
        return None
    rank = max(1, math.ceil(quantile * len(values)))
    return values[rank - 1]
