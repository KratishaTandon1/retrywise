from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta

from retrywise.packages.domain import (
    MINIMUM_LATE_CAPTURE_WINDOW,
    Approval,
    AuthorizationBindingError,
    CanonicalPaymentState,
    DomainError,
    IncidentState,
    InvalidTransition,
    LateCapturePolicy,
    Money,
    Probability,
    RecoveryAggregate,
    RecoveryState,
    VersionConflict,
)
from tests.domain.helpers import NOW, context, gate, proposal, snapshot


def new_case() -> RecoveryAggregate:
    return RecoveryAggregate(
        merchant_id="merchant_1",
        case_id="case_1",
        logical_order_id="order_1",
        amount_due=Money(129_900, "INR"),
    )


def assessing_case() -> RecoveryAggregate:
    case = new_case()
    observed_at = NOW - MINIMUM_LATE_CAPTURE_WINDOW
    case = case.observe_failure(
        expected_version=0,
        at=observed_at,
        provider_event_id="event_1",
    ).aggregate
    case = case.reconcile_payment_truth(
        CanonicalPaymentState.UNPAID,
        expected_version=1,
        at=observed_at + timedelta(seconds=1),
        evidence="snapshot_1",
    ).aggregate
    return case.mark_ready_for_evaluation(expected_version=2, at=NOW).aggregate


class RecoveryAggregateTests(unittest.TestCase):
    def test_observation_deadline_is_policy_owned_and_can_only_be_extended(self) -> None:
        shorter_suggestion = new_case().observe_failure(
            expected_version=0,
            at=NOW,
            provider_event_id="event_1",
            extend_observation_until=NOW + timedelta(seconds=10),
        )
        expected_floor = NOW + MINIMUM_LATE_CAPTURE_WINDOW
        self.assertEqual(shorter_suggestion.aggregate.observation_deadline, expected_floor)
        self.assertEqual(
            shorter_suggestion.events[0].payload["observation_deadline"],
            expected_floor.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )

        extended_deadline = NOW + timedelta(minutes=5)
        extended = RecoveryAggregate(
            merchant_id="merchant_1",
            case_id="case_2",
            logical_order_id="order_2",
            amount_due=Money(129_900, "INR"),
            late_capture_policy=LateCapturePolicy(timedelta(minutes=3)),
        ).observe_failure(
            expected_version=0,
            at=NOW,
            provider_event_id="event_2",
            extend_observation_until=extended_deadline,
        )
        self.assertEqual(extended.aggregate.observation_deadline, extended_deadline)

    def test_assessment_is_denied_before_deadline_and_allowed_at_or_after_it(self) -> None:
        def observing_unpaid(case_id: str) -> RecoveryAggregate:
            case = RecoveryAggregate(
                merchant_id="merchant_1",
                case_id=case_id,
                logical_order_id=f"order_{case_id}",
                amount_due=Money(129_900, "INR"),
            )
            case = case.observe_failure(
                expected_version=0,
                at=NOW,
                provider_event_id=f"event_{case_id}",
            ).aggregate
            return case.reconcile_payment_truth(
                CanonicalPaymentState.UNPAID,
                expected_version=1,
                at=NOW + timedelta(seconds=1),
                evidence=f"snapshot_{case_id}",
            ).aggregate

        deadline = NOW + MINIMUM_LATE_CAPTURE_WINDOW
        before = observing_unpaid("before")
        with self.assertRaisesRegex(DomainError, "observation window has not elapsed"):
            before.mark_ready_for_evaluation(
                expected_version=2,
                at=deadline - timedelta(microseconds=1),
            )

        at_boundary = observing_unpaid("boundary").mark_ready_for_evaluation(
            expected_version=2,
            at=deadline,
        )
        self.assertEqual(at_boundary.aggregate.state, RecoveryState.ASSESSING)

        after_boundary = observing_unpaid("after").mark_ready_for_evaluation(
            expected_version=2,
            at=deadline + timedelta(microseconds=1),
        )
        self.assertEqual(after_boundary.aggregate.state, RecoveryState.ASSESSING)

    def test_aggregate_rechecks_deadline_even_if_gate_context_is_incorrect(self) -> None:
        case = assessing_case()
        candidate = proposal(created_at=NOW + timedelta(seconds=2))
        policy_gate = gate()
        plan = policy_gate.evaluate_policy(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=3),
                aggregate_version=case.version,
                expected_aggregate_version=case.version,
                recovery_state=case.state,
                observation_deadline=NOW,
                snapshot=snapshot(observed_at=NOW + timedelta(seconds=2)),
            ),
        )
        self.assertTrue(plan.allowed)

        corrupted = replace(
            case,
            observation_deadline=NOW + timedelta(minutes=10),
        )
        with self.assertRaisesRegex(DomainError, "observation window has not elapsed"):
            corrupted.authorize_action(
                candidate,
                plan,
                expected_version=corrupted.version,
                at=NOW + timedelta(seconds=3),
            )

    def test_full_authorized_recovery_path(self) -> None:
        case = assessing_case()
        candidate = proposal(created_at=NOW + timedelta(seconds=2))
        policy_gate = gate()
        plan = policy_gate.evaluate_policy(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=3),
                aggregate_version=case.version,
                expected_aggregate_version=case.version,
                recovery_state=case.state,
                snapshot=snapshot(observed_at=NOW + timedelta(seconds=2)),
            ),
        )
        self.assertTrue(plan.allowed)
        change = case.authorize_action(
            candidate,
            plan,
            expected_version=case.version,
            at=NOW + timedelta(seconds=3),
        )
        case = change.aggregate
        self.assertEqual(case.state, RecoveryState.ACTION_QUEUED)
        self.assertEqual(case.version, 4)
        self.assertEqual(case.decision_version, 1)
        self.assertEqual(case.active_action_key, candidate.action_key)

        effect = policy_gate.evaluate_effect(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=4),
                aggregate_version=case.version,
                expected_aggregate_version=case.version,
                recovery_state=case.state,
                snapshot=snapshot(observed_at=NOW + timedelta(seconds=4)),
                durable_intent_recorded=True,
            ),
            prior_plan=plan,
        )
        self.assertTrue(effect.allowed)
        case = case.begin_execution(
            candidate,
            effect,
            expected_version=case.version,
            at=NOW + timedelta(seconds=4),
        ).aggregate
        case = case.record_action_active(
            expected_version=case.version,
            at=NOW + timedelta(seconds=5),
            action_key=candidate.action_key,
            instrument_reference="plink_1",
        ).aggregate
        case = case.record_recovery_paid(
            expected_version=case.version,
            at=NOW + timedelta(seconds=6),
            evidence="payment_link_paid_1",
        ).aggregate

        self.assertEqual(case.state, RecoveryState.RECOVERED)
        self.assertEqual(case.payment_state, CanonicalPaymentState.PAID)
        self.assertTrue(case.collection_closed)
        self.assertEqual(case.version, 7)

    def test_late_original_success_terminalizes_observation(self) -> None:
        case = (
            new_case()
            .observe_failure(expected_version=0, at=NOW, provider_event_id="event_1")
            .aggregate
        )
        case = case.reconcile_payment_truth(
            CanonicalPaymentState.UNPAID,
            expected_version=1,
            at=NOW + timedelta(seconds=1),
            evidence="snapshot_1",
        ).aggregate
        change = case.record_original_paid(
            expected_version=2,
            at=NOW + timedelta(seconds=2),
            evidence="payment_captured_1",
        )
        self.assertEqual(change.aggregate.state, RecoveryState.SUPPRESSED_PAID)
        self.assertEqual(change.aggregate.payment_state, CanonicalPaymentState.PAID)
        self.assertEqual(
            change.aggregate.observation_deadline,
            NOW + MINIMUM_LATE_CAPTURE_WINDOW,
        )
        with self.assertRaises(InvalidTransition):
            change.aggregate.mark_ready_for_evaluation(
                expected_version=3, at=NOW + timedelta(seconds=3)
            )

    def test_second_collection_after_recovery_opens_duplicate_review(self) -> None:
        case = assessing_case()
        candidate = proposal(created_at=NOW + timedelta(seconds=2))
        plan = gate().evaluate_policy(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=3),
                aggregate_version=3,
                expected_aggregate_version=3,
                snapshot=snapshot(observed_at=NOW + timedelta(seconds=3)),
            ),
        )
        case = case.authorize_action(
            candidate, plan, expected_version=3, at=NOW + timedelta(seconds=3)
        ).aggregate
        effect = gate().evaluate_effect(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=4),
                aggregate_version=4,
                expected_aggregate_version=4,
                recovery_state=RecoveryState.ACTION_QUEUED,
                snapshot=snapshot(observed_at=NOW + timedelta(seconds=4)),
                durable_intent_recorded=True,
            ),
            prior_plan=plan,
        )
        case = case.begin_execution(
            candidate, effect, expected_version=4, at=NOW + timedelta(seconds=4)
        ).aggregate
        case = case.record_action_active(
            expected_version=5,
            at=NOW + timedelta(seconds=5),
            action_key=candidate.action_key,
            instrument_reference="plink_1",
        ).aggregate
        case = case.record_recovery_paid(
            expected_version=6,
            at=NOW + timedelta(seconds=6),
            evidence="recovery_payment_1",
        ).aggregate
        case = case.record_original_paid(
            expected_version=7,
            at=NOW + timedelta(seconds=7),
            evidence="late_original_1",
        ).aggregate
        self.assertEqual(case.state, RecoveryState.DUPLICATE_REVIEW)
        self.assertEqual(case.payment_state, CanonicalPaymentState.OVERPAID)

    def test_redundant_success_signals_are_idempotent(self) -> None:
        case = (
            new_case()
            .observe_failure(expected_version=0, at=NOW, provider_event_id="event_1")
            .aggregate
        )
        case = case.record_original_paid(
            expected_version=1,
            at=NOW + timedelta(seconds=1),
            evidence="order_paid_1",
        ).aggregate
        duplicate_signal = case.record_original_paid(
            expected_version=2,
            at=NOW + timedelta(seconds=2),
            evidence="payment_captured_1",
        )
        self.assertFalse(duplicate_signal.changed)
        self.assertEqual(duplicate_signal.aggregate.version, 2)

    def test_optimistic_version_is_required_before_transition_validation(self) -> None:
        case = new_case()
        with self.assertRaises(VersionConflict) as raised:
            case.mark_ready_for_evaluation(expected_version=1, at=NOW)
        self.assertEqual(raised.exception.expected, 1)
        self.assertEqual(raised.exception.actual, 0)

    def test_same_truth_is_idempotent_and_does_not_increment_version(self) -> None:
        case = (
            new_case()
            .reconcile_payment_truth(
                CanonicalPaymentState.UNPAID,
                expected_version=0,
                at=NOW,
                evidence="snapshot_1",
            )
            .aggregate
        )
        unchanged = case.reconcile_payment_truth(
            CanonicalPaymentState.UNPAID,
            expected_version=1,
            at=NOW + timedelta(seconds=1),
            evidence="snapshot_2",
        )
        self.assertFalse(unchanged.changed)
        self.assertIs(unchanged.aggregate, case)
        self.assertEqual(case.version, 1)

    def test_payment_truth_cannot_regress(self) -> None:
        case = (
            new_case()
            .observe_failure(
                expected_version=0,
                at=NOW,
                provider_event_id="event_1",
            )
            .aggregate
        )
        case = case.record_original_paid(
            expected_version=1,
            at=NOW + timedelta(seconds=1),
            evidence="payment_captured_1",
        ).aggregate
        with self.assertRaises(InvalidTransition):
            case.reconcile_payment_truth(
                CanonicalPaymentState.UNPAID,
                expected_version=2,
                at=NOW + timedelta(seconds=2),
                evidence="stale_snapshot",
            )

    def test_incident_transitions_are_independent_and_strict(self) -> None:
        case = new_case()
        case = case.update_incident_state(
            IncidentState.SUSPECTED,
            expected_version=0,
            at=NOW,
            evidence="detector_1",
        ).aggregate
        case = case.update_incident_state(
            IncidentState.CONFIRMED,
            expected_version=1,
            at=NOW + timedelta(seconds=1),
            evidence="provider_1",
        ).aggregate
        self.assertEqual(case.incident_state, IncidentState.CONFIRMED)
        self.assertEqual(case.state, RecoveryState.DORMANT)
        with self.assertRaises(InvalidTransition):
            case.update_incident_state(
                IncidentState.NORMAL,
                expected_version=2,
                at=NOW + timedelta(seconds=2),
                evidence="too_early",
            )

    def test_ambiguous_action_is_reconciled_without_a_new_action_key(self) -> None:
        case = assessing_case()
        candidate = proposal(created_at=NOW + timedelta(seconds=2))
        plan = gate().evaluate_policy(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=3),
                aggregate_version=3,
                expected_aggregate_version=3,
                snapshot=snapshot(observed_at=NOW + timedelta(seconds=3)),
            ),
        )
        case = case.authorize_action(
            candidate, plan, expected_version=3, at=NOW + timedelta(seconds=3)
        ).aggregate
        effect = gate().evaluate_effect(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=4),
                aggregate_version=4,
                expected_aggregate_version=4,
                recovery_state=RecoveryState.ACTION_QUEUED,
                snapshot=snapshot(observed_at=NOW + timedelta(seconds=4)),
                durable_intent_recorded=True,
            ),
            prior_plan=plan,
        )
        case = case.begin_execution(
            candidate, effect, expected_version=4, at=NOW + timedelta(seconds=4)
        ).aggregate
        case = case.record_action_uncertain(
            expected_version=5,
            at=NOW + timedelta(seconds=5),
            action_key=candidate.action_key,
            failure_code="timeout_after_send",
        ).aggregate
        case = case.requeue_after_absence_proven(
            expected_version=6,
            at=NOW + timedelta(seconds=6),
            action_key=candidate.action_key,
        ).aggregate
        self.assertEqual(case.state, RecoveryState.ACTION_QUEUED)
        self.assertEqual(case.active_action_key, candidate.action_key)

    def test_approval_can_only_override_approval_class_failures(self) -> None:
        case = assessing_case()
        candidate = replace(
            proposal(created_at=NOW + timedelta(seconds=2)),
            amount=Money(600_000, "INR"),
            model_confidence=Probability("0.40"),
        )
        high_value_snapshot = snapshot(
            amount_due=Money(600_000, "INR"),
            observed_at=NOW + timedelta(seconds=2),
        )
        blocked = gate().evaluate_policy(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=3),
                aggregate_version=3,
                expected_aggregate_version=3,
                snapshot=high_value_snapshot,
            ),
        )
        case = case.request_approval(
            candidate,
            blocked,
            expected_version=3,
            at=NOW + timedelta(seconds=3),
        ).aggregate
        self.assertEqual(case.state, RecoveryState.APPROVAL_REQUIRED)

        approval = Approval(
            approval_id="approval_1",
            merchant_id="merchant_1",
            case_id="case_1",
            action_key=candidate.action_key,
            proposal_digest=candidate.proposal_digest,
            decision_version=1,
            approved_by="operator_1",
            approved_at=NOW + timedelta(seconds=3),
            expires_at=NOW + timedelta(minutes=5),
        )
        allowed = gate().evaluate_policy(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=4),
                aggregate_version=4,
                expected_aggregate_version=4,
                recovery_state=RecoveryState.APPROVAL_REQUIRED,
                snapshot=replace(
                    high_value_snapshot,
                    observed_at=NOW + timedelta(seconds=4),
                    method_health_observed_at=NOW + timedelta(seconds=4),
                ),
                approval=approval,
            ),
        )
        case = case.authorize_action(
            candidate,
            allowed,
            expected_version=4,
            at=NOW + timedelta(seconds=4),
        ).aggregate
        self.assertEqual(case.state, RecoveryState.ACTION_QUEUED)

        stale_snapshot_decision = gate().evaluate_policy(
            proposal(),
            context(snapshot=snapshot(observed_at=NOW - timedelta(minutes=5))),
        )
        with self.assertRaises(AuthorizationBindingError):
            assessing_case().request_approval(
                proposal(),
                stale_snapshot_decision,
                expected_version=3,
                at=NOW + timedelta(seconds=3),
            )

    def test_effect_gate_binding_cannot_be_reused_for_another_case_version(self) -> None:
        case = assessing_case()
        candidate = proposal(created_at=NOW + timedelta(seconds=2))
        plan = gate().evaluate_policy(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=3),
                aggregate_version=3,
                expected_aggregate_version=3,
                snapshot=snapshot(observed_at=NOW + timedelta(seconds=3)),
            ),
        )
        case = case.authorize_action(
            candidate, plan, expected_version=3, at=NOW + timedelta(seconds=3)
        ).aggregate
        stale_effect = gate().evaluate_effect(
            candidate,
            context(
                evaluated_at=NOW + timedelta(seconds=4),
                aggregate_version=4,
                expected_aggregate_version=4,
                recovery_state=RecoveryState.ACTION_QUEUED,
                snapshot=snapshot(observed_at=NOW + timedelta(seconds=4)),
                durable_intent_recorded=True,
            ),
            prior_plan=plan,
        )
        changed = case.update_incident_state(
            IncidentState.SUSPECTED,
            expected_version=4,
            at=NOW + timedelta(seconds=5),
            evidence="detector_1",
        ).aggregate
        with self.assertRaises(AuthorizationBindingError):
            changed.begin_execution(
                candidate,
                stale_effect,
                expected_version=5,
                at=NOW + timedelta(seconds=6),
            )


if __name__ == "__main__":
    unittest.main()
