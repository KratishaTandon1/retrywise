from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta

from retrywise.packages.domain import (
    ActionProposal,
    ActionType,
    Approval,
    CanonicalPaymentState,
    GateReason,
    GateStage,
    IncidentState,
    Money,
    Probability,
    RecoveryState,
)
from tests.domain.helpers import NOW, context, gate, proposal, snapshot


class DeterministicGateTests(unittest.TestCase):
    def test_collection_is_denied_before_observation_deadline_at_both_gate_stages(self) -> None:
        policy_gate = gate()
        candidate = proposal()
        future_deadline = NOW + timedelta(microseconds=1)
        plan = policy_gate.evaluate_policy(
            candidate,
            context(observation_deadline=future_deadline),
        )
        self.assertEqual(plan.reasons, (GateReason.OBSERVATION_WINDOW_ACTIVE,))

        allowed_plan = policy_gate.evaluate_policy(candidate, context())
        effect = policy_gate.evaluate_effect(
            candidate,
            context(
                aggregate_version=4,
                expected_aggregate_version=4,
                recovery_state=RecoveryState.ACTION_QUEUED,
                durable_intent_recorded=True,
                observation_deadline=future_deadline,
            ),
            prior_plan=allowed_plan,
        )
        self.assertEqual(effect.reasons, (GateReason.OBSERVATION_WINDOW_ACTIVE,))

    def test_collection_is_allowed_at_and_after_observation_deadline(self) -> None:
        for deadline in (NOW, NOW - timedelta(microseconds=1)):
            with self.subTest(deadline=deadline):
                decision = gate().evaluate_policy(
                    proposal(),
                    context(observation_deadline=deadline),
                )
                self.assertTrue(decision.allowed)

    def test_missing_observation_deadline_fails_closed_for_collection_only(self) -> None:
        collection = gate().evaluate_policy(
            proposal(),
            context(observation_deadline=None),
        )
        self.assertEqual(
            collection.reasons,
            (GateReason.OBSERVATION_DEADLINE_MISSING,),
        )

        cancellation = ActionProposal(
            proposal_id="cancel_missing_deadline",
            merchant_id="merchant_1",
            case_id="case_1",
            decision_version=1,
            action_type=ActionType.CANCEL_PAYMENT_LINK,
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            instrument_reference="plink_123",
        )
        protective = gate().evaluate_policy(
            cancellation,
            context(
                observation_deadline=None,
                recovery_state=RecoveryState.SUPPRESSED_PAID,
                snapshot=snapshot(
                    payment_state=CanonicalPaymentState.PAID,
                    active_instrument_count=1,
                ),
            ),
        )
        self.assertTrue(protective.allowed)

    def test_happy_policy_and_effect_authorizations(self) -> None:
        policy_gate = gate()
        candidate = proposal()
        plan = policy_gate.evaluate_policy(candidate, context())
        self.assertTrue(plan.allowed)
        self.assertEqual(plan.stage, GateStage.POLICY)
        self.assertEqual(plan.reasons, ())

        effect_context = context(
            aggregate_version=4,
            expected_aggregate_version=4,
            recovery_state=RecoveryState.ACTION_QUEUED,
            durable_intent_recorded=True,
        )
        effect = policy_gate.evaluate_effect(candidate, effect_context, prior_plan=plan)
        self.assertTrue(effect.allowed)
        self.assertEqual(effect.stage, GateStage.EFFECT)

    def test_effect_stage_rechecks_truth_and_requires_durable_plan(self) -> None:
        policy_gate = gate()
        candidate = proposal()
        changed_truth = snapshot(payment_state=CanonicalPaymentState.PAID)
        effect = policy_gate.evaluate_effect(
            candidate,
            context(
                aggregate_version=4,
                expected_aggregate_version=4,
                recovery_state=RecoveryState.ACTION_QUEUED,
                snapshot=changed_truth,
                durable_intent_recorded=False,
            ),
            prior_plan=None,
        )
        self.assertFalse(effect.allowed)
        self.assertEqual(
            effect.reasons,
            (
                GateReason.PAYMENT_TRUTH_NOT_UNPAID,
                GateReason.PLAN_AUTHORIZATION_MISSING,
                GateReason.DURABLE_INTENT_MISSING,
            ),
        )

    def test_reason_codes_have_stable_predicate_order(self) -> None:
        candidate = replace(proposal(), amount=Money(129_901, "INR"))
        stale = snapshot(
            payment_state=CanonicalPaymentState.PAID,
            amount_due=Money(129_900, "INR"),
            observed_at=NOW - timedelta(minutes=2),
            active_instrument_count=1,
            incident_state=IncidentState.CONFIRMED,
            method_health_observed_at=NOW - timedelta(minutes=2),
        )
        decision = gate().evaluate_policy(
            candidate,
            context(
                aggregate_version=3,
                expected_aggregate_version=4,
                recovery_state=RecoveryState.ACTIVE,
                snapshot=stale,
                environment_effects_enabled=False,
                global_kill_switch=True,
                merchant_kill_switch=True,
                attempts_used=3,
            ),
        )
        self.assertEqual(
            decision.reasons,
            (
                GateReason.ENVIRONMENT_EFFECTS_DISABLED,
                GateReason.GLOBAL_KILL_SWITCH_ACTIVE,
                GateReason.MERCHANT_KILL_SWITCH_ACTIVE,
                GateReason.AGGREGATE_VERSION_MISMATCH,
                GateReason.RECOVERY_STATE_NOT_ACTIONABLE,
                GateReason.PAYMENT_TRUTH_NOT_UNPAID,
                GateReason.PROVIDER_SNAPSHOT_STALE,
                GateReason.ACTIVE_INSTRUMENT_EXISTS,
                GateReason.AMOUNT_MISMATCH,
                GateReason.INCIDENT_HEALTH_STALE,
                GateReason.PAYMENT_METHOD_UNHEALTHY,
                GateReason.ATTEMPT_BUDGET_EXHAUSTED,
            ),
        )

    def test_protective_cancellation_remains_allowed_under_kill_switch(self) -> None:
        cancellation = ActionProposal(
            proposal_id="cancel_1",
            merchant_id="merchant_1",
            case_id="case_1",
            decision_version=1,
            action_type=ActionType.CANCEL_PAYMENT_LINK,
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            instrument_reference="plink_123",
        )
        decision = gate().evaluate_policy(
            cancellation,
            context(
                recovery_state=RecoveryState.SUPPRESSED_PAID,
                snapshot=snapshot(
                    payment_state=CanonicalPaymentState.PAID,
                    active_instrument_count=1,
                    incident_state=IncidentState.CONFIRMED,
                ),
                global_kill_switch=True,
                merchant_kill_switch=True,
                opted_out=True,
                quiet_hours_active=True,
            ),
        )
        self.assertTrue(decision.allowed)

    def test_low_confidence_high_value_action_can_only_use_bound_approval(self) -> None:
        candidate = replace(
            proposal(),
            amount=Money(600_000, "INR"),
            model_confidence=Probability("0.40"),
        )
        high_value_snapshot = snapshot(amount_due=Money(600_000, "INR"))
        missing = gate().evaluate_policy(candidate, context(snapshot=high_value_snapshot))
        self.assertEqual(
            missing.reasons,
            (
                GateReason.HIGH_VALUE_REQUIRES_APPROVAL,
                GateReason.CONFIDENCE_BELOW_THRESHOLD,
                GateReason.APPROVAL_REQUIRED,
            ),
        )

        approval = Approval(
            approval_id="approval_1",
            merchant_id=candidate.merchant_id,
            case_id=candidate.case_id,
            action_key=candidate.action_key,
            proposal_digest=candidate.proposal_digest,
            decision_version=candidate.decision_version,
            approved_by="operator_1",
            approved_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
        allowed = gate().evaluate_policy(
            candidate, context(snapshot=high_value_snapshot, approval=approval)
        )
        self.assertTrue(allowed.allowed)

        wrong_case = replace(approval, case_id="case_other")
        denied = gate().evaluate_policy(
            candidate,
            context(snapshot=high_value_snapshot, approval=wrong_case),
        )
        self.assertIn(GateReason.APPROVAL_BINDING_MISMATCH, denied.reasons)

    def test_external_diagnosis_requires_a_bound_operator_decision(self) -> None:
        candidate = replace(proposal(), requires_approval=True)
        missing = gate().evaluate_policy(
            candidate,
            context(external_diagnosis_review_required=True),
        )
        self.assertEqual(
            missing.reasons,
            (
                GateReason.EXTERNAL_DIAGNOSIS_REQUIRES_APPROVAL,
                GateReason.APPROVAL_REQUIRED,
            ),
        )

        approval = Approval(
            approval_id="approval_external_1",
            merchant_id=candidate.merchant_id,
            case_id=candidate.case_id,
            action_key=candidate.action_key,
            proposal_digest=candidate.proposal_digest,
            decision_version=candidate.decision_version,
            approved_by="operator_1",
            approved_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
        allowed = gate().evaluate_policy(
            candidate,
            context(
                external_diagnosis_review_required=True,
                approval=approval,
            ),
        )
        self.assertTrue(allowed.allowed)

    def test_contact_specific_stopping_rules_do_not_block_link_creation(self) -> None:
        link_creation = gate().evaluate_policy(
            proposal(),
            context(
                consent_granted=False,
                opted_out=True,
                contacts_in_window=2,
                quiet_hours_active=True,
            ),
        )
        self.assertTrue(link_creation.allowed)

        notification = ActionProposal(
            proposal_id="notify_1",
            merchant_id="merchant_1",
            case_id="case_1",
            decision_version=1,
            action_type=ActionType.NOTIFY_EXISTING_LINK,
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            amount=Money(129_900, "INR"),
            payment_method="upi",
            model_confidence=Probability("0.90"),
        )
        decision = gate().evaluate_policy(
            notification,
            context(
                recovery_state=RecoveryState.ACTIVE,
                snapshot=snapshot(active_instrument_count=1),
                consent_granted=False,
                opted_out=True,
                cooldown_until=NOW + timedelta(minutes=1),
                contacts_in_window=2,
                quiet_hours_active=True,
            ),
        )
        self.assertEqual(
            decision.reasons,
            (
                GateReason.CONSENT_MISSING,
                GateReason.CUSTOMER_OPTED_OUT,
                GateReason.COOLDOWN_ACTIVE,
                GateReason.CONTACT_CAP_REACHED,
                GateReason.QUIET_HOURS_ACTIVE,
            ),
        )

    def test_gate_digest_is_deterministic(self) -> None:
        policy_gate = gate()
        first = policy_gate.evaluate_policy(proposal(), context())
        second = policy_gate.evaluate_policy(proposal(), context())
        self.assertEqual(first.decision_digest, second.decision_digest)

    def test_effect_authorization_binds_the_entire_proposal(self) -> None:
        policy_gate = gate()
        planned = proposal()
        plan = policy_gate.evaluate_policy(planned, context())
        altered = replace(planned, payment_method="card")
        self.assertEqual(planned.action_key, altered.action_key)
        effect = policy_gate.evaluate_effect(
            altered,
            context(
                aggregate_version=4,
                expected_aggregate_version=4,
                recovery_state=RecoveryState.ACTION_QUEUED,
                snapshot=snapshot(payment_method="card"),
                durable_intent_recorded=True,
            ),
            prior_plan=plan,
        )
        self.assertEqual(effect.reasons, (GateReason.PLAN_BINDING_MISMATCH,))

    def test_future_dated_approval_is_not_valid(self) -> None:
        candidate = replace(
            proposal(),
            amount=Money(600_000, "INR"),
            model_confidence=Probability("0.90"),
        )
        approval = Approval(
            approval_id="approval_1",
            merchant_id=candidate.merchant_id,
            case_id=candidate.case_id,
            action_key=candidate.action_key,
            proposal_digest=candidate.proposal_digest,
            decision_version=candidate.decision_version,
            approved_by="operator_1",
            approved_at=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
        decision = gate().evaluate_policy(
            candidate,
            context(
                snapshot=snapshot(amount_due=Money(600_000, "INR")),
                approval=approval,
            ),
        )
        self.assertEqual(
            decision.reasons,
            (
                GateReason.HIGH_VALUE_REQUIRES_APPROVAL,
                GateReason.APPROVAL_NOT_YET_VALID,
            ),
        )


if __name__ == "__main__":
    unittest.main()
