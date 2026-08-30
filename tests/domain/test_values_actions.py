from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

from retrywise.packages.domain import (
    MINIMUM_LATE_CAPTURE_WINDOW,
    ActionProposal,
    ActionType,
    InvalidValue,
    LateCapturePolicy,
    Money,
    Probability,
)
from retrywise.packages.domain.canonical import canonical_json
from tests.domain.helpers import NOW, proposal


class MoneyTests(unittest.TestCase):
    def test_integer_minor_units_and_currency_are_enforced(self) -> None:
        for invalid in (-1, True, 1.5, "100"):
            with self.subTest(invalid=invalid), self.assertRaises(InvalidValue):
                Money(invalid, "INR")  # type: ignore[arg-type]
        for currency in ("inr", "IN", "INR1", "₹₹₹"):
            with self.subTest(currency=currency), self.assertRaises(InvalidValue):
                Money(100, currency)

    def test_arithmetic_preserves_currency_and_non_negative_invariant(self) -> None:
        self.assertEqual(Money(150, "INR") + Money(50, "INR"), Money(200, "INR"))
        self.assertEqual(Money(150, "INR") - Money(50, "INR"), Money(100, "INR"))
        with self.assertRaises(InvalidValue):
            _ = Money(100, "INR") + Money(100, "USD")
        with self.assertRaises(InvalidValue):
            _ = Money(50, "INR") - Money(100, "INR")


class LateCapturePolicyTests(unittest.TestCase):
    def test_hard_floor_rejects_accidentally_short_policy(self) -> None:
        with self.assertRaises(InvalidValue):
            LateCapturePolicy(MINIMUM_LATE_CAPTURE_WINDOW - timedelta(microseconds=1))

    def test_policy_floor_wins_over_shorter_suggestion(self) -> None:
        policy = LateCapturePolicy()
        self.assertEqual(
            policy.observation_deadline(
                observed_at=NOW,
                extend_until=NOW + timedelta(seconds=1),
            ),
            NOW + MINIMUM_LATE_CAPTURE_WINDOW,
        )


class ProbabilityTests(unittest.TestCase):
    def test_probability_uses_exact_decimal_values(self) -> None:
        probability = Probability(Decimal("0.9000"))
        self.assertEqual(probability.to_primitive(), "0.9")
        self.assertLess(Probability("0.74"), Probability("0.75"))

    def test_float_non_finite_and_out_of_range_values_are_rejected(self) -> None:
        for invalid in (0.5, "NaN", "Infinity", "-0.1", "1.1", True):
            with self.subTest(invalid=invalid), self.assertRaises(InvalidValue):
                Probability(invalid)  # type: ignore[arg-type]


class ActionProposalTests(unittest.TestCase):
    def test_action_key_is_stable_and_bound_to_decision_identity(self) -> None:
        first = proposal()
        duplicate = proposal()
        successor = replace(first, attempt_ordinal=2)
        self.assertEqual(first.action_key, duplicate.action_key)
        self.assertNotEqual(first.action_key, successor.action_key)
        self.assertTrue(first.action_key.startswith("act_"))
        self.assertEqual(len(first.action_key), 68)
        changed_content = replace(first, payment_method="card")
        self.assertEqual(first.action_key, changed_content.action_key)
        self.assertNotEqual(first.proposal_digest, changed_content.proposal_digest)

    def test_collection_and_cancellation_shapes_are_closed(self) -> None:
        with self.assertRaises(InvalidValue):
            ActionProposal(
                proposal_id="proposal_2",
                merchant_id="merchant_1",
                case_id="case_1",
                decision_version=1,
                action_type=ActionType.CREATE_STANDARD_PAYMENT_LINK,
                created_at=NOW,
                expires_at=NOW + timedelta(minutes=1),
                payment_method="upi",
            )
        with self.assertRaises(InvalidValue):
            ActionProposal(
                proposal_id="proposal_2",
                merchant_id="merchant_1",
                case_id="case_1",
                decision_version=1,
                action_type=ActionType.CANCEL_PAYMENT_LINK,
                created_at=NOW,
                expires_at=NOW + timedelta(minutes=1),
            )
        cancellation = ActionProposal(
            proposal_id="proposal_2",
            merchant_id="merchant_1",
            case_id="case_1",
            decision_version=1,
            action_type=ActionType.CANCEL_PAYMENT_LINK,
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
            instrument_reference="plink_123",
        )
        self.assertEqual(cancellation.instrument_reference, "plink_123")

    def test_expiry_and_canonical_payment_method_are_validated(self) -> None:
        with self.assertRaises(InvalidValue):
            replace(proposal(), expires_at=NOW)
        with self.assertRaises(InvalidValue):
            replace(proposal(), payment_method="UPI")
        with self.assertRaises(InvalidValue):
            replace(proposal(), action_type="create_standard_payment_link")
        with self.assertRaises(InvalidValue):
            replace(proposal(), decision_version="1")


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_does_not_change_serialization(self) -> None:
        self.assertEqual(
            canonical_json({"b": 2, "a": 1}),
            canonical_json({"a": 1, "b": 2}),
        )
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_float_is_forbidden_in_hash_evidence(self) -> None:
        with self.assertRaises(InvalidValue):
            canonical_json({"score": 0.9})


if __name__ == "__main__":
    unittest.main()
