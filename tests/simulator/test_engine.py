from __future__ import annotations

import unittest

from retrywise.packages.simulator.engine import VirtualClock, run_policy
from retrywise.packages.simulator.generator import generate_dataset
from retrywise.packages.simulator.policies import BlastAllPolicy, RetryWisePolicy


class VirtualClockTests(unittest.TestCase):
    def test_clock_orders_events_and_preserves_tie_insertion_order(self) -> None:
        clock = VirtualClock()
        clock.schedule(100, "later", "c")
        clock.schedule(50, "same-time", "a")
        clock.schedule(50, "same-time", "b")

        emitted = clock.run_until(100)

        self.assertEqual([item.payload for item in emitted], ["a", "b", "c"])
        self.assertEqual(clock.now_ms, 100)

    def test_clock_rejects_backwards_time(self) -> None:
        clock = VirtualClock()
        clock.run_until(10)
        with self.assertRaises(ValueError):
            clock.schedule(9, "past", None)
        with self.assertRaises(ValueError):
            clock.run_until(9)


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = generate_dataset(seed=42, case_count=300)

    def test_retrywise_satisfies_hard_safety_and_audit_contract(self) -> None:
        result = run_policy(self.dataset, RetryWisePolicy())

        self.assertEqual(result.metrics.hard_safety_violations, 0)
        self.assertEqual(result.metrics.audit_completeness_pct, 100.0)
        self.assertEqual(result.metrics.duplicate_effects_under_replay, 0)
        self.assertEqual(result.metrics.invalid_webhook_acceptances, 0)
        self.assertEqual(result.metrics.cross_tenant_effects, 0)
        self.assertEqual(result.metrics.unrecognized_overpayments, 0)
        self.assertGreater(result.metrics.invalid_events_rejected, 0)
        self.assertGreater(result.metrics.duplicate_events_suppressed, 0)

    def test_blast_all_exposes_duplicate_risk_and_policy_harm(self) -> None:
        result = run_policy(self.dataset, BlastAllPolicy())

        self.assertGreater(result.metrics.duplicate_risk_events, 0)
        self.assertGreater(result.metrics.hard_safety_violations, 0)
        self.assertGreater(result.metrics.stop_rule_violations, 0)
        self.assertGreater(result.metrics.unnecessary_contacts, 0)

    def test_policy_replay_is_exactly_deterministic(self) -> None:
        first = run_policy(self.dataset, RetryWisePolicy())
        second = run_policy(self.dataset, RetryWisePolicy())

        self.assertEqual(first, second)

    def test_permanent_diagnosis_does_not_shorten_late_capture_protection(self) -> None:
        regression_dataset = generate_dataset(seed=503, case_count=285)

        result = run_policy(regression_dataset, RetryWisePolicy())

        case = next(item for item in result.case_outcomes if item.scenario_id == "case-00284")
        self.assertFalse(case.action_executed)
        self.assertTrue(case.original_success_action_suppressed)
        self.assertEqual(case.safety_violations, ())


if __name__ == "__main__":
    unittest.main()
