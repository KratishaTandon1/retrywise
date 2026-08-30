from __future__ import annotations

import unittest

from retrywise.packages.simulator.generator import generate_dataset
from retrywise.packages.simulator.models import EventKind


class GeneratorTests(unittest.TestCase):
    def test_same_seed_is_byte_stable_at_dataset_boundary(self) -> None:
        first = generate_dataset(seed=20260829, case_count=200)
        second = generate_dataset(seed=20260829, case_count=200)

        self.assertEqual(first.dataset_hash, second.dataset_hash)
        self.assertEqual(first.scenarios, second.scenarios)
        self.assertEqual(first.merchant_policies, second.merchant_policies)

    def test_different_seed_changes_dataset(self) -> None:
        first = generate_dataset(seed=1, case_count=50)
        second = generate_dataset(seed=2, case_count=50)

        self.assertNotEqual(first.dataset_hash, second.dataset_hash)

    def test_dataset_contains_required_delivery_adversaries(self) -> None:
        dataset = generate_dataset(seed=42, case_count=200)
        mutations = {
            mutation for scenario in dataset.scenarios for mutation in scenario.delivery_mutations
        }
        self.assertTrue(
            {
                "duplicate",
                "invalid_signature",
                "cross_tenant",
                "delayed_capture",
                "dropped_capture",
                "early_downtime_signal",
                "late_downtime_signal",
                "missing_downtime_signal",
                "malformed",
            }.issubset(mutations)
        )
        adversarial_flags = {
            flag for scenario in dataset.scenarios for flag in scenario.adversarial_flags
        }
        self.assertTrue(
            {
                "partial_payment",
                "expired_order",
                "cancel_paid_race",
                "ambiguous_mapping",
                "provider_error",
                "worker_crash",
                "contact_cap_exhausted",
                "capture_while_link_creation_in_flight",
                "capture_during_observation",
                "both_collection_paths_can_capture",
            }.issubset(adversarial_flags)
        )
        self.assertTrue(
            any(
                event.kind is EventKind.PAYMENT_FAILED
                for scenario in dataset.scenarios
                for event in scenario.events
            )
        )

    def test_invalid_case_count_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            generate_dataset(seed=42, case_count=0)


if __name__ == "__main__":
    unittest.main()
