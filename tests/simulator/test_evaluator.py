from __future__ import annotations

import unittest
from itertools import pairwise

from retrywise.packages.diagnosis import PINNED_BUNDLED_VERSION, UnknownModelVersion
from retrywise.packages.simulator.evaluator import evaluate
from retrywise.packages.simulator.policies import POLICY_DISPLAY_NAMES


class EvaluatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = evaluate(
            seed=7,
            case_count=200,
            code_revision="test-revision",
            bootstrap_samples=100,
        )

    def test_required_policy_names_are_present(self) -> None:
        result_keys = {result.policy_key for result in self.report.results}

        self.assertEqual(
            result_keys,
            {"B0", "B1", "B2", "B3", "RetryWise", "oracle"},
        )
        self.assertEqual(
            {result.display_name for result in self.report.results},
            set(POLICY_DISPLAY_NAMES.values()),
        )

    def test_manifest_captures_reproducibility_inputs(self) -> None:
        manifest = self.report.manifest

        self.assertEqual(manifest.seed, 7)
        self.assertEqual(manifest.case_count, 200)
        self.assertEqual(manifest.code_revision, "test-revision")
        self.assertTrue(manifest.dataset_hash)
        self.assertTrue(manifest.policy_version)
        self.assertEqual(manifest.model_version, PINNED_BUNDLED_VERSION)
        self.assertEqual(manifest.bootstrap_samples, 100)
        self.assertTrue(manifest.scenario_family_counts)
        self.assertTrue(manifest.delivery_mutation_counts)
        self.assertTrue(manifest.adversarial_flag_counts)

    def test_default_code_revision_is_a_source_digest(self) -> None:
        report = evaluate(seed=9, case_count=10, bootstrap_samples=10)

        self.assertTrue(report.manifest.code_revision.startswith("source-sha256:"))

    def test_unregistered_model_version_cannot_relabel_the_same_policy(self) -> None:
        with self.assertRaises(UnknownModelVersion):
            evaluate(
                seed=9,
                case_count=10,
                bootstrap_samples=10,
                model_version="invented-model-label",
            )

    def test_labels_make_synthetic_boundary_explicit(self) -> None:
        labels = self.report.labels

        self.assertEqual(labels.execution_context, "offline_replay")
        self.assertIn("Synthetic", labels.dataset_label)
        self.assertIn("simulated", labels.value_label)
        self.assertFalse(labels.real_money)
        self.assertFalse(labels.observed_real_merchant_revenue_claimed)

    def test_comparisons_are_paired_and_clustered(self) -> None:
        self.assertGreater(len(self.report.comparisons), 0)
        for comparison in self.report.comparisons:
            self.assertEqual(
                comparison.paired_on,
                "scenario_id_and_precomputed_potential_outcomes",
            )
            self.assertEqual(
                comparison.confidence_interval.cluster_unit,
                "merchant_id",
            )
            self.assertEqual(
                comparison.wins + comparison.losses + comparison.ties,
                200,
            )

    def test_complete_report_is_reproducible(self) -> None:
        rerun = evaluate(
            seed=7,
            case_count=200,
            code_revision="test-revision",
            bootstrap_samples=100,
        )

        self.assertEqual(self.report, rerun)
        self.assertEqual(self.report.to_dict(), rerun.to_dict())

    def test_safety_is_ranked_before_value(self) -> None:
        by_key = {result.policy_key: result for result in self.report.results}
        ordered = self.report.deployable_ranking

        for left, right in pairwise(ordered):
            left_metrics = by_key[left].metrics
            right_metrics = by_key[right].metrics
            self.assertLessEqual(
                left_metrics.hard_safety_violations,
                right_metrics.hard_safety_violations,
            )


if __name__ == "__main__":
    unittest.main()
