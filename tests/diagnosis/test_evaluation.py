from __future__ import annotations

import unittest
from decimal import Decimal

from retrywise.packages.diagnosis import (
    BUNDLED_ARTIFACT,
    HELD_OUT_CORPUS,
    TRAINING_CORPUS,
    DiagnosisModel,
    evaluate_holdout,
)


class HeldOutEvaluationTests(unittest.TestCase):
    def test_held_out_examples_are_not_training_rows(self) -> None:
        training_vectors = {example.features for example in TRAINING_CORPUS}
        held_out_vectors = {example.features for example in HELD_OUT_CORPUS}

        self.assertTrue(training_vectors.isdisjoint(held_out_vectors))

    def test_frozen_holdout_accuracy_and_calibration_are_reported(self) -> None:
        metrics = evaluate_holdout(DiagnosisModel(BUNDLED_ARTIFACT), HELD_OUT_CORPUS)

        self.assertEqual(metrics.sample_count, 18)
        self.assertGreaterEqual(metrics.accuracy.value, Decimal("0.90"))
        self.assertLessEqual(metrics.multiclass_brier_score, Decimal("0.10"))
        self.assertLessEqual(metrics.expected_calibration_error, Decimal("0.20"))
        self.assertGreater(metrics.abstention_rate.value, Decimal(0))
        primitive = metrics.to_primitive()
        self.assertTrue(
            all(
                isinstance(primitive[name], str)
                for name in (
                    "accuracy",
                    "abstention_rate",
                    "multiclass_brier_score",
                    "expected_calibration_error",
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
