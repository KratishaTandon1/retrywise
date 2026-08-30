from __future__ import annotations

import unittest
from decimal import Decimal

from retrywise.packages.diagnosis import (
    BUNDLED_ARTIFACT,
    FAILURE_TAXONOMY,
    AbstentionReason,
    DiagnosisModel,
    FailureClass,
)
from retrywise.packages.domain.values import Probability

from .helpers import provider_incident_features


class DiagnosisInferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = DiagnosisModel(BUNDLED_ARTIFACT)

    def test_probabilities_are_exact_normalized_decimals(self) -> None:
        result = self.model.infer(provider_incident_features())

        self.assertEqual(result.predicted_class, FailureClass.PROVIDER_INCIDENT)
        self.assertEqual(
            tuple(item.failure_class for item in result.class_probabilities),
            FAILURE_TAXONOMY,
        )
        self.assertEqual(
            sum(
                (item.probability.value for item in result.class_probabilities),
                Decimal(0),
            ),
            Decimal(1),
        )
        primitive = result.to_primitive()
        self.assertIsInstance(primitive["confidence"], str)
        self.assertTrue(
            all(
                isinstance(item["probability"], str)
                for item in primitive["class_probabilities"]  # type: ignore[union-attr]
            )
        )

    def test_inference_is_repeatable_and_explanation_is_structured(self) -> None:
        first = self.model.infer(provider_incident_features())
        second = self.model.infer(provider_incident_features())

        self.assertEqual(first, second)
        self.assertFalse(first.abstained)
        self.assertTrue(first.evidence)
        self.assertEqual(first.to_primitive()["non_authoritative"], True)
        self.assertIn("incident_state", {item.feature_name for item in first.evidence})
        self.assertTrue(all(isinstance(item.likelihood_ratio, Decimal) for item in first.evidence))

    def test_ood_input_always_abstains_without_retaining_raw_value(self) -> None:
        features = provider_incident_features()
        features["payment_method"] = "unreleased_payment_rail_customer_987"

        result = self.model.infer(features)

        self.assertTrue(result.abstained)
        self.assertTrue(result.out_of_distribution)
        self.assertIn(AbstentionReason.OUT_OF_DISTRIBUTION, result.abstention_reasons)
        self.assertNotIn("customer_987", repr(result.to_primitive()))

    def test_low_confidence_threshold_forces_explicit_abstention(self) -> None:
        strict_model = DiagnosisModel(
            BUNDLED_ARTIFACT,
            min_confidence=Probability("0.99"),
        )

        result = strict_model.infer(provider_incident_features())

        self.assertTrue(result.abstained)
        self.assertFalse(result.out_of_distribution)
        self.assertEqual(result.abstention_reasons, (AbstentionReason.LOW_CONFIDENCE,))


if __name__ == "__main__":
    unittest.main()
