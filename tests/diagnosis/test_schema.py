from __future__ import annotations

import unittest

from retrywise.packages.diagnosis import (
    FEATURE_NAMES,
    FeatureValidationError,
    FeatureVector,
    SensitiveFeatureError,
    normalize_features,
)

from .helpers import provider_incident_features


class FeatureSchemaTests(unittest.TestCase):
    def test_only_closed_redacted_features_cross_boundary(self) -> None:
        features = provider_incident_features()
        features["email"] = "person@example.test"

        with self.assertRaises(SensitiveFeatureError) as raised:
            normalize_features(features)

        self.assertNotIn("person@example.test", str(raised.exception))

    def test_unknown_feature_key_is_rejected_without_echoing_value(self) -> None:
        features = provider_incident_features()
        features["experimental_signal"] = "secret-external-value"

        with self.assertRaises(FeatureValidationError) as raised:
            normalize_features(features)

        self.assertNotIn("secret-external-value", str(raised.exception))

    def test_unknown_category_is_redacted_and_marked_ood(self) -> None:
        features = provider_incident_features()
        features["error_reason"] = "issuer_message_with_unreviewed_text"

        vector = normalize_features(features)
        primitive = vector.to_primitive()

        self.assertTrue(vector.out_of_distribution)
        self.assertEqual(vector.unknown_features, ("error_reason",))
        self.assertEqual(vector.value_for("error_reason"), "__unknown__")
        self.assertNotIn("issuer_message_with_unreviewed_text", repr(primitive))

    def test_missing_feature_is_explicit_and_marked_ood(self) -> None:
        features = provider_incident_features()
        del features["incident_state"]

        vector = normalize_features(features)

        self.assertTrue(vector.out_of_distribution)
        self.assertEqual(vector.missing_features, ("incident_state",))
        self.assertEqual(vector.value_for("incident_state"), "__missing__")

    def test_direct_vector_cannot_hide_an_ood_marker(self) -> None:
        values = tuple(
            (name, "__unknown__" if name == "payment_method" else "__missing__")
            for name in FEATURE_NAMES
        )

        with self.assertRaises(FeatureValidationError):
            FeatureVector(values=values)


if __name__ == "__main__":
    unittest.main()
