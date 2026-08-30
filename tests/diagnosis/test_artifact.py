from __future__ import annotations

import hashlib
import unittest
from dataclasses import FrozenInstanceError

from retrywise.packages.diagnosis import (
    BUNDLED_ARTIFACT,
    BUNDLED_REGISTRY,
    PINNED_BUNDLED_VERSION,
    TRAINING_CORPUS,
    UnknownModelVersion,
    export_artifact_bytes,
    train_artifact,
)


class ArtifactTests(unittest.TestCase):
    def test_version_is_server_derived_from_exact_canonical_bytes(self) -> None:
        artifact_bytes = export_artifact_bytes(BUNDLED_ARTIFACT)
        expected = f"sha256:{hashlib.sha256(artifact_bytes).hexdigest()}"

        self.assertEqual(BUNDLED_ARTIFACT.version, expected)
        self.assertEqual(BUNDLED_ARTIFACT.version, PINNED_BUNDLED_VERSION)
        self.assertNotIn(BUNDLED_ARTIFACT.version.encode(), artifact_bytes)

    def test_deterministic_training_reproduces_pinned_artifact(self) -> None:
        first = train_artifact(TRAINING_CORPUS)
        second = train_artifact(tuple(TRAINING_CORPUS))

        self.assertEqual(export_artifact_bytes(first), export_artifact_bytes(second))
        self.assertEqual(first, BUNDLED_ARTIFACT)
        self.assertEqual(first.version, PINNED_BUNDLED_VERSION)

    def test_artifact_is_immutable(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            BUNDLED_ARTIFACT.sample_count = 0  # type: ignore[misc]

    def test_closed_registry_rejects_arbitrary_version_labels(self) -> None:
        self.assertIs(
            BUNDLED_REGISTRY.resolve(PINNED_BUNDLED_VERSION),
            BUNDLED_ARTIFACT,
        )
        for unissued in ("v1", "latest", "sha256:" + "0" * 64):
            with self.subTest(unissued=unissued), self.assertRaises(UnknownModelVersion):
                BUNDLED_REGISTRY.resolve(unissued)


if __name__ == "__main__":
    unittest.main()
