"""Pure deterministic trainer/exporter for the categorical model artifact."""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal

from .artifact import ClassValueCounts, FeatureCounts, ModelArtifact, ValueCounts
from .corpus import LabelledExample
from .errors import ArtifactValidationError
from .schema import FEATURE_SPECS
from .taxonomy import FAILURE_TAXONOMY, FailureClass


def train_artifact(
    examples: Sequence[LabelledExample], *, alpha: Decimal = Decimal("1")
) -> ModelArtifact:
    """Fit categorical count tables in canonical order without randomness or I/O."""

    if not isinstance(alpha, Decimal) or not alpha.is_finite() or alpha <= 0:
        raise ArtifactValidationError("training alpha must be a positive finite Decimal")
    if not examples:
        raise ArtifactValidationError("training corpus cannot be empty")
    if any(example.features.out_of_distribution for example in examples):
        raise ArtifactValidationError("training corpus contains missing or unknown categories")

    class_counts = tuple(
        (label, sum(1 for example in examples if example.label is label))
        for label in FAILURE_TAXONOMY
    )

    feature_tables: list[tuple[str, ClassValueCounts]] = []
    for spec in FEATURE_SPECS:
        class_tables: list[tuple[FailureClass, ValueCounts]] = []
        for label in FAILURE_TAXONOMY:
            counts = tuple(
                (
                    value,
                    sum(
                        1
                        for example in examples
                        if example.label is label and example.features.value_for(spec.name) == value
                    ),
                )
                for value in spec.vocabulary
            )
            class_tables.append((label, counts))
        feature_tables.append((spec.name, tuple(class_tables)))

    feature_counts: FeatureCounts = tuple(feature_tables)
    return ModelArtifact(
        alpha=alpha,
        sample_count=len(examples),
        class_counts=class_counts,
        feature_counts=feature_counts,
    )


def export_artifact_bytes(artifact: ModelArtifact) -> bytes:
    """Return deterministic deployable bytes; callers decide where to store them."""

    return artifact.canonical_bytes()
