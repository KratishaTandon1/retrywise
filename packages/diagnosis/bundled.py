"""Pinned learned artifact and its only supported runtime registry."""

from decimal import Decimal

from .artifact import ArtifactRegistry, FeatureCounts, ModelArtifact
from .errors import ArtifactValidationError
from .schema import FEATURE_SPECS
from .taxonomy import FAILURE_TAXONOMY

# Generated categorical count matrices. Rows follow FAILURE_TAXONOMY; columns
# follow each FeatureSpec vocabulary. Runtime inference loads these frozen
# learned counts and never imports or retrains from the labelled corpus.
_CLASS_SUPPORT = (10, 10, 10, 10, 10, 10)
_FEATURE_COUNT_MATRICES: tuple[tuple[tuple[int, ...], ...], ...] = (
    (
        (2, 3, 2, 2, 1, 0, 0),
        (3, 3, 2, 1, 1, 0, 0),
        (4, 2, 1, 2, 1, 0, 0),
        (3, 2, 2, 2, 1, 0, 0),
        (3, 2, 2, 2, 1, 0, 0),
        (2, 2, 2, 2, 2, 0, 0),
    ),
    (
        (0, 2, 5, 0, 3, 0, 0, 0),
        (9, 1, 0, 0, 0, 0, 0, 0),
        (3, 7, 0, 0, 0, 0, 0, 0),
        (4, 6, 0, 0, 0, 0, 0, 0),
        (0, 0, 0, 10, 0, 0, 0, 0),
        (1, 2, 1, 0, 1, 5, 0, 0),
    ),
    (
        (1, 0, 3, 5, 1, 0, 0, 0, 0),
        (3, 7, 0, 0, 0, 0, 0, 0, 0),
        (0, 6, 4, 0, 0, 0, 0, 0, 0),
        (0, 0, 10, 0, 0, 0, 0, 0, 0),
        (3, 0, 0, 2, 1, 4, 0, 0, 0),
        (1, 0, 0, 2, 0, 0, 7, 0, 0),
    ),
    (
        (2, 3, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 0, 0, 0, 3, 4, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 0, 0, 0, 0, 0, 0, 3, 4, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0),
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2, 2, 3, 0, 0, 0),
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0),
    ),
    (
        (0, 3, 5, 2, 0, 0),
        (10, 0, 0, 0, 0, 0),
        (10, 0, 0, 0, 0, 0),
        (10, 0, 0, 0, 0, 0),
        (8, 2, 0, 0, 0, 0),
        (7, 2, 0, 1, 0, 0),
    ),
    (
        (4, 3, 3, 0, 0),
        (5, 3, 2, 0, 0),
        (4, 3, 3, 0, 0),
        (4, 3, 3, 0, 0),
        (4, 3, 3, 0, 0),
        (4, 3, 3, 0, 0),
    ),
    (
        (6, 3, 1, 0, 0),
        (5, 4, 1, 0, 0),
        (4, 4, 2, 0, 0),
        (5, 3, 2, 0, 0),
        (5, 4, 1, 0, 0),
        (3, 4, 3, 0, 0),
    ),
)

PINNED_BUNDLED_VERSION = "sha256:78a93913ceef2b1f1e4886e833c41b5bd14f34cd791c9dd9dac706d654070855"


def _load_frozen_artifact() -> ModelArtifact:
    try:
        class_counts = tuple(zip(FAILURE_TAXONOMY, _CLASS_SUPPORT, strict=True))
        feature_counts: FeatureCounts = tuple(
            (
                spec.name,
                tuple(
                    (
                        label,
                        tuple(zip(spec.vocabulary, row, strict=True)),
                    )
                    for label, row in zip(FAILURE_TAXONOMY, matrix, strict=True)
                ),
            )
            for spec, matrix in zip(FEATURE_SPECS, _FEATURE_COUNT_MATRICES, strict=True)
        )
    except ValueError as exc:
        raise ArtifactValidationError("frozen artifact dimensions do not match the schema") from exc
    return ModelArtifact(
        alpha=Decimal("1"),
        sample_count=sum(_CLASS_SUPPORT),
        class_counts=class_counts,
        feature_counts=feature_counts,
    )


BUNDLED_ARTIFACT = _load_frozen_artifact()
if BUNDLED_ARTIFACT.version != PINNED_BUNDLED_VERSION:
    raise ArtifactValidationError("bundled artifact does not match its pinned digest")
BUNDLED_REGISTRY = ArtifactRegistry((BUNDLED_ARTIFACT,))
