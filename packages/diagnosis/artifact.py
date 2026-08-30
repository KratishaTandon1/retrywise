"""Immutable categorical Naive Bayes artifact and closed version registry."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256

from retrywise.packages.domain.canonical import canonical_json_bytes

from .errors import ArtifactValidationError, UnknownModelVersion
from .schema import FEATURE_NAMES, FEATURE_SCHEMA_NAME, FEATURE_SCHEMA_VERSION, FEATURE_SPECS
from .taxonomy import FAILURE_TAXONOMY, FailureClass

MODEL_NAME = "retrywise_categorical_naive_bayes"
ARTIFACT_SCHEMA_VERSION = 1

ValueCounts = tuple[tuple[str, int], ...]
ClassValueCounts = tuple[tuple[FailureClass, ValueCounts], ...]
FeatureCounts = tuple[tuple[str, ClassValueCounts], ...]


@dataclass(frozen=True, slots=True)
class ModelArtifact:
    """Learned count tables with no caller-controlled version field."""

    alpha: Decimal
    sample_count: int
    class_counts: tuple[tuple[FailureClass, int], ...]
    feature_counts: FeatureCounts
    model_name: str = MODEL_NAME
    artifact_schema_version: int = ARTIFACT_SCHEMA_VERSION
    feature_schema_name: str = FEATURE_SCHEMA_NAME
    feature_schema_version: int = FEATURE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.alpha, Decimal) or not self.alpha.is_finite() or self.alpha <= 0:
            raise ArtifactValidationError("alpha must be a positive finite Decimal")
        if (
            isinstance(self.sample_count, bool)
            or not isinstance(self.sample_count, int)
            or self.sample_count <= 0
        ):
            raise ArtifactValidationError("artifact must contain positive training support")
        if self.model_name != MODEL_NAME:
            raise ArtifactValidationError("artifact model name is not supported")
        if (
            isinstance(self.artifact_schema_version, bool)
            or not isinstance(self.artifact_schema_version, int)
            or self.artifact_schema_version != ARTIFACT_SCHEMA_VERSION
        ):
            raise ArtifactValidationError("artifact schema version is not supported")
        if (
            self.feature_schema_name != FEATURE_SCHEMA_NAME
            or isinstance(self.feature_schema_version, bool)
            or not isinstance(self.feature_schema_version, int)
            or self.feature_schema_version != FEATURE_SCHEMA_VERSION
        ):
            raise ArtifactValidationError("artifact feature schema is not supported")

        labels = tuple(label for label, _ in self.class_counts)
        if labels != FAILURE_TAXONOMY:
            raise ArtifactValidationError("artifact taxonomy is not complete and canonical")
        if any(
            isinstance(count, bool) or not isinstance(count, int) or count <= 0
            for _, count in self.class_counts
        ):
            raise ArtifactValidationError("every diagnosis class needs positive support")
        if sum(count for _, count in self.class_counts) != self.sample_count:
            raise ArtifactValidationError("class support does not equal artifact sample count")

        feature_names = tuple(name for name, _ in self.feature_counts)
        if feature_names != FEATURE_NAMES:
            raise ArtifactValidationError("artifact features are not complete and canonical")
        class_support = dict(self.class_counts)
        for (feature_name, by_class), spec in zip(self.feature_counts, FEATURE_SPECS, strict=True):
            if feature_name != spec.name:
                raise ArtifactValidationError("artifact feature order is not canonical")
            if tuple(label for label, _ in by_class) != FAILURE_TAXONOMY:
                raise ArtifactValidationError("artifact class tables are not canonical")
            for label, counts in by_class:
                if tuple(value for value, _ in counts) != spec.vocabulary:
                    raise ArtifactValidationError("artifact category tables are not canonical")
                if any(
                    isinstance(count, bool) or not isinstance(count, int) or count < 0
                    for _, count in counts
                ):
                    raise ArtifactValidationError("artifact category counts cannot be negative")
                if sum(count for _, count in counts) != class_support[label]:
                    raise ArtifactValidationError("feature support differs from class support")

    @property
    def version(self) -> str:
        """A server-derived digest; no human version label can be injected."""

        return f"sha256:{sha256(self.canonical_bytes()).hexdigest()}"

    def class_count(self, label: FailureClass) -> int:
        for candidate, count in self.class_counts:
            if candidate is label:
                return count
        raise ArtifactValidationError("class is outside the artifact taxonomy")

    def value_count(self, feature_name: str, label: FailureClass, value: str) -> int:
        for candidate_feature, by_class in self.feature_counts:
            if candidate_feature != feature_name:
                continue
            for candidate_label, counts in by_class:
                if candidate_label is not label:
                    continue
                for candidate_value, count in counts:
                    if candidate_value == value:
                        return count
        raise ArtifactValidationError("feature value is outside the artifact schema")

    def to_primitive(self) -> dict[str, object]:
        return {
            "alpha": self.alpha,
            "artifact_schema_version": self.artifact_schema_version,
            "class_counts": [
                {"class": label.value, "count": count} for label, count in self.class_counts
            ],
            "feature_counts": [
                {
                    "feature": feature_name,
                    "classes": [
                        {
                            "class": label.value,
                            "values": [{"count": count, "value": value} for value, count in counts],
                        }
                        for label, counts in by_class
                    ],
                }
                for feature_name, by_class in self.feature_counts
            ],
            "feature_schema_name": self.feature_schema_name,
            "feature_schema_version": self.feature_schema_version,
            "model_name": self.model_name,
            "sample_count": self.sample_count,
            "taxonomy": [label.value for label in FAILURE_TAXONOMY],
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_primitive())


@dataclass(frozen=True, slots=True)
class ArtifactRegistry:
    """A fixed registry with lookup only; runtime registration is deliberately absent."""

    artifacts: tuple[ModelArtifact, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.artifacts, tuple) or not self.artifacts:
            raise ArtifactValidationError("artifact registry cannot be empty")
        if any(not isinstance(artifact, ModelArtifact) for artifact in self.artifacts):
            raise ArtifactValidationError("registry accepts only validated model artifacts")
        versions = tuple(artifact.version for artifact in self.artifacts)
        if len(set(versions)) != len(versions):
            raise ArtifactValidationError("artifact registry contains duplicate versions")

    @property
    def versions(self) -> tuple[str, ...]:
        return tuple(artifact.version for artifact in self.artifacts)

    def resolve(self, version: str) -> ModelArtifact:
        if not isinstance(version, str):
            raise UnknownModelVersion("model version must be a server-issued string")
        for artifact in self.artifacts:
            if artifact.version == version:
                return artifact
        raise UnknownModelVersion("model version is not present in the closed registry")
