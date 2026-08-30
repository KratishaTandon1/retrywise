"""Deterministic, non-authoritative categorical diagnosis inference."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from enum import StrEnum

from retrywise.packages.domain.values import Probability

from .artifact import ArtifactRegistry, ModelArtifact
from .provenance import DiagnosisProvenance
from .schema import FEATURE_SPECS, FeatureVector, normalize_features
from .taxonomy import FAILURE_TAXONOMY, FailureClass

DEFAULT_MIN_CONFIDENCE = Probability("0.70")
_PROBABILITY_QUANTUM = Decimal("0.000000000001")
_EVIDENCE_QUANTUM = Decimal("0.000001")


class AbstentionReason(StrEnum):
    OUT_OF_DISTRIBUTION = "out_of_distribution"
    LOW_CONFIDENCE = "low_confidence"
    EXTERNAL_ENGINE_FALLBACK = "external_engine_fallback"


@dataclass(frozen=True, slots=True)
class ClassProbability:
    failure_class: FailureClass
    probability: Probability

    def to_primitive(self) -> dict[str, str]:
        return {
            "class": self.failure_class.value,
            "probability": self.probability.to_primitive(),
        }


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """Safe categorical evidence, not a causal claim or executable instruction."""

    feature_name: str
    observed_value: str
    predicted_support_count: int
    predicted_likelihood: Probability
    alternatives_mean_likelihood: Probability
    likelihood_ratio: Decimal

    def to_primitive(self) -> dict[str, object]:
        return {
            "alternatives_mean_likelihood": self.alternatives_mean_likelihood.to_primitive(),
            "feature_name": self.feature_name,
            "likelihood_ratio": _decimal_string(self.likelihood_ratio),
            "observed_value": self.observed_value,
            "predicted_likelihood": self.predicted_likelihood.to_primitive(),
            "predicted_support_count": self.predicted_support_count,
        }


@dataclass(frozen=True, slots=True)
class DiagnosisResult:
    artifact_version: str
    predicted_class: FailureClass
    confidence: Probability
    class_probabilities: tuple[ClassProbability, ...]
    abstained: bool
    abstention_reasons: tuple[AbstentionReason, ...]
    out_of_distribution: bool
    feature_snapshot: FeatureVector
    evidence: tuple[EvidenceItem, ...]
    provenance: DiagnosisProvenance = field(default_factory=DiagnosisProvenance)

    def __post_init__(self) -> None:
        if tuple(item.failure_class for item in self.class_probabilities) != FAILURE_TAXONOMY:
            raise ValueError("class probabilities must use the closed taxonomy")
        total = sum((item.probability.value for item in self.class_probabilities), Decimal(0))
        if total != Decimal(1):
            raise ValueError("class probabilities must sum exactly to one")
        maximum = max(item.probability.value for item in self.class_probabilities)
        predicted = next(
            item.failure_class
            for item in self.class_probabilities
            if item.probability.value == maximum
        )
        if predicted is not self.predicted_class or self.confidence.value != maximum:
            raise ValueError("prediction and confidence must match the probability vector")
        if self.abstained != bool(self.abstention_reasons):
            raise ValueError("abstention flag must match its reason codes")
        if self.out_of_distribution != self.feature_snapshot.out_of_distribution:
            raise ValueError("OOD flag must match normalized feature evidence")
        if not isinstance(self.provenance, DiagnosisProvenance):
            raise TypeError("provenance must be DiagnosisProvenance")

    def probability_for(self, failure_class: FailureClass) -> Probability:
        for item in self.class_probabilities:
            if item.failure_class is failure_class:
                return item.probability
        raise ValueError("class is outside the closed taxonomy")

    def to_primitive(self) -> dict[str, object]:
        """Return audit-safe evidence with decimal probabilities serialized as strings."""

        return {
            "abstained": self.abstained,
            "abstention_reasons": [reason.value for reason in self.abstention_reasons],
            "artifact_version": self.artifact_version,
            "class_probabilities": [item.to_primitive() for item in self.class_probabilities],
            "confidence": self.confidence.to_primitive(),
            "evidence": [item.to_primitive() for item in self.evidence],
            "feature_snapshot": self.feature_snapshot.to_primitive(),
            "non_authoritative": True,
            "out_of_distribution": self.out_of_distribution,
            "predicted_class": self.predicted_class.value,
            "provenance": self.provenance.to_primitive(),
        }


class DiagnosisModel:
    """Pure inference object; it has no provider, database, clock, or action access."""

    def __init__(
        self,
        artifact: ModelArtifact,
        *,
        min_confidence: Probability = DEFAULT_MIN_CONFIDENCE,
    ) -> None:
        if not isinstance(artifact, ModelArtifact):
            raise TypeError("artifact must be a validated ModelArtifact")
        if not isinstance(min_confidence, Probability):
            raise TypeError("min_confidence must be an exact Probability")
        self._artifact = artifact
        self._min_confidence = min_confidence

    @classmethod
    def from_registry(
        cls,
        registry: ArtifactRegistry,
        version: str,
        *,
        min_confidence: Probability = DEFAULT_MIN_CONFIDENCE,
    ) -> DiagnosisModel:
        return cls(registry.resolve(version), min_confidence=min_confidence)

    @property
    def artifact_version(self) -> str:
        return self._artifact.version

    def infer(self, raw_features: Mapping[str, object]) -> DiagnosisResult:
        return self.infer_vector(normalize_features(raw_features))

    def infer_vector(self, vector: FeatureVector) -> DiagnosisResult:
        if not isinstance(vector, FeatureVector):
            raise TypeError("inference requires a normalized FeatureVector")

        scores = self._unnormalized_scores(vector)
        probabilities = self._normalize(scores)
        maximum = max(probability for _, probability in probabilities)
        predicted = next(label for label, value in probabilities if value == maximum)
        probability_objects = tuple(
            ClassProbability(label, Probability(probability))
            for label, probability in probabilities
        )
        confidence = Probability(maximum)

        reasons: list[AbstentionReason] = []
        if vector.out_of_distribution:
            reasons.append(AbstentionReason.OUT_OF_DISTRIBUTION)
        if confidence < self._min_confidence:
            reasons.append(AbstentionReason.LOW_CONFIDENCE)

        return DiagnosisResult(
            artifact_version=self._artifact.version,
            predicted_class=predicted,
            confidence=confidence,
            class_probabilities=probability_objects,
            abstained=bool(reasons),
            abstention_reasons=tuple(reasons),
            out_of_distribution=vector.out_of_distribution,
            feature_snapshot=vector,
            evidence=self._evidence(vector, predicted),
            provenance=DiagnosisProvenance(model_name=self._artifact.model_name),
        )

    def _unnormalized_scores(
        self, vector: FeatureVector
    ) -> tuple[tuple[FailureClass, Decimal], ...]:
        artifact = self._artifact
        class_total = Decimal(artifact.sample_count)
        alpha = artifact.alpha
        class_count = Decimal(len(FAILURE_TAXONOMY))
        with localcontext() as context:
            context.prec = 60
            scores: list[tuple[FailureClass, Decimal]] = []
            for label in FAILURE_TAXONOMY:
                label_count = Decimal(artifact.class_count(label))
                score = (label_count + alpha) / (class_total + alpha * class_count)
                for spec in FEATURE_SPECS:
                    vocabulary_size = Decimal(len(spec.vocabulary))
                    count = Decimal(
                        artifact.value_count(spec.name, label, vector.value_for(spec.name))
                    )
                    score *= (count + alpha) / (label_count + alpha * vocabulary_size)
                scores.append((label, +score))
            return tuple(scores)

    @staticmethod
    def _normalize(
        scores: tuple[tuple[FailureClass, Decimal], ...],
    ) -> tuple[tuple[FailureClass, Decimal], ...]:
        total = sum((score for _, score in scores), Decimal(0))
        if total <= 0:
            raise ValueError("model produced no probability mass")
        with localcontext() as context:
            context.prec = 60
            rounded = [
                (label, (score / total).quantize(_PROBABILITY_QUANTUM, rounding=ROUND_HALF_EVEN))
                for label, score in scores
            ]
        winner_index = max(range(len(rounded)), key=lambda index: rounded[index][1])
        residual = Decimal(1) - sum((value for _, value in rounded), Decimal(0))
        label, value = rounded[winner_index]
        rounded[winner_index] = (label, value + residual)
        return tuple(rounded)

    def _evidence(self, vector: FeatureVector, predicted: FailureClass) -> tuple[EvidenceItem, ...]:
        artifact = self._artifact
        alpha = artifact.alpha
        predicted_count = Decimal(artifact.class_count(predicted))
        evidence_with_order: list[tuple[Decimal, int, EvidenceItem]] = []
        with localcontext() as context:
            context.prec = 60
            for order, spec in enumerate(FEATURE_SPECS):
                value = vector.value_for(spec.name)
                vocabulary_size = Decimal(len(spec.vocabulary))
                support = artifact.value_count(spec.name, predicted, value)
                predicted_likelihood = (Decimal(support) + alpha) / (
                    predicted_count + alpha * vocabulary_size
                )
                alternatives = []
                for label in FAILURE_TAXONOMY:
                    if label is predicted:
                        continue
                    label_count = Decimal(artifact.class_count(label))
                    count = Decimal(artifact.value_count(spec.name, label, value))
                    alternatives.append((count + alpha) / (label_count + alpha * vocabulary_size))
                alternatives_mean = sum(alternatives, Decimal(0)) / Decimal(len(alternatives))
                ratio = predicted_likelihood / alternatives_mean
                item = EvidenceItem(
                    feature_name=spec.name,
                    observed_value=value,
                    predicted_support_count=support,
                    predicted_likelihood=Probability(
                        predicted_likelihood.quantize(
                            _PROBABILITY_QUANTUM, rounding=ROUND_HALF_EVEN
                        )
                    ),
                    alternatives_mean_likelihood=Probability(
                        alternatives_mean.quantize(_PROBABILITY_QUANTUM, rounding=ROUND_HALF_EVEN)
                    ),
                    likelihood_ratio=ratio.quantize(_EVIDENCE_QUANTUM, rounding=ROUND_HALF_EVEN),
                )
                evidence_with_order.append((ratio, order, item))
        evidence_with_order.sort(key=lambda item: (-item[0], item[1]))
        return tuple(item for _, _, item in evidence_with_order)


def _decimal_string(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"
