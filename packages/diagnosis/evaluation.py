"""Exact held-out accuracy and calibration metrics for diagnosis artifacts."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from decimal import ROUND_FLOOR, ROUND_HALF_EVEN, Decimal, localcontext

from retrywise.packages.domain.values import Probability

from .corpus import LabelledExample
from .inference import DiagnosisModel, DiagnosisResult
from .taxonomy import FAILURE_TAXONOMY

_METRIC_QUANTUM = Decimal("0.000000000001")


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    sample_count: int
    accuracy: Probability
    abstention_rate: Probability
    multiclass_brier_score: Decimal
    expected_calibration_error: Decimal

    def to_primitive(self) -> dict[str, object]:
        return {
            "abstention_rate": self.abstention_rate.to_primitive(),
            "accuracy": self.accuracy.to_primitive(),
            "expected_calibration_error": _decimal_string(self.expected_calibration_error),
            "multiclass_brier_score": _decimal_string(self.multiclass_brier_score),
            "sample_count": self.sample_count,
        }


def evaluate_holdout(
    model: DiagnosisModel, examples: Sequence[LabelledExample]
) -> EvaluationMetrics:
    """Evaluate labelled examples without training, randomness, floats, or I/O."""

    if not examples:
        raise ValueError("held-out corpus cannot be empty")
    results = tuple(model.infer_vector(example.features) for example in examples)
    sample_count = Decimal(len(examples))
    correct = sum(
        1
        for example, result in zip(examples, results, strict=True)
        if result.predicted_class is example.label
    )
    abstained = sum(1 for result in results if result.abstained)

    with localcontext() as context:
        context.prec = 60
        brier_total = Decimal(0)
        for example, result in zip(examples, results, strict=True):
            for label in FAILURE_TAXONOMY:
                target = Decimal(1) if label is example.label else Decimal(0)
                delta = result.probability_for(label).value - target
                brier_total += delta * delta
        brier = (brier_total / sample_count).quantize(_METRIC_QUANTUM, rounding=ROUND_HALF_EVEN)
        ece = _expected_calibration_error(examples, results).quantize(
            _METRIC_QUANTUM, rounding=ROUND_HALF_EVEN
        )
        accuracy = (Decimal(correct) / sample_count).quantize(
            _METRIC_QUANTUM, rounding=ROUND_HALF_EVEN
        )
        abstention_rate = (Decimal(abstained) / sample_count).quantize(
            _METRIC_QUANTUM, rounding=ROUND_HALF_EVEN
        )

    return EvaluationMetrics(
        sample_count=len(examples),
        accuracy=Probability(accuracy),
        abstention_rate=Probability(abstention_rate),
        multiclass_brier_score=brier,
        expected_calibration_error=ece,
    )


def _expected_calibration_error(
    examples: Sequence[LabelledExample], results: Sequence[DiagnosisResult]
) -> Decimal:
    buckets: list[list[int]] = [[] for _ in range(10)]
    for index, result in enumerate(results):
        bucket = int(
            (result.confidence.value * Decimal(10)).to_integral_value(rounding=ROUND_FLOOR)
        )
        buckets[min(bucket, 9)].append(index)

    total = Decimal(len(examples))
    error = Decimal(0)
    for indices in buckets:
        if not indices:
            continue
        size = Decimal(len(indices))
        mean_confidence = (
            sum((results[index].confidence.value for index in indices), Decimal(0)) / size
        )
        empirical_accuracy = (
            Decimal(
                sum(
                    1
                    for index in indices
                    if results[index].predicted_class is examples[index].label
                )
            )
            / size
        )
        error += (size / total) * abs(mean_confidence - empirical_accuracy)
    return error


def _decimal_string(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"
