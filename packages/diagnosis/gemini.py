"""Bounded Gemini classifier over the closed, redacted failure feature schema."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Protocol, cast

from retrywise.packages.domain.values import Probability

from .inference import (
    DEFAULT_MIN_CONFIDENCE,
    AbstentionReason,
    ClassProbability,
    DiagnosisResult,
)
from .provenance import DiagnosisEngine, DiagnosisMode, DiagnosisProvenance
from .schema import FEATURE_NAMES, FeatureVector
from .taxonomy import FAILURE_TAXONOMY, FailureClass

_INTERACTIONS_URL = "https://generativelanguage.googleapis.com/v1beta/interactions"
_MAX_RESPONSE_BYTES = 65_536
_MODEL_NAME = "google_gemini"
_BASIS_POINTS = 10_000


class GeminiDiagnosisError(RuntimeError):
    """A sanitized external-classifier failure safe for persistence."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class GeminiTransport(Protocol):
    def post(
        self,
        *,
        api_key: str,
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]: ...


class UrlLibGeminiTransport:
    """Fixed-origin REST transport that never places the API key in the URL."""

    def post(
        self,
        *,
        api_key: str,
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        request = urllib.request.Request(
            _INTERACTIONS_URL,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise GeminiDiagnosisError("GEMINI_RESPONSE_TOO_LARGE")
        except GeminiDiagnosisError:
            raise
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                reason = "GEMINI_RATE_LIMITED"
            elif exc.code in {500, 502, 503, 504}:
                reason = "GEMINI_UNAVAILABLE"
            else:
                reason = "GEMINI_REQUEST_REJECTED"
            raise GeminiDiagnosisError(reason) from None
        except TimeoutError:
            raise GeminiDiagnosisError("GEMINI_TIMEOUT") from None
        except (OSError, urllib.error.URLError):
            raise GeminiDiagnosisError("GEMINI_UNAVAILABLE") from None
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GeminiDiagnosisError("GEMINI_INVALID_RESPONSE") from None
        if not isinstance(decoded, dict):
            raise GeminiDiagnosisError("GEMINI_INVALID_RESPONSE")
        return cast(Mapping[str, object], decoded)


def _response_schema() -> dict[str, object]:
    classes = [item.value for item in FAILURE_TAXONOMY]
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["predicted_class", "probabilities_basis_points"],
        "properties": {
            "predicted_class": {"type": "string", "enum": classes},
            "probabilities_basis_points": {
                "type": "object",
                "additionalProperties": False,
                "required": classes,
                "properties": {
                    item: {"type": "integer", "minimum": 0, "maximum": _BASIS_POINTS}
                    for item in classes
                },
            },
        },
    }


def _prompt(vector: FeatureVector) -> str:
    values = {name: vector.value_for(name) for name in FEATURE_NAMES}
    return (
        "Classify one failed payment using only the supplied categorical features. "
        "Return calibrated class probabilities in integer basis points that sum exactly "
        "to 10000. The predicted class must be the first maximum in this ordered taxonomy: "
        + ", ".join(item.value for item in FAILURE_TAXONOMY)
        + ". Do not infer identity, intent, or payment authority. Features: "
        + json.dumps(values, sort_keys=True, separators=(",", ":"))
    )


def _extract_model_json(response: Mapping[str, object]) -> Mapping[str, object]:
    if response.get("status") not in {None, "completed"}:
        raise GeminiDiagnosisError("GEMINI_INCOMPLETE_RESPONSE")
    steps = response.get("steps")
    if not isinstance(steps, list):
        raise GeminiDiagnosisError("GEMINI_INVALID_RESPONSE")
    for step in reversed(steps):
        if not isinstance(step, dict) or step.get("type") != "model_output":
            continue
        content = step.get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if (
                isinstance(item, dict)
                and item.get("type") == "text"
                and isinstance(item.get("text"), str)
            ):
                try:
                    decoded = json.loads(item["text"])
                except json.JSONDecodeError:
                    raise GeminiDiagnosisError("GEMINI_INVALID_STRUCTURED_OUTPUT") from None
                if not isinstance(decoded, dict):
                    raise GeminiDiagnosisError("GEMINI_INVALID_STRUCTURED_OUTPUT")
                return cast(Mapping[str, object], decoded)
    raise GeminiDiagnosisError("GEMINI_INVALID_RESPONSE")


def _diagnosis(
    value: Mapping[str, object],
    *,
    vector: FeatureVector,
    model: str,
    latency_ms: int,
) -> DiagnosisResult:
    if set(value) != {"predicted_class", "probabilities_basis_points"}:
        raise GeminiDiagnosisError("GEMINI_SCHEMA_MISMATCH")
    probabilities = value["probabilities_basis_points"]
    class_names = tuple(item.value for item in FAILURE_TAXONOMY)
    if not isinstance(probabilities, dict) or set(probabilities) != set(class_names):
        raise GeminiDiagnosisError("GEMINI_SCHEMA_MISMATCH")
    points: list[int] = []
    for name in class_names:
        point = probabilities[name]
        if type(point) is not int or not 0 <= point <= _BASIS_POINTS:
            raise GeminiDiagnosisError("GEMINI_SCHEMA_MISMATCH")
        points.append(point)
    if sum(points) != _BASIS_POINTS:
        raise GeminiDiagnosisError("GEMINI_PROBABILITY_MISMATCH")
    maximum = max(points)
    winner_index = points.index(maximum)
    predicted = value["predicted_class"]
    if predicted != class_names[winner_index]:
        raise GeminiDiagnosisError("GEMINI_PREDICTION_MISMATCH")
    probability_objects = tuple(
        ClassProbability(label, Probability(Decimal(point) / Decimal(_BASIS_POINTS)))
        for label, point in zip(FAILURE_TAXONOMY, points, strict=True)
    )
    confidence = probability_objects[winner_index].probability
    reasons: list[AbstentionReason] = []
    if vector.out_of_distribution:
        reasons.append(AbstentionReason.OUT_OF_DISTRIBUTION)
    if confidence < DEFAULT_MIN_CONFIDENCE:
        reasons.append(AbstentionReason.LOW_CONFIDENCE)
    return DiagnosisResult(
        artifact_version=model,
        predicted_class=FailureClass(predicted),
        confidence=confidence,
        class_probabilities=probability_objects,
        abstained=bool(reasons),
        abstention_reasons=tuple(reasons),
        out_of_distribution=vector.out_of_distribution,
        feature_snapshot=vector,
        evidence=(),
        provenance=DiagnosisProvenance(
            requested_mode=DiagnosisMode.HYBRID_GEMINI,
            executed_engine=DiagnosisEngine.GEMINI,
            model_name=_MODEL_NAME,
            latency_ms=latency_ms,
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class GeminiDiagnosisClient:
    api_key: str
    model: str = "gemini-2.5-flash"
    timeout_seconds: float = 8.0
    transport: GeminiTransport = field(default_factory=UrlLibGeminiTransport)

    def __post_init__(self) -> None:
        if not 16 <= len(self.api_key) <= 512 or self.api_key != self.api_key.strip():
            raise ValueError("Gemini API key is invalid")
        if not self.model or len(self.model) > 100 or self.model != self.model.strip():
            raise ValueError("Gemini model is invalid")
        if not 0.25 <= self.timeout_seconds <= 10:
            raise ValueError("Gemini timeout must be between 0.25 and 10 seconds")
        if not callable(getattr(self.transport, "post", None)):
            raise TypeError("transport must provide post")

    def __repr__(self) -> str:
        return f"GeminiDiagnosisClient(model={self.model!r}, api_key=<redacted>)"

    def infer_vector(self, vector: FeatureVector) -> DiagnosisResult:
        if not isinstance(vector, FeatureVector):
            raise TypeError("Gemini inference requires a normalized FeatureVector")
        payload = {
            "model": self.model,
            "input": _prompt(vector),
            "store": False,
            "generation_config": {
                "thinking_level": "low",
                "max_output_tokens": 512,
            },
            "response_format": {
                "type": "text",
                "mime_type": "application/json",
                "schema": _response_schema(),
            },
        }
        started = time.perf_counter_ns()
        response = self.transport.post(
            api_key=self.api_key,
            payload=payload,
            timeout_seconds=self.timeout_seconds,
        )
        latency_ms = min(60_000, max(0, (time.perf_counter_ns() - started) // 1_000_000))
        return _diagnosis(
            _extract_model_json(response),
            vector=vector,
            model=self.model,
            latency_ms=latency_ms,
        )


__all__ = [
    "GeminiDiagnosisClient",
    "GeminiDiagnosisError",
    "GeminiTransport",
    "UrlLibGeminiTransport",
]
