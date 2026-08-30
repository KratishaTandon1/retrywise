"""Audit-safe provenance for diagnosis engine routing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from retrywise.packages.domain.values import Probability

_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,99}$")


class DiagnosisMode(StrEnum):
    LOCAL_ML = "LOCAL_ML"
    HYBRID_GEMINI = "HYBRID_GEMINI"
    SHADOW = "SHADOW"


class DiagnosisEngine(StrEnum):
    LOCAL_ML = "LOCAL_ML"
    GEMINI = "GEMINI"


@dataclass(frozen=True, slots=True)
class ShadowDiagnosis:
    model_name: str
    model_version: str
    predicted_class: str
    confidence: Probability
    agreed: bool

    def __post_init__(self) -> None:
        if not _MODEL_RE.fullmatch(self.model_name):
            raise ValueError("shadow model_name is invalid")
        if not _MODEL_RE.fullmatch(self.model_version):
            raise ValueError("shadow model_version is invalid")
        if not isinstance(self.confidence, Probability):
            raise TypeError("shadow confidence must be Probability")
        if type(self.agreed) is not bool:
            raise TypeError("shadow agreed must be boolean")

    def to_primitive(self) -> dict[str, object]:
        return {
            "agreed": self.agreed,
            "confidence": self.confidence.to_primitive(),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "predicted_class": self.predicted_class,
        }


@dataclass(frozen=True, slots=True)
class DiagnosisProvenance:
    requested_mode: DiagnosisMode = DiagnosisMode.LOCAL_ML
    executed_engine: DiagnosisEngine = DiagnosisEngine.LOCAL_ML
    model_name: str = "retrywise_categorical_naive_bayes"
    latency_ms: int = 0
    fallback_reason_code: str | None = None
    shadow: ShadowDiagnosis | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.requested_mode, DiagnosisMode):
            raise TypeError("requested_mode must be DiagnosisMode")
        if not isinstance(self.executed_engine, DiagnosisEngine):
            raise TypeError("executed_engine must be DiagnosisEngine")
        if not _MODEL_RE.fullmatch(self.model_name):
            raise ValueError("model_name is invalid")
        if type(self.latency_ms) is not int or not 0 <= self.latency_ms <= 60_000:
            raise ValueError("latency_ms must be between zero and 60000")
        if self.fallback_reason_code is not None and not _REASON_RE.fullmatch(
            self.fallback_reason_code
        ):
            raise ValueError("fallback_reason_code is invalid")
        if self.shadow is not None and not isinstance(self.shadow, ShadowDiagnosis):
            raise TypeError("shadow must be ShadowDiagnosis")
        if self.requested_mode is DiagnosisMode.LOCAL_ML and (
            self.executed_engine is not DiagnosisEngine.LOCAL_ML
            or self.fallback_reason_code is not None
            or self.shadow is not None
        ):
            raise ValueError("local mode cannot claim external engine activity")
        if self.requested_mode is DiagnosisMode.HYBRID_GEMINI and self.shadow is not None:
            raise ValueError("hybrid mode cannot carry a shadow result")
        if self.requested_mode is DiagnosisMode.SHADOW:
            if self.executed_engine is not DiagnosisEngine.LOCAL_ML:
                raise ValueError("shadow mode must keep local ML authoritative")
            if self.shadow is None and self.fallback_reason_code is None:
                raise ValueError("shadow mode requires a result or a failure reason")

    @property
    def used_fallback(self) -> bool:
        return (
            self.requested_mode is DiagnosisMode.HYBRID_GEMINI
            and self.executed_engine is DiagnosisEngine.LOCAL_ML
        )

    def to_primitive(self) -> dict[str, object]:
        return {
            "executed_engine": self.executed_engine.value,
            "fallback_reason_code": self.fallback_reason_code,
            "latency_ms": self.latency_ms,
            "model_name": self.model_name,
            "requested_mode": self.requested_mode.value,
            "shadow": None if self.shadow is None else self.shadow.to_primitive(),
            "used_fallback": self.used_fallback,
        }


__all__ = [
    "DiagnosisEngine",
    "DiagnosisMode",
    "DiagnosisProvenance",
    "ShadowDiagnosis",
]
