"""Resilient diagnosis routing with local authority and bounded Gemini use."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import replace
from threading import Lock
from typing import Protocol

from .bundled import BUNDLED_ARTIFACT
from .gemini import GeminiDiagnosisClient, GeminiDiagnosisError
from .inference import AbstentionReason, DiagnosisModel, DiagnosisResult
from .provenance import (
    DiagnosisEngine,
    DiagnosisMode,
    DiagnosisProvenance,
    ShadowDiagnosis,
)
from .schema import normalize_features


class DiagnosisModeReader(Protocol):
    def diagnosis_mode(self, *, merchant_id: str) -> DiagnosisMode: ...


class StaticDiagnosisModeReader:
    def __init__(self, mode: DiagnosisMode = DiagnosisMode.LOCAL_ML) -> None:
        if not isinstance(mode, DiagnosisMode):
            raise TypeError("mode must be DiagnosisMode")
        self._mode = mode

    def diagnosis_mode(self, *, merchant_id: str) -> DiagnosisMode:
        if not merchant_id:
            raise ValueError("merchant_id is required")
        return self._mode


class _CircuitBreaker:
    def __init__(self, *, failure_threshold: int = 3, cooldown_seconds: float = 60) -> None:
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._failures = 0
        self._opened_until = 0.0
        self._lock = Lock()

    def before_call(self) -> None:
        with self._lock:
            if time.monotonic() < self._opened_until:
                raise GeminiDiagnosisError("GEMINI_CIRCUIT_OPEN")
            if self._opened_until:
                self._opened_until = 0.0
                self._failures = 0

    def succeeded(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_until = 0.0

    def failed(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._failure_threshold:
                self._opened_until = time.monotonic() + self._cooldown_seconds


class DiagnosisRouter:
    """Route redacted inference while deterministic policy remains authoritative."""

    def __init__(
        self,
        *,
        mode_reader: DiagnosisModeReader | None = None,
        gemini: GeminiDiagnosisClient | None = None,
        local_model: DiagnosisModel | None = None,
    ) -> None:
        self._mode_reader = mode_reader or StaticDiagnosisModeReader()
        self._gemini = gemini
        self._local = local_model or DiagnosisModel(BUNDLED_ARTIFACT)
        self._circuit = _CircuitBreaker()

    def infer(self, *, merchant_id: str, raw_features: Mapping[str, object]) -> DiagnosisResult:
        mode = self._mode_reader.diagnosis_mode(merchant_id=merchant_id)
        vector = normalize_features(raw_features)
        local = self._local.infer_vector(vector)
        if mode is DiagnosisMode.LOCAL_ML:
            return local
        started = time.perf_counter_ns()
        try:
            if self._gemini is None:
                raise GeminiDiagnosisError("GEMINI_NOT_CONFIGURED")
            self._circuit.before_call()
            external = self._gemini.infer_vector(vector)
            self._circuit.succeeded()
        except GeminiDiagnosisError as exc:
            if exc.reason_code not in {"GEMINI_NOT_CONFIGURED", "GEMINI_CIRCUIT_OPEN"}:
                self._circuit.failed()
            latency_ms = min(60_000, (time.perf_counter_ns() - started) // 1_000_000)
            fallback_reasons = list(local.abstention_reasons)
            if mode is DiagnosisMode.HYBRID_GEMINI and (
                AbstentionReason.EXTERNAL_ENGINE_FALLBACK not in fallback_reasons
            ):
                fallback_reasons.append(AbstentionReason.EXTERNAL_ENGINE_FALLBACK)
            return replace(
                local,
                abstained=bool(fallback_reasons),
                abstention_reasons=tuple(fallback_reasons),
                provenance=DiagnosisProvenance(
                    requested_mode=mode,
                    executed_engine=DiagnosisEngine.LOCAL_ML,
                    model_name=BUNDLED_ARTIFACT.model_name,
                    latency_ms=latency_ms,
                    fallback_reason_code=exc.reason_code,
                ),
            )
        if mode is DiagnosisMode.HYBRID_GEMINI:
            return replace(
                external,
                provenance=replace(
                    external.provenance,
                    requested_mode=DiagnosisMode.HYBRID_GEMINI,
                ),
            )
        return replace(
            local,
            provenance=DiagnosisProvenance(
                requested_mode=DiagnosisMode.SHADOW,
                executed_engine=DiagnosisEngine.LOCAL_ML,
                model_name=BUNDLED_ARTIFACT.model_name,
                latency_ms=external.provenance.latency_ms,
                shadow=ShadowDiagnosis(
                    model_name=external.provenance.model_name,
                    model_version=external.artifact_version,
                    predicted_class=external.predicted_class.value,
                    confidence=external.confidence,
                    agreed=external.predicted_class is local.predicted_class,
                ),
            ),
        )


__all__ = [
    "DiagnosisModeReader",
    "DiagnosisRouter",
    "StaticDiagnosisModeReader",
]
