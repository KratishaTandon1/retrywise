"""Versioned, deterministic, non-authoritative payment-failure diagnosis."""

from .artifact import ArtifactRegistry, ModelArtifact
from .bundled import BUNDLED_ARTIFACT, BUNDLED_REGISTRY, PINNED_BUNDLED_VERSION
from .corpus import HELD_OUT_CORPUS, TRAINING_CORPUS, LabelledExample
from .errors import (
    ArtifactValidationError,
    DiagnosisError,
    FeatureValidationError,
    SensitiveFeatureError,
    UnknownModelVersion,
)
from .evaluation import EvaluationMetrics, evaluate_holdout
from .gemini import GeminiDiagnosisClient, GeminiDiagnosisError, GeminiTransport
from .inference import (
    DEFAULT_MIN_CONFIDENCE,
    AbstentionReason,
    ClassProbability,
    DiagnosisModel,
    DiagnosisResult,
    EvidenceItem,
)
from .provenance import (
    DiagnosisEngine,
    DiagnosisMode,
    DiagnosisProvenance,
    ShadowDiagnosis,
)
from .router import DiagnosisModeReader, DiagnosisRouter, StaticDiagnosisModeReader
from .schema import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_NAME,
    FEATURE_SCHEMA_VERSION,
    FEATURE_SPECS,
    FeatureSpec,
    FeatureVector,
    normalize_features,
)
from .taxonomy import FAILURE_TAXONOMY, FailureClass
from .training import export_artifact_bytes, train_artifact

__all__ = [
    "BUNDLED_ARTIFACT",
    "BUNDLED_REGISTRY",
    "DEFAULT_MIN_CONFIDENCE",
    "FAILURE_TAXONOMY",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_NAME",
    "FEATURE_SCHEMA_VERSION",
    "FEATURE_SPECS",
    "HELD_OUT_CORPUS",
    "PINNED_BUNDLED_VERSION",
    "TRAINING_CORPUS",
    "AbstentionReason",
    "ArtifactRegistry",
    "ArtifactValidationError",
    "ClassProbability",
    "DiagnosisEngine",
    "DiagnosisError",
    "DiagnosisMode",
    "DiagnosisModeReader",
    "DiagnosisModel",
    "DiagnosisProvenance",
    "DiagnosisResult",
    "DiagnosisRouter",
    "EvaluationMetrics",
    "EvidenceItem",
    "FailureClass",
    "FeatureSpec",
    "FeatureValidationError",
    "FeatureVector",
    "GeminiDiagnosisClient",
    "GeminiDiagnosisError",
    "GeminiTransport",
    "LabelledExample",
    "ModelArtifact",
    "SensitiveFeatureError",
    "ShadowDiagnosis",
    "StaticDiagnosisModeReader",
    "UnknownModelVersion",
    "evaluate_holdout",
    "export_artifact_bytes",
    "normalize_features",
    "train_artifact",
]
