"""Stable failures for the deterministic diagnosis boundary."""


class DiagnosisError(ValueError):
    """Base class for invalid diagnosis inputs or artifacts."""


class FeatureValidationError(DiagnosisError):
    """A feature payload did not satisfy the closed feature schema."""


class SensitiveFeatureError(FeatureValidationError):
    """A payload attempted to cross the boundary with identifying data."""


class ArtifactValidationError(DiagnosisError):
    """A model artifact is structurally invalid or fails integrity checks."""


class UnknownModelVersion(DiagnosisError):
    """A caller requested a version that is not in the closed registry."""
