"""Strict, redacted, categorical feature contract for diagnosis inference."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .errors import FeatureValidationError, SensitiveFeatureError

FEATURE_SCHEMA_NAME = "payment_failure_features"
FEATURE_SCHEMA_VERSION = 1
MISSING_VALUE = "__missing__"
UNKNOWN_VALUE = "__unknown__"

_SENSITIVE_KEY_FRAGMENTS = (
    "address",
    "card_number",
    "contact",
    "customer_id",
    "email",
    "ip_address",
    "name",
    "notes",
    "pan",
    "phone",
    "upi_id",
    "vpa",
)


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    name: str
    categories: tuple[str, ...]

    @property
    def vocabulary(self) -> tuple[str, ...]:
        return (*self.categories, MISSING_VALUE, UNKNOWN_VALUE)


FEATURE_SPECS: tuple[FeatureSpec, ...] = (
    FeatureSpec("payment_method", ("card", "upi", "netbanking", "wallet", "other")),
    FeatureSpec(
        "error_source",
        ("customer", "issuer", "provider", "merchant", "network", "unknown"),
    ),
    FeatureSpec(
        "error_step",
        (
            "initiation",
            "authentication",
            "authorization",
            "processing",
            "capture",
            "callback",
            "unknown",
        ),
    ),
    FeatureSpec(
        "error_reason",
        (
            "provider_unavailable",
            "gateway_timeout",
            "network_timeout",
            "issuer_unavailable",
            "incorrect_pin",
            "otp_failed",
            "user_cancelled",
            "credential_expired",
            "credential_invalid",
            "account_restricted",
            "insufficient_funds",
            "limit_exceeded",
            "integration_error",
            "invalid_request",
            "signature_error",
            "callback_error",
            "unknown",
        ),
    ),
    FeatureSpec("incident_state", ("normal", "suspected", "confirmed", "cooling")),
    FeatureSpec("attempt_bucket", ("first", "second", "many")),
    FeatureSpec("failure_age_bucket", ("fresh", "recent", "stale")),
)

FEATURE_NAMES = tuple(spec.name for spec in FEATURE_SPECS)
_FEATURE_BY_NAME = {spec.name: spec for spec in FEATURE_SPECS}


@dataclass(frozen=True, slots=True)
class FeatureVector:
    """A complete safe vector; raw values never survive normalization."""

    values: tuple[tuple[str, str], ...]
    unknown_features: tuple[str, ...] = ()
    missing_features: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        names = tuple(name for name, _ in self.values)
        if names != FEATURE_NAMES:
            raise FeatureValidationError("feature vector does not match the closed schema")
        for name, value in self.values:
            if value not in _FEATURE_BY_NAME[name].vocabulary:
                raise FeatureValidationError("feature vector contains a non-canonical value")
        if tuple(sorted(set(self.unknown_features))) != self.unknown_features:
            raise FeatureValidationError("unknown feature markers must be sorted and unique")
        if tuple(sorted(set(self.missing_features))) != self.missing_features:
            raise FeatureValidationError("missing feature markers must be sorted and unique")
        expected_unknown = tuple(
            sorted(name for name, value in self.values if value == UNKNOWN_VALUE)
        )
        expected_missing = tuple(
            sorted(name for name, value in self.values if value == MISSING_VALUE)
        )
        if self.unknown_features != expected_unknown:
            raise FeatureValidationError("unknown markers do not match the normalized vector")
        if self.missing_features != expected_missing:
            raise FeatureValidationError("missing markers do not match the normalized vector")

    @property
    def out_of_distribution(self) -> bool:
        return bool(self.unknown_features or self.missing_features)

    def value_for(self, feature_name: str) -> str:
        for name, value in self.values:
            if name == feature_name:
                return value
        raise FeatureValidationError("feature is not in the closed schema")

    def to_primitive(self) -> dict[str, object]:
        return {
            "schema": FEATURE_SCHEMA_NAME,
            "schema_version": FEATURE_SCHEMA_VERSION,
            "values": {name: value for name, value in self.values},
            "unknown_features": list(self.unknown_features),
            "missing_features": list(self.missing_features),
        }


def normalize_features(raw: Mapping[str, object]) -> FeatureVector:
    """Allowlist and normalize a payload without retaining raw or identifying values."""

    if not isinstance(raw, Mapping):
        raise FeatureValidationError("features must be a mapping")

    for raw_key in raw:
        if not isinstance(raw_key, str):
            raise FeatureValidationError("feature keys must be strings")
        key = raw_key.strip().lower().replace("-", "_")
        if any(fragment in key for fragment in _SENSITIVE_KEY_FRAGMENTS):
            raise SensitiveFeatureError("sensitive or identifying features are not permitted")
        if key not in _FEATURE_BY_NAME or key != raw_key:
            raise FeatureValidationError("feature key is not allowlisted or canonical")

    values: list[tuple[str, str]] = []
    unknown: list[str] = []
    missing: list[str] = []
    for spec in FEATURE_SPECS:
        if spec.name not in raw:
            values.append((spec.name, MISSING_VALUE))
            missing.append(spec.name)
            continue
        raw_value = raw[spec.name]
        if not isinstance(raw_value, str) or len(raw_value) > 64:
            values.append((spec.name, UNKNOWN_VALUE))
            unknown.append(spec.name)
            continue
        normalized = raw_value.strip().lower()
        if normalized not in spec.categories:
            normalized = UNKNOWN_VALUE
            unknown.append(spec.name)
        values.append((spec.name, normalized))

    return FeatureVector(
        values=tuple(values),
        unknown_features=tuple(sorted(unknown)),
        missing_features=tuple(sorted(missing)),
    )
