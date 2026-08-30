"""Fail-closed runtime settings without a framework dependency."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlparse


class ConfigurationError(ValueError):
    """Runtime configuration would weaken an environment boundary."""


class DeploymentProfile(StrEnum):
    DEVELOPMENT = "development"
    SANDBOX = "sandbox"
    PRODUCTION = "production"


class DataSource(StrEnum):
    REPLAY = "REPLAY"
    RAZORPAY_TEST_MODE = "RAZORPAY_TEST_MODE"


class EffectsMode(StrEnum):
    DISABLED = "disabled"
    RAZORPAY_TEST = "razorpay_test"


def _parse_bool(mapping: Mapping[str, str], name: str, *, default: bool) -> bool:
    raw = mapping.get(name)
    if raw is None:
        return default
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise ConfigurationError(f"{name} must be exactly true or false")


def _parse_int(
    mapping: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = mapping.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _safe_http_url(value: str, *, field: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError(f"{field} must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ConfigurationError(f"{field} cannot contain credentials or a fragment")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query:
        raise ConfigurationError(f"{field} must be an origin without path or query")
    return value.rstrip("/")


@dataclass(frozen=True, slots=True)
class ControlPlaneSettings:
    environment: DeploymentProfile
    data_source: DataSource
    effects_mode: EffectsMode
    global_kill_switch: bool
    public_base_url: str
    cors_allowed_origins: tuple[str, ...]
    webhook_max_body_bytes: int
    code_revision: str
    database_require_tls: bool

    def __post_init__(self) -> None:
        if not isinstance(self.environment, DeploymentProfile):
            raise ConfigurationError("environment must be a closed deployment profile")
        if not isinstance(self.data_source, DataSource):
            raise ConfigurationError("data_source must be a closed DataSource")
        if not isinstance(self.effects_mode, EffectsMode):
            raise ConfigurationError("effects_mode must be a closed EffectsMode")
        if not isinstance(self.global_kill_switch, bool):
            raise ConfigurationError("global_kill_switch must be boolean")
        if not isinstance(self.database_require_tls, bool):
            raise ConfigurationError("database_require_tls must be boolean")
        object.__setattr__(
            self,
            "public_base_url",
            _safe_http_url(self.public_base_url, field="public_base_url"),
        )
        origins = tuple(
            _safe_http_url(origin, field="cors_allowed_origin")
            for origin in self.cors_allowed_origins
        )
        if not origins:
            raise ConfigurationError("at least one CORS origin is required")
        object.__setattr__(self, "cors_allowed_origins", origins)
        if not 1_024 <= self.webhook_max_body_bytes <= 1_048_576:
            raise ConfigurationError("webhook_max_body_bytes must be between 1 KiB and 1 MiB")
        if not self.code_revision or self.code_revision != self.code_revision.strip():
            raise ConfigurationError("code_revision must be non-empty")
        if len(self.code_revision) > 128:
            raise ConfigurationError("code_revision cannot exceed 128 characters")
        if self.environment in {
            DeploymentProfile.SANDBOX,
            DeploymentProfile.PRODUCTION,
        }:
            urls = (self.public_base_url, *self.cors_allowed_origins)
            if any(urlparse(url).scheme != "https" for url in urls):
                raise ConfigurationError("deployed profiles require HTTPS origins")
            if self.code_revision == "local-development":
                raise ConfigurationError("deployed profiles require an immutable code revision")
            if not self.database_require_tls:
                raise ConfigurationError("deployed profiles require DATABASE_REQUIRE_TLS=true")

        if (
            self.effects_mode is EffectsMode.RAZORPAY_TEST
            and self.data_source is not DataSource.RAZORPAY_TEST_MODE
        ):
            raise ConfigurationError("provider effects cannot be enabled inside Replay data source")

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, str]) -> ControlPlaneSettings:
        try:
            environment = DeploymentProfile(
                mapping.get("RETRYWISE_ENVIRONMENT", DeploymentProfile.DEVELOPMENT.value)
            )
        except ValueError as exc:
            raise ConfigurationError("RETRYWISE_ENVIRONMENT is invalid") from exc
        try:
            data_source = DataSource(mapping.get("RETRYWISE_DATA_SOURCE", "REPLAY"))
        except ValueError as exc:
            raise ConfigurationError("RETRYWISE_DATA_SOURCE is invalid") from exc
        try:
            effects_mode = EffectsMode(
                mapping.get("RETRYWISE_EFFECTS_MODE", EffectsMode.DISABLED.value)
            )
        except ValueError as exc:
            raise ConfigurationError("RETRYWISE_EFFECTS_MODE is invalid") from exc

        raw_origins = mapping.get("RETRYWISE_CORS_ALLOWED_ORIGINS", "http://127.0.0.1:3000")
        origins = tuple(item.strip() for item in raw_origins.split(",") if item.strip())
        if mapping.get("RAZORPAY_KEY_ID") or mapping.get("RAZORPAY_KEY_SECRET"):
            raise ConfigurationError(
                "raw Razorpay API credentials are not accepted; enroll a versioned "
                "managed-secret binding"
            )
        if mapping.get("GEMINI_API_KEY"):
            raise ConfigurationError(
                "raw Gemini credentials are not accepted; configure RETRYWISE_GEMINI_API_KEY_FILE"
            )
        return cls(
            environment=environment,
            data_source=data_source,
            effects_mode=effects_mode,
            global_kill_switch=_parse_bool(mapping, "RETRYWISE_GLOBAL_KILL_SWITCH", default=True),
            public_base_url=_safe_http_url(
                mapping.get("RETRYWISE_PUBLIC_BASE_URL", "http://127.0.0.1:8000"),
                field="RETRYWISE_PUBLIC_BASE_URL",
            ),
            cors_allowed_origins=origins,
            webhook_max_body_bytes=_parse_int(
                mapping,
                "RETRYWISE_WEBHOOK_MAX_BODY_BYTES",
                default=262_144,
                minimum=1_024,
                maximum=1_048_576,
            ),
            code_revision=mapping.get("RETRYWISE_CODE_REVISION", "local-development"),
            database_require_tls=_parse_bool(
                mapping,
                "DATABASE_REQUIRE_TLS",
                default=False,
            ),
        )

    def public_summary(self) -> dict[str, object]:
        """Return non-secret configuration safe for health diagnostics."""

        return {
            "environment": self.environment.value,
            "data_source": self.data_source.value,
            "effects_mode": self.effects_mode.value,
            "global_kill_switch": self.global_kill_switch,
            "webhook_max_body_bytes": self.webhook_max_body_bytes,
            "code_revision": self.code_revision,
            "database_tls_required": self.database_require_tls,
            "razorpay_effect_credential_source": "versioned_managed_secret_binding",
        }
