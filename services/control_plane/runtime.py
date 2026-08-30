"""Composition root for the API and worker process roles."""

from __future__ import annotations

import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from ...packages.razorpay import InMemoryWebhookInbox, WebhookInbox
from .approval_request import PostgresApprovalRequestService
from .auth import DenyAllAuthorizer, OperatorAuthorizer, StaticBearerAuthorizer
from .diagnosis_controls import PostgresDiagnosisControlService
from .merchant_controls import PostgresMerchantControlService
from .operator_store import PostgresOperatorStore
from .postgres_audit import PostgresAuditAppender
from .postgres_connection import (
    PostgresConnectionConfigurationError,
    PostgresConnectionPolicy,
)
from .postgres_inbox import PostgresWebhookInbox
from .replay import ReplayService
from .settings import (
    ConfigurationError,
    ControlPlaneSettings,
    DataSource,
    DeploymentProfile,
    EffectsMode,
)
from .webhook_ingress import EndpointBinding, StaticEndpointRegistry, WebhookIngress
from .webhook_secrets import WebhookSecretFileError, load_webhook_secret_file
from .worker_heartbeat import PostgresWorkerHeartbeatRepository


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _validated_clock_value(clock: Callable[[], datetime]) -> datetime:
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
        raise ConfigurationError("runtime clock must return an aware UTC datetime")
    return now


def _previous_secret_expiry(raw: str) -> datetime:
    if not raw or raw != raw.strip():
        raise ConfigurationError(
            "RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT must be canonical UTC"
        )
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ConfigurationError(
            "RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT must use YYYY-MM-DDTHH:MM:SSZ"
        ) from exc


@dataclass(frozen=True, slots=True)
class ControlPlaneRuntime:
    settings: ControlPlaneSettings
    replay: ReplayService
    webhook_ingress: WebhookIngress
    operator_authorizer: OperatorAuthorizer
    webhook_configured: bool
    worker_composed: bool = False
    worker_readiness: PostgresWorkerHeartbeatRepository | None = None
    operator_store: PostgresOperatorStore | None = None
    approval_requests: PostgresApprovalRequestService | None = None
    merchant_controls: PostgresMerchantControlService | None = None
    diagnosis_controls: PostgresDiagnosisControlService | None = None

    def readiness(self) -> tuple[bool, dict[str, object]]:
        """Return a safe dependency report and the HTTP readiness verdict."""

        durable_ingress = self.webhook_ingress.durable
        ingress_ready = True
        if self.webhook_configured and durable_ingress:
            try:
                ingress_ready = self.webhook_ingress.check_ready()
            except Exception:  # A dependency exception is a failed probe, never readiness.
                ingress_ready = False
        elif self.webhook_configured:
            ingress_ready = self.settings.environment is DeploymentProfile.DEVELOPMENT

        effect_path_required = self.settings.effects_mode is EffectsMode.RAZORPAY_TEST
        effect_path_ready = not effect_path_required or self.worker_composed
        if effect_path_required and self.worker_readiness is not None:
            try:
                effect_path_ready = self.worker_readiness.is_fresh(
                    code_revision=self.settings.code_revision
                )
            except Exception:
                effect_path_ready = False
        ready = ingress_ready and effect_path_ready
        return ready, {
            "status": "ready" if ready else "not_ready",
            "webhook_configured": self.webhook_configured,
            "durable_ingress": durable_ingress,
            "webhook_ingress_ready": ingress_ready,
            "effect_path_required": effect_path_required,
            "effect_path_ready": effect_path_ready,
            "worker_composed": self.worker_readiness is not None or self.worker_composed,
            **self.settings.public_summary(),
        }

    @classmethod
    def from_mapping(
        cls,
        mapping: Mapping[str, str],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> ControlPlaneRuntime:
        active_clock = clock or _utc_now
        composition_time = _validated_clock_value(active_clock)
        settings = ControlPlaneSettings.from_mapping(mapping)
        webhook_secret_file = mapping.get("RAZORPAY_WEBHOOK_SECRET_FILE", "")
        file_snapshot = None
        if webhook_secret_file:
            if any(
                mapping.get(field, "")
                for field in (
                    "RAZORPAY_WEBHOOK_SECRET_CURRENT",
                    "RAZORPAY_WEBHOOK_SECRET_PREVIOUS",
                    "RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT",
                )
            ):
                raise ConfigurationError(
                    "configure exactly one webhook secret authority: file or environment"
                )
            try:
                file_snapshot = load_webhook_secret_file(webhook_secret_file)
            except WebhookSecretFileError as exc:
                raise ConfigurationError("webhook secret file is unavailable") from exc
        endpoint_fields = {
            "endpoint_token": mapping.get("RETRYWISE_WEBHOOK_ENDPOINT_TOKEN", ""),
            "merchant_id": mapping.get("RETRYWISE_MERCHANT_ID", ""),
            "provider_account_id": mapping.get("RETRYWISE_PROVIDER_ACCOUNT_ID", ""),
            "provider_account_identifier": mapping.get("RAZORPAY_ACCOUNT_ID", ""),
            "current_secret": (
                file_snapshot.current
                if file_snapshot is not None
                else mapping.get("RAZORPAY_WEBHOOK_SECRET_CURRENT", "")
            ),
        }
        webhook_specific_fields = (
            "endpoint_token",
            "provider_account_id",
            "provider_account_identifier",
            "current_secret",
        )
        previous = (
            file_snapshot.previous
            if file_snapshot is not None and file_snapshot.previous is not None
            else mapping.get("RAZORPAY_WEBHOOK_SECRET_PREVIOUS", "")
        )
        previous_expiry_raw = (
            file_snapshot.previous_expires_at
            if file_snapshot is not None and file_snapshot.previous_expires_at is not None
            else mapping.get("RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT", "")
        )
        if bool(previous) != bool(previous_expiry_raw):
            raise ConfigurationError(
                "previous webhook secret and its UTC expiry must be configured together"
            )
        previous_expiry = (
            _previous_secret_expiry(previous_expiry_raw) if previous_expiry_raw else None
        )
        if previous_expiry is not None and previous_expiry <= composition_time:
            raise ConfigurationError("previous webhook secret expiry must be in the future")
        if previous and hmac.compare_digest(previous, endpoint_fields["current_secret"]):
            raise ConfigurationError("current and previous webhook secrets must be different")

        webhook_requested = any(endpoint_fields[name] for name in webhook_specific_fields) or bool(
            previous or previous_expiry_raw
        )
        bindings: tuple[EndpointBinding, ...] = ()
        if webhook_requested:
            if not all(endpoint_fields.values()):
                missing = ", ".join(name for name, value in endpoint_fields.items() if not value)
                raise ConfigurationError(f"webhook endpoint configuration is incomplete: {missing}")
            secrets = [endpoint_fields["current_secret"].encode("utf-8")]
            if previous:
                secrets.append(previous.encode("utf-8"))
            bindings = (
                EndpointBinding(
                    endpoint_token=endpoint_fields["endpoint_token"],
                    merchant_id=endpoint_fields["merchant_id"],
                    provider_account_id=endpoint_fields["provider_account_id"],
                    provider_account_identifier=endpoint_fields["provider_account_identifier"],
                    webhook_secrets=tuple(secrets),
                    previous_secret_expires_at=previous_expiry,
                ),
            )

        database_url = mapping.get("DATABASE_URL", "")
        if database_url and (not database_url.strip() or database_url != database_url.strip()):
            raise ConfigurationError("DATABASE_URL cannot contain surrounding whitespace")
        deployed = settings.environment in {
            DeploymentProfile.SANDBOX,
            DeploymentProfile.PRODUCTION,
        }
        if deployed and bindings and not database_url:
            raise ConfigurationError(
                "deployed webhook ingress requires DATABASE_URL for durable acceptance"
            )
        if deployed and settings.data_source is DataSource.RAZORPAY_TEST_MODE and not bindings:
            raise ConfigurationError(
                "deployed Razorpay Test Mode requires a configured webhook endpoint"
            )
        if database_url:
            try:
                PostgresConnectionPolicy(require_tls=settings.database_require_tls).validate_dsn(
                    database_url
                )
            except PostgresConnectionConfigurationError as exc:
                raise ConfigurationError(str(exc)) from exc

        raw_operator_token = mapping.get("RETRYWISE_OPERATOR_TOKEN", "")
        authorizer: OperatorAuthorizer
        if raw_operator_token:
            merchant_id = mapping.get("RETRYWISE_MERCHANT_ID", "")
            if not merchant_id:
                raise ConfigurationError("RETRYWISE_OPERATOR_TOKEN requires RETRYWISE_MERCHANT_ID")
            authorizer = StaticBearerAuthorizer(
                token=raw_operator_token.encode("utf-8"),
                subject=mapping.get("RETRYWISE_OPERATOR_SUBJECT", "local-operator"),
                merchant_id=merchant_id,
            )
        else:
            authorizer = DenyAllAuthorizer()

        inbox: WebhookInbox = InMemoryWebhookInbox()
        if bindings and database_url:
            try:
                inbox = PostgresWebhookInbox(
                    merchant_id=endpoint_fields["merchant_id"],
                    provider_account_id=endpoint_fields["provider_account_id"],
                    provider_account_identifier=endpoint_fields["provider_account_identifier"],
                    dsn=database_url,
                    require_tls=settings.database_require_tls,
                )
            except (TypeError, ValueError) as exc:
                raise ConfigurationError(
                    "durable webhook ingress requires ULID merchant and provider account ids"
                ) from exc

        worker_readiness = None
        operator_store = None
        approval_requests = None
        merchant_controls = None
        diagnosis_controls = None
        if database_url:
            operator_store = PostgresOperatorStore(
                dsn=database_url,
                require_tls=settings.database_require_tls,
            )
            approval_requests = PostgresApprovalRequestService(
                dsn=database_url,
                require_tls=settings.database_require_tls,
                audit_appender=PostgresAuditAppender(),
            )
            merchant_controls = PostgresMerchantControlService(
                dsn=database_url,
                require_tls=settings.database_require_tls,
            )
            diagnosis_controls = PostgresDiagnosisControlService(
                dsn=database_url,
                require_tls=settings.database_require_tls,
                gemini_configured=bool(mapping.get("RETRYWISE_GEMINI_API_KEY_FILE", "")),
            )
        if database_url and settings.effects_mode is EffectsMode.RAZORPAY_TEST:
            worker_readiness = PostgresWorkerHeartbeatRepository(
                dsn=database_url,
                require_tls=settings.database_require_tls,
            )

        return cls(
            settings=settings,
            replay=ReplayService(),
            webhook_ingress=WebhookIngress(
                registry=StaticEndpointRegistry(bindings),
                inbox=inbox,
                max_body_bytes=settings.webhook_max_body_bytes,
                clock=active_clock,
            ),
            operator_authorizer=authorizer,
            webhook_configured=bool(bindings),
            worker_composed=worker_readiness is not None,
            worker_readiness=worker_readiness,
            operator_store=operator_store,
            approval_requests=approval_requests,
            merchant_controls=merchant_controls,
            diagnosis_controls=diagnosis_controls,
        )
