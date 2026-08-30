"""Executable composition root for the durable RetryWise outbox worker."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import signal
import socket
import sys
import time
from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import cast

from ...packages.diagnosis import DiagnosisRouter, GeminiDiagnosisClient
from .approval_command import MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE
from .approval_service import PostgresApprovalService
from .approval_worker import (
    MaterializeApprovedActionHandler,
    PostgresApprovalCompletionProbe,
)
from .assessment_intent import (
    AssessmentToIntentService,
    PostgresAssessmentIntentRepository,
    StandardPaymentLinkAssessmentPlanner,
)
from .assessment_worker import (
    ASSESS_RECOVERY_CASE_COMMAND_TYPE,
    AssessRecoveryCaseHandler,
    PostgresAssessmentCompletionProbe,
    PostgresAssessmentScheduler,
)
from .cancellation_command_codec import CANCEL_PAYMENT_LINK_COMMAND_TYPE
from .cancellation_worker import (
    CancelPaymentLinkHandler,
    PostgresCancellationRepository,
    PostgresCancellationScheduler,
)
from .create_effect_worker import CreateStandardPaymentLinkHandler, PostgresCreateEffectRepository
from .diagnosis_controls import PostgresDiagnosisControlService
from .effect_command_codec import CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE
from .gemini_secret import GeminiSecretFileError, load_gemini_api_key_file
from .normalized_event_projector import (
    PROCESS_NORMALIZED_PROVIDER_EVENT,
    PostgresNormalizedEventRepository,
    ProcessNormalizedProviderEventHandler,
)
from .normalized_event_router import ProcessNormalizedProviderEventRouter
from .outbox_worker import OutboxWorker, PollResult
from .payment_enrichment import (
    ENRICH_FAILED_PAYMENT_COMMAND_TYPE,
    EnrichFailedPaymentHandler,
    PostgresFailedPaymentEnrichmentRepository,
)
from .policy import production_gate
from .postgres_audit import PostgresAuditAppender
from .postgres_connection import PostgresConnectionPolicy
from .postgres_outbox import PostgresOutboxRepository
from .provider_readers import (
    BoundRazorpayTestAdapterFactory,
    PostgresFreshMethodHealthReader,
    RazorpayFreshProviderTruthReader,
)
from .razorpay_account_binding import PostgresRazorpayAccountBindingRepository
from .settings import ConfigurationError, ControlPlaneSettings, EffectsMode
from .terminal_event_projector import (
    PostgresTerminalEventRepository,
    ProcessTerminalProviderEventHandler,
)
from .test_mode_secrets import FileRazorpayCredentialSecretResolver
from .worker_heartbeat import PostgresWorkerHeartbeatRepository, WorkerHeartbeat

_LOGGER = logging.getLogger("retrywise.worker")


def _new_ulid() -> str:
    timestamp_ms = time.time_ns() // 1_000_000
    if not 0 <= timestamp_ms < 1 << 48:
        raise RuntimeError("system clock is outside the ULID timestamp range")
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = (timestamp_ms << 80) | secrets.randbits(80)
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = alphabet[value & 31]
        value >>= 5
    return "".join(characters)


def _required(mapping: Mapping[str, str], field: str) -> str:
    value = mapping.get(field, "")
    if not value or value != value.strip():
        raise ConfigurationError(f"{field} is required for the worker")
    return value


def _worker_id(mapping: Mapping[str, str]) -> str:
    configured = mapping.get("RETRYWISE_WORKER_ID", "")
    if configured:
        if configured != configured.strip() or len(configured) > 128:
            raise ConfigurationError("RETRYWISE_WORKER_ID is invalid")
        return configured
    host_digest = hashlib.sha256(socket.gethostname().encode("utf-8")).hexdigest()[:16]
    return f"outbox:{host_digest}:{os.getpid()}"


def _gemini_client(mapping: Mapping[str, str]) -> GeminiDiagnosisClient | None:
    secret_file = mapping.get("RETRYWISE_GEMINI_API_KEY_FILE", "")
    if not secret_file:
        return None
    try:
        api_key = load_gemini_api_key_file(secret_file)
    except GeminiSecretFileError as exc:
        raise ConfigurationError("Gemini secret file is unavailable") from exc
    raw_timeout = mapping.get("RETRYWISE_GEMINI_TIMEOUT_SECONDS", "8")
    try:
        timeout = float(raw_timeout)
    except ValueError as exc:
        raise ConfigurationError("RETRYWISE_GEMINI_TIMEOUT_SECONDS is invalid") from exc
    try:
        return GeminiDiagnosisClient(
            api_key=api_key,
            model=mapping.get("RETRYWISE_GEMINI_MODEL", "gemini-2.5-flash"),
            timeout_seconds=timeout,
        )
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("Gemini diagnosis configuration is invalid") from exc


class WorkerRuntime:
    """Fully composed worker with credential startup attestation and heartbeat."""

    def __init__(self, *, mapping: Mapping[str, str]) -> None:
        self.settings = ControlPlaneSettings.from_mapping(mapping)
        if self.settings.effects_mode is not EffectsMode.RAZORPAY_TEST:
            raise ConfigurationError("worker requires RETRYWISE_EFFECTS_MODE=razorpay_test")
        dsn = _required(mapping, "DATABASE_URL")
        merchant_id = _required(mapping, "RETRYWISE_MERCHANT_ID")
        provider_account_id = _required(mapping, "RETRYWISE_PROVIDER_ACCOUNT_ID")
        secret_root = _required(mapping, "RETRYWISE_SECRET_ROOT")
        worker_id = _worker_id(mapping)

        connection_policy = PostgresConnectionPolicy(require_tls=self.settings.database_require_tls)
        connection_policy.validate_dsn(dsn)

        def connector() -> object:
            return connection_policy.connect(dsn, component="WorkerRuntime")

        account_bindings = PostgresRazorpayAccountBindingRepository(
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
        )
        secret_resolver = FileRazorpayCredentialSecretResolver(secret_root=secret_root)
        adapter_factory = BoundRazorpayTestAdapterFactory(
            account_bindings=account_bindings,
            secret_resolver=secret_resolver,
        )
        # Startup is not ready unless the exact configured account and secret
        # generation can be composed. This performs no Razorpay request.
        startup_adapter = adapter_factory(merchant_id, provider_account_id)
        startup_adapter.close()

        provider_truth = RazorpayFreshProviderTruthReader(adapter_factory=adapter_factory)
        method_health = PostgresFreshMethodHealthReader(
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
        )
        audit = PostgresAuditAppender()
        gate = production_gate()
        gemini = _gemini_client(mapping)
        diagnosis_controls = PostgresDiagnosisControlService(
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
            gemini_configured=gemini is not None,
            id_factory=_new_ulid,
        )
        diagnosis_router = DiagnosisRouter(
            mode_reader=diagnosis_controls,
            gemini=gemini,
        )
        assessment_repository = PostgresAssessmentIntentRepository(
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
            audit_appender=audit,
            id_factory=_new_ulid,
        )
        assessment_service = AssessmentToIntentService(
            repository=assessment_repository,
            provider_truth_reader=provider_truth,
            method_health_reader=method_health,
            planner=StandardPaymentLinkAssessmentPlanner(
                gate=gate,
                id_factory=_new_ulid,
                global_kill_switch=self.settings.global_kill_switch,
                diagnosis_router=diagnosis_router,
            ),
        )
        completion_probe = PostgresAssessmentCompletionProbe(
            connector=cast(object, connector)  # type: ignore[arg-type]
        )
        assessment_handler = AssessRecoveryCaseHandler(
            service=assessment_service,
            completion_probe=completion_probe,
        )
        create_repository = PostgresCreateEffectRepository(
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
            provider_truth_reader=provider_truth,
            method_health_reader=method_health,
            policy_version=gate.policy.version,
            global_kill_switch=self.settings.global_kill_switch,
            audit_appender=audit,
            audit_id_factory=_new_ulid,
        )
        create_handler = CreateStandardPaymentLinkHandler(
            gate=gate,
            repository=create_repository,
            adapter_factory=adapter_factory,
            clock=lambda: datetime.now(UTC),
        )
        approval_handler = MaterializeApprovedActionHandler(
            service=PostgresApprovalService(
                gate=gate,
                provider_truth_reader=provider_truth,
                method_health_reader=method_health,
                dsn=dsn,
                require_tls=self.settings.database_require_tls,
                global_kill_switch=self.settings.global_kill_switch,
                audit_appender=audit,
                id_factory=_new_ulid,
            ),
            completion_probe=PostgresApprovalCompletionProbe(
                dsn=dsn,
                require_tls=self.settings.database_require_tls,
            ),
        )
        cancellation_repository = PostgresCancellationRepository(
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
            global_kill_switch=self.settings.global_kill_switch,
            audit_appender=audit,
            id_factory=_new_ulid,
        )
        cancellation_handler = CancelPaymentLinkHandler(
            gate=gate,
            repository=cancellation_repository,
            adapter_factory=adapter_factory,
            clock=lambda: datetime.now(UTC),
        )
        failure_handler = ProcessNormalizedProviderEventHandler(
            PostgresNormalizedEventRepository(
                dsn=dsn,
                require_tls=self.settings.database_require_tls,
            )
        )
        enrichment_handler = EnrichFailedPaymentHandler(
            repository=PostgresFailedPaymentEnrichmentRepository(
                dsn=dsn,
                require_tls=self.settings.database_require_tls,
                id_factory=_new_ulid,
            ),
            adapter_factory=adapter_factory,
            clock=lambda: datetime.now(UTC),
        )
        terminal_handler = ProcessTerminalProviderEventHandler(
            PostgresTerminalEventRepository(
                dsn=dsn,
                require_tls=self.settings.database_require_tls,
            )
        )
        event_router = ProcessNormalizedProviderEventRouter(
            failure_handler=failure_handler,
            terminal_handler=terminal_handler,
        )
        outbox = PostgresOutboxRepository(
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
        )
        if not outbox.check_ready():
            raise ConfigurationError("durable outbox is not ready")
        self._scheduler = PostgresAssessmentScheduler(
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
            id_factory=_new_ulid,
        )
        self._cancellation_scheduler = PostgresCancellationScheduler(
            gate=gate,
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
            id_factory=_new_ulid,
            audit_appender=audit,
        )
        self._worker = OutboxWorker(
            repository=outbox,
            worker_id=worker_id,
            handlers={
                PROCESS_NORMALIZED_PROVIDER_EVENT: event_router,
                ENRICH_FAILED_PAYMENT_COMMAND_TYPE: enrichment_handler,
                ASSESS_RECOVERY_CASE_COMMAND_TYPE: assessment_handler,
                CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE: create_handler,
                CANCEL_PAYMENT_LINK_COMMAND_TYPE: cancellation_handler,
                MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE: approval_handler,
            },
            batch_size=25,
            lease_duration=timedelta(seconds=30),
        )
        self._heartbeat_repository = PostgresWorkerHeartbeatRepository(
            dsn=dsn,
            require_tls=self.settings.database_require_tls,
        )
        self._heartbeat = WorkerHeartbeat(
            worker_id=worker_id,
            code_revision=self.settings.code_revision,
        )

    def run(self, *, stop: Event, idle_delay_seconds: float = 1.0) -> None:
        if not isinstance(stop, Event):
            raise TypeError("stop must be a threading.Event")
        self._heartbeat_repository.beat(self._heartbeat)
        while not stop.is_set():
            try:
                self._scheduler.schedule_due()
                self._cancellation_scheduler.schedule_due()
                result = self._worker.poll_once()
                self._heartbeat_repository.beat(self._heartbeat, result=result)
                if result.selected == 0:
                    stop.wait(idle_delay_seconds)
            except Exception as exc:
                reason = f"worker_loop:{type(exc).__name__}"[:200]
                _LOGGER.exception("worker loop failed", extra={"reason_code": reason})
                with suppress(Exception):
                    self._heartbeat_repository.beat(
                        self._heartbeat,
                        result=PollResult(0, 0, 0, 0, 0, 0),
                        last_error_code=reason,
                    )
                stop.wait(min(5.0, idle_delay_seconds * 2))


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    try:
        runtime = WorkerRuntime(mapping=os.environ)
    except Exception as exc:
        _LOGGER.error("worker composition failed: %s", type(exc).__name__)
        return 2
    stop = Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    runtime.run(stop=stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["WorkerRuntime", "main"]
