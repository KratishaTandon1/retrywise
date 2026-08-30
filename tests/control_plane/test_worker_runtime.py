from __future__ import annotations

import unittest
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock, patch

from retrywise.services.control_plane import worker_runtime as runtime_module
from retrywise.services.control_plane.outbox_worker import PollResult
from retrywise.services.control_plane.settings import ConfigurationError


def mapping() -> dict[str, str]:
    return {
        "RETRYWISE_DATA_SOURCE": "RAZORPAY_TEST_MODE",
        "RETRYWISE_EFFECTS_MODE": "razorpay_test",
        "RETRYWISE_GLOBAL_KILL_SWITCH": "true",
        "DATABASE_URL": "postgresql://retrywise@database/retrywise",
        "RETRYWISE_MERCHANT_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "RETRYWISE_PROVIDER_ACCOUNT_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAW",
        "RETRYWISE_SECRET_ROOT": "/managed/retrywise/secrets",
        "RETRYWISE_WORKER_ID": "outbox:test-worker",
    }


def composition_replacements(*, outbox_ready: bool = True) -> tuple[dict[str, object], Mock]:
    connection_policy = Mock()
    startup_adapter = Mock()
    adapter_factory = Mock(return_value=startup_adapter)
    outbox = Mock()
    outbox.check_ready.return_value = outbox_ready
    worker = Mock()
    heartbeat_repository = Mock()

    replacements: dict[str, object] = {
        "PostgresConnectionPolicy": Mock(return_value=connection_policy),
        "PostgresRazorpayAccountBindingRepository": Mock(return_value=Mock()),
        "FileRazorpayCredentialSecretResolver": Mock(return_value=Mock()),
        "BoundRazorpayTestAdapterFactory": Mock(return_value=adapter_factory),
        "RazorpayFreshProviderTruthReader": Mock(return_value=Mock()),
        "PostgresFreshMethodHealthReader": Mock(return_value=Mock()),
        "PostgresAuditAppender": Mock(return_value=Mock()),
        "production_gate": Mock(
            return_value=SimpleNamespace(policy=SimpleNamespace(version="policy-v1"))
        ),
        "PostgresAssessmentIntentRepository": Mock(return_value=Mock()),
        "AssessmentToIntentService": Mock(return_value=Mock()),
        "StandardPaymentLinkAssessmentPlanner": Mock(return_value=Mock()),
        "PostgresAssessmentCompletionProbe": Mock(return_value=Mock()),
        "AssessRecoveryCaseHandler": Mock(return_value=Mock()),
        "PostgresCreateEffectRepository": Mock(return_value=Mock()),
        "CreateStandardPaymentLinkHandler": Mock(return_value=Mock()),
        "PostgresApprovalService": Mock(return_value=Mock()),
        "PostgresApprovalCompletionProbe": Mock(return_value=Mock()),
        "MaterializeApprovedActionHandler": Mock(return_value=Mock()),
        "PostgresCancellationRepository": Mock(return_value=Mock()),
        "CancelPaymentLinkHandler": Mock(return_value=Mock()),
        "PostgresNormalizedEventRepository": Mock(return_value=Mock()),
        "ProcessNormalizedProviderEventHandler": Mock(return_value=Mock()),
        "PostgresFailedPaymentEnrichmentRepository": Mock(return_value=Mock()),
        "EnrichFailedPaymentHandler": Mock(return_value=Mock()),
        "PostgresTerminalEventRepository": Mock(return_value=Mock()),
        "ProcessTerminalProviderEventHandler": Mock(return_value=Mock()),
        "ProcessNormalizedProviderEventRouter": Mock(return_value=Mock()),
        "PostgresOutboxRepository": Mock(return_value=outbox),
        "PostgresAssessmentScheduler": Mock(return_value=Mock()),
        "PostgresCancellationScheduler": Mock(return_value=Mock()),
        "OutboxWorker": Mock(return_value=worker),
        "PostgresWorkerHeartbeatRepository": Mock(return_value=heartbeat_repository),
        "WorkerHeartbeat": Mock(return_value=Mock()),
    }
    replacements["_test_startup_adapter"] = startup_adapter
    replacements["_test_worker"] = worker
    replacements["_test_heartbeat_repository"] = heartbeat_repository
    replacements["_test_connection_policy"] = connection_policy
    return replacements, replacements["OutboxWorker"]  # type: ignore[return-value]


class WorkerRuntimeCompositionTests(unittest.TestCase):
    def test_release_policy_is_pinned_and_complete(self) -> None:
        gate = runtime_module.production_gate()
        self.assertEqual("policy-v1", gate.policy.version)
        self.assertEqual(3, gate.policy.max_attempts)
        self.assertEqual(2, gate.policy.max_contacts_in_window)

    def test_helpers_are_strict_and_do_not_require_a_configured_worker_id(self) -> None:
        self.assertEqual("value", runtime_module._required({"FIELD": "value"}, "FIELD"))
        for value in ("", " value"):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                runtime_module._required({"FIELD": value}, "FIELD")

        generated = runtime_module._worker_id({})
        self.assertTrue(generated.startswith("outbox:"))
        self.assertEqual(
            "configured", runtime_module._worker_id({"RETRYWISE_WORKER_ID": "configured"})
        )
        for value in (" invalid", "x" * 129):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                runtime_module._worker_id({"RETRYWISE_WORKER_ID": value})
        self.assertEqual(26, len(runtime_module._new_ulid()))

    def test_gemini_client_uses_reliable_bounded_default(self) -> None:
        with patch.object(
            runtime_module,
            "load_gemini_api_key_file",
            return_value="test-key-1234567890",
        ):
            configured = runtime_module._gemini_client(
                {"RETRYWISE_GEMINI_API_KEY_FILE": "/managed/gemini.json"}
            )

        self.assertIsNotNone(configured)
        self.assertEqual(8.0, configured.timeout_seconds)  # type: ignore[union-attr]

    def test_composes_every_durable_handler_and_attests_credentials(self) -> None:
        replacements, outbox_worker_class = composition_replacements()
        startup_adapter = replacements.pop("_test_startup_adapter")
        worker = replacements.pop("_test_worker")
        heartbeat_repository = replacements.pop("_test_heartbeat_repository")
        connection_policy = replacements.pop("_test_connection_policy")
        with patch.multiple(runtime_module, **replacements):
            runtime = runtime_module.WorkerRuntime(mapping=mapping())

        startup_adapter.close.assert_called_once_with()  # type: ignore[union-attr]
        connection_policy.validate_dsn.assert_called_once()  # type: ignore[union-attr]
        handler_keys = set(outbox_worker_class.call_args.kwargs["handlers"])
        self.assertEqual(
            {
                runtime_module.PROCESS_NORMALIZED_PROVIDER_EVENT,
                runtime_module.ENRICH_FAILED_PAYMENT_COMMAND_TYPE,
                runtime_module.ASSESS_RECOVERY_CASE_COMMAND_TYPE,
                runtime_module.CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
                runtime_module.CANCEL_PAYMENT_LINK_COMMAND_TYPE,
                runtime_module.MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE,
            },
            handler_keys,
        )
        self.assertIs(worker, runtime._worker)
        self.assertIs(heartbeat_repository, runtime._heartbeat_repository)

    def test_refuses_disabled_effect_mode_and_unready_outbox(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "requires RETRYWISE_EFFECTS_MODE"):
            runtime_module.WorkerRuntime(
                mapping={**mapping(), "RETRYWISE_EFFECTS_MODE": "disabled"}
            )

        replacements, _outbox_worker = composition_replacements(outbox_ready=False)
        for key in tuple(replacements):
            if key.startswith("_test_"):
                replacements.pop(key)
        with (
            patch.multiple(runtime_module, **replacements),
            self.assertRaisesRegex(ConfigurationError, "durable outbox is not ready"),
        ):
            runtime_module.WorkerRuntime(mapping=mapping())

    def test_run_records_success_and_failure_heartbeats(self) -> None:
        runtime = runtime_module.WorkerRuntime.__new__(runtime_module.WorkerRuntime)
        runtime._scheduler = Mock()
        runtime._cancellation_scheduler = Mock()
        runtime._worker = Mock()
        runtime._heartbeat_repository = Mock()
        runtime._heartbeat = Mock()
        stop = Event()
        runtime._worker.poll_once.side_effect = lambda: stop.set() or PollResult(1, 1, 1, 0, 0, 0)

        runtime.run(stop=stop, idle_delay_seconds=0.001)

        runtime._scheduler.schedule_due.assert_called_once_with()
        runtime._cancellation_scheduler.schedule_due.assert_called_once_with()
        self.assertEqual(2, runtime._heartbeat_repository.beat.call_count)

        failing = runtime_module.WorkerRuntime.__new__(runtime_module.WorkerRuntime)
        failing._scheduler = Mock()
        failing._cancellation_scheduler = Mock()
        failing._worker = Mock()
        failing._heartbeat_repository = Mock()
        failing._heartbeat = Mock()
        failed_stop = Event()

        def fail_once() -> PollResult:
            failed_stop.set()
            raise RuntimeError("private detail")

        failing._worker.poll_once.side_effect = fail_once
        failing.run(stop=failed_stop, idle_delay_seconds=0.001)
        self.assertEqual(2, failing._heartbeat_repository.beat.call_count)
        self.assertEqual(
            "worker_loop:RuntimeError",
            failing._heartbeat_repository.beat.call_args.kwargs["last_error_code"],
        )

        with self.assertRaises(TypeError):
            failing.run(stop=object())  # type: ignore[arg-type]

    def test_main_reports_composition_failure_and_runs_composed_worker(self) -> None:
        with patch.object(runtime_module, "WorkerRuntime", side_effect=RuntimeError("secret")):
            self.assertEqual(2, runtime_module.main())

        runtime = Mock()
        with (
            patch.object(runtime_module, "WorkerRuntime", return_value=runtime),
            patch.object(runtime_module.signal, "signal") as install_signal,
        ):
            self.assertEqual(0, runtime_module.main())
        self.assertEqual(2, install_signal.call_count)
        runtime.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
