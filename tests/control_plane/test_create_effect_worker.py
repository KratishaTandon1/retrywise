from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

from retrywise.services.control_plane import assessment_intent as assessment_module
from retrywise.services.control_plane.create_effect_worker import (
    CreateEffectPersistenceError,
    CreateStandardPaymentLinkHandler,
    PostgresCreateEffectRepository,
    _result_audit_facts,
)
from retrywise.services.control_plane.effect_command_codec import (
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
    encode_create_standard_payment_link_command,
)
from retrywise.services.control_plane.executor import ExecutionDisposition, ExecutionResult
from retrywise.services.control_plane.outbox import OutboxJob, RetryMode
from retrywise.services.control_plane.outbox_worker import HandlerDisposition
from retrywise.services.control_plane.postgres_audit import _normalize_facts
from retrywise.services.control_plane.postgres_outbox import ClaimedOutboxCommand
from tests.control_plane.test_assessment_intent import (
    ACTION_ID as VALID_ACTION_ID,
)
from tests.control_plane.test_assessment_intent import (
    MERCHANT_ID,
    OUTBOX_JOB_ID,
    PROVIDER_ACCOUNT_ID,
    candidate_row,
    method_health,
    planner,
    provider_truth,
)
from tests.control_plane.test_assessment_intent import (
    command as assessment_command,
)
from tests.control_plane.test_executor import NOW, leased_job, planning_context
from tests.control_plane.test_executor import command as make_command

ACTION_ID = "action_1"
INSTRUMENT_ID = "instrument_1"


class _Step:
    def __init__(self, marker: str, row: Sequence[object] | None) -> None:
        self.marker = marker
        self.row = row


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.row: Sequence[object] | None = None

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: Mapping[str, object]) -> None:
        if not self.connection.steps:
            raise AssertionError(f"unexpected query: {query}")
        step = self.connection.steps.pop(0)
        if step.marker not in query:
            raise AssertionError(f"expected {step.marker!r}, got {query!r}")
        self.connection.executions.append((query, dict(params)))
        self.row = step.row

    def fetchone(self) -> Sequence[object] | None:
        return self.row


class _Connection:
    def __init__(self, steps: list[_Step]) -> None:
        self.steps = list(steps)
        self.executions: list[tuple[str, dict[str, object]]] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def transaction(self) -> _Connection:
        return self

    def cursor(self) -> _Cursor:
        return _Cursor(self)


class _Connector:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __call__(self) -> _Connection:
        return self.connection


def repository(connection: _Connection) -> PostgresCreateEffectRepository:
    return PostgresCreateEffectRepository(
        connector=_Connector(connection),  # type: ignore[arg-type]
        provider_truth_reader=object(),  # type: ignore[arg-type]
        method_health_reader=object(),  # type: ignore[arg-type]
    )


def authorized_command() -> object:
    snapshot = assessment_module._snapshot_from_row(
        candidate_row(),
        command=assessment_command(),
    )
    outcome = planner().plan(snapshot, provider_truth(), method_health())
    return outcome.command  # type: ignore[union-attr]


class _TruthReader:
    def fetch_fresh_payment_truth(self, _query: object) -> object:
        return provider_truth()


class _HealthReader:
    def fetch_fresh_method_health(self, _query: object) -> object:
        return method_health()


def claim(command: object, **overrides: object) -> ClaimedOutboxCommand:
    values: dict[str, object] = {
        "job_id": OUTBOX_JOB_ID,
        "merchant_id": MERCHANT_ID,
        "aggregate_type": "ACTION",
        "aggregate_id": VALID_ACTION_ID,
        "command_type": CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
        "command_schema_version": CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
        "command_payload": encode_create_standard_payment_link_command(command),  # type: ignore[arg-type]
        "idempotency_key": f"create-standard-payment-link:{command.proposal.action_key}",  # type: ignore[attr-defined]
        "attempt_count": 1,
        "max_attempts": 8,
        "worker_id": "worker-a",
        "lease_token": "lease-a",
        "lease_expires_at": NOW + timedelta(minutes=1),
        "delivery_version": 2,
        "retry_mode": RetryMode.RECONCILE_ONLY,
        "created_at": NOW - timedelta(minutes=1),
        "claimed_at": NOW,
    }
    values.update(overrides)
    return ClaimedOutboxCommand(**values)  # type: ignore[arg-type]


def path_row(
    command: object,
    *,
    action_status: str = "EXECUTING",
    case_state: str = "EXECUTING",
    case_version: int = 4,
    instrument_status: str = "CREATING",
    existing_link: str | None = None,
) -> tuple[object, ...]:
    return (
        ACTION_ID,
        action_status,
        command.proposal.action_key,  # type: ignore[attr-defined]
        command.request.reference_id,  # type: ignore[attr-defined]
        {},
        case_state,
        case_version,
        INSTRUMENT_ID,
        instrument_status,
        command.request.reference_id,  # type: ignore[attr-defined]
        existing_link,
        "UNPAID",
        "ACTIVE",
        False,
        "TEST",
        True,
    )


def execution_result(
    disposition: ExecutionDisposition, *, payment_link: str | None = None
) -> tuple[object, object, ExecutionResult]:
    _gate, command = make_command()
    job = leased_job(command)
    return (
        command,
        job,
        ExecutionResult(
            disposition=disposition,
            job=job,
            effect_decision=command.prior_plan,
            reason_code=f"test_{disposition.value}",
            reference_id=command.request.reference_id,
            payment_link_id=payment_link,
        ),
    )


class CreateEffectRepositoryTests(unittest.TestCase):
    def test_result_audit_facts_are_closed_for_composite_executor_reasons(self) -> None:
        _command, _job, result = execution_result(ExecutionDisposition.SUPPRESSED)
        result = replace(
            result,
            reason_code="effect_gate_denied:APPROVAL_EXPIRED,PROPOSAL_EXPIRED",
        )

        facts = _result_audit_facts(action_id=VALID_ACTION_ID, result=result)

        self.assertEqual("SUPPRESSED", facts["disposition"])
        self.assertEqual(64, len(str(facts["reason_sha256"])))
        self.assertEqual(facts, _normalize_facts(facts))

    def test_loads_fresh_provider_and_detector_truth_into_gate_context(self) -> None:
        command = authorized_command()
        row = (
            VALID_ACTION_ID,
            "QUEUED",
            None,
            "ACTION_QUEUED",
            4,
            NOW - timedelta(minutes=1),
            1,
            0,
            None,
            "ACTIVE",
            False,
            "policy-v1",
            "acc_retrywise_test_1",
            "TEST",
            True,
            7,
            129_900,
            "INR",
            "01ARZ3NDEKTSV4RRFFQ69G5FAY",
            "pay_test_1",
            "order_test_1",
            129_900,
            "INR",
            "upi",
            0,
            None,
            None,
            None,
            None,
            None,
        )
        connection = _Connection([_Step("FROM retrywise.actions AS action", row)])
        active_repository = PostgresCreateEffectRepository(
            connector=_Connector(connection),  # type: ignore[arg-type]
            provider_truth_reader=_TruthReader(),  # type: ignore[arg-type]
            method_health_reader=_HealthReader(),  # type: ignore[arg-type]
        )

        context = active_repository.load_fresh_gate_context(
            proposal=command.proposal,  # type: ignore[attr-defined]
            provider_account_id=PROVIDER_ACCOUNT_ID,
            evaluated_at=NOW,
        )

        self.assertEqual(4, context.aggregate_version)
        self.assertEqual("upi", context.snapshot.payment_method)
        self.assertTrue(context.environment_effects_enabled)
        self.assertEqual([], connection.steps)

        with self.assertRaises(CreateEffectPersistenceError):
            PostgresCreateEffectRepository(
                connector=_Connector(
                    _Connection([_Step("FROM retrywise.actions AS action", row[:-1])])
                ),  # type: ignore[arg-type]
                provider_truth_reader=_TruthReader(),  # type: ignore[arg-type]
                method_health_reader=_HealthReader(),  # type: ignore[arg-type]
            ).load_fresh_gate_context(
                proposal=command.proposal,  # type: ignore[attr-defined]
                provider_account_id=PROVIDER_ACCOUNT_ID,
                evaluated_at=NOW,
            )

    def test_loads_exact_durable_intent_and_sanitizes_malformed_storage(self) -> None:
        _gate, command = make_command()
        metadata = {
            "action_key": command.proposal.action_key,
            "executor_payload_sha256": command.payload_digest,
            "prior_plan_sha256": command.prior_plan.decision_digest,
            "proposal_sha256": command.proposal.proposal_digest,
            "provider_account_id": command.provider_account_id,
            "provider_request_sha256": command.request_digest,
            "recorded_at": NOW.isoformat(),
            "reference_id": command.request.reference_id,
            "schema": "retrywise-durable-action-intent",
            "schema_version": 1,
        }
        connection = _Connection(
            [_Step("FROM retrywise.actions AS action", ("merchant_1", metadata))]
        )

        intent = repository(connection).load_durable_intent(
            action_key=command.proposal.action_key,
            provider_account_id=command.provider_account_id,
        )

        self.assertEqual(command.payload_digest, intent.payload_digest)  # type: ignore[union-attr]
        self.assertEqual([], connection.steps)

        self.assertIsNone(
            repository(
                _Connection([_Step("FROM retrywise.actions AS action", None)])
            ).load_durable_intent(
                action_key=command.proposal.action_key,
                provider_account_id=command.provider_account_id,
            )
        )
        with self.assertRaises(CreateEffectPersistenceError):
            repository(
                _Connection([_Step("FROM retrywise.actions AS action", ("merchant_1", {}))])
            ).load_durable_intent(
                action_key=command.proposal.action_key,
                provider_account_id=command.provider_account_id,
            )

    def test_authorization_is_fenced_and_committed_before_create_or_reconciliation(self) -> None:
        _gate, command = make_command()
        job = leased_job(command)
        context = planning_context()
        queued_path = path_row(
            command,
            action_status="QUEUED",
            case_state="ACTION_QUEUED",
            case_version=context.aggregate_version,
        )
        connection = _Connection(
            [
                _Step("FROM retrywise.outbox_jobs", (True,)),
                _Step("FROM retrywise.actions AS action", queued_path),
                _Step("UPDATE retrywise.recovery_cases", (context.aggregate_version + 1,)),
                _Step("UPDATE retrywise.actions", ("EXECUTING",)),
            ]
        )

        repository(connection).record_effect_authorization(
            job=job,
            command=command,
            decision=command.prior_plan,
            context=context,
            worker_id=job.lease_owner or "",
            reconciliation_only=False,
        )
        fence_query, fence_params = connection.executions[0]
        self.assertIn("JOIN retrywise.actions AS action", fence_query)
        self.assertNotIn("%(action_id)s", fence_query)
        self.assertNotIn("action_id", fence_params)
        self.assertEqual([], connection.steps)

        reconnection = _Connection(
            [
                _Step("FROM retrywise.outbox_jobs", (True,)),
                _Step(
                    "FROM retrywise.actions AS action",
                    path_row(
                        command,
                        action_status="UNCERTAIN",
                        case_state="ACTION_UNCERTAIN",
                        case_version=context.aggregate_version,
                        instrument_status="UNCERTAIN",
                    ),
                ),
                _Step("UPDATE retrywise.actions", ("RECONCILING",)),
            ]
        )
        repository(reconnection).record_effect_authorization(
            job=job,
            command=command,
            decision=command.prior_plan,
            context=context,
            worker_id=job.lease_owner or "",
            reconciliation_only=True,
        )
        self.assertEqual([], reconnection.steps)

    def test_persists_created_uncertain_requeued_failed_and_suppressed_results(self) -> None:
        command, job, result = execution_result(
            ExecutionDisposition.CREATED, payment_link="plink_created"
        )
        created = _Connection(
            [
                _Step("FROM retrywise.outbox_jobs", (True,)),
                _Step("FROM retrywise.actions AS action", path_row(command)),
                _Step("UPDATE retrywise.recovery_instruments", ("ISSUED",)),
                _Step("SET status = 'ACTIVE'", ("ACTIVE",)),
                _Step("UPDATE retrywise.actions", ("SUCCEEDED",)),
                _Step("SET state = 'ACTIVE'", (5,)),
            ]
        )
        repository(created).persist_result(job=job, command=command, result=result)
        result_fence_query, result_fence_params = created.executions[0]
        self.assertIn("JOIN retrywise.actions AS action", result_fence_query)
        self.assertNotIn("%(action_id)s", result_fence_query)
        self.assertNotIn("action_id", result_fence_params)
        self.assertEqual([], created.steps)

        scenarios = (
            (
                ExecutionDisposition.REQUERY_REQUIRED,
                path_row(command),
                [
                    _Step("UPDATE retrywise.actions", ("UNCERTAIN",)),
                    _Step("UPDATE retrywise.recovery_instruments", ("UNCERTAIN",)),
                    _Step("UPDATE retrywise.recovery_cases", (5,)),
                ],
            ),
            (
                ExecutionDisposition.REQUEUED,
                path_row(command),
                [
                    _Step("UPDATE retrywise.actions", ("FAILED_RETRYABLE",)),
                    _Step("UPDATE retrywise.actions", ("QUEUED",)),
                    _Step("UPDATE retrywise.recovery_cases", (5,)),
                    _Step("UPDATE retrywise.recovery_cases", (6,)),
                ],
            ),
            (
                ExecutionDisposition.REQUEUED,
                path_row(
                    command,
                    action_status="RECONCILING",
                    case_state="ACTION_UNCERTAIN",
                    instrument_status="UNCERTAIN",
                ),
                [
                    _Step("UPDATE retrywise.actions", ("QUEUED",)),
                    _Step("UPDATE retrywise.recovery_cases", (5,)),
                    _Step("UPDATE retrywise.recovery_instruments", ("CREATING",)),
                ],
            ),
            (
                ExecutionDisposition.ESCALATED,
                path_row(command),
                [
                    _Step("UPDATE retrywise.actions", ("FAILED_SAFE",)),
                    _Step("UPDATE retrywise.recovery_instruments", ("FAILED",)),
                    _Step("UPDATE retrywise.recovery_cases", (5,)),
                ],
            ),
            (
                ExecutionDisposition.SUPPRESSED,
                path_row(
                    command,
                    action_status="QUEUED",
                    case_state="ACTION_QUEUED",
                ),
                [
                    _Step("UPDATE retrywise.actions", ("CANCELLED",)),
                    _Step("UPDATE retrywise.recovery_instruments", ("FAILED",)),
                    _Step("UPDATE retrywise.recovery_cases", (5,)),
                ],
            ),
        )
        for disposition, row, updates in scenarios:
            with self.subTest(disposition=disposition, action_status=row[1]):
                active_command, active_job, active_result = execution_result(disposition)
                connection = _Connection(
                    [
                        _Step("FROM retrywise.outbox_jobs", (True,)),
                        _Step("FROM retrywise.actions AS action", row),
                        *updates,
                    ]
                )
                repository(connection).persist_result(
                    job=active_job,
                    command=active_command,
                    result=active_result,
                )
                self.assertEqual([], connection.steps)

    def test_binding_change_and_missing_provider_link_fail_closed(self) -> None:
        command, job, result = execution_result(ExecutionDisposition.CREATED)
        connection = _Connection(
            [
                _Step("FROM retrywise.outbox_jobs", (True,)),
                _Step("FROM retrywise.actions AS action", path_row(command)),
            ]
        )
        with self.assertRaises(CreateEffectPersistenceError):
            repository(connection).persist_result(job=job, command=command, result=result)


class CreateEffectHandlerTests(unittest.TestCase):
    def test_rejects_invalid_payload_and_outbox_binding(self) -> None:
        command = authorized_command()
        handler = CreateStandardPaymentLinkHandler(
            gate=planner().gate,
            repository=Mock(),
            adapter_factory=Mock(),
            clock=lambda: NOW,
        )
        invalid = handler(claim(command, command_payload={"invalid": True}))
        mismatched = handler(claim(command, aggregate_type="APPROVAL"))
        self.assertEqual(HandlerDisposition.DEAD_LETTER, invalid.disposition)
        self.assertEqual(HandlerDisposition.DEAD_LETTER, mismatched.disposition)

    def test_maps_executor_outcomes_and_always_closes_provider(self) -> None:
        command = authorized_command()
        claimed = claim(command)
        job = OutboxJob.create(
            job_id=OUTBOX_JOB_ID,
            action_key=command.proposal.action_key,  # type: ignore[attr-defined]
            payload_digest=command.payload_digest,  # type: ignore[attr-defined]
            now=NOW - timedelta(minutes=1),
            max_attempts=8,
        ).claim(
            worker_id="worker-a",
            now=NOW,
            lease_duration=timedelta(minutes=1),
            expected_version=0,
        )
        provider = Mock()
        repository_mock = Mock()
        handler = CreateStandardPaymentLinkHandler(
            gate=planner().gate,
            repository=repository_mock,
            adapter_factory=lambda *_args: provider,
            clock=lambda: NOW,
        )
        outcomes = (
            (ExecutionDisposition.CREATED, "plink_created", HandlerDisposition.SUCCEEDED),
            (ExecutionDisposition.SUPPRESSED, None, HandlerDisposition.SUCCEEDED),
            (ExecutionDisposition.REQUERY_REQUIRED, None, HandlerDisposition.RETRY),
            (ExecutionDisposition.ESCALATED, None, HandlerDisposition.DEAD_LETTER),
        )
        for disposition, link_id, expected in outcomes:
            with self.subTest(disposition=disposition):
                result = SimpleNamespace(
                    disposition=disposition,
                    payment_link_id=link_id,
                    effect_decision=command.prior_plan,  # type: ignore[attr-defined]
                    reason_code=f"test_{disposition.value}",
                    job=replace(job, retry_mode=RetryMode.RECONCILE_ONLY),
                )
                executor = Mock()
                executor.execute.return_value = result
                with patch(
                    "retrywise.services.control_plane.create_effect_worker.CreatePaymentLinkExecutor",
                    return_value=executor,
                ):
                    handled = handler(claimed)
                self.assertEqual(expected, handled.disposition)
        self.assertEqual(4, provider.close.call_count)

    def test_persistence_and_unexpected_errors_retry_reconciliation_only(self) -> None:
        command = authorized_command()
        for error, reason in (
            (CreateEffectPersistenceError("db"), "create_effect_persistence_unavailable"),
            (RuntimeError("provider"), "create_effect_execution_unavailable"),
        ):
            with self.subTest(error=type(error).__name__):
                provider = Mock()
                with patch(
                    "retrywise.services.control_plane.create_effect_worker.CreatePaymentLinkExecutor",
                    side_effect=error,
                ):
                    handled = CreateStandardPaymentLinkHandler(
                        gate=planner().gate,
                        repository=Mock(),
                        adapter_factory=lambda *_args, provider=provider: provider,
                        clock=lambda: NOW,
                    )(claim(command))
                self.assertEqual(HandlerDisposition.RETRY, handled.disposition)
                self.assertEqual(reason, handled.reason)
                provider.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
