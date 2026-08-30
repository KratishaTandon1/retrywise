from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

from retrywise.packages.domain import DeterministicGate
from retrywise.packages.razorpay import make_recovery_reference_id
from retrywise.services.control_plane.cancellation import (
    CancellationDisposition,
    CancellationExecutionResult,
    CancelPaymentLinkCommand,
    DurableInstrumentStatus,
    ProviderPaymentLinkStatus,
)
from retrywise.services.control_plane.cancellation_command_codec import (
    CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    CANCEL_PAYMENT_LINK_COMMAND_TYPE,
    encode_cancel_payment_link_command,
)
from retrywise.services.control_plane.cancellation_worker import (
    CancellationPersistenceError,
    CancelPaymentLinkHandler,
    PostgresCancellationRepository,
    PostgresCancellationScheduler,
)
from retrywise.services.control_plane.outbox import RetryMode
from retrywise.services.control_plane.outbox_worker import HandlerDisposition
from retrywise.services.control_plane.postgres_outbox import ClaimedOutboxCommand
from tests.control_plane.test_cancellation import (
    NOW,
    context,
    leased_job,
    policy,
)
from tests.control_plane.test_cancellation import (
    command as make_command,
)

IDS = (
    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "01ARZ3NDEKTSV4RRFFQ69G5FAW",
    "01ARZ3NDEKTSV4RRFFQ69G5FAX",
    "01ARZ3NDEKTSV4RRFFQ69G5FAY",
    "01ARZ3NDEKTSV4RRFFQ69G5FAZ",
    "01ARZ3NDEKTSV4RRFFQ69G5FB0",
    "01ARZ3NDEKTSV4RRFFQ69G5FB1",
    "01ARZ3NDEKTSV4RRFFQ69G5FB2",
)


class _Step:
    def __init__(
        self,
        marker: str,
        row: Sequence[object] | None = None,
        *,
        rows: Sequence[Sequence[object]] | None = None,
    ) -> None:
        self.marker = marker
        self.row = row
        self.rows = rows


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.step: _Step | None = None

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
        self.step = step

    def fetchone(self) -> Sequence[object] | None:
        return None if self.step is None else self.step.row

    def fetchall(self) -> Sequence[Sequence[object]]:
        if self.step is None or self.step.rows is None:
            return ()
        return self.step.rows


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


def repository(connection: _Connection) -> PostgresCancellationRepository:
    return PostgresCancellationRepository(
        connector=_Connector(connection),  # type: ignore[arg-type]
    )


def claim(*, payload: object | None = None, **overrides: object) -> ClaimedOutboxCommand:
    command = worker_command()
    values: dict[str, object] = {
        "job_id": "01ARZ3NDEKTSV4RRFFQ69G5FB3",
        "merchant_id": command.target.merchant_id,
        "aggregate_type": "ACTION",
        "aggregate_id": command.target.action_id,
        "command_type": CANCEL_PAYMENT_LINK_COMMAND_TYPE,
        "command_schema_version": CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
        "command_payload": payload or encode_cancel_payment_link_command(command),
        "idempotency_key": f"cancel-payment-link:{command.proposal.action_key}",
        "attempt_count": 1,
        "max_attempts": 8,
        "worker_id": "worker_1",
        "lease_token": "lease_1",
        "lease_expires_at": NOW + timedelta(minutes=1),
        "delivery_version": 2,
        "retry_mode": RetryMode.RECONCILE_ONLY,
        "created_at": NOW - timedelta(minutes=2),
        "claimed_at": NOW,
    }
    values.update(overrides)
    return ClaimedOutboxCommand(**values)  # type: ignore[arg-type]


def worker_command() -> CancelPaymentLinkCommand:
    gate, original = make_command()
    merchant_id, case_id, account_id, action_id, instrument_id = IDS[:5]
    proposal = replace(
        original.proposal,
        merchant_id=merchant_id,
        case_id=case_id,
    )
    plan = gate.evaluate_policy(
        proposal,
        replace(context(), merchant_id=merchant_id, case_id=case_id),
    )
    target = replace(
        original.target,
        merchant_id=merchant_id,
        case_id=case_id,
        provider_account_id=account_id,
        action_id=action_id,
        action_key=proposal.action_key,
        instrument_id=instrument_id,
        reference_id=make_recovery_reference_id(
            case_id,
            provider_account_id=account_id,
        ),
    )
    return CancelPaymentLinkCommand(proposal=proposal, prior_plan=plan, target=target)


def execution_result(
    disposition: CancellationDisposition,
    *,
    action_status: ProviderPaymentLinkStatus | None = None,
    cancel_attempted: bool = False,
) -> tuple[object, object, CancellationExecutionResult]:
    _gate, command = make_command()
    job = leased_job(command)
    return (
        command,
        job,
        CancellationExecutionResult(
            disposition=disposition,
            job=job,
            effect_decision=command.prior_plan,
            reason_code=f"test_{disposition.value}",
            payment_link_id=command.target.payment_link_id,
            target_digest=command.target_digest,
            provider_status=action_status,
            cancel_attempted=cancel_attempted,
        ),
    )


class CancellationSchedulerTests(unittest.TestCase):
    def test_schedules_terminal_collectible_link_as_one_atomic_command(self) -> None:
        case_id, merchant_id, order_id, account_id, instrument_id = IDS[:5]
        action_id, decision_id, outbox_id = IDS[5:8]
        row = (
            case_id,
            merchant_id,
            order_id,
            account_id,
            "SUPPRESSED_PAID",
            4,
            1,
            instrument_id,
            "ACTIVE",
            "plink_ExjpAUN3gVHrPJ",
            make_recovery_reference_id(case_id, provider_account_id=account_id),
            129_900,
            "INR",
            "ACTIVE",
            False,
            "TEST",
            True,
            "PAID",
            "upi",
            datetime(2026, 8, 29, 12, tzinfo=UTC),
        )
        connection = _Connection(
            [
                _Step("FOR UPDATE OF recovery_case, instrument SKIP LOCKED", rows=[row]),
                _Step("INSERT INTO retrywise.decisions", (decision_id,)),
                _Step("INSERT INTO retrywise.actions", (action_id,)),
                _Step("SET status = 'QUEUED'", ("QUEUED",)),
                _Step("SET status = 'CANCEL_PENDING'", ("CANCEL_PENDING",)),
                _Step("INSERT INTO retrywise.outbox_jobs", (outbox_id,)),
            ]
        )
        ids = iter((action_id, decision_id, outbox_id))
        scheduler = PostgresCancellationScheduler(
            gate=DeterministicGate(policy()),
            connector=_Connector(connection),  # type: ignore[arg-type]
            id_factory=lambda: next(ids),
        )

        result = scheduler.schedule_due()

        self.assertEqual((1, 1), (result.selected, result.scheduled))
        self.assertEqual([], connection.steps)
        command_payload = connection.executions[-1][1]["command_payload"]
        self.assertNotIn("secret", str(command_payload).lower())

    def test_rejects_invalid_rows_and_closed_gate(self) -> None:
        scheduler = PostgresCancellationScheduler(
            gate=DeterministicGate(policy()),
            connector=_Connector(_Connection([])),  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(
            CancellationPersistenceError, "cancellation_schedule_row_unsafe"
        ):
            scheduler._schedule(_Cursor(_Connection([])), ("unsafe",))

        with self.assertRaises(ValueError):
            PostgresCancellationScheduler(
                gate=DeterministicGate(policy()),
                connector=_Connector(_Connection([])),  # type: ignore[arg-type]
                batch_size=0,
            )


class CancellationRepositoryTests(unittest.TestCase):
    def test_loads_binding_and_fresh_context_from_minimized_rows(self) -> None:
        command = worker_command()
        target = command.target
        metadata = {
            "recorded_at": NOW.isoformat(),
            "schema": "retrywise-durable-cancellation-binding",
            "schema_version": 1,
            "target_sha256": target.target_digest,
        }
        connection = _Connection(
            [
                _Step(
                    "FROM retrywise.actions AS action",
                    (
                        metadata,
                        NOW - timedelta(hours=1),
                        "QUEUED",
                        "ACTIVE",
                        target.reference_id,
                        target.amount_minor,
                        target.currency,
                        target.payment_link_id,
                    ),
                ),
                _Step(
                    "FROM retrywise.recovery_cases AS recovery_case",
                    (
                        "ACTIVE",
                        5,
                        129_900,
                        "INR",
                        NOW + timedelta(minutes=10),
                        1,
                        0,
                        "ACTIVE",
                        False,
                        "TEST",
                        True,
                        "UNPAID",
                        "upi",
                        1,
                    ),
                ),
            ]
        )
        repo = repository(connection)
        values = {
            "merchant_id": target.merchant_id,
            "case_id": target.case_id,
            "action_id": target.action_id,
            "action_key": target.action_key,
            "instrument_id": target.instrument_id,
            "provider_account_id": target.provider_account_id,
            "payment_link_id": target.payment_link_id,
            "target_digest": target.target_digest,
        }

        binding = repo.load_cancellation_binding(**values)
        fresh = repo.load_fresh_gate_context(
            proposal=command.proposal,
            provider_account_id=target.provider_account_id,
            evaluated_at=NOW,
        )

        self.assertEqual(DurableInstrumentStatus.ACTIVE, binding.instrument_status)  # type: ignore[union-attr]
        self.assertTrue(fresh.environment_effects_enabled)
        self.assertEqual(5, fresh.aggregate_version)
        self.assertEqual([], connection.steps)

        self.assertIsNone(
            repository(
                _Connection([_Step("FROM retrywise.actions AS action", None)])
            ).load_cancellation_binding(**values)
        )
        with self.assertRaises(CancellationPersistenceError):
            repository(
                _Connection([_Step("FROM retrywise.actions AS action", ({}, NOW))])
            ).load_cancellation_binding(**values)

    def test_authorization_and_every_result_class_are_fenced(self) -> None:
        command = worker_command()
        job = leased_job(command)
        connection = _Connection(
            [
                _Step("FROM retrywise.outbox_jobs", (True,)),
                _Step("FROM retrywise.actions AS action", ("QUEUED", "CANCEL_PENDING")),
                _Step("SET status = 'EXECUTING'", ("EXECUTING",)),
            ]
        )
        repository(connection).record_cancellation_authorization(
            job=job,
            command=command,
            decision=command.prior_plan,
            context=context(),
            worker_id=job.lease_owner or "",
        )
        self.assertEqual([], connection.steps)

        scenarios = (
            (
                CancellationDisposition.CANCELLED,
                "EXECUTING",
                "CANCEL_PENDING",
                [
                    _Step("SET status = %(new_status)s", ("SUCCEEDED",)),
                    _Step("UPDATE retrywise.recovery_instruments", ("CANCELLED",)),
                ],
                False,
            ),
            (
                CancellationDisposition.EXPIRED,
                "QUEUED",
                "ACTIVE",
                [
                    _Step("SET status = 'CANCELLED'", ("CANCELLED",)),
                    _Step("UPDATE retrywise.recovery_instruments", ("EXPIRED",)),
                ],
                False,
            ),
            (
                CancellationDisposition.ALREADY_CANCELLED,
                "UNCERTAIN",
                "CANCEL_PENDING",
                [
                    _Step("SET status = 'RECONCILING'", ("RECONCILING",)),
                    _Step("SET status = %(new_status)s", ("RECONCILED",)),
                    _Step("UPDATE retrywise.recovery_instruments", ("CANCELLED",)),
                ],
                False,
            ),
            (
                CancellationDisposition.RECONCILE_REQUIRED,
                "EXECUTING",
                "CANCEL_PENDING",
                [_Step("SET status = 'UNCERTAIN'", ("UNCERTAIN",))],
                True,
            ),
            (
                CancellationDisposition.RECONCILE_REQUIRED,
                "UNCERTAIN",
                "CANCEL_PENDING",
                [
                    _Step("SET status = 'RECONCILING'", ("RECONCILING",)),
                    _Step("SET status = 'QUEUED'", ("QUEUED",)),
                ],
                False,
            ),
            (
                CancellationDisposition.REVIEW_REQUIRED,
                "EXECUTING",
                "CANCEL_PENDING",
                [
                    _Step("SET status = CASE", ("FAILED_SAFE",)),
                    _Step("SET state = 'DUPLICATE_REVIEW'", ("DUPLICATE_REVIEW",)),
                ],
                False,
            ),
            (
                CancellationDisposition.BLOCKED,
                "EXECUTING",
                "CANCEL_PENDING",
                [
                    _Step("SET status = CASE", ("FAILED_SAFE",)),
                    _Step("SET status = 'ACTIVE'", ("ACTIVE",)),
                ],
                False,
            ),
        )
        for disposition, action_status, instrument_status, mutations, attempted in scenarios:
            with self.subTest(disposition=disposition, action_status=action_status):
                steps = [
                    _Step("FROM retrywise.outbox_jobs", (True,)),
                    _Step("FROM retrywise.actions AS action", (action_status, instrument_status)),
                    *mutations,
                ]
                scenario_connection = _Connection(steps)
                _command, _job_value, result = execution_result(
                    disposition,
                    action_status=ProviderPaymentLinkStatus.CREATED,
                    cancel_attempted=attempted,
                )
                repository(scenario_connection).persist_result(
                    job=job,
                    command=command,
                    result=result,
                    completed_at=NOW,
                )
                self.assertEqual([], scenario_connection.steps)


class CancellationHandlerTests(unittest.TestCase):
    def test_rejects_invalid_envelope_and_cross_binding(self) -> None:
        handler = CancelPaymentLinkHandler(
            gate=DeterministicGate(policy()),
            repository=Mock(),
            adapter_factory=Mock(),
            clock=lambda: NOW,
        )
        invalid = handler(claim(payload={"not": "a command"}))
        mismatched = handler(claim(aggregate_id="another_action"))
        self.assertEqual(HandlerDisposition.DEAD_LETTER, invalid.disposition)
        self.assertEqual(HandlerDisposition.DEAD_LETTER, mismatched.disposition)

    def test_maps_success_retry_deadletter_and_closes_adapter(self) -> None:
        _gate, command = make_command()
        adapter = Mock()
        repository_mock = Mock()
        handler = CancelPaymentLinkHandler(
            gate=DeterministicGate(policy()),
            repository=repository_mock,
            adapter_factory=lambda *_args: adapter,
            clock=lambda: NOW,
        )
        outcomes = (
            (CancellationDisposition.CANCELLED, HandlerDisposition.SUCCEEDED),
            (CancellationDisposition.RECONCILE_REQUIRED, HandlerDisposition.RETRY),
            (CancellationDisposition.REVIEW_REQUIRED, HandlerDisposition.DEAD_LETTER),
        )
        for disposition, expected in outcomes:
            with self.subTest(disposition=disposition):
                job = leased_job(command)
                result = CancellationExecutionResult(
                    disposition=disposition,
                    job=replace(job, retry_mode=RetryMode.RECONCILE_ONLY),
                    effect_decision=command.prior_plan,
                    reason_code=f"test_{disposition.value}",
                    payment_link_id=command.target.payment_link_id,
                    target_digest=command.target_digest,
                    provider_status=ProviderPaymentLinkStatus.CREATED,
                )
                executor = Mock()
                executor.execute.return_value = result
                with patch(
                    "retrywise.services.control_plane.cancellation_worker.CancelPaymentLinkExecutor",
                    return_value=executor,
                ):
                    handled = handler(claim())
                self.assertEqual(expected, handled.disposition)
        self.assertEqual(3, adapter.close.call_count)

    def test_persistence_and_unexpected_failures_retry_reconciliation_only(self) -> None:
        for error, reason in (
            (CancellationPersistenceError("db"), "cancellation_persistence_unavailable"),
            (RuntimeError("provider"), "cancellation_execution_unavailable"),
        ):
            with self.subTest(error=type(error).__name__):
                adapter = Mock()
                with patch(
                    "retrywise.services.control_plane.cancellation_worker.CancelPaymentLinkExecutor",
                    side_effect=error,
                ):
                    handled = CancelPaymentLinkHandler(
                        gate=DeterministicGate(policy()),
                        repository=Mock(),
                        adapter_factory=lambda *_args, adapter=adapter: adapter,
                        clock=lambda: NOW,
                    )(claim())
                self.assertEqual(HandlerDisposition.RETRY, handled.disposition)
                self.assertEqual(reason, handled.reason)
                adapter.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
