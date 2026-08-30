from __future__ import annotations

import unittest
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from retrywise.services.control_plane.outbox import BackoffPolicy, RetryMode
from retrywise.services.control_plane.outbox_worker import (
    HandlerDisposition,
    HandlerResult,
    OutboxWorker,
    PollResult,
)
from retrywise.services.control_plane.postgres_outbox import (
    ClaimedOutboxCommand,
    OutboxClaimBatch,
    OutboxFenceLost,
    PostgresOutboxRepository,
)

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"


RowFactory = Callable[[Mapping[str, object]], list[Sequence[object]]]


@dataclass(frozen=True)
class _Step:
    marker: str
    rows: RowFactory = lambda _params: []


class _FakeCursor:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection
        self._rows: list[Sequence[object]] = []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: Mapping[str, object]) -> None:
        if not self._connection.steps:
            raise AssertionError(f"unexpected query: {query}")
        step = self._connection.steps.pop(0)
        if step.marker not in query:
            raise AssertionError(f"expected query containing {step.marker!r}, got {query!r}")
        copied_params = dict(params)
        self._connection.executions.append((query, copied_params))
        self._rows = step.rows(copied_params)

    def fetchone(self) -> Sequence[object] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> Sequence[Sequence[object]]:
        return list(self._rows)


class _FakeTransaction:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def __enter__(self) -> object:
        self._connection.transactions_started += 1
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: object | None,
    ) -> None:
        if exc_type is None:
            self._connection.transactions_committed += 1
        else:
            self._connection.transactions_rolled_back += 1
        return None


class _FakeConnection:
    def __init__(self, steps: list[_Step]) -> None:
        self.steps = list(steps)
        self.executions: list[tuple[str, dict[str, object]]] = []
        self.transactions_started = 0
        self.transactions_committed = 0
        self.transactions_rolled_back = 0

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)


class _FakeConnector:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection
        self.calls = 0

    def __call__(self) -> _FakeConnection:
        self.calls += 1
        return self.connection


def _claimed_row(
    params: Mapping[str, object],
    *,
    status: str = "IN_PROGRESS",
    job_id: str = JOB_ID,
) -> Sequence[object]:
    version = 4
    if status == "IN_PROGRESS":
        worker_id = params["worker_id"]
        lease_token = f"{params['lease_nonce']}:{job_id}:{version}"
        lease_expires_at = NOW + params["lease_duration"]  # type: ignore[operator]
    else:
        worker_id = None
        lease_token = None
        lease_expires_at = None
    return (
        status,
        job_id,
        MERCHANT_ID,
        "RECOVERY_ACTION",
        "action_123",
        "CREATE_STANDARD_PAYMENT_LINK",
        1,
        {"action_key": "action_123", "schema_version": 1},
        "create-payment-link:action_123",
        2,
        4,
        worker_id,
        lease_token,
        lease_expires_at,
        version,
        "RECONCILE_ONLY",
        NOW - timedelta(hours=1),
        NOW,
    )


def _command(
    *,
    command_type: str = "CREATE_STANDARD_PAYMENT_LINK",
    attempt_count: int = 2,
) -> ClaimedOutboxCommand:
    return ClaimedOutboxCommand(
        job_id=JOB_ID,
        merchant_id=MERCHANT_ID,
        aggregate_type="RECOVERY_ACTION",
        aggregate_id="action_123",
        command_type=command_type,
        command_schema_version=1,
        command_payload={"schema_version": 1},
        idempotency_key="create-payment-link:action_123",
        attempt_count=attempt_count,
        max_attempts=4,
        worker_id="worker-a",
        lease_token="lease-token-4",
        lease_expires_at=NOW + timedelta(seconds=30),
        delivery_version=4,
        retry_mode=RetryMode.RECONCILE_ONLY,
        created_at=NOW - timedelta(hours=1),
        claimed_at=NOW,
    )


class PostgresOutboxRepositoryTests(unittest.TestCase):
    def _repository(
        self, connection: _FakeConnection
    ) -> tuple[PostgresOutboxRepository, _FakeConnector]:
        connector = _FakeConnector(connection)
        repository = PostgresOutboxRepository(
            connector=connector,
            backoff=BackoffPolicy(
                base_delay=timedelta(seconds=2),
                maximum_delay=timedelta(minutes=1),
            ),
            token_factory=lambda: "nonce-a",
        )
        return repository, connector

    def test_claim_is_bounded_skip_locked_and_closes_exhausted_stale_rows(self) -> None:
        second_job_id = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        connection = _FakeConnection(
            [
                _Step(
                    "FOR UPDATE OF j SKIP LOCKED",
                    lambda params: [
                        _claimed_row(params),
                        _claimed_row(params, status="DEAD_LETTER", job_id=second_job_id),
                    ],
                )
            ]
        )
        repository, connector = self._repository(connection)

        batch = repository.claim_batch(
            worker_id="worker-a",
            batch_size=2,
            lease_duration=timedelta(seconds=30),
        )

        self.assertEqual(2, batch.selected_count)
        self.assertEqual(1, batch.expired_dead_lettered)
        self.assertEqual(1, len(batch.commands))
        command = batch.commands[0]
        self.assertEqual("worker-a", command.worker_id)
        self.assertEqual("nonce-a:" + JOB_ID + ":4", command.lease_token)
        self.assertEqual(RetryMode.RECONCILE_ONLY, command.retry_mode)
        self.assertEqual(4, command.delivery_version)
        self.assertEqual(2, command.attempt_count)
        self.assertEqual({"action_key": "action_123", "schema_version": 1}, command.command_payload)

        query, params = connection.executions[0]
        self.assertIn("LIMIT %(batch_size)s", query)
        self.assertIn("delivery_version = j.delivery_version + 1", query)
        self.assertIn("j.lease_expires_at <= statement.now", query)
        self.assertIn("SELECT clock_timestamp() AS now", query)
        self.assertEqual(2, params["batch_size"])
        self.assertEqual(timedelta(seconds=30), params["lease_duration"])
        self.assertNotIn("now", params)
        self.assertEqual(1, connector.calls)
        self.assertEqual(1, connection.transactions_committed)

    def test_claim_rejects_unbounded_or_excessive_leases_before_connecting(self) -> None:
        connection = _FakeConnection([])
        repository, connector = self._repository(connection)

        for batch_size in (0, 101, True):
            with self.subTest(batch_size=batch_size), self.assertRaises(ValueError):
                repository.claim_batch(worker_id="worker-a", batch_size=batch_size)
        with self.assertRaises(ValueError):
            repository.claim_batch(
                worker_id="worker-a",
                lease_duration=timedelta(minutes=16),
            )
        self.assertEqual(0, connector.calls)

    def test_completion_compare_and_swaps_every_fence_dimension(self) -> None:
        connection = _FakeConnection([_Step("SET status = 'SUCCEEDED'", lambda _params: [(5,)])])
        repository, _connector = self._repository(connection)

        version = repository.complete(_command(), completion_reference="plink_test_1")

        self.assertEqual(5, version)
        query, params = connection.executions[0]
        self.assertIn("AND lease_expires_at > statement.now", query)
        self.assertIn("SELECT clock_timestamp() AS now", query)
        self.assertIn("AND delivery_version = %(expected_version)s", query)
        self.assertIn("AND lease_owner = %(worker_id)s", query)
        self.assertIn("AND lease_token = %(lease_token)s", query)
        self.assertEqual(4, params["expected_version"])
        self.assertEqual("lease-token-4", params["lease_token"])
        self.assertEqual("worker-a", params["worker_id"])
        self.assertEqual("plink_test_1", params["completion_reference"])

    def test_missing_settlement_row_is_reported_as_a_lost_fence(self) -> None:
        connection = _FakeConnection([_Step("SET status = 'SUCCEEDED'")])
        repository, _connector = self._repository(connection)

        with self.assertRaisesRegex(OutboxFenceLost, "lost its fenced lease"):
            repository.complete(_command(), completion_reference="plink_test_1")

        self.assertEqual(0, connection.transactions_committed)
        self.assertEqual(1, connection.transactions_rolled_back)

    def test_retry_uses_attempt_based_backoff_and_explicit_safety_mode(self) -> None:
        connection = _FakeConnection(
            [_Step("SET status = 'RETRY_SCHEDULED'", lambda _params: [(5,)])]
        )
        repository, _connector = self._repository(connection)

        version = repository.retry(
            _command(),
            reason="provider_certain_failure",
            retry_mode=RetryMode.RETRY_SAME_EFFECT,
        )

        self.assertEqual(5, version)
        _query, params = connection.executions[0]
        self.assertEqual(timedelta(seconds=4), params["retry_delay"])
        self.assertEqual("RETRY_SAME_EFFECT", params["retry_mode"])
        self.assertEqual("provider_certain_failure", params["reason"])

    def test_retry_of_final_attempt_dead_letters_instead_of_rescheduling(self) -> None:
        connection = _FakeConnection([_Step("SET status = 'DEAD_LETTER'", lambda _params: [(5,)])])
        repository, _connector = self._repository(connection)

        repository.retry(_command(attempt_count=4), reason="x" * 500)

        query, params = connection.executions[0]
        self.assertNotIn("RETRY_SCHEDULED", query)
        self.assertEqual(500, len(str(params["reason"])))
        self.assertTrue(str(params["reason"]).startswith("max_attempts_exhausted:"))

    def test_readiness_requires_writable_fenced_schema_and_trigger(self) -> None:
        for ready in (True, False):
            with self.subTest(ready=ready):
                connection = _FakeConnection(
                    [
                        _Step(
                            "current_setting('transaction_read_only')",
                            lambda _params, value=ready: [(value,)],
                        )
                    ]
                )
                repository, _connector = self._repository(connection)
                self.assertIs(ready, repository.check_ready())
                self.assertTrue(repository.durable)

    def test_tls_cannot_be_claimed_for_an_unverifiable_injected_connector(self) -> None:
        with self.assertRaisesRegex(ValueError, "policy is verifiable"):
            PostgresOutboxRepository(
                connector=_FakeConnector(_FakeConnection([])),
                require_tls=True,
            )


class _WorkerRepository:
    def __init__(self, batches: list[OutboxClaimBatch]) -> None:
        self.batches = list(batches)
        self.completed: list[tuple[ClaimedOutboxCommand, str]] = []
        self.retried: list[tuple[ClaimedOutboxCommand, str, RetryMode]] = []
        self.dead: list[tuple[ClaimedOutboxCommand, str]] = []
        self.claim_arguments: list[tuple[str, int, timedelta]] = []
        self.lose_complete_fence = False

    def claim_batch(
        self,
        *,
        worker_id: str,
        batch_size: int,
        lease_duration: timedelta,
    ) -> OutboxClaimBatch:
        self.claim_arguments.append((worker_id, batch_size, lease_duration))
        return self.batches.pop(0)

    def complete(self, command: ClaimedOutboxCommand, *, completion_reference: str) -> int:
        if self.lose_complete_fence:
            raise OutboxFenceLost("simulated lost fence")
        self.completed.append((command, completion_reference))
        return command.delivery_version + 1

    def retry(
        self,
        command: ClaimedOutboxCommand,
        *,
        reason: str,
        retry_mode: RetryMode,
    ) -> int:
        self.retried.append((command, reason, retry_mode))
        return command.delivery_version + 1

    def dead_letter(self, command: ClaimedOutboxCommand, *, reason: str) -> int:
        self.dead.append((command, reason))
        return command.delivery_version + 1


class OutboxWorkerTests(unittest.TestCase):
    def test_poll_once_dispatches_registered_handlers_and_fails_closed(self) -> None:
        success = _command(command_type="SUCCESS")
        throws = _command(command_type="THROWS")
        invalid = _command(command_type="INVALID")
        unknown = _command(command_type="UNKNOWN")
        batch = OutboxClaimBatch(5, (success, throws, invalid, unknown), 1)
        repository = _WorkerRepository([batch])

        def throwing_handler(_command: ClaimedOutboxCommand) -> HandlerResult:
            raise TimeoutError("detail must not be persisted")

        worker = OutboxWorker(
            repository=repository,
            worker_id="worker-a",
            handlers={
                "SUCCESS": lambda _command: HandlerResult.succeeded("processed:event-1"),
                "THROWS": throwing_handler,
                "INVALID": lambda _command: None,  # type: ignore[dict-item]
            },
            batch_size=4,
        )

        result = worker.poll_once()

        self.assertEqual(5, result.selected)
        self.assertEqual(4, result.claimed)
        self.assertEqual(1, result.succeeded)
        self.assertEqual(1, result.retried)
        self.assertEqual(3, result.dead_lettered)
        self.assertEqual(0, result.fence_lost)
        self.assertEqual("processed:event-1", repository.completed[0][1])
        self.assertEqual("handler_exception:TimeoutError", repository.retried[0][1])
        self.assertEqual(RetryMode.RECONCILE_ONLY, repository.retried[0][2])
        self.assertEqual(
            ["invalid_handler_result", "unregistered_command_type:UNKNOWN"],
            [reason for _command_value, reason in repository.dead],
        )
        self.assertEqual(
            ("worker-a", 4, timedelta(seconds=30)),
            repository.claim_arguments[0],
        )

    def test_poll_reports_lost_fence_without_acknowledging_success(self) -> None:
        command = _command(command_type="SUCCESS")
        repository = _WorkerRepository([OutboxClaimBatch(1, (command,), 0)])
        repository.lose_complete_fence = True
        worker = OutboxWorker(
            repository=repository,
            worker_id="worker-a",
            handlers={"SUCCESS": lambda _command: HandlerResult.succeeded("done")},
        )

        result = worker.poll_once()

        self.assertEqual(0, result.succeeded)
        self.assertEqual(1, result.fence_lost)
        self.assertEqual([], repository.completed)

    def test_run_until_stopped_injects_idle_sleep_and_returns_summary(self) -> None:
        repository = _WorkerRepository([OutboxClaimBatch(0, (), 0)])
        sleeps: list[float] = []
        stop_values = iter((False, False, True))
        worker = OutboxWorker(
            repository=repository,
            worker_id="worker-a",
            handlers={},
            sleeper=sleeps.append,
        )

        summary = worker.run_until_stopped(
            stop_requested=lambda: next(stop_values),
            idle_delay_seconds=0.25,
        )

        self.assertEqual(1, summary.polls)
        self.assertEqual(0, summary.selected)
        self.assertEqual([0.25], sleeps)

    def test_handler_result_never_allows_ambiguous_normal_retry(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit safe retry mode"):
            HandlerResult.retry_safely("ambiguous", retry_mode=RetryMode.NORMAL)

    def test_handler_result_shapes_are_closed_and_bounded(self) -> None:
        invalid = (
            {"disposition": "succeeded"},
            {"disposition": HandlerDisposition.SUCCEEDED},
            {
                "disposition": HandlerDisposition.SUCCEEDED,
                "completion_reference": "done",
                "reason": "extra",
            },
            {"disposition": HandlerDisposition.RETRY},
            {
                "disposition": HandlerDisposition.RETRY,
                "reason": "retry",
                "retry_mode": RetryMode.RECONCILE_ONLY,
                "completion_reference": "forbidden",
            },
            {
                "disposition": HandlerDisposition.DEAD_LETTER,
                "reason": "dead",
                "retry_mode": RetryMode.RECONCILE_ONLY,
            },
            {
                "disposition": HandlerDisposition.DEAD_LETTER,
                "reason": "bad\nreason",
            },
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises((TypeError, ValueError)):
                HandlerResult(**values)  # type: ignore[arg-type]

        self.assertEqual(
            HandlerDisposition.DEAD_LETTER,
            HandlerResult.dead_letter("terminal_reason").disposition,
        )
        self.assertEqual(
            RetryMode.RETRY_SAME_EFFECT,
            HandlerResult.retry_safely(
                "certain_pre_request_failure",
                retry_mode=RetryMode.RETRY_SAME_EFFECT,
            ).retry_mode,
        )

    def test_poll_result_rejects_inconsistent_accounting(self) -> None:
        invalid = (
            {"selected": -1},
            {"claimed": 2, "selected": 1},
            {"selected": 1},
        )
        defaults = {
            "selected": 0,
            "claimed": 0,
            "succeeded": 0,
            "retried": 0,
            "dead_lettered": 0,
            "fence_lost": 0,
        }
        for replacement in invalid:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                PollResult(**{**defaults, **replacement})

    def test_worker_constructor_and_run_loop_bounds_are_enforced(self) -> None:
        repository = _WorkerRepository([OutboxClaimBatch(0, (), 0)])
        invalid_constructors = (
            {"worker_id": " bad"},
            {"batch_size": 0},
            {"batch_size": True},
            {"batch_size": 101},
            {"lease_duration": timedelta(0)},
            {"lease_duration": timedelta(minutes=16)},
            {"handlers": []},
            {"handlers": {"TYPE": "not-callable"}},
            {"handlers": {"bad\ncommand": lambda _command: HandlerResult.dead_letter("x")}},
            {"sleeper": "not-callable"},
        )
        base: dict[str, object] = {
            "repository": repository,
            "worker_id": "worker-a",
            "handlers": {},
        }
        for replacement in invalid_constructors:
            with (
                self.subTest(replacement=tuple(replacement)),
                self.assertRaises((TypeError, ValueError)),
            ):
                OutboxWorker(**{**base, **replacement})  # type: ignore[arg-type]

        worker = OutboxWorker(**base)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            worker.run_until_stopped(stop_requested=False)  # type: ignore[arg-type]
        for delay in (0, -1, 61, True, "one"):
            with self.subTest(delay=delay), self.assertRaises(ValueError):
                worker.run_until_stopped(
                    stop_requested=lambda: True,
                    idle_delay_seconds=delay,  # type: ignore[arg-type]
                )

    def test_worker_rejects_repository_batch_contract_violation(self) -> None:
        class BadRepository(_WorkerRepository):
            def claim_batch(
                self,
                *,
                worker_id: str,
                batch_size: int,
                lease_duration: timedelta,
            ) -> OutboxClaimBatch:
                del worker_id, batch_size, lease_duration
                return "not-a-batch"  # type: ignore[return-value]

        worker = OutboxWorker(
            repository=BadRepository([]),
            worker_id="worker-a",
            handlers={},
        )
        with self.assertRaises(TypeError):
            worker.poll_once()


if __name__ == "__main__":
    unittest.main()
