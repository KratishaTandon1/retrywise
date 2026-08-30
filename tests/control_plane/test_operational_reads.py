from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from retrywise.services.control_plane.operator_store import PostgresOperatorStore
from retrywise.services.control_plane.outbox_worker import PollResult
from retrywise.services.control_plane.worker_heartbeat import (
    PostgresWorkerHeartbeatRepository,
    WorkerHeartbeat,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
ORDER_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


class _Step:
    def __init__(
        self,
        marker: str,
        *,
        row: Sequence[object] | None = None,
        rows: Sequence[Sequence[object]] = (),
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
        self.step = self.connection.steps.pop(0)
        if self.step.marker not in query:
            raise AssertionError(f"expected {self.step.marker!r}, got {query!r}")
        self.connection.executions.append((query, dict(params)))

    def fetchone(self) -> Sequence[object] | None:
        assert self.step is not None
        return self.step.row

    def fetchall(self) -> Sequence[Sequence[object]]:
        assert self.step is not None
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


class OperationalReadTests(unittest.TestCase):
    def test_worker_heartbeat_persists_poll_totals_and_checks_exact_revision(self) -> None:
        connection = _Connection(
            [
                _Step("INSERT INTO retrywise.worker_heartbeats", row=("worker-a",)),
                _Step("SELECT EXISTS", row=(True,)),
            ]
        )
        repository = PostgresWorkerHeartbeatRepository(
            connector=_Connector(connection),  # type: ignore[arg-type]
        )
        heartbeat = WorkerHeartbeat(worker_id="worker-a", code_revision="revision-a")
        result = PollResult(5, 5, 3, 1, 1, 0)

        repository.beat(heartbeat, result=result, last_error_code="one_retry")
        self.assertTrue(repository.is_fresh(code_revision="revision-a"))

        written = connection.executions[0][1]
        self.assertEqual(5, written["selected"])
        self.assertEqual(3, written["succeeded"])
        self.assertEqual(1, written["retried"])
        self.assertEqual("one_retry", written["last_error_code"])
        self.assertEqual(timedelta(seconds=45), connection.executions[1][1]["maximum_age"])

    def test_worker_heartbeat_rejects_malformed_inputs_and_rows(self) -> None:
        with self.assertRaises(ValueError):
            WorkerHeartbeat(worker_id="", code_revision="revision-a")
        connection = _Connection([_Step("SELECT EXISTS", row=("true",))])
        repository = PostgresWorkerHeartbeatRepository(
            connector=_Connector(connection),  # type: ignore[arg-type]
        )
        with self.assertRaises(RuntimeError):
            repository.is_fresh(code_revision="revision-a")
        with self.assertRaises(ValueError):
            repository.is_fresh(code_revision="")
        with self.assertRaises(ValueError):
            repository.is_fresh(code_revision="revision-a", maximum_age=timedelta(minutes=10))

    def test_operator_store_projects_all_console_queries_and_audit_proof(self) -> None:
        case_row = (
            CASE_ID,
            "merchant-order",
            129_900,
            "INR",
            "OBSERVING",
            1,
            "upi",
            None,
            NOW,
            NOW,
            None,
            None,
        )
        detail_row = (
            CASE_ID,
            ORDER_ID,
            ACCOUNT_ID,
            "merchant-order",
            "order_test",
            129_900,
            "INR",
            "OBSERVING",
            1,
            0,
            0,
            NOW,
            None,
            None,
            None,
            "UNPAID",
            0,
            0,
            1,
            NOW,
            "acc_test",
            "TEST",
            True,
            True,
        )
        connection = _Connection(
            [
                _Step(
                    "FROM retrywise.recovery_cases AS recovery_case", row=(NOW, 1, 2, 3, 5000, 1, 0)
                ),
                _Step("LEFT JOIN LATERAL", rows=(case_row,)),
                _Step("WHERE recovery_case.merchant_id", row=detail_row),
                _Step("FROM retrywise.decisions", rows=()),
                _Step("FROM retrywise.actions", rows=()),
                _Step("FROM retrywise.recovery_instruments", rows=()),
                _Step(
                    "FROM retrywise.incidents",
                    rows=(
                        (
                            ACCOUNT_ID,
                            ACCOUNT_ID,
                            "upi",
                            "CONFIRMED",
                            "HIGH",
                            "0.9",
                            "d1",
                            "t1",
                            NOW,
                            NOW,
                            NOW,
                            NOW,
                        ),
                    ),
                ),
                _Step(
                    "FROM retrywise.approvals",
                    rows=(
                        (
                            ACCOUNT_ID,
                            CASE_ID,
                            ORDER_ID,
                            1,
                            "PENDING",
                            NOW,
                            NOW,
                            None,
                            None,
                            None,
                            129_900,
                            "INR",
                            "APPROVAL_REQUIRED",
                        ),
                    ),
                ),
            ]
        )
        with (
            patch(
                "retrywise.services.control_plane.operator_store._dsn_factory",
                return_value=_Connector(connection),
            ),
            patch("retrywise.services.control_plane.operator_store.PostgresAuditRepository"),
        ):
            store = PostgresOperatorStore(dsn="postgresql://unused")
        overview = store.overview(merchant_id=MERCHANT_ID)
        cases = store.list_cases(merchant_id=MERCHANT_ID)
        detail = store.case_detail(merchant_id=MERCHANT_ID, recovery_case_id=CASE_ID)
        incidents = store.list_incidents(merchant_id=MERCHANT_ID)
        approvals = store.list_approvals(merchant_id=MERCHANT_ID)

        self.assertEqual("RAZORPAY_TEST_MODE", overview["environment"])
        self.assertEqual(CASE_ID, cases[0]["id"])
        self.assertEqual([], detail["actions"])  # type: ignore[index]
        self.assertEqual("CONFIRMED", incidents[0]["state"])
        self.assertEqual("PENDING", approvals[0]["verdict"])

        entry = SimpleNamespace(
            audit_entry_id=ACCOUNT_ID,
            sequence_number=1,
            entry_type="CASE_OPENED",
            actor_type=SimpleNamespace(value="WORKER"),
            facts={"safe": True},
            entry_hash="ab" * 32,
            previous_entry_hash=None,
            created_at=NOW,
        )
        store._audit = SimpleNamespace(
            verify_chain=lambda **_kwargs: SimpleNamespace(
                valid=True,
                reason=SimpleNamespace(value="VALID"),
                checked_entries=1,
                error_sequence=None,
                head_hash="ab" * 32,
                entries=(entry,),
            )
        )
        proof = store.verify_audit(merchant_id=MERCHANT_ID, recovery_case_id=CASE_ID)
        self.assertTrue(proof["valid"])
        self.assertEqual("CASE_OPENED", proof["entries"][0]["entry_type"])

    def test_operator_store_bounds_and_malformed_rows_fail_closed(self) -> None:
        connection = _Connection(
            [_Step("FROM retrywise.recovery_cases AS recovery_case", row=None)]
        )
        with (
            patch(
                "retrywise.services.control_plane.operator_store._dsn_factory",
                return_value=_Connector(connection),
            ),
            patch("retrywise.services.control_plane.operator_store.PostgresAuditRepository"),
        ):
            store = PostgresOperatorStore(dsn="postgresql://unused")
        with self.assertRaises(RuntimeError):
            store.overview(merchant_id=MERCHANT_ID)
        for method in (store.list_cases, store.list_incidents, store.list_approvals):
            with self.assertRaises(ValueError):
                method(merchant_id=MERCHANT_ID, limit=0)


if __name__ == "__main__":
    unittest.main()
