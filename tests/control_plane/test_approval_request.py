from __future__ import annotations

import json
import unittest
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta

from retrywise.services.control_plane.approval_request import (
    ApprovalRequestConflict,
    ApprovalRequestNotFound,
    PostgresApprovalRequestService,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
APPROVAL_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
OUTBOX_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
AUDIT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


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


class _Context:
    def __enter__(self) -> object:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _Connection:
    def __init__(self, steps: list[_Step]) -> None:
        self.steps = list(steps)
        self.executions: list[tuple[str, dict[str, object]]] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def transaction(self) -> _Context:
        return _Context()

    def cursor(self) -> _Cursor:
        return _Cursor(self)


class _Connector:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __call__(self) -> _Connection:
        return self.connection


class _Audit:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def append(self, **values: object) -> None:
        self.calls.append(dict(values))


def snapshot(
    *,
    verdict: str = "PENDING",
    state: str = "APPROVAL_REQUIRED",
    expires_at: datetime | None = None,
) -> tuple[object, ...]:
    return (verdict, CASE_ID, expires_at or NOW + timedelta(minutes=5), state, 4, NOW)


def service(
    connection: _Connection,
    *,
    audit: _Audit | None = None,
) -> PostgresApprovalRequestService:
    ids = iter((OUTBOX_ID, AUDIT_ID))
    return PostgresApprovalRequestService(
        connector=_Connector(connection),  # type: ignore[arg-type]
        audit_appender=audit,  # type: ignore[arg-type]
        id_factory=lambda: next(ids),
    )


def act(value: PostgresApprovalRequestService, verdict: str = "APPROVED") -> object:
    return value.act(
        merchant_id=MERCHANT_ID,
        approval_id=APPROVAL_ID,
        operator_subject="operator-ayu",
        verdict=verdict,
        reason_code="operator_verified" if verdict == "APPROVED" else "operator_rejected",
        idempotency_key="approval-request-0001",
    )


class ApprovalRequestTests(unittest.TestCase):
    def test_approval_queues_exact_secret_free_worker_command_and_audit(self) -> None:
        audit = _Audit()
        connection = _Connection(
            [
                _Step("FROM retrywise.approvals AS approval", snapshot()),
                _Step("FROM retrywise.outbox_jobs", None),
                _Step("INSERT INTO retrywise.outbox_jobs", (OUTBOX_ID, "PENDING")),
            ]
        )

        result = act(service(connection, audit=audit))

        self.assertEqual("APPROVAL_QUEUED", result.verdict)
        self.assertEqual(OUTBOX_ID, result.outbox_job_id)
        insert_params = connection.executions[2][1]
        payload = json.loads(str(insert_params["command_payload"]))
        self.assertEqual(APPROVAL_ID, payload["approval_id"])
        self.assertNotIn("operator-ayu", str(payload))
        self.assertEqual(1, len(audit.calls))
        self.assertEqual("APPROVAL_REQUESTED", audit.calls[0]["entry_type"])
        self.assertEqual(
            "OPERATOR_VERIFIED",
            audit.calls[0]["facts"]["reason_code"],  # type: ignore[index]
        )

    def test_existing_identical_command_closes_commit_settlement_gap(self) -> None:
        first = _Connection(
            [
                _Step("FROM retrywise.approvals AS approval", snapshot()),
                _Step("FROM retrywise.outbox_jobs", None),
                _Step("INSERT INTO retrywise.outbox_jobs", (OUTBOX_ID, "PENDING")),
            ]
        )
        created = act(service(first))
        payload = json.loads(str(first.executions[2][1]["command_payload"]))
        second = _Connection(
            [
                _Step("FROM retrywise.approvals AS approval", snapshot()),
                _Step("FROM retrywise.outbox_jobs", (OUTBOX_ID, "IN_PROGRESS", payload)),
            ]
        )

        replay = act(service(second))

        self.assertEqual(created.outbox_job_id, replay.outbox_job_id)
        self.assertEqual("IN_PROGRESS", replay.command_status)

    def test_rejection_suppresses_case_only_when_no_materialization_exists(self) -> None:
        audit = _Audit()
        connection = _Connection(
            [
                _Step("FROM retrywise.approvals AS approval", snapshot()),
                _Step("FROM retrywise.outbox_jobs", None),
                _Step("UPDATE retrywise.approvals", ("REJECTED",)),
                _Step("UPDATE retrywise.recovery_cases", (5,)),
            ]
        )

        result = act(service(connection, audit=audit), "REJECTED")

        self.assertEqual("REJECTED", result.verdict)
        self.assertEqual(5, result.case_version)
        self.assertEqual("APPROVAL_ACTED", audit.calls[0]["entry_type"])

        conflict = _Connection(
            [
                _Step("FROM retrywise.approvals AS approval", snapshot()),
                _Step("FROM retrywise.outbox_jobs", (OUTBOX_ID, "PENDING", {})),
            ]
        )
        with self.assertRaises(ApprovalRequestConflict):
            act(service(conflict), "REJECTED")

    def test_expired_request_is_terminally_suppressed(self) -> None:
        connection = _Connection(
            [
                _Step(
                    "FROM retrywise.approvals AS approval",
                    snapshot(expires_at=NOW - timedelta(seconds=1)),
                ),
                _Step("UPDATE retrywise.approvals", ("EXPIRED",)),
                _Step("UPDATE retrywise.recovery_cases", (5,)),
            ]
        )

        result = act(service(connection))

        self.assertEqual("EXPIRED", result.verdict)
        self.assertEqual(5, result.case_version)

    def test_final_idempotency_and_all_unsafe_snapshots_fail_closed(self) -> None:
        final = _Connection(
            [_Step("FROM retrywise.approvals AS approval", snapshot(verdict="REJECTED"))]
        )
        self.assertEqual("REJECTED", act(service(final), "REJECTED").verdict)

        cases: list[tuple[Sequence[object] | None, type[Exception]]] = [
            (None, ApprovalRequestNotFound),
            (("PENDING",), ApprovalRequestConflict),
            (snapshot(verdict="EXPIRED"), ApprovalRequestConflict),
            (snapshot(state="OBSERVING"), ApprovalRequestConflict),
        ]
        for row, error in cases:
            with self.subTest(row=row):
                connection = _Connection([_Step("FROM retrywise.approvals AS approval", row)])
                with self.assertRaises(error):
                    act(service(connection))

    def test_invalid_public_arguments_fail_before_database_access(self) -> None:
        connection = _Connection([])
        value = service(connection)
        invalid = (
            {"merchant_id": "bad"},
            {"verdict": "EXPIRED"},
            {"reason_code": "not allowed"},
            {"operator_subject": ""},
            {"idempotency_key": "short"},
        )
        base: dict[str, object] = {
            "merchant_id": MERCHANT_ID,
            "approval_id": APPROVAL_ID,
            "operator_subject": "operator-ayu",
            "verdict": "APPROVED",
            "reason_code": "operator_verified",
            "idempotency_key": "approval-request-0001",
        }
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(ValueError):
                value.act(**{**base, **change})  # type: ignore[arg-type]
        self.assertEqual([], connection.executions)


if __name__ == "__main__":
    unittest.main()
