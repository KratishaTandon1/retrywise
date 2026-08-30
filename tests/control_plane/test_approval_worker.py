from __future__ import annotations

import hashlib
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from retrywise.services.control_plane.approval_command import (
    MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE,
    MATERIALIZE_APPROVED_ACTION_SCHEMA_VERSION,
    ApprovalCommandCodecError,
    MaterializeApprovedActionCommand,
    decode_materialize_approved_action_command,
)
from retrywise.services.control_plane.approval_service import ApprovalConflict, ApprovalNotFound
from retrywise.services.control_plane.approval_worker import (
    MaterializeApprovedActionHandler,
    PostgresApprovalCompletionProbe,
)
from retrywise.services.control_plane.outbox import RetryMode
from retrywise.services.control_plane.outbox_worker import HandlerDisposition
from retrywise.services.control_plane.postgres_outbox import ClaimedOutboxCommand

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
APPROVAL_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
ACTION_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def command() -> MaterializeApprovedActionCommand:
    return MaterializeApprovedActionCommand(
        merchant_id=MERCHANT_ID,
        approval_id=APPROVAL_ID,
        operator_subject="operator:" + hashlib.sha256(b"operator-1").hexdigest(),
        reason_code="operator_verified",
        request_idempotency_sha256=hashlib.sha256(b"approval-request-0001").hexdigest(),
    )


def claim() -> ClaimedOutboxCommand:
    return ClaimedOutboxCommand(
        job_id=JOB_ID,
        merchant_id=MERCHANT_ID,
        aggregate_type="APPROVAL",
        aggregate_id=APPROVAL_ID,
        command_type=MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE,
        command_schema_version=MATERIALIZE_APPROVED_ACTION_SCHEMA_VERSION,
        command_payload=command().to_primitive(),
        idempotency_key=f"materialize-approved-action:{APPROVAL_ID}",
        attempt_count=1,
        max_attempts=8,
        worker_id="worker-a",
        lease_token="lease-a",
        lease_expires_at=NOW + timedelta(seconds=30),
        delivery_version=1,
        retry_mode=RetryMode.RECONCILE_ONLY,
        created_at=NOW - timedelta(minutes=1),
        claimed_at=NOW,
    )


class _Probe:
    def __init__(self, result: str | None = None) -> None:
        self.value = result

    def result(self, _command: object) -> str | None:
        return self.value


class _Service:
    def __init__(self, result: object | Exception) -> None:
        self.result = result
        self.calls = 0

    def act(self, **_values: object) -> object:
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class _Cursor:
    def __init__(self, row: Sequence[object] | None) -> None:
        self.row = row

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, _query: str, _params: Mapping[str, object]) -> None:
        return None

    def fetchone(self) -> Sequence[object] | None:
        return self.row


class _Connection:
    def __init__(self, row: Sequence[object] | None) -> None:
        self.cursor_value = _Cursor(row)

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _Cursor:
        return self.cursor_value


class _Connector:
    def __init__(self, row: Sequence[object] | None) -> None:
        self.connection = _Connection(row)

    def __call__(self) -> _Connection:
        return self.connection


class ApprovalWorkerTests(unittest.TestCase):
    def test_completion_probe_validates_and_closes_every_terminal_state(self) -> None:
        scenarios = (
            (("APPROVED", ACTION_ID, JOB_ID), f"approved:{ACTION_ID}:{JOB_ID}"),
            (("REJECTED", None, None), "rejected"),
            (("EXPIRED", None, None), "expired"),
            (("CANCELLED", None, None), "cancelled"),
            (("PENDING", None, None), None),
            (None, None),
        )
        for row, expected in scenarios:
            with self.subTest(row=row):
                probe = PostgresApprovalCompletionProbe(
                    connector=_Connector(row),  # type: ignore[arg-type]
                )
                self.assertEqual(expected, probe.result(command()))

        for unsafe in (("APPROVED", None, None), ("APPROVED", ACTION_ID), (1, None, None)):
            with self.subTest(unsafe=unsafe), self.assertRaises(RuntimeError):
                PostgresApprovalCompletionProbe(
                    connector=_Connector(unsafe),  # type: ignore[arg-type]
                ).result(command())

        with self.assertRaises(ValueError):
            PostgresApprovalCompletionProbe()

    def test_codec_rejects_unknown_fields_and_wrong_envelope(self) -> None:
        decoded = decode_materialize_approved_action_command(
            command().to_primitive(),
            command_type=MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE,
            command_schema_version=1,
        )
        self.assertEqual(command(), decoded)
        with self.assertRaises(ApprovalCommandCodecError):
            decode_materialize_approved_action_command(
                {**command().to_primitive(), "extra": True},
                command_type=MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE,
                command_schema_version=1,
            )

    def test_completion_probe_closes_crash_gap_without_rematerializing(self) -> None:
        service = _Service(RuntimeError("must not run"))
        handler = MaterializeApprovedActionHandler(
            service=service,  # type: ignore[arg-type]
            completion_probe=_Probe(f"approved:{ACTION_ID}:{JOB_ID}"),  # type: ignore[arg-type]
        )

        result = handler(claim())

        self.assertEqual(HandlerDisposition.SUCCEEDED, result.disposition)
        self.assertEqual(0, service.calls)

    def test_fresh_truth_failure_retries_without_executing_an_effect(self) -> None:
        service = _Service(RuntimeError("private provider detail"))
        handler = MaterializeApprovedActionHandler(
            service=service,  # type: ignore[arg-type]
            completion_probe=_Probe(),  # type: ignore[arg-type]
        )

        result = handler(claim())

        self.assertEqual(HandlerDisposition.RETRY, result.disposition)
        self.assertEqual("approval_fresh_truth_unavailable", result.reason)
        self.assertNotIn("private provider detail", str(result))

    def test_outbox_binding_mismatch_is_dead_lettered(self) -> None:
        handler = MaterializeApprovedActionHandler(
            service=_Service(SimpleNamespace()),  # type: ignore[arg-type]
            completion_probe=_Probe(),  # type: ignore[arg-type]
        )

        result = handler(replace(claim(), aggregate_id=ACTION_ID))

        self.assertEqual(HandlerDisposition.DEAD_LETTER, result.disposition)

        invalid = handler(replace(claim(), command_payload={"invalid": True}))
        self.assertEqual(HandlerDisposition.DEAD_LETTER, invalid.disposition)

    def test_materializes_and_maps_final_reconciliation_outcomes(self) -> None:
        materialized = SimpleNamespace(
            approval_id=APPROVAL_ID,
            verdict="APPROVED",
            action_id=ACTION_ID,
        )
        result = MaterializeApprovedActionHandler(
            service=_Service(materialized),  # type: ignore[arg-type]
            completion_probe=_Probe(),  # type: ignore[arg-type]
        )(claim())
        self.assertEqual(HandlerDisposition.SUCCEEDED, result.disposition)
        self.assertIn(ACTION_ID, result.completion_reference or "")

        scenarios = (
            (
                ApprovalNotFound("missing"),
                _Probe(f"approved:{ACTION_ID}:{JOB_ID}"),
                HandlerDisposition.SUCCEEDED,
            ),
            (ApprovalNotFound("missing"), _Probe(), HandlerDisposition.DEAD_LETTER),
            (
                ApprovalConflict("approval_state_changed"),
                _Probe("rejected"),
                HandlerDisposition.SUCCEEDED,
            ),
            (
                ApprovalConflict("approval_state_changed"),
                _Probe(),
                HandlerDisposition.DEAD_LETTER,
            ),
            (
                ApprovalConflict("another_conflict"),
                _Probe(),
                HandlerDisposition.DEAD_LETTER,
            ),
        )
        for error, probe, expected in scenarios:
            with self.subTest(error=str(error), completed=probe.value):
                handled = MaterializeApprovedActionHandler(
                    service=_Service(error),  # type: ignore[arg-type]
                    completion_probe=probe,  # type: ignore[arg-type]
                )(claim())
                self.assertEqual(expected, handled.disposition)


if __name__ == "__main__":
    unittest.main()
