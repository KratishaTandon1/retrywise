from __future__ import annotations

import json
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from retrywise.services.control_plane import assessment_worker as worker_module
from retrywise.services.control_plane.assessment_intent import (
    AssessmentAuthorizationError,
    AssessmentDisposition,
    AssessmentError,
    AssessmentMethodHealthError,
    AssessmentNotEligibleError,
    AssessmentPersistenceError,
    AssessmentProviderTruthError,
    AssessmentResult,
    AssessmentStateChangedError,
    AssessmentToIntentService,
    AssessRecoveryCaseCommand,
)
from retrywise.services.control_plane.assessment_worker import (
    ASSESS_RECOVERY_CASE_COMMAND_TYPE,
    AssessmentCommandError,
    AssessRecoveryCaseHandler,
    PostgresAssessmentCompletionProbe,
    PostgresAssessmentScheduler,
    decode_assess_recovery_case_command,
    encode_assess_recovery_case_command,
)
from retrywise.services.control_plane.outbox import RetryMode
from retrywise.services.control_plane.outbox_worker import HandlerDisposition
from retrywise.services.control_plane.postgres_outbox import ClaimedOutboxCommand

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
ORDER_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
PAYMENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def command() -> AssessRecoveryCaseCommand:
    return AssessRecoveryCaseCommand(
        merchant_id=MERCHANT_ID,
        provider_account_id=PROVIDER_ACCOUNT_ID,
        logical_order_id=ORDER_ID,
        payment_record_id=PAYMENT_ID,
        recovery_case_id=CASE_ID,
        expected_case_version=0,
    )


def claim() -> ClaimedOutboxCommand:
    return ClaimedOutboxCommand(
        job_id=JOB_ID,
        merchant_id=MERCHANT_ID,
        aggregate_type="RECOVERY_CASE",
        aggregate_id=CASE_ID,
        command_type=ASSESS_RECOVERY_CASE_COMMAND_TYPE,
        command_schema_version=1,
        command_payload=encode_assess_recovery_case_command(command()),
        idempotency_key=f"assess-recovery-case:{CASE_ID}:v0",
        attempt_count=1,
        max_attempts=12,
        worker_id="worker-a",
        lease_token="lease-a",
        lease_expires_at=NOW + timedelta(seconds=30),
        delivery_version=1,
        retry_mode=RetryMode.RECONCILE_ONLY,
        created_at=NOW - timedelta(minutes=1),
        claimed_at=NOW,
    )


class _Cursor:
    def __init__(self, rows: Sequence[Sequence[object]], *, inserted: bool) -> None:
        self.rows = rows
        self.inserted = inserted
        self.current: Sequence[object] | None = None
        self.executions: list[tuple[str, Mapping[str, object]]] = []

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, params: Mapping[str, object]) -> None:
        self.executions.append((query, dict(params)))
        if "INSERT INTO retrywise.outbox_jobs" in query:
            self.current = (JOB_ID,) if self.inserted else None
        elif "SELECT EXISTS" in query:
            self.current = (self.inserted,)
        else:
            self.current = None

    def fetchall(self) -> Sequence[Sequence[object]]:
        return self.rows

    def fetchone(self) -> Sequence[object] | None:
        return self.current


class _Connection:
    def __init__(self, cursor: _Cursor) -> None:
        self.cursor_value = cursor

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def transaction(self) -> _Connection:
        return self

    def cursor(self) -> _Cursor:
        return self.cursor_value


class AssessmentWorkerTests(unittest.TestCase):
    def test_scheduler_and_handler_reject_unsafe_composition_and_rows(self) -> None:
        self.assertEqual(26, len(worker_module._new_ulid()))
        with self.assertRaises(TypeError):
            encode_assess_recovery_case_command(object())  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            decode_assess_recovery_case_command(object())  # type: ignore[arg-type]

        for kwargs, error in (
            ({}, ValueError),
            (
                {"connector": lambda: _Connection(_Cursor((), inserted=False)), "batch_size": 0},
                ValueError,
            ),
            (
                {"connector": lambda: _Connection(_Cursor((), inserted=False)), "id_factory": None},
                TypeError,
            ),
            (
                {
                    "connector": lambda: _Connection(_Cursor((), inserted=False)),
                    "require_tls": True,
                },
                ValueError,
            ),
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(error):
                PostgresAssessmentScheduler(**kwargs)  # type: ignore[arg-type]

        unsafe_rows = (
            ((CASE_ID,), JOB_ID),
            (("bad", MERCHANT_ID, PROVIDER_ACCOUNT_ID, ORDER_ID, 0, PAYMENT_ID), JOB_ID),
            ((CASE_ID, MERCHANT_ID, PROVIDER_ACCOUNT_ID, ORDER_ID, -1, PAYMENT_ID), JOB_ID),
            ((CASE_ID, MERCHANT_ID, PROVIDER_ACCOUNT_ID, ORDER_ID, 0, PAYMENT_ID), "bad"),
        )
        for row, generated_id in unsafe_rows:
            with self.subTest(row=row, generated_id=generated_id), self.assertRaises(RuntimeError):
                PostgresAssessmentScheduler(
                    connector=lambda row=row: _Connection(_Cursor((row,), inserted=True)),
                    id_factory=lambda generated_id=generated_id: generated_id,
                ).schedule_due()

        with self.assertRaises(TypeError):
            PostgresAssessmentCompletionProbe(connector=None)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            AssessRecoveryCaseHandler(
                service=object(),  # type: ignore[arg-type]
                completion_probe=object(),  # type: ignore[arg-type]
            )
        with self.assertRaises(TypeError):
            AssessRecoveryCaseHandler(
                service=object.__new__(AssessmentToIntentService),
                completion_probe=object(),  # type: ignore[arg-type]
            )

    def test_codec_is_exact_and_binds_the_outbox_envelope(self) -> None:
        self.assertEqual(command(), decode_assess_recovery_case_command(claim()))
        for malformed in (
            replace(claim(), aggregate_id=ORDER_ID),
            replace(claim(), command_schema_version=2),
            replace(claim(), idempotency_key="wrong"),
            replace(claim(), command_payload={**claim().command_payload, "extra": True}),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(AssessmentCommandError):
                decode_assess_recovery_case_command(malformed)

    def test_scheduler_inserts_one_version_bound_idempotent_command(self) -> None:
        cursor = _Cursor(
            ((CASE_ID, MERCHANT_ID, PROVIDER_ACCOUNT_ID, ORDER_ID, 0, PAYMENT_ID),),
            inserted=True,
        )
        scheduler = PostgresAssessmentScheduler(
            connector=lambda: _Connection(cursor),
            id_factory=lambda: JOB_ID,
        )

        result = scheduler.schedule_due()

        self.assertEqual((1, 1, 0), (result.selected, result.scheduled, result.already_scheduled))
        insert = cursor.executions[1][1]
        payload = json.loads(str(insert["command_payload"]))
        self.assertEqual(CASE_ID, payload["recovery_case_id"])
        self.assertEqual(0, payload["expected_case_version"])
        self.assertEqual(f"assess-recovery-case:{CASE_ID}:v0", insert["idempotency_key"])

    def test_scheduler_counts_existing_idempotency_without_acknowledging_new_work(self) -> None:
        cursor = _Cursor(
            ((CASE_ID, MERCHANT_ID, PROVIDER_ACCOUNT_ID, ORDER_ID, 0, PAYMENT_ID),),
            inserted=False,
        )
        result = PostgresAssessmentScheduler(
            connector=lambda: _Connection(cursor),
            id_factory=lambda: JOB_ID,
        ).schedule_due()
        self.assertEqual((1, 0, 1), (result.selected, result.scheduled, result.already_scheduled))

    def test_completion_probe_uses_case_version_and_decision_evidence(self) -> None:
        cursor = _Cursor((), inserted=True)
        probe = PostgresAssessmentCompletionProbe(connector=lambda: _Connection(cursor))

        self.assertTrue(probe.already_applied(command()))
        self.assertEqual(0, cursor.executions[0][1]["expected_case_version"])

    def test_handler_maps_every_safe_failure_and_crash_recovery_path(self) -> None:
        service = object.__new__(AssessmentToIntentService)

        class Probe:
            applied = False

            def already_applied(self, _command: object) -> bool:
                return self.applied

        probe = Probe()
        handler = AssessRecoveryCaseHandler(service=service, completion_probe=probe)

        cases = (
            (
                AssessmentAuthorizationError(("MERCHANT_KILL_SWITCH",)),
                HandlerDisposition.RETRY,
                "assessment_outcome_not_persisted",
            ),
            (
                AssessmentNotEligibleError("assessment_not_eligible"),
                HandlerDisposition.DEAD_LETTER,
                "assessment_not_eligible",
            ),
            (
                AssessmentProviderTruthError("fresh_provider_truth_unavailable"),
                HandlerDisposition.RETRY,
                "assessment_fresh_truth_unavailable",
            ),
            (
                AssessmentMethodHealthError("fresh_method_health_unavailable"),
                HandlerDisposition.RETRY,
                "assessment_fresh_truth_unavailable",
            ),
            (
                AssessmentPersistenceError("assessment_commit_failed"),
                HandlerDisposition.RETRY,
                "assessment_persistence_failed",
            ),
            (
                AssessmentError("assessment_unknown"),
                HandlerDisposition.RETRY,
                "assessment_persistence_failed",
            ),
        )
        for error, disposition, reason in cases:
            with (
                self.subTest(error=type(error).__name__),
                patch.object(AssessmentToIntentService, "assess", side_effect=error),
            ):
                result = handler(claim())
                self.assertEqual(disposition, result.disposition)
                self.assertEqual(reason, result.reason)

        with patch.object(
            AssessmentToIntentService,
            "assess",
            side_effect=AssessmentStateChangedError("assessment_state_changed"),
        ):
            retry = handler(claim())
            probe.applied = True
            completed = handler(claim())
        self.assertEqual(HandlerDisposition.RETRY, retry.disposition)
        self.assertEqual(HandlerDisposition.SUCCEEDED, completed.disposition)

        with patch.object(AssessmentToIntentService, "assess", return_value=object()):
            invalid = handler(claim())
        self.assertEqual(HandlerDisposition.DEAD_LETTER, invalid.disposition)

        success = object.__new__(AssessmentResult)
        object.__setattr__(success, "recovery_case_id", CASE_ID)
        object.__setattr__(success, "disposition", AssessmentDisposition.WAITING)
        with patch.object(AssessmentToIntentService, "assess", return_value=success):
            result = handler(claim())
        self.assertEqual(HandlerDisposition.SUCCEEDED, result.disposition)
        self.assertIn(":waiting", result.completion_reference or "")

        malformed = handler(replace(claim(), aggregate_id=ORDER_ID))
        self.assertEqual(HandlerDisposition.DEAD_LETTER, malformed.disposition)


if __name__ == "__main__":
    unittest.main()
