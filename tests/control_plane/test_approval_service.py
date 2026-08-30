from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence
from datetime import timedelta

from retrywise.packages.domain import (
    ActionProposal,
    ActionType,
    DeterministicGate,
    Money,
    Probability,
)
from retrywise.services.control_plane.approval_service import (
    ApprovalConflict,
    ApprovalNotFound,
    PostgresApprovalService,
)
from tests.control_plane.test_assessment_intent import (
    ACTION_ID,
    AMOUNT,
    CASE_ID,
    DECISION_ID,
    INSTRUMENT_ID,
    LOGICAL_ORDER_ID,
    MERCHANT_ID,
    NOW,
    OUTBOX_JOB_ID,
    PAYMENT_RECORD_ID,
    PROVIDER_ACCOUNT_ID,
    gate_policy,
    method_health,
    provider_truth,
)

APPROVAL_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB5"
AUDIT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB6"


def proposal() -> ActionProposal:
    return ActionProposal(
        proposal_id="approval-proposal-1",
        merchant_id=MERCHANT_ID,
        case_id=CASE_ID,
        decision_version=3,
        action_type=ActionType.CREATE_STANDARD_PAYMENT_LINK,
        created_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
        amount=Money(AMOUNT, "INR"),
        payment_method="upi",
        expected_value_minor=25_000,
        model_confidence=Probability("0.91"),
        requires_approval=True,
    )


def snapshot_row(
    *, expires_at: object | None = None, candidates: object | None = None
) -> tuple[object, ...]:
    return (
        APPROVAL_ID,
        DECISION_ID,
        3,
        NOW - timedelta(minutes=2),
        expires_at or NOW + timedelta(minutes=30),
        [proposal().to_primitive()] if candidates is None else candidates,
        "policy-v1",
        CASE_ID,
        LOGICAL_ORDER_ID,
        PROVIDER_ACCOUNT_ID,
        "INR",
        AMOUNT,
        "APPROVAL_REQUIRED",
        3,
        NOW - timedelta(minutes=1),
        0,
        0,
        None,
        "ACTIVE",
        False,
        "acc_retrywise_test_1",
        "TEST",
        True,
        7,
        "UNPAID",
        PAYMENT_RECORD_ID,
        "pay_test_1",
        "order_test_1",
        "upi",
        0,
        NOW,
    )


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


class _TruthReader:
    def fetch_fresh_payment_truth(self, _query: object) -> object:
        return provider_truth()


class _HealthReader:
    def fetch_fresh_method_health(self, _query: object) -> object:
        return method_health()


class _Audit:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def append(self, **values: object) -> None:
        self.calls.append(dict(values))


def service(
    connection: _Connection,
    *,
    global_kill_switch: bool = False,
    audit: _Audit | None = None,
) -> PostgresApprovalService:
    ids = iter((ACTION_ID, INSTRUMENT_ID, OUTBOX_JOB_ID, AUDIT_ID))
    return PostgresApprovalService(
        gate=DeterministicGate(gate_policy()),
        provider_truth_reader=_TruthReader(),  # type: ignore[arg-type]
        method_health_reader=_HealthReader(),  # type: ignore[arg-type]
        connector=_Connector(connection),  # type: ignore[arg-type]
        global_kill_switch=global_kill_switch,
        audit_appender=audit,  # type: ignore[arg-type]
        id_factory=lambda: next(ids),
    )


class ApprovalServiceTests(unittest.TestCase):
    def test_approval_materializes_one_bound_effect_command_atomically(self) -> None:
        row = snapshot_row()
        audit = _Audit()
        connection = _Connection(
            [
                _Step("FROM retrywise.approvals AS approval", row),
                _Step("FOR UPDATE OF approval, recovery_case", row),
                _Step("SET verdict = 'APPROVED'", ("APPROVED",)),
                _Step("INSERT INTO retrywise.actions", (ACTION_ID,)),
                _Step("INSERT INTO retrywise.recovery_instruments", (INSTRUMENT_ID,)),
                _Step("SET status = 'QUEUED'", ("QUEUED",)),
                _Step("SET state = 'ACTION_QUEUED'", (4,)),
                _Step("INSERT INTO retrywise.outbox_jobs", (OUTBOX_JOB_ID,)),
            ]
        )

        result = service(connection, audit=audit).act(
            merchant_id=MERCHANT_ID,
            approval_id=APPROVAL_ID,
            operator_subject="local-operator",
            verdict="APPROVED",
            reason_code="operator_verified",
        )

        self.assertEqual("APPROVED", result.verdict)
        self.assertEqual(ACTION_ID, result.action_id)
        self.assertEqual(OUTBOX_JOB_ID, result.outbox_job_id)
        self.assertEqual([], connection.steps)
        outbox_payload = connection.executions[-1][1]["command_payload"]
        self.assertNotIn("secret", str(outbox_payload).lower())
        self.assertEqual("OPERATOR_VERIFIED", audit.calls[0]["facts"]["reason_code"])  # type: ignore[index]

    def test_rejection_suppresses_case_without_creating_an_effect(self) -> None:
        row = snapshot_row()
        connection = _Connection(
            [
                _Step("FROM retrywise.approvals AS approval", row),
                _Step("FOR UPDATE OF approval, recovery_case", row),
                _Step("SET verdict = 'REJECTED'", ("REJECTED",)),
                _Step("SET state = 'SUPPRESSED_POLICY'", (4,)),
            ]
        )

        result = service(connection).act(
            merchant_id=MERCHANT_ID,
            approval_id=APPROVAL_ID,
            operator_subject="local-operator",
            verdict="REJECTED",
            reason_code="operator_declined",
        )

        self.assertEqual("REJECTED", result.verdict)
        self.assertIsNone(result.action_id)
        self.assertEqual([], connection.steps)

    def test_expired_or_newly_unsafe_approval_is_cancelled_before_effect(self) -> None:
        scenarios = (
            (snapshot_row(expires_at=NOW), False, "EXPIRED"),
            (snapshot_row(), True, "CANCELLED"),
        )
        for row, kill_switch, expected in scenarios:
            with self.subTest(expected=expected):
                connection = _Connection(
                    [
                        _Step("FROM retrywise.approvals AS approval", row),
                        _Step("FOR UPDATE OF approval, recovery_case", row),
                        _Step("SET verdict = %(verdict)s", (expected,)),
                        _Step("SET state = 'SUPPRESSED_POLICY'", (4,)),
                    ]
                )
                result = service(connection, global_kill_switch=kill_switch).act(
                    merchant_id=MERCHANT_ID,
                    approval_id=APPROVAL_ID,
                    operator_subject="local-operator",
                    verdict="APPROVED",
                    reason_code="operator_verified",
                )
                self.assertEqual(expected, result.verdict)
                self.assertEqual([], connection.steps)

    def test_snapshot_and_input_validation_fail_closed(self) -> None:
        for kwargs in (
            {"verdict": "MAYBE", "reason_code": "operator_verified"},
            {"verdict": "APPROVED", "reason_code": "Invalid Reason"},
            {"verdict": "APPROVED", "reason_code": "operator_verified", "operator_subject": ""},
        ):
            values = {
                "merchant_id": MERCHANT_ID,
                "approval_id": APPROVAL_ID,
                "operator_subject": "local-operator",
                "verdict": "APPROVED",
                "reason_code": "operator_verified",
                **kwargs,
            }
            with self.subTest(values=values), self.assertRaises(ValueError):
                service(_Connection([])).act(**values)

        with self.assertRaises(ApprovalNotFound):
            service(_Connection([_Step("FROM retrywise.approvals AS approval", None)])).act(
                merchant_id=MERCHANT_ID,
                approval_id=APPROVAL_ID,
                operator_subject="local-operator",
                verdict="APPROVED",
                reason_code="operator_verified",
            )
        with self.assertRaises(ApprovalConflict):
            service(
                _Connection(
                    [
                        _Step(
                            "FROM retrywise.approvals AS approval",
                            snapshot_row(candidates=[]),
                        )
                    ]
                )
            ).act(
                merchant_id=MERCHANT_ID,
                approval_id=APPROVAL_ID,
                operator_subject="local-operator",
                verdict="APPROVED",
                reason_code="operator_verified",
            )

        with self.assertRaises(ValueError):
            PostgresApprovalService(
                gate=DeterministicGate(gate_policy()),
                provider_truth_reader=_TruthReader(),  # type: ignore[arg-type]
                method_health_reader=_HealthReader(),  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
