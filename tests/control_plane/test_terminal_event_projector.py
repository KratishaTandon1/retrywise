from __future__ import annotations

import unittest
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from retrywise.packages.razorpay import make_recovery_reference_id
from retrywise.services.control_plane import terminal_event_projector as terminal
from retrywise.services.control_plane.normalized_event_projector import (
    NormalizedEventEvidenceError,
    NormalizedEventFenceLost,
    NormalizedEventProjectionResult,
    ProjectionDisposition,
    decode_process_normalized_provider_event_command,
)
from retrywise.services.control_plane.outbox import RetryMode
from retrywise.services.control_plane.outbox_worker import HandlerDisposition
from retrywise.services.control_plane.postgres_outbox import ClaimedOutboxCommand
from retrywise.services.control_plane.terminal_event_projector import (
    PostgresTerminalEventRepository,
    ProcessTerminalProviderEventHandler,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
EVENT_RECORD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
INBOX_EVENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
PAYMENT_RECORD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
LOGICAL_ORDER_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
INSTRUMENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB3"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
OCCURRED_AT = datetime.fromtimestamp(1_788_000_000, UTC)
BODY_DIGEST = bytes.fromhex("cd" * 32)
AMOUNT = 129_900
REFERENCE_ID = make_recovery_reference_id(CASE_ID, provider_account_id=PROVIDER_ACCOUNT_ID)


def _payload(event_type: str) -> dict[str, object]:
    return {
        "event_type": event_type,
        "inbox_event_id": INBOX_EVENT_ID,
        "merchant_id": MERCHANT_ID,
        "provider_account_id": PROVIDER_ACCOUNT_ID,
        "provider_event_id": "evt_terminal_1",
        "provider_event_record_id": EVENT_RECORD_ID,
        "schema_version": 1,
    }


def _claim(event_type: str = "payment.captured", **updates: object) -> ClaimedOutboxCommand:
    values: dict[str, object] = {
        "job_id": JOB_ID,
        "merchant_id": MERCHANT_ID,
        "aggregate_type": "PROVIDER_EVENT",
        "aggregate_id": EVENT_RECORD_ID,
        "command_type": "PROCESS_NORMALIZED_PROVIDER_EVENT",
        "command_schema_version": 1,
        "command_payload": _payload(event_type),
        "idempotency_key": f"normalized-provider-event:{EVENT_RECORD_ID}",
        "attempt_count": 1,
        "max_attempts": 8,
        "worker_id": "terminal-worker-a",
        "lease_token": "lease-token-terminal",
        "lease_expires_at": NOW + timedelta(seconds=30),
        "delivery_version": 1,
        "retry_mode": RetryMode.RECONCILE_ONLY,
        "created_at": NOW - timedelta(minutes=1),
        "claimed_at": NOW,
    }
    values.update(updates)
    return ClaimedOutboxCommand(**values)  # type: ignore[arg-type]


def _capture_canonical(**resource_updates: object) -> dict[str, object]:
    resource: dict[str, object] = {
        "amount": AMOUNT,
        "amount_refunded": 0,
        "captured": True,
        "currency": "INR",
        "entity": "payment",
        "id": "pay_original",
        "method": "upi",
        "order_id": "order_original",
        "status": "captured",
    }
    resource.update(resource_updates)
    return _canonical_envelope(
        event_type="payment.captured",
        resource_type="payment",
        resource=resource,
        related={"payment": dict(resource)},
    )


def _link_canonical(
    event_type: str = "payment_link.paid",
    *,
    amount_paid: int = AMOUNT,
    resource_updates: Mapping[str, object] | None = None,
    payment_updates: Mapping[str, object] | None = None,
) -> dict[str, object]:
    status = "paid" if event_type == "payment_link.paid" else "partially_paid"
    resource: dict[str, object] = {
        "accept_partial": False,
        "amount": AMOUNT,
        "amount_paid": amount_paid,
        "currency": "INR",
        "entity": "payment_link",
        "id": "plink_recovery",
        "order_id": "order_recovery",
        "reference_id": REFERENCE_ID,
        "status": status,
        "upi_link": False,
    }
    if resource_updates:
        resource.update(resource_updates)
    payment: dict[str, object] = {
        "amount": amount_paid,
        "amount_refunded": 0,
        "captured": True,
        "currency": "INR",
        "entity": "payment",
        "id": "pay_recovery",
        "order_id": "order_recovery",
        "status": "captured",
    }
    if payment_updates:
        payment.update(payment_updates)
    order: dict[str, object] = {
        "amount": AMOUNT,
        "amount_paid": amount_paid,
        "currency": "INR",
        "entity": "order",
        "id": "order_recovery",
        "status": "paid" if amount_paid == AMOUNT else "attempted",
    }
    return _canonical_envelope(
        event_type=event_type,
        resource_type="payment_link",
        resource=resource,
        related={"payment_link": dict(resource), "payment": payment, "order": order},
    )


def _canonical_envelope(
    *,
    event_type: str,
    resource_type: str,
    resource: Mapping[str, object],
    related: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_id": "evt_terminal_1",
        "provider_account_id": "acc_test_1",
        "event_name": event_type,
        "event_type": event_type,
        "occurred_at_epoch": 1_788_000_000,
        "resource_type": resource_type,
        "resource_id": resource["id"],
        "resource": dict(resource),
        "related_resources": {key: dict(value) for key, value in related.items()},
        "raw_body_sha256": BODY_DIGEST.hex(),
    }


def _event_row(
    *,
    event_type: str = "payment.captured",
    canonical: Mapping[str, object] | None = None,
    inbox_status: str = "RECEIVED",
    resource_type: str | None = None,
    resource_id: str | None = None,
) -> Sequence[object]:
    canonical_value = dict(canonical or _capture_canonical())
    resource = canonical_value["resource"]
    assert isinstance(resource, Mapping)
    return (
        INBOX_EVENT_ID,
        inbox_status,
        0,
        8,
        False,
        MERCHANT_ID,
        PROVIDER_ACCOUNT_ID,
        "acc_test_1",
        EVENT_RECORD_ID,
        "evt_terminal_1",
        event_type,
        resource_type or str(canonical_value["resource_type"]),
        resource_id or str(resource["id"]),
        BODY_DIGEST,
        True,
        True,
        1,
        canonical_value,
        OCCURRED_AT,
        NOW,
    )


def _capture_target_row(
    *,
    status: str = "FAILED",
    captured_minor: int = 0,
    canonical_truth: str = "UNPAID",
    captured_total: int = 0,
    amount_due: int = AMOUNT,
    provider_order_id: str | None = "order_original",
    mapping_status: str = "MAPPED",
) -> Sequence[object]:
    return (
        PAYMENT_RECORD_ID,
        LOGICAL_ORDER_ID,
        "pay_original",
        provider_order_id,
        status,
        AMOUNT,
        "INR",
        captured_minor,
        0,
        "upi",
        OCCURRED_AT - timedelta(seconds=5),
        "order_original",
        amount_due,
        "INR",
        canonical_truth,
        captured_total,
        0,
        OCCURRED_AT - timedelta(seconds=5),
        mapping_status,
    )


def _link_target_row(
    *,
    instrument_status: str = "ACTIVE",
    case_state: str = "ACTIVE",
    case_version: int = 7,
    canonical_truth: str = "UNPAID",
    captured_total: int = 0,
    reference_id: str = REFERENCE_ID,
    collected_minor: int = 0,
) -> Sequence[object]:
    return (
        INSTRUMENT_ID,
        CASE_ID,
        LOGICAL_ORDER_ID,
        PROVIDER_ACCOUNT_ID,
        "plink_recovery",
        "order_recovery",
        None,
        reference_id,
        AMOUNT,
        "INR",
        instrument_status,
        False,
        collected_minor,
        0,
        OCCURRED_AT - timedelta(seconds=5),
        case_state,
        case_version,
        "order_original",
        AMOUNT,
        "INR",
        canonical_truth,
        captured_total,
        0,
        OCCURRED_AT - timedelta(seconds=5),
        "MAPPED",
    )


def _path_payment_row(*, status: str = "FAILED", captured_minor: int = 0) -> Sequence[object]:
    return (
        PAYMENT_RECORD_ID,
        "pay_original",
        "order_original",
        status,
        AMOUNT,
        "INR",
        captured_minor,
        0,
    )


def _path_instrument_row(
    *,
    status: str = "ACTIVE",
    collected_minor: int = 0,
    case_id: str = CASE_ID,
) -> Sequence[object]:
    return (
        INSTRUMENT_ID,
        case_id,
        status,
        AMOUNT,
        "INR",
        collected_minor,
        0,
        "plink_recovery",
        "order_recovery",
        None if collected_minor == 0 else "pay_recovery",
        REFERENCE_ID,
        False,
        OCCURRED_AT - timedelta(seconds=5),
    )


def _case_row(state: str = "ACTIVE", version: int = 7) -> Sequence[object]:
    terminal = state not in {
        "OBSERVING",
        "ASSESSING",
        "WAITING",
        "APPROVAL_REQUIRED",
        "ACTION_QUEUED",
        "EXECUTING",
        "ACTION_UNCERTAIN",
        "ACTIVE",
    }
    return (
        CASE_ID,
        state,
        version,
        "existing_terminal" if terminal else None,
        NOW - timedelta(seconds=10) if terminal else None,
    )


ResultFactory = Callable[
    [Mapping[str, object]], Sequence[object] | Sequence[Sequence[object]] | None
]


@dataclass(frozen=True)
class _Step:
    marker: str
    result_factory: ResultFactory = lambda _params: None
    many: bool = False


class _FakeCursor:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection
        self.result: Sequence[object] | Sequence[Sequence[object]] | None = None
        self.many = False

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: Mapping[str, object]) -> None:
        if not self.connection.steps:
            raise AssertionError(f"unexpected query: {query}")
        step = self.connection.steps.pop(0)
        if step.marker not in query:
            raise AssertionError(f"expected query containing {step.marker!r}, got {query!r}")
        copied = dict(params)
        self.connection.executions.append((query, copied))
        self.result = step.result_factory(copied)
        self.many = step.many

    def fetchone(self) -> Sequence[object] | None:
        if self.many:
            raise AssertionError("fetchone called for a multi-row fake result")
        return self.result  # type: ignore[return-value]

    def fetchall(self) -> Sequence[Sequence[object]]:
        if not self.many:
            raise AssertionError("fetchall called for a single-row fake result")
        return self.result or ()  # type: ignore[return-value]


class _FakeTransaction:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection

    def __enter__(self) -> None:
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: object | None,
    ) -> None:
        if exc_type is None:
            self.connection.commits += 1
        else:
            self.connection.rollbacks += 1
        return None


class _FakeConnection:
    def __init__(self, steps: Sequence[_Step]) -> None:
        self.steps = list(steps)
        self.executions: list[tuple[str, Mapping[str, object]]] = []
        self.commits = 0
        self.rollbacks = 0

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)


def _repository(connection: _FakeConnection) -> PostgresTerminalEventRepository:
    return PostgresTerminalEventRepository(connector=lambda: connection)


def _settlement_steps(disposition: str = "PROCESSED") -> list[_Step]:
    return [
        _Step("SELECT lease_expires_at >", lambda _params: (True,)),
        _Step("SET status = %(inbox_status)s", lambda _params: (disposition,)),
    ]


class CaptureProjectionTests(unittest.TestCase):
    def test_new_payment_on_the_exact_original_order_is_materialized_then_projected(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step("FROM retrywise.provider_payments AS payment\nJOIN", lambda _params: None),
                _Step(
                    "FROM retrywise.logical_orders AS logical_order",
                    lambda _params: (
                        LOGICAL_ORDER_ID,
                        "order_original",
                        AMOUNT,
                        "INR",
                        "UNPAID",
                        "MAPPED",
                    ),
                ),
                _Step(
                    "INSERT INTO retrywise.provider_payments",
                    lambda _params: (PAYMENT_RECORD_ID,),
                ),
                _Step(
                    "FROM retrywise.provider_payments AS payment\nJOIN",
                    lambda _params: _capture_target_row(status="UNKNOWN"),
                ),
                _Step(
                    "ORDER BY payment.id",
                    lambda _params: [_path_payment_row(status="UNKNOWN")],
                    many=True,
                ),
                _Step("ORDER BY instrument.id", lambda _params: [], many=True),
                _Step("ORDER BY recovery_case.id", lambda _params: [_case_row()], many=True),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("SET status = 'CAPTURED'", lambda _params: ("CAPTURED",)),
                _Step("SET captured_total_minor", lambda _params: ("PAID",)),
                _Step("SET state = %(new_case_state)s", lambda _params: ("SUPPRESSED_PAID",)),
                *_settlement_steps(),
            ]
        )
        claim = _claim()

        result = PostgresTerminalEventRepository(
            connector=lambda: connection,
            payment_id_factory=lambda: PAYMENT_RECORD_ID,
        ).project(decode_process_normalized_provider_event_command(claim), claim=claim)

        self.assertIs(result.disposition, ProjectionDisposition.PROCESSED)
        inserted = next(
            params
            for query, params in connection.executions
            if "INSERT INTO retrywise.provider_payments" in query
        )
        self.assertEqual("pay_original", inserted["provider_payment_id"])
        self.assertEqual(LOGICAL_ORDER_ID, inserted["logical_order_id"])

    def test_exact_original_capture_projects_money_and_suppresses_open_case(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment\nJOIN",
                    lambda _params: _capture_target_row(),
                ),
                _Step("ORDER BY payment.id", lambda _params: [_path_payment_row()], many=True),
                _Step(
                    "ORDER BY instrument.id", lambda _params: [_path_instrument_row()], many=True
                ),
                _Step("ORDER BY recovery_case.id", lambda _params: [_case_row()], many=True),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("SET status = 'CAPTURED'", lambda _params: ("CAPTURED",)),
                _Step("SET captured_total_minor", lambda _params: ("PAID",)),
                _Step("SET state = %(new_case_state)s", lambda _params: ("SUPPRESSED_PAID",)),
                *_settlement_steps(),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertIs(result.disposition, ProjectionDisposition.PROCESSED)
        self.assertEqual(1, connection.commits)
        order_params = next(
            params for query, params in connection.executions if "SET captured_total_minor" in query
        )
        self.assertEqual(AMOUNT, order_params["captured_total_minor"])
        self.assertEqual("PAID", order_params["canonical_truth"])
        case_params = next(
            params
            for query, params in connection.executions
            if "SET state = %(new_case_state)s" in query
        )
        self.assertEqual("SUPPRESSED_PAID", case_params["new_case_state"])
        self.assertEqual("original_payment_captured", case_params["terminal_reason_code"])

    def test_original_capture_after_recovery_opens_duplicate_review_and_overpaid_truth(
        self,
    ) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment\nJOIN",
                    lambda _params: _capture_target_row(
                        canonical_truth="PAID", captured_total=AMOUNT
                    ),
                ),
                _Step("ORDER BY payment.id", lambda _params: [_path_payment_row()], many=True),
                _Step(
                    "ORDER BY instrument.id",
                    lambda _params: [_path_instrument_row(status="PAID", collected_minor=AMOUNT)],
                    many=True,
                ),
                _Step(
                    "ORDER BY recovery_case.id", lambda _params: [_case_row("RECOVERED")], many=True
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("SET status = 'CAPTURED'", lambda _params: ("CAPTURED",)),
                _Step("SET captured_total_minor", lambda _params: ("OVERPAID",)),
                _Step("SET state = %(new_case_state)s", lambda _params: ("DUPLICATE_REVIEW",)),
                *_settlement_steps(),
            ]
        )
        claim = _claim()

        _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        order_params = next(
            params for query, params in connection.executions if "SET captured_total_minor" in query
        )
        self.assertEqual(AMOUNT * 2, order_params["captured_total_minor"])
        self.assertEqual("OVERPAID", order_params["canonical_truth"])
        case_params = next(
            params
            for query, params in connection.executions
            if "SET state = %(new_case_state)s" in query
        )
        self.assertEqual("DUPLICATE_REVIEW", case_params["new_case_state"])

    def test_mapping_conflict_is_ignored_without_money_mutation(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment\nJOIN",
                    lambda _params: _capture_target_row(amount_due=AMOUNT + 1),
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                *_settlement_steps("IGNORED"),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertIs(result.disposition, ProjectionDisposition.IGNORED)
        self.assertEqual("captured_payment_mapping_conflict", result.reason_code)
        self.assertFalse(
            any("SET captured_total_minor" in query for query, _ in connection.executions)
        )

    def test_malformed_capture_evidence_rolls_back_before_inbox_claim(self) -> None:
        canonical = _capture_canonical(captured=False)
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step(
                    "FROM retrywise.inbox_events AS inbox",
                    lambda _params: _event_row(canonical=canonical),
                ),
                _Step("body_sha256 =", lambda _params: None),
            ]
        )
        claim = _claim()

        with self.assertRaises(NormalizedEventEvidenceError):
            _repository(connection).project(
                decode_process_normalized_provider_event_command(claim), claim=claim
            )

        self.assertEqual(1, connection.rollbacks)
        self.assertFalse(
            any("SET status = 'PROCESSING'" in query for query, _ in connection.executions)
        )

    def test_final_outbox_fence_loss_rolls_back_all_terminal_money_mutations(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment\nJOIN",
                    lambda _params: _capture_target_row(),
                ),
                _Step("ORDER BY payment.id", lambda _params: [_path_payment_row()], many=True),
                _Step("ORDER BY instrument.id", lambda _params: [], many=True),
                _Step("ORDER BY recovery_case.id", lambda _params: [], many=True),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("SET status = 'CAPTURED'", lambda _params: ("CAPTURED",)),
                _Step("SET captured_total_minor", lambda _params: ("PAID",)),
                _Step("SELECT lease_expires_at >", lambda _params: (False,)),
            ]
        )
        claim = _claim()

        with self.assertRaises(NormalizedEventFenceLost):
            _repository(connection).project(
                decode_process_normalized_provider_event_command(claim), claim=claim
            )

        self.assertEqual(1, connection.rollbacks)
        self.assertEqual(0, connection.commits)
        self.assertFalse(
            any("SET status = %(inbox_status)s" in query for query, _ in connection.executions)
        )


class PaymentLinkProjectionTests(unittest.TestCase):
    def _project_link(
        self,
        *,
        event_type: str = "payment_link.paid",
        amount_paid: int = AMOUNT,
        target: Sequence[object] | None = None,
        original_payment: Sequence[object] | None = None,
        instrument: Sequence[object] | None = None,
        expected_truth: str = "PAID",
        expected_case: str = "RECOVERED",
    ) -> tuple[NormalizedEventProjectionResult, _FakeConnection]:
        canonical = _link_canonical(event_type, amount_paid=amount_paid)
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step(
                    "FROM retrywise.inbox_events AS inbox",
                    lambda _params: _event_row(event_type=event_type, canonical=canonical),
                ),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.recovery_instruments AS instrument\nJOIN",
                    lambda _params: target or _link_target_row(),
                ),
                _Step(
                    "ORDER BY payment.id",
                    lambda _params: [original_payment or _path_payment_row()],
                    many=True,
                ),
                _Step(
                    "ORDER BY instrument.id",
                    lambda _params: [instrument or _path_instrument_row()],
                    many=True,
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step(
                    "SET status = %(new_instrument_status)s",
                    lambda _params: (
                        "PAID" if event_type == "payment_link.paid" else "PARTIALLY_PAID",
                    ),
                ),
                _Step("SET captured_total_minor", lambda _params: (expected_truth,)),
                _Step("SET state = %(new_case_state)s", lambda _params: (expected_case,)),
                *_settlement_steps(),
            ]
        )
        claim = _claim(event_type)
        return (
            _repository(connection).project(
                decode_process_normalized_provider_event_command(claim), claim=claim
            ),
            connection,
        )

    def test_exact_paid_link_marks_instrument_order_and_case_recovered(self) -> None:
        result, connection = self._project_link()

        self.assertIs(result.disposition, ProjectionDisposition.PROCESSED)
        instrument_params = next(
            params
            for query, params in connection.executions
            if "SET status = %(new_instrument_status)s" in query
        )
        self.assertEqual("PAID", instrument_params["new_instrument_status"])
        self.assertEqual("pay_recovery", instrument_params["provider_payment_id"])
        case_params = next(
            params
            for query, params in connection.executions
            if "SET state = %(new_case_state)s" in query
        )
        self.assertEqual("RECOVERED", case_params["new_case_state"])
        self.assertEqual("recovery_payment_link_paid", case_params["terminal_reason_code"])

    def test_forbidden_partial_payment_is_projected_to_explicit_review(self) -> None:
        amount_paid = 40_000
        result, connection = self._project_link(
            event_type="payment_link.partially_paid",
            amount_paid=amount_paid,
            instrument=_path_instrument_row(),
            expected_truth="PARTIALLY_PAID",
            expected_case="DUPLICATE_REVIEW",
        )

        self.assertIs(result.disposition, ProjectionDisposition.PROCESSED)
        order_params = next(
            params for query, params in connection.executions if "SET captured_total_minor" in query
        )
        self.assertEqual(amount_paid, order_params["captured_total_minor"])
        self.assertEqual("PARTIALLY_PAID", order_params["canonical_truth"])
        case_params = next(
            params
            for query, params in connection.executions
            if "SET state = %(new_case_state)s" in query
        )
        self.assertEqual(
            "partial_collection_violated_link_contract", case_params["terminal_reason_code"]
        )

    def test_paid_link_after_original_capture_is_overpaid_duplicate_review(self) -> None:
        _, connection = self._project_link(
            target=_link_target_row(canonical_truth="PAID", captured_total=AMOUNT),
            original_payment=_path_payment_row(status="CAPTURED", captured_minor=AMOUNT),
            expected_truth="OVERPAID",
            expected_case="DUPLICATE_REVIEW",
        )

        order_params = next(
            params for query, params in connection.executions if "SET captured_total_minor" in query
        )
        self.assertEqual(AMOUNT * 2, order_params["captured_total_minor"])
        case_params = next(
            params
            for query, params in connection.executions
            if "SET state = %(new_case_state)s" in query
        )
        self.assertEqual(
            "both_original_and_recovery_paths_collected", case_params["terminal_reason_code"]
        )

    def test_paid_money_after_cancelled_link_dominates_and_opens_duplicate_review(self) -> None:
        _, connection = self._project_link(
            target=_link_target_row(
                instrument_status="CANCELLED",
                case_state="SUPPRESSED_PAID",
                canonical_truth="PAID",
                captured_total=AMOUNT,
            ),
            original_payment=_path_payment_row(status="CAPTURED", captured_minor=AMOUNT),
            instrument=_path_instrument_row(status="CANCELLED"),
            expected_truth="OVERPAID",
            expected_case="DUPLICATE_REVIEW",
        )

        instrument_params = next(
            params
            for query, params in connection.executions
            if "SET status = %(new_instrument_status)s" in query
        )
        self.assertEqual("CANCELLED", instrument_params["expected_instrument_status"])
        self.assertEqual("PAID", instrument_params["new_instrument_status"])
        case_params = next(
            params
            for query, params in connection.executions
            if "SET state = %(new_case_state)s" in query
        )
        self.assertEqual("DUPLICATE_REVIEW", case_params["new_case_state"])
        self.assertEqual(
            "both_original_and_recovery_paths_collected", case_params["terminal_reason_code"]
        )

    def test_partial_money_after_expired_link_dominates_to_manual_review(self) -> None:
        amount_paid = 40_000
        _, connection = self._project_link(
            event_type="payment_link.partially_paid",
            amount_paid=amount_paid,
            target=_link_target_row(
                instrument_status="EXPIRED",
                case_state="EXHAUSTED",
            ),
            instrument=_path_instrument_row(status="EXPIRED"),
            expected_truth="PARTIALLY_PAID",
            expected_case="DUPLICATE_REVIEW",
        )

        instrument_params = next(
            params
            for query, params in connection.executions
            if "SET status = %(new_instrument_status)s" in query
        )
        self.assertEqual("EXPIRED", instrument_params["expected_instrument_status"])
        self.assertEqual("PARTIALLY_PAID", instrument_params["new_instrument_status"])
        case_params = next(
            params
            for query, params in connection.executions
            if "SET state = %(new_case_state)s" in query
        )
        self.assertEqual(
            "partial_collection_violated_link_contract", case_params["terminal_reason_code"]
        )

    def test_reference_conflict_is_ignored_before_instrument_mutation(self) -> None:
        canonical = _link_canonical()
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step(
                    "FROM retrywise.inbox_events AS inbox",
                    lambda _params: _event_row(event_type="payment_link.paid", canonical=canonical),
                ),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.recovery_instruments AS instrument\nJOIN",
                    lambda _params: _link_target_row(reference_id="rtw_wrong_reference"),
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                *_settlement_steps("IGNORED"),
            ]
        )
        claim = _claim("payment_link.paid")

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertEqual("recovery_payment_link_mapping_conflict", result.reason_code)
        self.assertFalse(
            any(
                "SET status = %(new_instrument_status)s" in query
                for query, _ in connection.executions
            )
        )

    def test_cancelled_and_expired_are_retained_but_not_business_projected(self) -> None:
        for event_type, provider_status in (
            ("payment_link.cancelled", "cancelled"),
            ("payment_link.expired", "expired"),
        ):
            with self.subTest(event_type=event_type):
                canonical = _link_canonical(
                    "payment_link.paid",
                    resource_updates={"status": provider_status},
                )
                canonical["event_name"] = event_type
                canonical["event_type"] = event_type
                connection = _FakeConnection(
                    [
                        _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                        _Step(
                            "FROM retrywise.inbox_events AS inbox",
                            lambda _params, e=event_type, c=canonical: _event_row(
                                event_type=e, canonical=c
                            ),
                        ),
                        _Step("body_sha256 =", lambda _params: None),
                        _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                        *_settlement_steps("IGNORED"),
                    ]
                )
                claim = _claim(event_type)

                result = _repository(connection).project(
                    decode_process_normalized_provider_event_command(claim), claim=claim
                )

                self.assertEqual(
                    "terminal_link_event_requires_case_policy_projection", result.reason_code
                )
                self.assertFalse(
                    any(
                        "recovery_instruments AS instrument\nJOIN" in query
                        for query, _ in connection.executions
                    )
                )


class StrictEvidenceValidationTests(unittest.TestCase):
    def test_capture_decoder_rejects_ambiguous_money_identity_and_related_evidence(self) -> None:
        invalid: list[Mapping[str, object]] = []

        wrong_event = _capture_canonical()
        wrong_event["event_type"] = "payment.authorized"
        invalid.append(wrong_event)

        missing_amount = _capture_canonical()
        del missing_amount["resource"]["amount"]  # type: ignore[index]
        invalid.append(missing_amount)

        refunded = _capture_canonical(amount_refunded=1)
        invalid.append(refunded)

        bad_method = _capture_canonical(method="UPI CUSTOMER")
        invalid.append(bad_method)

        bad_currency = _capture_canonical(currency="inr")
        invalid.append(bad_currency)

        unexpected_related = _capture_canonical()
        unexpected_related["related_resources"]["customer"] = {}  # type: ignore[index]
        invalid.append(unexpected_related)

        disagreed_related = _capture_canonical()
        disagreed_related["related_resources"]["payment"] = {"id": "pay_other"}  # type: ignore[index]
        invalid.append(disagreed_related)

        for canonical in invalid:
            with (
                self.subTest(canonical=canonical),
                self.assertRaises(NormalizedEventEvidenceError),
            ):
                terminal._captured_payment(canonical)

    def test_link_decoder_rejects_partial_mode_money_and_cross_resource_conflicts(self) -> None:
        invalid: list[Mapping[str, object]] = []

        wrong_event = _link_canonical()
        wrong_event["event_type"] = "payment_link.cancelled"
        invalid.append(wrong_event)

        mismatched_envelope = _link_canonical()
        mismatched_envelope["event_name"] = "payment_link.partially_paid"
        invalid.append(mismatched_envelope)

        status_conflict = _link_canonical(resource_updates={"status": "created"})
        invalid.append(status_conflict)

        partial_enabled = _link_canonical(resource_updates={"accept_partial": True})
        invalid.append(partial_enabled)

        upi_link = _link_canonical(resource_updates={"upi_link": True})
        invalid.append(upi_link)

        short_paid = _link_canonical(amount_paid=AMOUNT - 1)
        invalid.append(short_paid)

        zero_partial = _link_canonical("payment_link.partially_paid", amount_paid=0)
        invalid.append(zero_partial)

        full_partial = _link_canonical("payment_link.partially_paid", amount_paid=AMOUNT)
        invalid.append(full_partial)

        unexpected_related = _link_canonical()
        unexpected_related["related_resources"]["customer"] = {}  # type: ignore[index]
        invalid.append(unexpected_related)

        link_disagreement = _link_canonical()
        link_disagreement["related_resources"]["payment_link"] = {"id": "plink_other"}  # type: ignore[index]
        invalid.append(link_disagreement)

        missing_payment = _link_canonical()
        del missing_payment["related_resources"]["payment"]  # type: ignore[index]
        invalid.append(missing_payment)

        payment_not_captured = _link_canonical(payment_updates={"captured": False})
        invalid.append(payment_not_captured)

        payment_order_conflict = _link_canonical(payment_updates={"order_id": "order_other"})
        invalid.append(payment_order_conflict)

        payment_currency_conflict = _link_canonical(payment_updates={"currency": "USD"})
        invalid.append(payment_currency_conflict)

        payment_too_large = _link_canonical(payment_updates={"amount": AMOUNT + 1})
        invalid.append(payment_too_large)

        payment_refunded = _link_canonical(payment_updates={"amount_refunded": 1})
        invalid.append(payment_refunded)

        malformed_order = _link_canonical()
        malformed_order["related_resources"]["order"] = "not-an-object"  # type: ignore[index]
        invalid.append(malformed_order)

        order_money_conflict = _link_canonical()
        order_money_conflict["related_resources"]["order"]["amount_paid"] = 1  # type: ignore[index]
        invalid.append(order_money_conflict)

        for canonical in invalid:
            with (
                self.subTest(canonical=canonical),
                self.assertRaises(NormalizedEventEvidenceError),
            ):
                terminal._payment_link_collection(canonical)

        without_order = _link_canonical()
        del without_order["related_resources"]["order"]  # type: ignore[index]
        decoded = terminal._payment_link_collection(without_order)
        self.assertEqual("pay_recovery", decoded.provider_payment_id)

    def test_persisted_row_decoders_reject_wrong_shapes_and_types(self) -> None:
        self.assertIsNone(terminal._capture_target(None))
        self.assertIsNone(terminal._link_target(None))
        invalid_calls: list[Callable[[], object]] = [
            lambda: terminal._capture_target(("short",)),
            lambda: terminal._capture_target((None, *_capture_target_row()[1:])),
            lambda: terminal._capture_target(
                (*_capture_target_row()[:3], 7, *_capture_target_row()[4:])
            ),
            lambda: terminal._capture_target(
                (*_capture_target_row()[:5], "129900", *_capture_target_row()[6:])
            ),
            lambda: terminal._capture_target(
                (*_capture_target_row()[:10], None, *_capture_target_row()[11:])
            ),
            lambda: terminal._link_target(("short",)),
            lambda: terminal._link_target((None, *_link_target_row()[1:])),
            lambda: terminal._link_target((*_link_target_row()[:4], 7, *_link_target_row()[5:])),
            lambda: terminal._link_target(
                (*_link_target_row()[:8], "129900", *_link_target_row()[9:])
            ),
            lambda: terminal._link_target(
                (*_link_target_row()[:11], "false", *_link_target_row()[12:])
            ),
            lambda: terminal._path_payment(("short",)),
            lambda: terminal._path_payment((*_path_payment_row()[:2], 7, *_path_payment_row()[3:])),
            lambda: terminal._path_payment(
                (*_path_payment_row()[:4], "129900", *_path_payment_row()[5:])
            ),
            lambda: terminal._path_instrument(("short",)),
            lambda: terminal._path_instrument(
                (*_path_instrument_row()[:3], "129900", *_path_instrument_row()[4:])
            ),
            lambda: terminal._path_instrument(
                (*_path_instrument_row()[:7], 7, *_path_instrument_row()[8:])
            ),
            lambda: terminal._case(("short",)),
            lambda: terminal._case((CASE_ID, "ACTIVE", "7", None, None)),
            lambda: terminal._case((CASE_ID, "ACTIVE", 7, 7, None)),
        ]
        for call in invalid_calls:
            with (
                self.subTest(call=call),
                self.assertRaises((NormalizedEventEvidenceError, RuntimeError)),
            ):
                call()

    def test_money_path_aggregation_is_absolute_bounded_and_monotonic(self) -> None:
        payment = terminal._path_payment(_path_payment_row())
        instrument = terminal._path_instrument(_path_instrument_row())
        capture = terminal._captured_payment(_capture_canonical())
        link = terminal._payment_link_collection(_link_canonical())

        self.assertEqual(
            AMOUNT,
            terminal._original_total(
                (payment,),
                currency="INR",
                capture_override=capture,
                capture_record_id=PAYMENT_RECORD_ID,
            ),
        )
        self.assertEqual(
            AMOUNT,
            terminal._recovery_total(
                (instrument,),
                currency="INR",
                link_override=link,
                instrument_id=INSTRUMENT_ID,
            ),
        )
        self.assertEqual("PARTIALLY_PAID", terminal._truth_for_total(1, AMOUNT))
        self.assertEqual("PAID", terminal._truth_for_total(AMOUNT, AMOUNT))
        self.assertEqual("OVERPAID", terminal._truth_for_total(AMOUNT + 1, AMOUNT))
        self.assertTrue(
            terminal._money_is_monotonic(
                current_total=0,
                projected_total=AMOUNT,
                refunded_total=0,
                current_truth="UNPAID",
                projected_truth="PAID",
            )
        )
        self.assertFalse(
            terminal._money_is_monotonic(
                current_total=AMOUNT,
                projected_total=AMOUNT - 1,
                refunded_total=0,
                current_truth="PAID",
                projected_truth="PARTIALLY_PAID",
            )
        )
        self.assertFalse(
            terminal._money_is_monotonic(
                current_total=0,
                projected_total=AMOUNT,
                refunded_total=0,
                current_truth="EXCEPTION",
                projected_truth="PAID",
            )
        )

        with self.assertRaises(NormalizedEventEvidenceError):
            terminal._checked_sum(((1 << 63) - 1, 1), field="overflow")
        with self.assertRaises(NormalizedEventEvidenceError):
            terminal._truth_for_total(0, AMOUNT)
        with self.assertRaises(NormalizedEventEvidenceError):
            terminal._original_total(
                (payment,),
                currency="USD",
                capture_override=capture,
                capture_record_id=PAYMENT_RECORD_ID,
            )
        with self.assertRaises(NormalizedEventEvidenceError):
            terminal._original_total(
                (payment,),
                currency="INR",
                capture_override=capture,
                capture_record_id="01ARZ3NDEKTSV4RRFFQ69G5FC0",
            )
        with self.assertRaises(NormalizedEventEvidenceError):
            terminal._recovery_total(
                (instrument,),
                currency="USD",
                link_override=link,
                instrument_id=INSTRUMENT_ID,
            )
        with self.assertRaises(NormalizedEventEvidenceError):
            terminal._recovery_total(
                (instrument,),
                currency="INR",
                link_override=link,
                instrument_id="01ARZ3NDEKTSV4RRFFQ69G5FC0",
            )


class IdempotencyAndHandlerTests(unittest.TestCase):
    def test_terminal_inbox_redelivery_rechecks_fence_without_reprojection(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step(
                    "FROM retrywise.inbox_events AS inbox",
                    lambda _params: _event_row(inbox_status="PROCESSED"),
                ),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertIs(result.disposition, ProjectionDisposition.PROCESSED)
        self.assertEqual(3, len(connection.executions))

    def test_same_body_under_different_event_id_is_ignored(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: ("evt_reused",)),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                *_settlement_steps("IGNORED"),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertEqual("suspicious_body_reused_across_event_ids", result.reason_code)
        self.assertFalse(
            any("provider_payments AS payment\nJOIN" in query for query, _ in connection.executions)
        )

    def test_handler_retries_fence_loss_and_rejects_nonterminal_dispatch(self) -> None:
        class FenceLostRepository:
            def project(self, *_args: object, **_kwargs: object) -> NormalizedEventProjectionResult:
                raise NormalizedEventFenceLost("lost")

        handler = ProcessTerminalProviderEventHandler(FenceLostRepository())

        retry = handler(_claim())
        unsupported = handler(_claim("payment.failed"))

        self.assertIs(retry.disposition, HandlerDisposition.RETRY)
        self.assertIs(retry.retry_mode, RetryMode.RECONCILE_ONLY)
        self.assertEqual("terminal_event_fence_lost", retry.reason)
        self.assertIs(unsupported.disposition, HandlerDisposition.DEAD_LETTER)
        self.assertEqual("unsupported_terminal_event_command", unsupported.reason)


if __name__ == "__main__":
    unittest.main()
