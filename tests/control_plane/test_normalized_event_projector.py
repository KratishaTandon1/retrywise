from __future__ import annotations

import json
import unittest
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from retrywise.services.control_plane.normalized_event_projector import (
    MAX_NORMALIZED_EVENT_COMMAND_BYTES,
    NormalizedEventBindingError,
    NormalizedEventBusy,
    NormalizedEventCommandError,
    NormalizedEventEvidenceError,
    NormalizedEventFenceLost,
    NormalizedEventProjectionResult,
    PostgresNormalizedEventRepository,
    ProcessNormalizedProviderEventCommand,
    ProcessNormalizedProviderEventHandler,
    ProjectionDisposition,
    decode_process_normalized_provider_event_command,
)
from retrywise.services.control_plane.outbox import RetryMode
from retrywise.services.control_plane.outbox_worker import HandlerDisposition
from retrywise.services.control_plane.postgres_outbox import ClaimedOutboxCommand

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
EVENT_RECORD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
INBOX_EVENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
PAYMENT_RECORD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
LOGICAL_ORDER_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
EXISTING_CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB3"
ENRICHMENT_JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB4"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
OCCURRED_AT = datetime.fromtimestamp(1_788_000_000, UTC)
BODY_DIGEST = bytes.fromhex("ab" * 32)


def _payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "event_type": "payment.failed",
        "inbox_event_id": INBOX_EVENT_ID,
        "merchant_id": MERCHANT_ID,
        "provider_account_id": PROVIDER_ACCOUNT_ID,
        "provider_event_id": "evt_test_1",
        "provider_event_record_id": EVENT_RECORD_ID,
        "schema_version": 1,
    }
    payload.update(updates)
    return payload


def _claim(**updates: object) -> ClaimedOutboxCommand:
    values: dict[str, object] = {
        "job_id": JOB_ID,
        "merchant_id": MERCHANT_ID,
        "aggregate_type": "PROVIDER_EVENT",
        "aggregate_id": EVENT_RECORD_ID,
        "command_type": "PROCESS_NORMALIZED_PROVIDER_EVENT",
        "command_schema_version": 1,
        "command_payload": _payload(),
        "idempotency_key": f"normalized-provider-event:{EVENT_RECORD_ID}",
        "attempt_count": 1,
        "max_attempts": 8,
        "worker_id": "normalized-worker-a",
        "lease_token": "lease-token-1",
        "lease_expires_at": NOW + timedelta(seconds=30),
        "delivery_version": 1,
        "retry_mode": RetryMode.RECONCILE_ONLY,
        "created_at": NOW - timedelta(minutes=1),
        "claimed_at": NOW,
    }
    values.update(updates)
    return ClaimedOutboxCommand(**values)  # type: ignore[arg-type]


def _canonical(
    *,
    event_name: str = "payment.failed",
    event_type: str | None = None,
    resource_type: str = "payment",
    resource_id: str | None = "pay_test_1",
    resource_updates: Mapping[str, object] | None = None,
) -> dict[str, object]:
    resource: dict[str, object] = {
        "amount": 129_900,
        "captured": False,
        "currency": "INR",
        "entity": "payment",
        "error_code": "BAD_REQUEST_ERROR",
        "error_reason": "payment_failed",
        "error_source": "customer",
        "error_step": "payment_authentication",
        "id": "pay_test_1",
        "method": "upi",
        "order_id": "order_test_1",
        "status": "failed",
    }
    if resource_updates:
        resource.update(resource_updates)
    return {
        "schema_version": 1,
        "event_id": "evt_test_1",
        "provider_account_id": "acc_test_1",
        "event_name": event_name,
        "event_type": event_type or event_name,
        "occurred_at_epoch": 1_788_000_000,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource": resource,
        "related_resources": {"payment": dict(resource)},
        "raw_body_sha256": BODY_DIGEST.hex(),
    }


def _event_row(
    *,
    inbox_status: str = "RECEIVED",
    attempt_count: int = 0,
    max_attempts: int = 8,
    processing_lease_expired: bool = False,
    event_type: str = "payment.failed",
    resource_type: str = "payment",
    resource_id: str | None = "pay_test_1",
    canonical: Mapping[str, object] | None = None,
    signature_verified: bool = True,
    account_verified: bool = True,
    provider_account_identifier: str = "acc_test_1",
) -> Sequence[object]:
    return (
        INBOX_EVENT_ID,
        inbox_status,
        attempt_count,
        max_attempts,
        processing_lease_expired,
        MERCHANT_ID,
        PROVIDER_ACCOUNT_ID,
        provider_account_identifier,
        EVENT_RECORD_ID,
        "evt_test_1",
        event_type,
        resource_type,
        resource_id,
        BODY_DIGEST,
        signature_verified,
        account_verified,
        1,
        dict(canonical or _canonical()),
        OCCURRED_AT,
        NOW,
    )


def _payment_row(
    *,
    status: str = "CREATED",
    error_facts: Mapping[str, object] | None = None,
    canonical_truth: str = "UNPAID",
    provider_order_id: str | None = "order_test_1",
    original_provider_order_id: str | None = "order_test_1",
    mapping_status: str = "MAPPED",
    amount_minor: int = 129_900,
    amount_due_minor: int = 129_900,
    currency: str = "INR",
    order_currency: str = "INR",
    payment_method: str | None = None,
    provider_snapshot_at: datetime = OCCURRED_AT - timedelta(seconds=10),
) -> Sequence[object]:
    return (
        PAYMENT_RECORD_ID,
        LOGICAL_ORDER_ID,
        "pay_test_1",
        provider_order_id,
        status,
        amount_minor,
        currency,
        payment_method,
        dict(error_facts or {}),
        provider_snapshot_at,
        original_provider_order_id,
        amount_due_minor,
        order_currency,
        canonical_truth,
        mapping_status,
    )


def _case_row(
    case_id: str = CASE_ID,
    *,
    state: str = "OBSERVING",
    contract_version: int = 1,
    observation_window: timedelta = timedelta(minutes=2),
) -> Sequence[object]:
    return (
        case_id,
        state,
        contract_version,
        NOW,
        NOW + observation_window,
    )


RowFactory = Callable[[Mapping[str, object]], Sequence[object] | None]


@dataclass(frozen=True)
class _Step:
    marker: str
    row_factory: RowFactory = lambda _params: None


class _FakeCursor:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection
        self._row: Sequence[object] | None = None

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
        self._row = step.row_factory(copied_params)

    def fetchone(self) -> Sequence[object] | None:
        return self._row


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

    def __call__(self) -> _FakeConnection:
        return self.connection


def _repository(connection: _FakeConnection) -> PostgresNormalizedEventRepository:
    return PostgresNormalizedEventRepository(
        connector=_FakeConnector(connection),
        case_id_factory=lambda: CASE_ID,
        enrichment_job_id_factory=lambda: ENRICHMENT_JOB_ID,
    )


class NormalizedEventCommandCodecTests(unittest.TestCase):
    def test_decodes_exact_v1_payload_and_all_envelope_bindings(self) -> None:
        decoded = decode_process_normalized_provider_event_command(_claim())

        self.assertEqual(MERCHANT_ID, decoded.merchant_id)
        self.assertEqual(PROVIDER_ACCOUNT_ID, decoded.provider_account_id)
        self.assertEqual(EVENT_RECORD_ID, decoded.provider_event_record_id)
        self.assertEqual(INBOX_EVENT_ID, decoded.inbox_event_id)
        self.assertEqual("evt_test_1", decoded.provider_event_id)
        self.assertEqual("payment.failed", decoded.event_type)

    def test_rejects_missing_unknown_and_wrongly_typed_payload_fields(self) -> None:
        malformed_payloads = []
        missing = _payload()
        missing.pop("inbox_event_id")
        malformed_payloads.append(missing)
        malformed_payloads.append(_payload(unknown="x"))
        malformed_payloads.append(_payload(schema_version=True))
        malformed_payloads.append(_payload(provider_event_id=" event "))
        malformed_payloads.append(_payload(provider_account_id="not-a-ulid"))

        for payload in malformed_payloads:
            with self.subTest(payload=payload), self.assertRaises(NormalizedEventCommandError):
                decode_process_normalized_provider_event_command(_claim(command_payload=payload))

    def test_rejects_every_outbox_envelope_mismatch(self) -> None:
        mismatches: list[dict[str, object]] = [
            {"command_type": "OTHER"},
            {"command_schema_version": 2},
            {"aggregate_type": "OTHER"},
            {"aggregate_id": LOGICAL_ORDER_ID},
            {"merchant_id": PROVIDER_ACCOUNT_ID},
            {"idempotency_key": "normalized-provider-event:wrong"},
        ]
        for updates in mismatches:
            with self.subTest(updates=updates), self.assertRaises(NormalizedEventCommandError):
                decode_process_normalized_provider_event_command(_claim(**updates))

    def test_rejects_non_json_and_oversized_payloads(self) -> None:
        non_json = _payload()
        non_json["event_type"] = object()
        with self.assertRaisesRegex(NormalizedEventCommandError, "JSON"):
            decode_process_normalized_provider_event_command(_claim(command_payload=non_json))

        oversized = _payload(event_type="x" * MAX_NORMALIZED_EVENT_COMMAND_BYTES)
        with self.assertRaisesRegex(NormalizedEventCommandError, "4 KiB"):
            decode_process_normalized_provider_event_command(_claim(command_payload=oversized))

    def test_requires_a_claimed_command_instance(self) -> None:
        with self.assertRaises(TypeError):
            decode_process_normalized_provider_event_command(object())  # type: ignore[arg-type]


class PostgresNormalizedEventRepositoryTests(unittest.TestCase):
    def test_projects_failure_and_creates_one_db_timed_observing_case(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment", lambda _params: _payment_row()
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("UPDATE retrywise.provider_payments", lambda _params: ("FAILED",)),
                _Step("INSERT INTO retrywise.recovery_cases", lambda _params: _case_row()),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("PROCESSED",)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim),
            claim=claim,
        )

        self.assertIs(result.disposition, ProjectionDisposition.PROCESSED)
        self.assertEqual(CASE_ID, result.recovery_case_id)
        self.assertTrue(result.recovery_case_created)
        self.assertEqual(
            f"normalized-provider-event:{EVENT_RECORD_ID}:processed:case:{CASE_ID}",
            result.completion_reference,
        )
        self.assertEqual(1, connection.transactions_committed)
        self.assertEqual([], connection.steps)

        outbox_query, outbox_params = connection.executions[0]
        self.assertIn("FOR UPDATE OF job", outbox_query)
        self.assertIn("lease_expires_at > clock_timestamp()", outbox_query)
        self.assertEqual(claim.lease_token, outbox_params["lease_token"])
        self.assertEqual(
            _payload(),
            json.loads(str(outbox_params["command_payload"])),
        )
        evidence_query = connection.executions[1][0]
        self.assertIn("JOIN retrywise.provider_accounts AS account", evidence_query)
        self.assertIn("account.environment = 'TEST'", evidence_query)
        self.assertIn("account.enabled", evidence_query)
        self.assertIn("FOR SHARE OF account", evidence_query)
        payment_params = connection.executions[5][1]
        payment_query = connection.executions[5][0]
        self.assertIn("updated_at = clock_timestamp()", payment_query)
        error_facts = json.loads(str(payment_params["error_facts"]))
        self.assertEqual("payment-failed/v1", error_facts["projection_contract"])
        self.assertEqual(EVENT_RECORD_ID, error_facts["retrywise_provider_event_record_id"])
        self.assertNotIn("customer", error_facts)
        insert_query = connection.executions[6][0]
        insert_columns = insert_query.split(") VALUES", 1)[0]
        self.assertNotIn("observation_started_at", insert_columns)
        self.assertNotIn("observation_deadline_at", insert_columns)
        self.assertIn("observation_started_at", insert_query.split("RETURNING", 1)[1])
        settlement_params = connection.executions[-1][1]
        settlement_query = connection.executions[-1][0]
        self.assertEqual("PROCESSED", settlement_params["inbox_status"])
        self.assertIsNone(settlement_params["reason_code"])
        self.assertEqual(2, settlement_query.count("%(reason_code)s::text"))

    def test_same_body_under_another_event_id_is_ignored_before_payment_mutation(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: ("evt_reused",)),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("IGNORED",)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertIs(result.disposition, ProjectionDisposition.IGNORED)
        self.assertEqual("suspicious_body_reused_across_event_ids", result.reason_code)
        self.assertFalse(
            any("UPDATE retrywise.provider_payments" in query for query, _ in connection.executions)
        )
        self.assertEqual("IGNORED", connection.executions[-1][1]["inbox_status"])

    def test_unsupported_event_is_explicitly_ignored(self) -> None:
        canonical = _canonical(event_name="payment.captured")
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step(
                    "FROM retrywise.inbox_events AS inbox",
                    lambda _params: _event_row(event_type="payment.captured", canonical=canonical),
                ),
                _Step("body_sha256 =", lambda _params: None),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("IGNORED",)),
            ]
        )
        claim = _claim(command_payload=_payload(event_type="payment.captured"))

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertEqual("unsupported_event_type", result.reason_code)
        self.assertIs(result.disposition, ProjectionDisposition.IGNORED)

    def test_terminal_inbox_redelivery_is_idempotent_and_does_not_reproject(self) -> None:
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
        self.assertFalse(result.recovery_case_created)
        self.assertEqual(3, len(connection.executions))

    def test_missing_mapping_is_deferred_but_conflicts_are_ignored_fail_closed(self) -> None:
        mappings: list[Sequence[object] | None] = [
            None,
            _payment_row(amount_due_minor=200_000),
            _payment_row(mapping_status="AMBIGUOUS"),
            _payment_row(payment_method="card"),
        ]
        reasons = [
            "provider_payment_projection_not_ready",
            "payment_mapping_conflict",
            "payment_mapping_conflict",
            "payment_mapping_conflict",
        ]
        dispositions = [
            ProjectionDisposition.RETRY_SCHEDULED,
            ProjectionDisposition.IGNORED,
            ProjectionDisposition.IGNORED,
            ProjectionDisposition.IGNORED,
        ]
        for mapping, expected_reason, expected_disposition in zip(
            mappings,
            reasons,
            dispositions,
            strict=True,
        ):
            with self.subTest(expected_reason=expected_reason):
                settlement = (
                    _Step(
                        "SET status = 'RETRY_SCHEDULED'",
                        lambda _params: ("RETRY_SCHEDULED",),
                    )
                    if expected_disposition is ProjectionDisposition.RETRY_SCHEDULED
                    else _Step(
                        "SET status = %(inbox_status)s",
                        lambda _params: ("IGNORED",),
                    )
                )
                connection = _FakeConnection(
                    [
                        _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                        _Step(
                            "FROM retrywise.inbox_events AS inbox",
                            lambda _params: _event_row(),
                        ),
                        _Step("body_sha256 =", lambda _params: None),
                        _Step(
                            "FROM retrywise.provider_payments AS payment",
                            lambda _params, row=mapping: row,
                        ),
                        _Step(
                            "SET status = 'PROCESSING'",
                            lambda _params: ("PROCESSING", 1),
                        ),
                        *(
                            [
                                _Step(
                                    "INSERT INTO retrywise.outbox_jobs",
                                    lambda _params: (ENRICHMENT_JOB_ID,),
                                )
                            ]
                            if mapping is None
                            else []
                        ),
                        _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                        settlement,
                    ]
                )
                claim = _claim()

                result = _repository(connection).project(
                    decode_process_normalized_provider_event_command(claim), claim=claim
                )

                self.assertEqual(expected_reason, result.reason_code)
                self.assertIs(expected_disposition, result.disposition)
                self.assertFalse(
                    any(
                        "UPDATE retrywise.provider_payments" in query
                        for query, _ in connection.executions
                    )
                )
                if mapping is None:
                    enqueue = next(
                        params
                        for query, params in connection.executions
                        if "INSERT INTO retrywise.outbox_jobs" in query
                    )
                    self.assertEqual("pay_test_1", enqueue["enrichment_provider_payment_id"])
                    self.assertNotIn("evt_test_1", str(enqueue["enrichment_payload"]))

    def test_orderless_provider_payment_is_valid_evidence_but_not_recovery_eligible(self) -> None:
        canonical = _canonical(resource_updates={"order_id": None})
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step(
                    "FROM retrywise.inbox_events AS inbox",
                    lambda _params: _event_row(canonical=canonical),
                ),
                _Step("body_sha256 =", lambda _params: None),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("IGNORED",)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertEqual("payment_missing_order_binding", result.reason_code)
        self.assertFalse(
            any(
                "FROM retrywise.provider_payments AS payment" in query
                for query, _ in connection.executions
            )
        )

    def test_authorized_or_paid_state_dominates_stale_failed_event(self) -> None:
        for payment_status in ("AUTHORIZED", "CAPTURED", "REFUNDED"):
            with self.subTest(payment_status=payment_status):
                connection = _FakeConnection(
                    [
                        _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                        _Step(
                            "FROM retrywise.inbox_events AS inbox",
                            lambda _params: _event_row(),
                        ),
                        _Step("body_sha256 =", lambda _params: None),
                        _Step(
                            "FROM retrywise.provider_payments AS payment",
                            lambda _params, status=payment_status: _payment_row(status=status),
                        ),
                        _Step(
                            "SET status = 'PROCESSING'",
                            lambda _params: ("PROCESSING", 1),
                        ),
                        _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                        _Step(
                            "SET status = %(inbox_status)s",
                            lambda _params: ("IGNORED",),
                        ),
                    ]
                )
                claim = _claim()

                result = _repository(connection).project(
                    decode_process_normalized_provider_event_command(claim), claim=claim
                )

                self.assertEqual(
                    "capture_capable_payment_state_dominates_failure",
                    result.reason_code,
                )
                self.assertIs(result.disposition, ProjectionDisposition.IGNORED)
                self.assertFalse(
                    any(
                        "UPDATE retrywise.provider_payments" in query
                        for query, _ in connection.executions
                    )
                )
                self.assertFalse(
                    any(
                        "INSERT INTO retrywise.recovery_cases" in query
                        for query, _ in connection.executions
                    )
                )

    def test_newer_provider_snapshot_dominates_out_of_order_failure(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment",
                    lambda _params: _payment_row(
                        provider_snapshot_at=OCCURRED_AT + timedelta(seconds=1)
                    ),
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("IGNORED",)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertEqual("stale_provider_snapshot_dominates_failure", result.reason_code)
        self.assertFalse(
            any("UPDATE retrywise.provider_payments" in query for query, _ in connection.executions)
        )

    def test_newer_failed_provider_snapshot_confirms_failure_and_opens_case(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment",
                    lambda _params: _payment_row(
                        status="FAILED",
                        provider_snapshot_at=OCCURRED_AT + timedelta(seconds=1),
                    ),
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("UPDATE retrywise.provider_payments", lambda _params: ("FAILED",)),
                _Step("INSERT INTO retrywise.recovery_cases", lambda _params: _case_row()),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("PROCESSED",)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertIs(result.disposition, ProjectionDisposition.PROCESSED)
        self.assertEqual(CASE_ID, result.recovery_case_id)
        self.assertTrue(result.recovery_case_created)

    def test_existing_failure_signal_reuses_open_case_without_reopening(self) -> None:
        existing_facts = {"retrywise_provider_event_record_id": LOGICAL_ORDER_ID}
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment",
                    lambda _params: _payment_row(status="FAILED", error_facts=existing_facts),
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("FROM retrywise.recovery_cases", lambda _params: _case_row(EXISTING_CASE_ID)),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("PROCESSED",)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertEqual(EXISTING_CASE_ID, result.recovery_case_id)
        self.assertFalse(result.recovery_case_created)
        self.assertFalse(
            any(
                "INSERT INTO retrywise.recovery_cases" in query
                for query, _ in connection.executions
            )
        )

    def test_case_unique_conflict_loads_the_winning_open_case(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment", lambda _params: _payment_row()
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("UPDATE retrywise.provider_payments", lambda _params: ("FAILED",)),
                _Step("INSERT INTO retrywise.recovery_cases", lambda _params: None),
                _Step("FROM retrywise.recovery_cases", lambda _params: _case_row(EXISTING_CASE_ID)),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("PROCESSED",)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertEqual(EXISTING_CASE_ID, result.recovery_case_id)
        self.assertFalse(result.recovery_case_created)

    def test_unsafe_order_truth_still_projects_payment_but_never_opens_recovery(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment",
                    lambda _params: _payment_row(canonical_truth="PAID"),
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("UPDATE retrywise.provider_payments", lambda _params: ("FAILED",)),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("PROCESSED",)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertIsNone(result.recovery_case_id)
        self.assertFalse(
            any(
                "INSERT INTO retrywise.recovery_cases" in query
                for query, _ in connection.executions
            )
        )

    def test_database_observation_contract_is_validated_before_commit(self) -> None:
        for case_row in (
            _case_row(contract_version=0),
            _case_row(observation_window=timedelta(seconds=119)),
            _case_row(state="RECOVERED"),
        ):
            with self.subTest(case_row=case_row):
                connection = _FakeConnection(
                    [
                        _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                        _Step(
                            "FROM retrywise.inbox_events AS inbox",
                            lambda _params: _event_row(),
                        ),
                        _Step("body_sha256 =", lambda _params: None),
                        _Step(
                            "FROM retrywise.provider_payments AS payment",
                            lambda _params: _payment_row(),
                        ),
                        _Step(
                            "SET status = 'PROCESSING'",
                            lambda _params: ("PROCESSING", 1),
                        ),
                        _Step(
                            "UPDATE retrywise.provider_payments",
                            lambda _params: ("FAILED",),
                        ),
                        _Step(
                            "INSERT INTO retrywise.recovery_cases",
                            lambda _params, row=case_row: row,
                        ),
                    ]
                )
                claim = _claim()

                with self.assertRaises(NormalizedEventEvidenceError):
                    _repository(connection).project(
                        decode_process_normalized_provider_event_command(claim), claim=claim
                    )

                self.assertEqual(1, connection.transactions_rolled_back)
                self.assertEqual(0, connection.transactions_committed)

    def test_malformed_existing_projection_marker_rolls_back_without_reopening(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: None),
                _Step(
                    "FROM retrywise.provider_payments AS payment",
                    lambda _params: _payment_row(
                        status="FAILED",
                        error_facts={"retrywise_provider_event_record_id": ["not", "scalar"]},
                    ),
                ),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
            ]
        )
        claim = _claim()

        with self.assertRaisesRegex(NormalizedEventEvidenceError, "marker"):
            _repository(connection).project(
                decode_process_normalized_provider_event_command(claim), claim=claim
            )

        self.assertEqual(1, connection.transactions_rolled_back)
        self.assertFalse(
            any(
                "INSERT INTO retrywise.recovery_cases" in query
                for query, _ in connection.executions
            )
        )

    def test_missing_or_expired_outbox_fence_rolls_back(self) -> None:
        for steps in (
            [_Step("FROM retrywise.outbox_jobs AS job", lambda _params: None)],
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step("FROM retrywise.inbox_events AS inbox", lambda _params: _event_row()),
                _Step("body_sha256 =", lambda _params: ("evt_reused",)),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 1)),
                _Step("SELECT lease_expires_at >", lambda _params: (False,)),
            ],
        ):
            with self.subTest(steps=len(steps)):
                connection = _FakeConnection(steps)
                claim = _claim()
                with self.assertRaises(NormalizedEventFenceLost):
                    _repository(connection).project(
                        decode_process_normalized_provider_event_command(claim), claim=claim
                    )
                self.assertEqual(1, connection.transactions_rolled_back)

    def test_active_inbox_lease_is_not_stolen_but_expired_lease_is_reclaimed(self) -> None:
        active = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step(
                    "FROM retrywise.inbox_events AS inbox",
                    lambda _params: _event_row(inbox_status="PROCESSING"),
                ),
            ]
        )
        claim = _claim()
        with self.assertRaises(NormalizedEventBusy):
            _repository(active).project(
                decode_process_normalized_provider_event_command(claim), claim=claim
            )

        expired = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step(
                    "FROM retrywise.inbox_events AS inbox",
                    lambda _params: _event_row(
                        inbox_status="PROCESSING",
                        attempt_count=1,
                        processing_lease_expired=True,
                    ),
                ),
                _Step("body_sha256 =", lambda _params: ("evt_reused",)),
                _Step("SET status = 'PROCESSING'", lambda _params: ("PROCESSING", 2)),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
                _Step("SET status = %(inbox_status)s", lambda _params: ("IGNORED",)),
            ]
        )
        result = _repository(expired).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )
        self.assertIs(result.disposition, ProjectionDisposition.IGNORED)

    def test_exhausted_inbox_is_dead_lettered_transactionally(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                _Step(
                    "FROM retrywise.inbox_events AS inbox",
                    lambda _params: _event_row(attempt_count=8, max_attempts=8),
                ),
                _Step("body_sha256 =", lambda _params: ("evt_reused",)),
                _Step("SET status = 'PROCESSING'", lambda _params: None),
                _Step("SET status = 'DEAD_LETTER'", lambda _params: ("DEAD_LETTER",)),
                _Step("SELECT lease_expires_at >", lambda _params: (True,)),
            ]
        )
        claim = _claim()

        result = _repository(connection).project(
            decode_process_normalized_provider_event_command(claim), claim=claim
        )

        self.assertIs(result.disposition, ProjectionDisposition.DEAD_LETTER)
        self.assertEqual("normalized_event_attempts_exhausted", result.reason_code)

    def test_invalid_persisted_bindings_and_canonical_evidence_roll_back(self) -> None:
        invalid_rows = [
            _event_row(signature_verified=False),
            _event_row(provider_account_identifier="acc_other"),
            _event_row(canonical={**_canonical(), "event_id": "evt_other"}),
            _event_row(canonical={**_canonical(), "event_type": "unknown"}),
            _event_row(canonical={**_canonical(), "unexpected": True}),
            _event_row(canonical=_canonical(resource_updates={"captured": True})),
            _event_row(canonical=_canonical(resource_updates={"status": "captured"})),
            _event_row(canonical=_canonical(resource_updates={"currency": "inr"})),
            _event_row(canonical=_canonical(resource_updates={"error_reason": "9876543210"})),
        ]
        for event_row in invalid_rows:
            with self.subTest(event_row=event_row):
                connection = _FakeConnection(
                    [
                        _Step("FROM retrywise.outbox_jobs AS job", lambda _params: (True,)),
                        _Step(
                            "FROM retrywise.inbox_events AS inbox",
                            lambda _params, row=event_row: row,
                        ),
                        _Step("body_sha256 =", lambda _params: None),
                    ]
                )
                claim = _claim()
                with self.assertRaises((NormalizedEventBindingError, NormalizedEventEvidenceError)):
                    _repository(connection).project(
                        decode_process_normalized_provider_event_command(claim), claim=claim
                    )
                self.assertEqual(1, connection.transactions_rolled_back)

    def test_constructor_and_argument_contracts_fail_before_database_use(self) -> None:
        with self.assertRaises(ValueError):
            PostgresNormalizedEventRepository()
        with self.assertRaises(ValueError):
            PostgresNormalizedEventRepository(
                connector=_FakeConnector(_FakeConnection([])), require_tls=True
            )
        with self.assertRaises(TypeError):
            PostgresNormalizedEventRepository(
                connector=_FakeConnector(_FakeConnection([])),
                case_id_factory=None,  # type: ignore[arg-type]
            )
        repository = _repository(_FakeConnection([]))
        with self.assertRaises(TypeError):
            repository.project(object(), claim=_claim())  # type: ignore[arg-type]


class _ResultRepository:
    def __init__(
        self,
        result: NormalizedEventProjectionResult | BaseException | object,
    ) -> None:
        self.result = result

    def project(
        self,
        _command: ProcessNormalizedProviderEventCommand,
        *,
        claim: ClaimedOutboxCommand,
    ) -> NormalizedEventProjectionResult:
        self.claim = claim
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result  # type: ignore[return-value]


class ProcessNormalizedProviderEventHandlerTests(unittest.TestCase):
    def test_maps_processed_ignored_and_exhausted_results_for_outbox_worker(self) -> None:
        results = [
            (
                NormalizedEventProjectionResult(
                    ProjectionDisposition.PROCESSED,
                    EVENT_RECORD_ID,
                    recovery_case_id=CASE_ID,
                    recovery_case_created=True,
                ),
                HandlerDisposition.SUCCEEDED,
            ),
            (
                NormalizedEventProjectionResult(
                    ProjectionDisposition.IGNORED,
                    EVENT_RECORD_ID,
                    reason_code="unsupported_event_type",
                ),
                HandlerDisposition.SUCCEEDED,
            ),
            (
                NormalizedEventProjectionResult(
                    ProjectionDisposition.DEAD_LETTER,
                    EVENT_RECORD_ID,
                    reason_code="normalized_event_attempts_exhausted",
                ),
                HandlerDisposition.DEAD_LETTER,
            ),
        ]
        for result, expected in results:
            with self.subTest(result=result):
                handled = ProcessNormalizedProviderEventHandler(_ResultRepository(result))(_claim())
                self.assertIs(handled.disposition, expected)

    def test_maps_schema_evidence_fence_busy_and_invalid_result_fail_closed(self) -> None:
        invalid_claim = _claim(command_payload=_payload(unknown=True))
        invalid_command = ProcessNormalizedProviderEventHandler(
            _ResultRepository(
                NormalizedEventProjectionResult(ProjectionDisposition.PROCESSED, EVENT_RECORD_ID)
            )
        )(invalid_claim)
        self.assertIs(invalid_command.disposition, HandlerDisposition.DEAD_LETTER)
        self.assertEqual("invalid_normalized_event_command", invalid_command.reason)

        errors: list[tuple[object, HandlerDisposition, str]] = [
            (
                NormalizedEventBindingError("x"),
                HandlerDisposition.DEAD_LETTER,
                "invalid_normalized_event_evidence",
            ),
            (
                NormalizedEventEvidenceError("x"),
                HandlerDisposition.DEAD_LETTER,
                "invalid_normalized_event_evidence",
            ),
            (
                NormalizedEventFenceLost("x"),
                HandlerDisposition.RETRY,
                "normalized_event_fence_lost",
            ),
            (
                NormalizedEventBusy("x"),
                HandlerDisposition.RETRY,
                "normalized_event_inbox_busy",
            ),
            (
                object(),
                HandlerDisposition.DEAD_LETTER,
                "invalid_normalized_event_projection_result",
            ),
        ]
        for outcome, disposition, reason in errors:
            with self.subTest(outcome=outcome):
                handled = ProcessNormalizedProviderEventHandler(_ResultRepository(outcome))(
                    _claim()
                )
                self.assertIs(handled.disposition, disposition)
                self.assertEqual(reason, handled.reason)
                if disposition is HandlerDisposition.RETRY:
                    self.assertIs(handled.retry_mode, RetryMode.RECONCILE_ONLY)

    def test_handler_requires_repository_project_method(self) -> None:
        with self.assertRaises(TypeError):
            ProcessNormalizedProviderEventHandler(object())  # type: ignore[arg-type]


class ProjectionResultContractTests(unittest.TestCase):
    def test_rejects_internally_inconsistent_results(self) -> None:
        with self.assertRaises(ValueError):
            NormalizedEventProjectionResult(
                ProjectionDisposition.IGNORED,
                EVENT_RECORD_ID,
            )
        with self.assertRaises(ValueError):
            NormalizedEventProjectionResult(
                ProjectionDisposition.IGNORED,
                EVENT_RECORD_ID,
                recovery_case_id=CASE_ID,
                reason_code="ignored",
            )
        with self.assertRaises(ValueError):
            NormalizedEventProjectionResult(
                ProjectionDisposition.PROCESSED,
                EVENT_RECORD_ID,
                recovery_case_created=True,
            )


if __name__ == "__main__":
    unittest.main()
