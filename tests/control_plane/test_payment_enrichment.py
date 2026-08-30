from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from retrywise.services.control_plane import payment_enrichment as enrichment_module
from retrywise.services.control_plane.outbox import RetryMode
from retrywise.services.control_plane.outbox_worker import HandlerDisposition
from retrywise.services.control_plane.payment_enrichment import (
    ENRICH_FAILED_PAYMENT_COMMAND_TYPE,
    EnrichFailedPaymentCommand,
    EnrichFailedPaymentHandler,
    PaymentEnrichmentBindingError,
    PaymentEnrichmentCommandError,
    PaymentEnrichmentPersistenceError,
    PaymentEnrichmentResult,
    PostgresFailedPaymentEnrichmentRepository,
    canonical_enrichment_payload,
    decode_enrich_failed_payment_command,
    encode_enrich_failed_payment_command,
)
from retrywise.services.control_plane.postgres_outbox import ClaimedOutboxCommand
from retrywise.services.control_plane.razorpay_test_adapter import (
    OrderRecord,
    OrderStatus,
    PaymentRecord,
    PaymentStatus,
    RazorpayReadError,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
EVENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
LOGICAL_ORDER_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
PAYMENT_RECORD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
PAYMENT_ID = "pay_ExjpAUN3gVHrPJ"
ORDER_ID = "order_ExjpAUN3gVHrPJ"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def command() -> EnrichFailedPaymentCommand:
    return EnrichFailedPaymentCommand(
        merchant_id=MERCHANT_ID,
        provider_account_id=ACCOUNT_ID,
        provider_payment_id=PAYMENT_ID,
        provider_order_id=ORDER_ID,
        amount_minor=129_900,
        currency="INR",
    )


def claim() -> ClaimedOutboxCommand:
    value = command()
    return ClaimedOutboxCommand(
        job_id=JOB_ID,
        merchant_id=MERCHANT_ID,
        aggregate_type="PROVIDER_PAYMENT",
        aggregate_id=PAYMENT_ID,
        command_type=ENRICH_FAILED_PAYMENT_COMMAND_TYPE,
        command_schema_version=1,
        command_payload=encode_enrich_failed_payment_command(value),
        idempotency_key=value.idempotency_key,
        attempt_count=1,
        max_attempts=8,
        worker_id="enrichment-worker-a",
        lease_token="lease-a",
        lease_expires_at=NOW + timedelta(seconds=30),
        delivery_version=1,
        retry_mode=RetryMode.RECONCILE_ONLY,
        created_at=NOW - timedelta(minutes=1),
        claimed_at=NOW,
    )


def payment(**overrides: object) -> PaymentRecord:
    values: dict[str, object] = {
        "payment_id": PAYMENT_ID,
        "order_id": ORDER_ID,
        "status": PaymentStatus.FAILED,
        "amount_minor": 129_900,
        "currency": "INR",
        "captured_minor": 0,
        "refunded_minor": 0,
        "payment_method": "upi",
        "error_source": "customer",
        "error_step": "payment_authentication",
        "error_reason": "payment_failed",
        "created_at_epoch": int((NOW - timedelta(minutes=2)).timestamp()),
    }
    values.update(overrides)
    return PaymentRecord(**values)  # type: ignore[arg-type]


def order(**overrides: object) -> OrderRecord:
    values: dict[str, object] = {
        "order_id": ORDER_ID,
        "amount_minor": 129_900,
        "amount_paid_minor": 0,
        "amount_due_minor": 129_900,
        "currency": "INR",
        "status": OrderStatus.ATTEMPTED,
        "attempts": 1,
        "created_at_epoch": int((NOW - timedelta(minutes=3)).timestamp()),
    }
    values.update(overrides)
    return OrderRecord(**values)  # type: ignore[arg-type]


class _Adapter:
    def __init__(self, result: object | Exception = None) -> None:
        self.result = result
        self.closed = False
        self.payment_calls = 0
        self.order_calls = 0

    def fetch_payment(self, **_kwargs: object) -> PaymentRecord:
        self.payment_calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return payment()

    def fetch_order(self, **_kwargs: object) -> OrderRecord:
        self.order_calls += 1
        return order()

    def close(self) -> None:
        self.closed = True


class _Repository:
    def __init__(self, result: object | Exception) -> None:
        self.result = result
        self.calls = 0

    def persist(self, **_kwargs: object) -> PaymentEnrichmentResult:
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]


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
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __enter__(self) -> object:
        return self

    def __exit__(self, exc_type: object, *_args: object) -> None:
        if exc_type is None:
            self.connection.commits += 1
        else:
            self.connection.rollbacks += 1
        return None


class _Connection:
    def __init__(self, steps: list[_Step]) -> None:
        self.steps = steps
        self.executions: list[tuple[str, dict[str, object]]] = []
        self.commits = 0
        self.rollbacks = 0

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def transaction(self) -> _Context:
        return _Context(self)

    def cursor(self) -> _Cursor:
        return _Cursor(self)


class _Connector:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __call__(self) -> _Connection:
        return self.connection


class PaymentEnrichmentTests(unittest.TestCase):
    def test_command_and_canonical_json_boundaries_are_closed(self) -> None:
        invalid = (
            {"merchant_id": "bad"},
            {"provider_account_id": "bad"},
            {"provider_payment_id": "order_wrong"},
            {"provider_order_id": "pay_wrong"},
            {"amount_minor": 0},
            {"currency": "inr"},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(PaymentEnrichmentCommandError):
                replace(command(), **changes)

        with self.assertRaises(TypeError):
            encode_enrich_failed_payment_command(object())  # type: ignore[arg-type]
        with self.assertRaises(PaymentEnrichmentCommandError):
            canonical_enrichment_payload({"not_json": object()})
        with self.assertRaises(PaymentEnrichmentCommandError):
            canonical_enrichment_payload(
                {"padding": "x" * enrichment_module.MAX_ENRICHMENT_COMMAND_BYTES}
            )
        with self.assertRaises(TypeError):
            decode_enrich_failed_payment_command(object())  # type: ignore[arg-type]
        with self.assertRaises(PaymentEnrichmentCommandError):
            decode_enrich_failed_payment_command(replace(claim(), command_schema_version=2))
        wrong_schema = encode_enrich_failed_payment_command(command())
        wrong_schema["schema_version"] = 2
        with self.assertRaises(PaymentEnrichmentCommandError):
            decode_enrich_failed_payment_command(replace(claim(), command_payload=wrong_schema))

    def test_command_codec_is_exact_and_binds_every_outbox_field(self) -> None:
        self.assertEqual(command(), decode_enrich_failed_payment_command(claim()))

        unknown = encode_enrich_failed_payment_command(command())
        unknown["extra"] = True
        with self.assertRaises(PaymentEnrichmentCommandError):
            decode_enrich_failed_payment_command(replace(claim(), command_payload=unknown))
        with self.assertRaises(PaymentEnrichmentCommandError):
            decode_enrich_failed_payment_command(replace(claim(), aggregate_id="pay_other"))

    def test_handler_reads_payment_then_order_closes_adapter_and_succeeds(self) -> None:
        adapter = _Adapter()
        repository = _Repository(
            PaymentEnrichmentResult(
                logical_order_id=LOGICAL_ORDER_ID,
                payment_record_id=PAYMENT_RECORD_ID,
            )
        )
        handler = EnrichFailedPaymentHandler(
            repository=repository,  # type: ignore[arg-type]
            adapter_factory=lambda _merchant, _account: adapter,
            clock=lambda: NOW,
        )

        result = handler(claim())

        self.assertEqual(HandlerDisposition.SUCCEEDED, result.disposition)
        self.assertEqual(
            f"enriched-provider-payment:{PAYMENT_RECORD_ID}", result.completion_reference
        )
        self.assertEqual(1, adapter.payment_calls)
        self.assertEqual(1, adapter.order_calls)
        self.assertTrue(adapter.closed)
        self.assertEqual(1, repository.calls)

    def test_provider_read_failure_retries_with_no_private_error_text(self) -> None:
        adapter = _Adapter(RazorpayReadError("provider_order_response_invalid"))
        repository = _Repository(RuntimeError("must not persist"))
        handler = EnrichFailedPaymentHandler(
            repository=repository,  # type: ignore[arg-type]
            adapter_factory=lambda _merchant, _account: adapter,
            clock=lambda: NOW,
        )

        result = handler(claim())

        self.assertEqual(HandlerDisposition.RETRY, result.disposition)
        self.assertEqual(RetryMode.RETRY_SAME_EFFECT, result.retry_mode)
        self.assertEqual("provider_enrichment_read_unavailable", result.reason)
        self.assertTrue(adapter.closed)
        self.assertEqual(0, repository.calls)

    def test_fresh_binding_conflict_is_dead_lettered(self) -> None:
        adapter = _Adapter()
        handler = EnrichFailedPaymentHandler(
            repository=_Repository(PaymentEnrichmentBindingError("private provider response")),  # type: ignore[arg-type]
            adapter_factory=lambda _merchant, _account: adapter,
            clock=lambda: NOW,
        )

        result = handler(claim())

        self.assertEqual(HandlerDisposition.DEAD_LETTER, result.disposition)
        self.assertEqual("provider_enrichment_binding_conflict", result.reason)
        self.assertNotIn("private provider response", str(result))

    def test_handler_maps_persistence_unexpected_and_invalid_command_failures(self) -> None:
        for error, expected_reason in (
            (
                PaymentEnrichmentPersistenceError("database"),
                "provider_enrichment_persistence_unavailable",
            ),
            (RuntimeError("unexpected"), "provider_enrichment_unavailable"),
        ):
            with self.subTest(error=type(error).__name__):
                adapter = _Adapter()
                handled = EnrichFailedPaymentHandler(
                    repository=_Repository(error),  # type: ignore[arg-type]
                    adapter_factory=lambda _merchant, _account, adapter=adapter: adapter,
                    clock=lambda: NOW,
                )(claim())
                self.assertEqual(HandlerDisposition.RETRY, handled.disposition)
                self.assertEqual(expected_reason, handled.reason)
                self.assertTrue(adapter.closed)

        invalid = EnrichFailedPaymentHandler(
            repository=_Repository(RuntimeError("must not persist")),  # type: ignore[arg-type]
            adapter_factory=lambda _merchant, _account: _Adapter(),
            clock=lambda: NOW,
        )(replace(claim(), command_type="WRONG"))
        self.assertEqual(HandlerDisposition.DEAD_LETTER, invalid.disposition)

        with self.assertRaises(TypeError):
            EnrichFailedPaymentHandler(
                repository=_Repository(RuntimeError()),  # type: ignore[arg-type]
                adapter_factory=None,  # type: ignore[arg-type]
                clock=lambda: NOW,
            )

    def test_repository_persists_only_verified_operational_projection(self) -> None:
        connection = _Connection(
            [
                _Step("FROM retrywise.outbox_jobs AS job", (True,)),
                _Step("FROM retrywise.provider_accounts AS account", (True,)),
                _Step("INSERT INTO retrywise.logical_orders", (LOGICAL_ORDER_ID,)),
                _Step(
                    "FROM retrywise.logical_orders",
                    (LOGICAL_ORDER_ID, ORDER_ID, 129_900, "INR", "MAPPED", 0, NOW),
                ),
                _Step("UPDATE retrywise.logical_orders", (LOGICAL_ORDER_ID,)),
                _Step("INSERT INTO retrywise.provider_payments", (PAYMENT_RECORD_ID,)),
                _Step(
                    "FROM retrywise.provider_payments",
                    (PAYMENT_RECORD_ID, LOGICAL_ORDER_ID, ORDER_ID, 129_900, "INR", NOW),
                ),
                _Step("UPDATE retrywise.provider_payments", (PAYMENT_RECORD_ID,)),
                _Step("SELECT lease_expires_at >", (True,)),
            ]
        )
        ids = iter((LOGICAL_ORDER_ID, PAYMENT_RECORD_ID))
        repository = PostgresFailedPaymentEnrichmentRepository(
            connector=_Connector(connection),  # type: ignore[arg-type]
            id_factory=lambda: next(ids),
        )

        result = repository.persist(
            command=command(),
            payment=payment(),
            order=order(),
            observed_at=NOW,
            claim=claim(),
        )

        self.assertEqual(PAYMENT_RECORD_ID, result.payment_record_id)
        self.assertEqual(1, connection.commits)
        self.assertEqual([], connection.steps)
        all_params = str([params for _query, params in connection.executions])
        self.assertNotIn("email", all_params)
        self.assertNotIn("contact", all_params)
        self.assertNotIn("receipt", all_params)
        self.assertIn("provider-api-enrichment/v1", all_params)
        all_queries = "\n".join(query for query, _params in connection.executions)
        self.assertIn(
            "%(canonical_truth)s::retrywise.canonical_payment_truth",
            all_queries,
        )
        self.assertIn(
            "END::retrywise.canonical_payment_truth",
            all_queries,
        )
        self.assertEqual(
            2,
            all_queries.count("%(payment_status)s::retrywise.provider_payment_status"),
        )

    def test_repository_rejects_payment_order_amount_disagreement_before_sql(self) -> None:
        connection = _Connection([])
        repository = PostgresFailedPaymentEnrichmentRepository(
            connector=_Connector(connection),  # type: ignore[arg-type]
            id_factory=lambda: LOGICAL_ORDER_ID,
        )
        with self.assertRaises(PaymentEnrichmentBindingError):
            repository.persist(
                command=command(),
                payment=payment(),
                order=order(amount_minor=200_000, amount_due_minor=200_000),
                observed_at=NOW,
                claim=claim(),
            )
        self.assertEqual([], connection.executions)


if __name__ == "__main__":
    unittest.main()
