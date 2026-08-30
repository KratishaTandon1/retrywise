from __future__ import annotations

import json
import unittest
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

try:
    import httpx
except ImportError as exc:  # Dependency-free CI intentionally skips provider HTTP tests.
    raise unittest.SkipTest("the api extra with httpx is not installed") from exc

from retrywise.packages.razorpay import StandardPaymentLinkRequest
from retrywise.services.control_plane.executor import ProviderCreateStatus
from retrywise.services.control_plane.razorpay_test_adapter import (
    OrderStatus,
    PaymentLinkStatus,
    PaymentStatus,
    ProviderAccountMismatchError,
    ProviderCancelStatus,
    RazorpayAdapterError,
    RazorpayReadError,
    RazorpayTestModePaymentLinkAdapter,
)

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
NOW_EPOCH = int(NOW.timestamp())
ACCOUNT = "provider_account_test_1"
KEY_ID = "rzp_test_not_a_real_key"
KEY_SECRET = "not-a-real-secret"
REFERENCE = "rtw_case1_abcdefghijklmnopqrstuv"
PAYMENT_LINK_ID = "plink_ExjpAUN3gVHrPJ"
PAYMENT_ID = "pay_ExjpAUN3gVHrPJ"


def payment_link_request() -> StandardPaymentLinkRequest:
    return StandardPaymentLinkRequest(
        amount_minor=129_900,
        currency="INR",
        reference_id=REFERENCE,
        description="Retry payment for order ORD-1042",
        expire_by_epoch=int((NOW + timedelta(hours=1)).timestamp()),
        notes={"recovery_case_id": "case_1"},
    )


def provider_link(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": PAYMENT_LINK_ID,
        "reference_id": REFERENCE,
        "amount": 129_900,
        "amount_paid": 0,
        "currency": "INR",
        "accept_partial": False,
        "upi_link": False,
        "status": "created",
        "short_url": "https://rzp.io/i/example",
    }
    value.update(overrides)
    return value


class RecordingTransport:
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[httpx.Request] = []

        def recording_handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return handler(request)

        self.transport = httpx.MockTransport(recording_handler)


def adapter(
    recorder: RecordingTransport,
    *,
    key_id: str = KEY_ID,
    key_secret: str = KEY_SECRET,
) -> RazorpayTestModePaymentLinkAdapter:
    return RazorpayTestModePaymentLinkAdapter(
        key_id=key_id,
        key_secret=key_secret,
        provider_account_id=ACCOUNT,
        transport=recorder.transport,
        epoch_clock=lambda: NOW_EPOCH,
    )


class RazorpayTestModePaymentLinkAdapterTests(unittest.TestCase):
    def test_fetch_order_returns_only_verified_operational_totals(self) -> None:
        provider_order = {
            "id": "order_ExjpAUN3gVHrPJ",
            "entity": "order",
            "amount": 129_900,
            "amount_paid": 0,
            "amount_due": 129_900,
            "currency": "INR",
            "status": "attempted",
            "attempts": 1,
            "created_at": NOW_EPOCH - 60,
            "receipt": "private-merchant-reference",
            "notes": {"customer": "discard"},
        }
        recorder = RecordingTransport(lambda request: httpx.Response(200, json=provider_order))
        with adapter(recorder) as provider:
            record = provider.fetch_order(
                order_id="order_ExjpAUN3gVHrPJ",
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(OrderStatus.ATTEMPTED, record.status)
        self.assertEqual(129_900, record.amount_due_minor)
        self.assertNotIn("private-merchant-reference", repr(record))
        self.assertEqual(
            "https://api.razorpay.com/v1/orders/order_ExjpAUN3gVHrPJ",
            str(recorder.requests[0].url),
        )

    def test_fetch_order_rejects_inconsistent_amounts_or_id(self) -> None:
        values = (
            {
                "id": "order_other",
                "entity": "order",
                "amount": 100,
                "amount_paid": 0,
                "amount_due": 100,
                "currency": "INR",
                "status": "attempted",
                "attempts": 1,
                "created_at": NOW_EPOCH,
            },
            {
                "id": "order_ExjpAUN3gVHrPJ",
                "entity": "order",
                "amount": 100,
                "amount_paid": 50,
                "amount_due": 60,
                "currency": "INR",
                "status": "attempted",
                "attempts": 1,
                "created_at": NOW_EPOCH,
            },
        )
        responses = iter(httpx.Response(200, json=value) for value in values)
        recorder = RecordingTransport(lambda request: next(responses))
        with adapter(recorder) as provider:
            with self.assertRaises(RazorpayReadError):
                provider.fetch_order(order_id="order_ExjpAUN3gVHrPJ", provider_account_id=ACCOUNT)
            with self.assertRaises(RazorpayReadError):
                provider.fetch_order(order_id="order_ExjpAUN3gVHrPJ", provider_account_id=ACCOUNT)

    def test_fetch_payment_returns_only_strict_current_truth(self) -> None:
        provider_payment = {
            "id": PAYMENT_ID,
            "entity": "payment",
            "amount": 129_900,
            "currency": "INR",
            "status": "failed",
            "order_id": "order_ExjpAUN3gVHrPJ",
            "method": "upi",
            "captured": False,
            "amount_refunded": 0,
            "error_source": "customer",
            "error_step": "payment_authentication",
            "error_reason": "payment_failed",
            "email": "private@example.test",
            "contact": "+919999999999",
            "notes": {"private": "discard"},
        }
        recorder = RecordingTransport(lambda request: httpx.Response(200, json=provider_payment))
        with adapter(recorder) as provider:
            record = provider.fetch_payment(
                payment_id=PAYMENT_ID,
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(PaymentStatus.FAILED, record.status)
        self.assertEqual("customer", record.error_source)
        self.assertNotIn("private@example.test", repr(record))
        self.assertEqual(
            f"https://api.razorpay.com/v1/payments/{PAYMENT_ID}",
            str(recorder.requests[0].url),
        )

    def test_fetch_payment_rejects_misbound_or_inconsistent_truth(self) -> None:
        values = (
            {
                "id": "pay_other",
                "amount": 100,
                "currency": "INR",
                "status": "failed",
                "order_id": "order_test",
                "method": "upi",
                "captured": False,
                "amount_refunded": 0,
            },
            {
                "id": PAYMENT_ID,
                "amount": 100,
                "currency": "INR",
                "status": "captured",
                "order_id": "order_test",
                "method": "upi",
                "captured": False,
                "amount_refunded": 1,
            },
        )
        responses = iter(httpx.Response(200, json=value) for value in values)
        recorder = RecordingTransport(lambda request: next(responses))
        with adapter(recorder) as provider:
            with self.assertRaises(RazorpayReadError):
                provider.fetch_payment(payment_id=PAYMENT_ID, provider_account_id=ACCOUNT)
            with self.assertRaises(RazorpayReadError):
                provider.fetch_payment(payment_id=PAYMENT_ID, provider_account_id=ACCOUNT)

    def test_create_uses_fixed_origin_basic_auth_and_safe_standard_payload(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual("POST", request.method)
            self.assertEqual("https://api.razorpay.com/v1/payment_links", str(request.url))
            self.assertTrue(request.headers["authorization"].startswith("Basic "))
            payload = json.loads(request.content)
            self.assertEqual(REFERENCE, payload["reference_id"])
            self.assertFalse(payload["accept_partial"])
            self.assertFalse(payload["upi_link"])
            self.assertEqual({"sms": False, "email": False}, payload["notify"])
            self.assertFalse(payload["reminder_enable"])
            return httpx.Response(200, json=provider_link())

        recorder = RecordingTransport(handler)
        with adapter(recorder) as provider:
            outcome = provider.create_standard_payment_link(
                payment_link_request(),
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(ProviderCreateStatus.CERTAIN_SUCCESS, outcome.status)
        self.assertEqual(PAYMENT_LINK_ID, outcome.payment_link_id)
        self.assertEqual(1, len(recorder.requests))

    def test_live_or_non_test_keys_are_rejected_without_transport_use(self) -> None:
        recorder = RecordingTransport(lambda request: httpx.Response(500))

        for key_id in ("rzp_live_unsafe", "key_without_test_prefix"):
            with self.subTest(key_id=key_id), self.assertRaises(ValueError):
                adapter(recorder, key_id=key_id)

        self.assertEqual([], recorder.requests)

    def test_account_binding_mismatch_fails_before_network_and_leaks_no_secret(self) -> None:
        recorder = RecordingTransport(lambda request: httpx.Response(500))
        provider = adapter(recorder)

        with self.assertRaises(ProviderAccountMismatchError) as raised:
            provider.create_standard_payment_link(
                payment_link_request(),
                provider_account_id="provider_account_other",
            )

        self.assertNotIn(KEY_ID, repr(provider))
        self.assertNotIn(KEY_SECRET, repr(provider))
        self.assertNotIn(KEY_ID, str(raised.exception))
        self.assertNotIn(KEY_SECRET, str(raised.exception))
        self.assertEqual([], recorder.requests)
        provider.close()

    def test_read_timeout_is_ambiguous_and_never_raised_with_request_details(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("simulated body timeout", request=request)

        recorder = RecordingTransport(handler)
        with adapter(recorder) as provider:
            outcome = provider.create_standard_payment_link(
                payment_link_request(),
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(ProviderCreateStatus.AMBIGUOUS, outcome.status)
        self.assertEqual("provider_read_timeout_unknown_outcome", outcome.reason_code)
        self.assertEqual(1, len(recorder.requests))

    def test_local_pool_timeout_is_a_certain_pre_request_failure(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.PoolTimeout("simulated pool timeout", request=request)

        recorder = RecordingTransport(handler)
        with adapter(recorder) as provider:
            outcome = provider.create_standard_payment_link(
                payment_link_request(),
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(ProviderCreateStatus.CERTAIN_FAILURE, outcome.status)
        self.assertEqual("provider_pool_timeout_before_request", outcome.reason_code)

    def test_duplicate_reference_is_ambiguous_and_forces_reference_lookup(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(
                    400,
                    json={
                        "error": {
                            "description": (
                                "payment link with given reference_id: "
                                "customer notes already exists"
                            ),
                            "customer_email": "private@example.test",
                        }
                    },
                )
            self.assertEqual(REFERENCE, request.url.params["reference_id"])
            return httpx.Response(200, json={"payment_links": [provider_link()]})

        recorder = RecordingTransport(handler)
        with adapter(recorder) as provider:
            create = provider.create_standard_payment_link(
                payment_link_request(),
                provider_account_id=ACCOUNT,
            )
            lookup = provider.lookup_payment_links(
                reference_id=REFERENCE,
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(ProviderCreateStatus.AMBIGUOUS, create.status)
        self.assertEqual("provider_reference_exists_requires_lookup", create.reason_code)
        self.assertTrue(lookup.completed)
        self.assertEqual(PAYMENT_LINK_ID, lookup.candidates[0]["id"])
        self.assertEqual(["POST", "GET"], [request.method for request in recorder.requests])

    def test_definitive_validation_reject_is_certain_failure(self) -> None:
        recorder = RecordingTransport(
            lambda request: httpx.Response(
                422,
                json={"error": {"description": "customer contact is invalid"}},
            )
        )
        with adapter(recorder) as provider:
            outcome = provider.create_standard_payment_link(
                payment_link_request(),
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(ProviderCreateStatus.CERTAIN_FAILURE, outcome.status)
        self.assertEqual("provider_rejected_create_http_422", outcome.reason_code)
        self.assertNotIn("contact", outcome.reason_code)

    def test_5xx_and_malformed_success_are_ambiguous(self) -> None:
        responses = iter(
            (
                httpx.Response(503, json={"error": {"description": "unknown"}}),
                httpx.Response(200, text="not json", headers={"content-type": "text/plain"}),
                httpx.Response(200, json=provider_link(amount=42)),
                httpx.Response(200, json=provider_link(reference_id=" invalid")),
            )
        )
        recorder = RecordingTransport(lambda request: next(responses))
        with adapter(recorder) as provider:
            outcomes = [
                provider.create_standard_payment_link(
                    payment_link_request(),
                    provider_account_id=ACCOUNT,
                )
                for _ in range(4)
            ]

        self.assertEqual(
            [ProviderCreateStatus.AMBIGUOUS] * 4,
            [outcome.status for outcome in outcomes],
        )
        self.assertEqual("provider_create_response_invalid", outcomes[1].reason_code)
        self.assertEqual("provider_create_response_conflicts", outcomes[2].reason_code)
        self.assertEqual("provider_create_response_invalid", outcomes[3].reason_code)

    def test_oversized_create_response_is_ambiguous_without_buffering_the_body(self) -> None:
        recorder = RecordingTransport(
            lambda request: httpx.Response(
                200,
                content=b"{}",
                headers={
                    "content-type": "application/json",
                    "content-length": str(256 * 1024 + 1),
                },
            )
        )
        with adapter(recorder) as provider:
            outcome = provider.create_standard_payment_link(
                payment_link_request(),
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(ProviderCreateStatus.AMBIGUOUS, outcome.status)
        self.assertEqual("provider_create_response_invalid", outcome.reason_code)

    def test_lookup_returns_only_reconciliation_fields_and_drops_customer_data(self) -> None:
        raw = provider_link(
            customer={"name": "Private", "email": "private@example.test", "contact": "999"},
            notes={"secret": "do not persist"},
            payments=[{"email": "payer@example.test"}],
        )
        recorder = RecordingTransport(
            lambda request: httpx.Response(200, json={"payment_links": [raw]})
        )
        with adapter(recorder) as provider:
            result = provider.lookup_payment_links(
                reference_id=REFERENCE,
                provider_account_id=ACCOUNT,
            )

        self.assertTrue(result.completed)
        self.assertEqual(
            {
                "id",
                "reference_id",
                "amount",
                "currency",
                "accept_partial",
                "upi_link",
                "status",
            },
            set(result.candidates[0]),
        )
        self.assertNotIn("private@example.test", repr(result))

    def test_failed_or_reference_mismatched_lookup_is_incomplete(self) -> None:
        responses = iter(
            (
                httpx.Response(503, json={"error": {"description": "unavailable"}}),
                httpx.Response(
                    200,
                    json={"payment_links": [provider_link(reference_id="different_reference")]},
                ),
            )
        )
        recorder = RecordingTransport(lambda request: next(responses))
        with adapter(recorder) as provider:
            unavailable = provider.lookup_payment_links(
                reference_id=REFERENCE,
                provider_account_id=ACCOUNT,
            )
            mismatched = provider.lookup_payment_links(
                reference_id=REFERENCE,
                provider_account_id=ACCOUNT,
            )

        self.assertFalse(unavailable.completed)
        self.assertFalse(mismatched.completed)

    def test_fetch_validates_path_and_provider_id(self) -> None:
        recorder = RecordingTransport(lambda request: httpx.Response(200, json=provider_link()))
        with adapter(recorder) as provider:
            result = provider.fetch_payment_link(
                payment_link_id=PAYMENT_LINK_ID,
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(PAYMENT_LINK_ID, result.payment_link_id)
        self.assertEqual(0, result.amount_paid_minor)
        self.assertEqual(PaymentLinkStatus.CREATED, result.status)
        self.assertEqual(
            f"https://api.razorpay.com/v1/payment_links/{PAYMENT_LINK_ID}",
            str(recorder.requests[0].url),
        )

    def test_payment_link_amount_paid_is_required_bounded_and_status_consistent(self) -> None:
        invalid_links = (
            {key: value for key, value in provider_link().items() if key != "amount_paid"},
            provider_link(amount_paid=-1),
            provider_link(amount_paid=129_901),
            provider_link(amount_paid=1),
            provider_link(status="cancelled", amount_paid=1),
            provider_link(status="expired", amount_paid=1),
            provider_link(status="paid", amount_paid=129_899),
            provider_link(status="partially_paid", amount_paid=0),
            provider_link(status="partially_paid", amount_paid=129_900),
        )
        responses = iter(httpx.Response(200, json=value) for value in invalid_links)
        recorder = RecordingTransport(lambda request: next(responses))

        with adapter(recorder) as provider:
            for value in invalid_links:
                with self.subTest(value=value), self.assertRaises(RazorpayReadError) as raised:
                    provider.fetch_payment_link(
                        payment_link_id=PAYMENT_LINK_ID,
                        provider_account_id=ACCOUNT,
                    )
                self.assertEqual("provider_fetch_response_invalid", raised.exception.reason_code)

    def test_paid_and_partially_paid_amounts_are_preserved(self) -> None:
        responses = iter(
            (
                httpx.Response(200, json=provider_link(status="paid", amount_paid=129_900)),
                httpx.Response(
                    200,
                    json=provider_link(status="partially_paid", amount_paid=64_950),
                ),
            )
        )
        recorder = RecordingTransport(lambda request: next(responses))

        with adapter(recorder) as provider:
            paid = provider.fetch_payment_link(
                payment_link_id=PAYMENT_LINK_ID,
                provider_account_id=ACCOUNT,
            )
            partially_paid = provider.fetch_payment_link(
                payment_link_id=PAYMENT_LINK_ID,
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(129_900, paid.amount_paid_minor)
        self.assertEqual(64_950, partially_paid.amount_paid_minor)

    def test_fetch_non_200_raises_only_sanitized_read_error(self) -> None:
        recorder = RecordingTransport(
            lambda request: httpx.Response(
                401,
                json={"error": {"description": "secret was invalid for private@example.test"}},
            )
        )
        with adapter(recorder) as provider, self.assertRaises(RazorpayReadError) as raised:
            provider.fetch_payment_link(
                payment_link_id=PAYMENT_LINK_ID,
                provider_account_id=ACCOUNT,
            )

        self.assertEqual("provider_read_http_401", raised.exception.reason_code)
        self.assertNotIn("private@example.test", str(raised.exception))

    def test_malformed_read_drops_raw_body_and_exception_chain(self) -> None:
        private_body = b'{"customer_email":"private@example.test"'
        recorder = RecordingTransport(
            lambda request: httpx.Response(
                200,
                content=private_body,
                headers={"content-type": "application/json"},
            )
        )
        with adapter(recorder) as provider, self.assertRaises(RazorpayReadError) as raised:
            provider.list_payment_links_by_reference(
                reference_id=REFERENCE,
                provider_account_id=ACCOUNT,
            )

        self.assertEqual("provider_lookup_response_invalid", raised.exception.reason_code)
        self.assertIsNone(raised.exception.__cause__)
        self.assertNotIn("private@example.test", str(raised.exception))

    def test_confirmed_cancel_requires_matching_id_and_cancelled_state(self) -> None:
        recorder = RecordingTransport(
            lambda request: httpx.Response(200, json=provider_link(status="cancelled"))
        )
        with adapter(recorder) as provider:
            outcome = provider.cancel_payment_link(
                payment_link_id=PAYMENT_LINK_ID,
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(ProviderCancelStatus.CERTAIN_SUCCESS, outcome.status)
        self.assertIsNotNone(outcome.payment_link)
        self.assertEqual("provider_confirmed_cancel", outcome.reason_code)

    def test_cancel_timeout_or_update_lock_is_ambiguous(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise httpx.WriteTimeout("simulated write timeout", request=request)
            return httpx.Response(
                400,
                json={"error": {"description": "an update is already in progress"}},
            )

        recorder = RecordingTransport(handler)
        with adapter(recorder) as provider:
            timeout = provider.cancel_payment_link(
                payment_link_id=PAYMENT_LINK_ID,
                provider_account_id=ACCOUNT,
            )
            update_lock = provider.cancel_payment_link(
                payment_link_id=PAYMENT_LINK_ID,
                provider_account_id=ACCOUNT,
            )

        self.assertEqual(ProviderCancelStatus.AMBIGUOUS, timeout.status)
        self.assertEqual("provider_write_timeout_unknown_outcome", timeout.reason_code)
        self.assertEqual(ProviderCancelStatus.AMBIGUOUS, update_lock.status)
        self.assertEqual("provider_cancel_update_in_progress", update_lock.reason_code)

    def test_closed_adapter_fails_before_network(self) -> None:
        recorder = RecordingTransport(lambda request: httpx.Response(200, json=provider_link()))
        provider = adapter(recorder)
        provider.close()

        with self.assertRaises(RazorpayAdapterError) as raised:
            provider.lookup_payment_links(
                reference_id=REFERENCE,
                provider_account_id=ACCOUNT,
            )

        self.assertEqual("provider_adapter_closed", raised.exception.reason_code)
        self.assertEqual([], recorder.requests)


if __name__ == "__main__":
    unittest.main()
