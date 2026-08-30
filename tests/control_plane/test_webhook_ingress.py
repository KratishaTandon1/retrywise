from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta, timezone

from retrywise.packages.razorpay import (
    AccountMismatchError,
    InboxConflictError,
    InMemoryWebhookInbox,
    WebhookVerificationError,
    calculate_webhook_signature,
)
from retrywise.services.control_plane.webhook_ingress import (
    EndpointBinding,
    EndpointNotFound,
    IngressStatus,
    PayloadTooLarge,
    StaticEndpointRegistry,
    UnsupportedMediaType,
    WebhookIngress,
)

TOKEN = "endpoint_token_1234567890abcdef"
SECRET = b"test-webhook-secret-32-bytes-long"
PREVIOUS_SECRET = b"previous-webhook-secret"


def body(*, event_id_suffix: str = "1", account_id: str = "acc_test_1") -> bytes:
    return json.dumps(
        {
            "account_id": account_id,
            "event": "payment.failed",
            "created_at": 1_788_000_000,
            "payload": {
                "payment": {
                    "entity": {
                        "id": f"pay_test_{event_id_suffix}",
                        "order_id": "order_test_1",
                        "amount": 129900,
                        "currency": "INR",
                        "status": "failed",
                    }
                }
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class WebhookIngressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inbox = InMemoryWebhookInbox()
        binding = EndpointBinding(
            endpoint_token=TOKEN,
            merchant_id="merchant-1",
            provider_account_id="provider-account-1",
            provider_account_identifier="acc_test_1",
            webhook_secrets=(SECRET,),
        )
        self.ingress = WebhookIngress(
            registry=StaticEndpointRegistry((binding,)),
            inbox=self.inbox,
            max_body_bytes=2_048,
        )

    def accept(self, raw: bytes, *, event_id: str = "event-1"):
        signature = calculate_webhook_signature(raw, SECRET)
        return self.ingress.accept(
            endpoint_token=TOKEN,
            raw_body=raw,
            headers={
                "X-Razorpay-Signature": signature,
                "X-Razorpay-Event-Id": event_id,
            },
            content_type="application/json; charset=utf-8",
            received_at_epoch=1_788_000_001,
        )

    def test_valid_event_is_verified_normalized_and_stored(self) -> None:
        raw = body()
        receipt = self.accept(raw)
        self.assertIs(receipt.status, IngressStatus.ACCEPTED)
        self.assertTrue(receipt.enqueued)
        self.assertEqual(receipt.merchant_id, "merchant-1")
        self.assertEqual(receipt.canonical_event.resource_id, "pay_test_1")
        self.assertEqual(len(self.inbox), 1)

    def test_exact_replay_is_idempotent(self) -> None:
        raw = body()
        first = self.accept(raw)
        second = self.accept(raw)
        self.assertIs(first.status, IngressStatus.ACCEPTED)
        self.assertIs(second.status, IngressStatus.DUPLICATE)
        self.assertFalse(second.enqueued)
        self.assertEqual(len(self.inbox), 1)

    def test_reused_event_id_with_changed_signed_body_is_conflict(self) -> None:
        self.accept(body(event_id_suffix="1"), event_id="event-shared")
        with self.assertRaises(InboxConflictError):
            self.accept(body(event_id_suffix="2"), event_id="event-shared")

    def test_invalid_signature_is_rejected_before_storage(self) -> None:
        raw = body()
        with self.assertRaises(WebhookVerificationError):
            self.ingress.accept(
                endpoint_token=TOKEN,
                raw_body=raw,
                headers={
                    "X-Razorpay-Signature": "0" * 64,
                    "x-razorpay-event-id": "event-1",
                },
                content_type="application/json",
                received_at_epoch=1,
            )
        self.assertEqual(len(self.inbox), 0)

    def test_account_binding_is_enforced(self) -> None:
        with self.assertRaises(AccountMismatchError):
            self.accept(body(account_id="acc_other"))

    def test_unknown_endpoint_fails_closed(self) -> None:
        raw = body()
        with self.assertRaises(EndpointNotFound):
            self.ingress.accept(
                endpoint_token="unknown_token_1234567890abcdef",
                raw_body=raw,
                headers={},
                content_type="application/json",
                received_at_epoch=1,
            )

    def test_body_limit_and_media_type_are_enforced(self) -> None:
        with self.assertRaises(PayloadTooLarge):
            self.ingress.accept(
                endpoint_token=TOKEN,
                raw_body=b"x" * 2_049,
                headers={},
                content_type="application/json",
                received_at_epoch=1,
            )
        with self.assertRaises(UnsupportedMediaType):
            self.ingress.accept(
                endpoint_token=TOKEN,
                raw_body=b"{}",
                headers={},
                content_type="text/plain",
                received_at_epoch=1,
            )

    def test_previous_secret_stops_verifying_at_its_runtime_expiry(self) -> None:
        current_time = [datetime(2026, 8, 29, 12, 0, tzinfo=UTC)]
        expiry = datetime(2026, 8, 29, 12, 5, tzinfo=UTC)
        binding = EndpointBinding(
            endpoint_token=TOKEN,
            merchant_id="merchant-1",
            provider_account_id="provider-account-1",
            provider_account_identifier="acc_test_1",
            webhook_secrets=(SECRET, PREVIOUS_SECRET),
            previous_secret_expires_at=expiry,
        )
        ingress = WebhookIngress(
            registry=StaticEndpointRegistry((binding,)),
            inbox=InMemoryWebhookInbox(),
            max_body_bytes=2_048,
            clock=lambda: current_time[0],
        )

        first_body = body(event_id_suffix="before")
        first = ingress.accept(
            endpoint_token=TOKEN,
            raw_body=first_body,
            headers={
                "X-Razorpay-Signature": calculate_webhook_signature(first_body, PREVIOUS_SECRET),
                "X-Razorpay-Event-Id": "event-before-expiry",
            },
            content_type="application/json",
            received_at_epoch=1_788_000_001,
        )
        self.assertIs(first.status, IngressStatus.ACCEPTED)

        current_time[0] = expiry
        expired_body = body(event_id_suffix="expired")
        with self.assertRaises(WebhookVerificationError):
            ingress.accept(
                endpoint_token=TOKEN,
                raw_body=expired_body,
                headers={
                    "X-Razorpay-Signature": calculate_webhook_signature(
                        expired_body, PREVIOUS_SECRET
                    ),
                    "X-Razorpay-Event-Id": "event-at-expiry",
                },
                content_type="application/json",
                received_at_epoch=1_788_000_301,
            )

        current_body = body(event_id_suffix="current")
        current = ingress.accept(
            endpoint_token=TOKEN,
            raw_body=current_body,
            headers={
                "X-Razorpay-Signature": calculate_webhook_signature(current_body, SECRET),
                "X-Razorpay-Event-Id": "event-current-secret",
            },
            content_type="application/json",
            received_at_epoch=1_788_000_302,
        )
        self.assertIs(current.status, IngressStatus.ACCEPTED)

    def test_endpoint_binding_rejects_ambiguous_rotation_and_identity(self) -> None:
        expiry = datetime(2026, 8, 30, tzinfo=UTC)
        invalid = (
            {"endpoint_token": "short"},
            {"merchant_id": " merchant-1"},
            {"provider_account_id": ""},
            {"provider_account_identifier": "account\n"},
            {"webhook_secrets": ()},
            {"webhook_secrets": (b"",)},
            {"webhook_secrets": ("not-bytes",)},
            {"previous_secret_expires_at": expiry},
            {"webhook_secrets": (SECRET, PREVIOUS_SECRET)},
            {
                "webhook_secrets": (SECRET, PREVIOUS_SECRET, b"third"),
                "previous_secret_expires_at": expiry,
            },
            {
                "webhook_secrets": (SECRET, PREVIOUS_SECRET),
                "previous_secret_expires_at": datetime(2026, 8, 30),
            },
            {
                "webhook_secrets": (SECRET, PREVIOUS_SECRET),
                "previous_secret_expires_at": datetime(
                    2026, 8, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))
                ),
            },
            {
                "webhook_secrets": (SECRET, SECRET),
                "previous_secret_expires_at": expiry,
            },
        )
        base: dict[str, object] = {
            "endpoint_token": TOKEN,
            "merchant_id": "merchant-1",
            "provider_account_id": "provider-account-1",
            "provider_account_identifier": "acc_test_1",
            "webhook_secrets": (SECRET,),
        }
        for replacement in invalid:
            with self.subTest(fields=tuple(replacement)), self.assertRaises(ValueError):
                EndpointBinding(**{**base, **replacement})  # type: ignore[arg-type]

    def test_binding_clock_registry_and_ingress_construction_fail_closed(self) -> None:
        binding = EndpointBinding(
            endpoint_token=TOKEN,
            merchant_id="merchant-1",
            provider_account_id="provider-account-1",
            provider_account_identifier="acc_test_1",
            webhook_secrets=(SECRET,),
        )
        for invalid_now in (
            "now",
            datetime(2026, 8, 29),
            datetime(2026, 8, 29, tzinfo=timezone(timedelta(hours=1))),
        ):
            with self.subTest(invalid_now=repr(invalid_now)), self.assertRaises(ValueError):
                binding.active_webhook_secrets(now=invalid_now)  # type: ignore[arg-type]

        with self.assertRaisesRegex(ValueError, "duplicate endpoint token"):
            StaticEndpointRegistry((binding, binding))
        for size in (1_023, 1_048_577):
            with self.subTest(size=size), self.assertRaises(ValueError):
                WebhookIngress(
                    registry=StaticEndpointRegistry((binding,)),
                    inbox=InMemoryWebhookInbox(),
                    max_body_bytes=size,
                )
        with self.assertRaises(TypeError):
            WebhookIngress(
                registry=StaticEndpointRegistry((binding,)),
                inbox=InMemoryWebhookInbox(),
                clock="not-callable",  # type: ignore[arg-type]
            )

    def test_readiness_and_request_shape_fail_closed(self) -> None:
        class DurableWithoutProbe:
            durable = True

        class DurableProbe:
            durable = True

            def check_ready(self) -> bool:
                return True

        binding = EndpointBinding(
            endpoint_token=TOKEN,
            merchant_id="merchant-1",
            provider_account_id="provider-account-1",
            provider_account_identifier="acc_test_1",
            webhook_secrets=(SECRET,),
        )
        registry = StaticEndpointRegistry((binding,))
        self.assertFalse(
            WebhookIngress(
                registry=registry,
                inbox=DurableWithoutProbe(),  # type: ignore[arg-type]
            ).check_ready()
        )
        self.assertTrue(
            WebhookIngress(
                registry=registry,
                inbox=DurableProbe(),  # type: ignore[arg-type]
            ).check_ready()
        )

        calls = (
            {"raw_body": "not-bytes", "received_at_epoch": 1},
            {"raw_body": b"", "received_at_epoch": 1},
            {"raw_body": b"{}", "received_at_epoch": -1},
            {"raw_body": b"{}", "received_at_epoch": True},
        )
        for values in calls:
            with self.subTest(values=values), self.assertRaises((TypeError, ValueError)):
                self.ingress.accept(
                    endpoint_token=TOKEN,
                    raw_body=values["raw_body"],  # type: ignore[arg-type]
                    headers={},
                    content_type="application/json",
                    received_at_epoch=values["received_at_epoch"],  # type: ignore[arg-type]
                )


if __name__ == "__main__":
    unittest.main()
