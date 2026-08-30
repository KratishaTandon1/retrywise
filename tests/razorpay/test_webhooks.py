import hashlib
import json
import unittest

from retrywise.packages.razorpay import (
    AccountMismatchError,
    CanonicalEventType,
    WebhookDecodeError,
    WebhookHeaders,
    WebhookVerificationError,
    calculate_webhook_signature,
    normalize_verified_webhook,
    verify_and_normalize_webhook,
    verify_webhook_signature,
)


def _body(event="payment.failed", account_id="acc_test"):
    resource_key = "payment"
    resource_id = "pay_123"
    if event.startswith("payment.downtime."):
        resource_key = "payment.downtime"
        resource_id = "down_123"
    elif event.startswith("payment_link."):
        resource_key = "payment_link"
        resource_id = "plink_123"
    elif event == "order.paid":
        resource_key = "order"
        resource_id = "order_123"
    payload = {
        resource_key: {
            "entity": {
                "id": resource_id,
                "status": event.rsplit(".", 1)[-1],
                "amount": 1200,
            }
        }
    }
    if event == "payment_link.paid":
        payload["payment"] = {"entity": {"id": "pay_recovery", "status": "captured"}}
        payload["order"] = {"entity": {"id": "order_recovery", "status": "paid"}}
    return json.dumps(
        {
            "entity": "event",
            "account_id": account_id,
            "event": event,
            "contains": list(payload),
            "payload": payload,
            "created_at": 1_725_000_000,
        },
        separators=(",", ":"),
    ).encode()


class SignatureTests(unittest.TestCase):
    def test_exact_raw_bytes_are_verified(self):
        raw = b'{"event":"payment.failed", "amount":100}'
        secret = b"test-only-secret"
        signature = calculate_webhook_signature(raw, secret)
        verify_webhook_signature(raw, signature, [secret])

        reencoded = json.dumps(json.loads(raw), separators=(",", ":")).encode()
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(reencoded, signature, [secret])

    def test_previous_secret_is_accepted_during_rotation(self):
        raw = _body()
        old = b"old-test-secret"
        signature = calculate_webhook_signature(raw, old)
        verify_webhook_signature(raw, signature, [b"current-test-secret", old])

    def test_malformed_signature_fails_without_echoing_secrets(self):
        with self.assertRaisesRegex(WebhookVerificationError, "invalid Razorpay"):
            verify_webhook_signature(_body(), "not-hex", [b"test-only-secret"])

    def test_raw_body_must_be_bytes(self):
        with self.assertRaises(TypeError):
            calculate_webhook_signature("{}", b"secret")  # type: ignore[arg-type]


class NormalizationTests(unittest.TestCase):
    def test_verified_payment_failure_is_canonicalized(self):
        raw = _body()
        secret = b"test-only-secret"
        event = verify_and_normalize_webhook(
            raw,
            headers=WebhookHeaders(
                signature=calculate_webhook_signature(raw, secret),
                event_id="evt_123",
            ),
            secrets=[secret],
            expected_account_id="acc_test",
        )
        self.assertEqual(CanonicalEventType.PAYMENT_FAILED, event.event_type)
        self.assertEqual("payment", event.resource_type)
        self.assertEqual("pay_123", event.resource_id)
        self.assertEqual("evt_123", event.event_id)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), event.raw_body_sha256)
        self.assertEqual("failed", event.resource["status"])
        self.assertEqual("payment.failed", event.to_dict()["event_name"])

    def test_payment_link_event_keeps_related_entities(self):
        event = normalize_verified_webhook(_body("payment_link.paid"), event_id="evt_link")
        self.assertEqual(CanonicalEventType.PAYMENT_LINK_PAID, event.event_type)
        self.assertEqual({"payment_link", "payment", "order"}, set(event.related_resources))
        self.assertEqual("pay_recovery", event.related_resources["payment"]["id"])

    def test_canonical_event_drops_contact_credentials_and_free_form_notes(self):
        raw = json.dumps(
            {
                "account_id": "acc_test",
                "event": "payment.failed",
                "created_at": 10,
                "payload": {
                    "payment": {
                        "entity": {
                            "id": "pay_private",
                            "status": "failed",
                            "amount": 1200,
                            "currency": "INR",
                            "method": "upi",
                            "email": "customer@example.com",
                            "contact": "+919999999999",
                            "vpa": "customer@bank",
                            "notes": {"secret": "do-not-store"},
                            "card": {"last4": "1111"},
                            "error_description": "free form provider text",
                        }
                    }
                },
            }
        ).encode()
        event = normalize_verified_webhook(raw, event_id="evt_private")
        persisted = json.dumps(event.to_dict(), sort_keys=True)

        self.assertEqual("pay_private", event.resource["id"])
        self.assertEqual(1200, event.resource["amount"])
        for secret_value in (
            "customer@example.com",
            "+919999999999",
            "customer@bank",
            "do-not-store",
            "1111",
            "free form provider text",
        ):
            self.assertNotIn(secret_value, persisted)

    def test_downtime_uses_dotted_payload_key(self):
        event = normalize_verified_webhook(_body("payment.downtime.started"), event_id="evt_down")
        self.assertEqual(CanonicalEventType.PAYMENT_DOWNTIME_STARTED, event.event_type)
        self.assertEqual("down_123", event.resource_id)

    def test_unknown_event_is_preserved_not_rejected(self):
        raw = json.dumps(
            {
                "account_id": "acc_test",
                "event": "future.entity.changed",
                "created_at": 10,
                "payload": {"future": {"entity": {"id": "future_1", "x": 1}}},
            }
        ).encode()
        event = normalize_verified_webhook(raw, event_id="evt_future")
        self.assertEqual(CanonicalEventType.UNKNOWN, event.event_type)
        self.assertEqual("future.entity.changed", event.event_name)
        self.assertEqual("future_1", event.resource_id)

    def test_account_scope_mismatch_is_rejected(self):
        with self.assertRaises(AccountMismatchError):
            normalize_verified_webhook(
                _body(account_id="acc_other"),
                event_id="evt_123",
                expected_account_id="acc_expected",
            )

    def test_duplicate_json_keys_are_rejected_at_every_depth(self):
        duplicate_root = (
            b'{"account_id":"acc_test","account_id":"acc_other",'
            b'"event":"payment.failed","created_at":10,"payload":{}}'
        )
        duplicate_nested = (
            b'{"account_id":"acc_test","event":"payment.failed","created_at":10,'
            b'"payload":{"payment":{"entity":{"id":"pay_1","id":"pay_2"}}}}'
        )
        for raw in (duplicate_root, duplicate_nested):
            with (
                self.subTest(raw=raw),
                self.assertRaisesRegex(
                    WebhookDecodeError,
                    "duplicate object key",
                ),
            ):
                normalize_verified_webhook(raw, event_id="evt_duplicate")

    def test_headers_are_case_insensitive_and_event_id_is_required(self):
        headers = WebhookHeaders.from_mapping(
            {"X-RAZORPAY-SIGNATURE": "a" * 64, "X-Razorpay-Event-Id": "evt_1"}
        )
        self.assertEqual("evt_1", headers.event_id)
        with self.assertRaises(WebhookDecodeError):
            WebhookHeaders.from_mapping({"X-Razorpay-Signature": "a" * 64})


if __name__ == "__main__":
    unittest.main()
