import json
import unittest

from retrywise.packages.razorpay import (
    InboxConflictError,
    InboxRecord,
    InboxWriteResult,
    InMemoryWebhookInbox,
    normalize_verified_webhook,
)


def _event(event_id="evt_1", account_id="acc_1", status="failed"):
    raw = json.dumps(
        {
            "account_id": account_id,
            "event": "payment.failed",
            "created_at": 1,
            "payload": {"payment": {"entity": {"id": "pay_1", "status": status, "amount": 100}}},
        },
        separators=(",", ":"),
    ).encode()
    return normalize_verified_webhook(raw, event_id=event_id)


class InboxTests(unittest.TestCase):
    def test_same_account_and_event_id_is_deduplicated(self):
        inbox = InMemoryWebhookInbox()
        record = InboxRecord(_event(), received_at_epoch=2)
        self.assertEqual(InboxWriteResult.STORED, inbox.store_once(record))
        self.assertEqual(InboxWriteResult.DUPLICATE, inbox.store_once(record))
        self.assertEqual(1, len(inbox))

    def test_dedupe_key_is_scoped_by_provider_account(self):
        inbox = InMemoryWebhookInbox()
        self.assertEqual(
            InboxWriteResult.STORED,
            inbox.store_once(InboxRecord(_event(account_id="acc_1"), 2)),
        )
        self.assertEqual(
            InboxWriteResult.STORED,
            inbox.store_once(InboxRecord(_event(account_id="acc_2"), 2)),
        )
        self.assertEqual(2, len(inbox))

    def test_same_event_id_with_different_content_is_a_conflict(self):
        inbox = InMemoryWebhookInbox()
        inbox.store_once(InboxRecord(_event(status="failed"), 2))
        with self.assertRaises(InboxConflictError):
            inbox.store_once(InboxRecord(_event(status="captured"), 3))


if __name__ == "__main__":
    unittest.main()
