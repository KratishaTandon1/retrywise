from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from retrywise.services.control_plane.normalized_event_router import (
    ProcessNormalizedProviderEventRouter,
)
from retrywise.services.control_plane.outbox import RetryMode
from retrywise.services.control_plane.outbox_worker import HandlerDisposition, HandlerResult
from retrywise.services.control_plane.postgres_outbox import ClaimedOutboxCommand

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
EVENT_RECORD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
INBOX_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def claim(event_type: str = "payment.failed") -> ClaimedOutboxCommand:
    return ClaimedOutboxCommand(
        job_id=JOB_ID,
        merchant_id=MERCHANT_ID,
        aggregate_type="PROVIDER_EVENT",
        aggregate_id=EVENT_RECORD_ID,
        command_type="PROCESS_NORMALIZED_PROVIDER_EVENT",
        command_schema_version=1,
        command_payload={
            "event_type": event_type,
            "inbox_event_id": INBOX_ID,
            "merchant_id": MERCHANT_ID,
            "provider_account_id": PROVIDER_ACCOUNT_ID,
            "provider_event_id": "evt_test_1",
            "provider_event_record_id": EVENT_RECORD_ID,
            "schema_version": 1,
        },
        idempotency_key=f"normalized-provider-event:{EVENT_RECORD_ID}",
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


class ProcessNormalizedProviderEventRouterTests(unittest.TestCase):
    def test_routes_failure_unknown_and_terminal_without_double_dispatch(self) -> None:
        calls: list[str] = []
        router = ProcessNormalizedProviderEventRouter(
            failure_handler=lambda command: (
                calls.append("failure") or HandlerResult.succeeded("failure")
            ),
            terminal_handler=lambda command: (
                calls.append("terminal") or HandlerResult.succeeded("terminal")
            ),
        )

        self.assertEqual("failure", router(claim()).completion_reference)
        self.assertEqual("terminal", router(claim("payment.captured")).completion_reference)
        self.assertEqual("failure", router(claim("refund.processed")).completion_reference)
        self.assertEqual(["failure", "terminal", "failure"], calls)

    def test_invalid_envelope_dead_letters_before_handlers(self) -> None:
        calls: list[str] = []
        router = ProcessNormalizedProviderEventRouter(
            failure_handler=lambda command: (
                calls.append("failure") or HandlerResult.succeeded("failure")
            ),
            terminal_handler=lambda command: (
                calls.append("terminal") or HandlerResult.succeeded("terminal")
            ),
        )
        malformed = replace(claim(), command_schema_version=2)

        result = router(malformed)

        self.assertEqual(HandlerDisposition.DEAD_LETTER, result.disposition)
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()
