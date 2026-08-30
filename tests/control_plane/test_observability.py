from __future__ import annotations

import asyncio
import json
import logging
import unittest
from io import StringIO
from types import SimpleNamespace

from retrywise.services.control_plane.api import _read_bounded_body
from retrywise.services.control_plane.observability import (
    REDACTED,
    CounterName,
    InProcessCounters,
    Observability,
    StructuredJsonFormatter,
    bind_request_id,
    choose_request_id,
    reset_request_id,
    safe_route_template,
)
from retrywise.services.control_plane.webhook_ingress import PayloadTooLarge


class _ChunkedRequest:
    def __init__(self, chunks: tuple[bytes, ...], content_length: str | None = None) -> None:
        self._chunks = chunks
        self.headers = {} if content_length is None else {"content-length": content_length}

    async def stream(self):  # type annotation is inferred as an async iterator by mypy.
        for chunk in self._chunks:
            yield chunk


class ObservabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.output = StringIO()
        logger = logging.Logger("retrywise.test.observability", level=logging.INFO)
        handler = logging.StreamHandler(self.output)
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)
        self.observability = Observability(logger=logger)

    def test_structured_event_recursively_redacts_credentials_and_customer_data(self) -> None:
        request_id_token = bind_request_id("request-safe-0001")
        try:
            self.observability.event(
                "security.redaction.checked",
                fields={
                    "Authorization": "Bearer operator-secret",
                    "endpoint_token": "webhook-endpoint-secret",
                    "event": "caller-injected-event",
                    "nested": {
                        "customer_email": "buyer@example.com",
                        "phone": "+919876543210",
                        "webhook_secret": "signing-secret",
                    },
                    "raw_body": b'{"email":"buyer@example.com"}',
                    "safe_message": (
                        "POST /api/v1/webhooks/razorpay/webhook-endpoint-secret"
                        "?email=buyer@example.com"
                    ),
                },
            )
        finally:
            reset_request_id(request_id_token)

        document = json.loads(self.output.getvalue())
        self.assertEqual(document["event"], "security.redaction.checked")
        self.assertEqual(document["request_id"], "request-safe-0001")
        self.assertEqual(document["Authorization"], REDACTED)
        self.assertEqual(document["endpoint_token"], REDACTED)
        self.assertEqual(document["raw_body"], REDACTED)
        self.assertEqual(document["nested"]["customer_email"], REDACTED)
        self.assertEqual(document["nested"]["phone"], REDACTED)
        serialized = self.output.getvalue()
        for forbidden in (
            "operator-secret",
            "webhook-endpoint-secret",
            "buyer@example.com",
            "+919876543210",
            "signing-secret",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_request_ids_and_routes_are_safe_before_logging(self) -> None:
        self.assertEqual(choose_request_id("caller-request-0001"), "caller-request-0001")
        generated = choose_request_id("bad request id with spaces and a secret")
        self.assertRegex(generated, r"^req_[0-9a-f]{32}$")
        self.assertEqual(safe_route_template({}), "<unmatched>")
        self.assertEqual(
            safe_route_template(
                {"route": SimpleNamespace(path="/api/v1/webhooks/razorpay/live-secret-token")}
            ),
            "/api/v1/webhooks/razorpay/{endpoint_token}",
        )

    def test_counters_have_a_fixed_zero_initialized_schema(self) -> None:
        counters = InProcessCounters()
        counters.increment(CounterName.WEBHOOK_ACCEPTED)
        snapshot = counters.snapshot()
        self.assertEqual(snapshot["webhook_accepted_total"], 1)
        self.assertEqual(snapshot["webhook_duplicate_total"], 0)
        self.assertEqual(snapshot["webhook_conflict_total"], 0)
        self.assertEqual(snapshot["webhook_verification_failure_total"], 0)
        self.assertEqual(snapshot["replay_submission_total"], 0)

    def test_bounded_reader_preserves_chunks_and_rejects_declared_or_actual_overflow(self) -> None:
        exact = asyncio.run(
            _read_bounded_body(
                _ChunkedRequest((b'{"pay', b'ment":1}'), "13"),
                max_body_bytes=13,
            )
        )
        self.assertEqual(exact, b'{"payment":1}')

        with self.assertRaises(PayloadTooLarge):
            asyncio.run(
                _read_bounded_body(
                    _ChunkedRequest((b"small",), "14"),
                    max_body_bytes=13,
                )
            )
        with self.assertRaises(PayloadTooLarge):
            asyncio.run(
                _read_bounded_body(
                    _ChunkedRequest((b"1234567", b"8901234")),
                    max_body_bytes=13,
                )
            )


if __name__ == "__main__":
    unittest.main()
