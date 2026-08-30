from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from retrywise.packages.domain import IncidentState
from retrywise.services.control_plane.assessment_intent import (
    AssessmentMethodHealthError,
    AssessmentProviderTruthError,
    MethodHealthQuery,
    ProviderPaymentStatus,
    ProviderTruthQuery,
)
from retrywise.services.control_plane.provider_readers import (
    PostgresFreshMethodHealthReader,
    RazorpayFreshProviderTruthReader,
)
from retrywise.services.control_plane.razorpay_test_adapter import PaymentRecord, PaymentStatus

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
PAYMENT_RECORD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
INCIDENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def provider_query() -> ProviderTruthQuery:
    return ProviderTruthQuery(
        merchant_id=MERCHANT_ID,
        provider_account_id=PROVIDER_ACCOUNT_ID,
        provider_account_identifier="acc_test_1",
        credential_binding_version=3,
        payment_record_id=PAYMENT_RECORD_ID,
        provider_payment_id="pay_test_1",
        provider_order_id="order_test_1",
    )


class _Adapter:
    def __init__(self, record: PaymentRecord) -> None:
        self.record = record
        self.closed = False

    def fetch_payment(self, *, payment_id: str, provider_account_id: str) -> PaymentRecord:
        return self.record

    def close(self) -> None:
        self.closed = True


class _Cursor:
    def __init__(self, row: Sequence[object] | None) -> None:
        self.row = row
        self.queries: list[str] = []

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, params: Mapping[str, object] | None = None) -> None:
        self.queries.append(query)

    def fetchone(self) -> Sequence[object] | None:
        return self.row


class _Connection:
    def __init__(self, cursor: _Cursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def transaction(self) -> _Connection:
        return self

    def cursor(self) -> _Cursor:
        return self._cursor


class ProviderReaderTests(unittest.TestCase):
    def test_provider_reader_converts_redacted_fresh_truth_and_closes_adapter(self) -> None:
        adapter = _Adapter(
            PaymentRecord(
                payment_id="pay_test_1",
                order_id="order_test_1",
                status=PaymentStatus.FAILED,
                amount_minor=129_900,
                currency="INR",
                captured_minor=0,
                refunded_minor=0,
                payment_method="upi",
                error_source="customer",
                error_step="payment_authentication",
                error_reason="payment_failed",
            )
        )
        reader = RazorpayFreshProviderTruthReader(
            adapter_factory=lambda merchant_id, account_id: adapter,
            clock=lambda: NOW,
        )

        result = reader.fetch_fresh_payment_truth(provider_query())

        self.assertEqual(ProviderPaymentStatus.FAILED, result.status)
        self.assertEqual(3, result.credential_binding_version)
        self.assertTrue(adapter.closed)

    def test_provider_reader_rejects_provider_identity_drift(self) -> None:
        adapter = _Adapter(
            PaymentRecord(
                payment_id="pay_other",
                order_id="order_test_1",
                status=PaymentStatus.FAILED,
                amount_minor=129_900,
                currency="INR",
                captured_minor=0,
                refunded_minor=0,
                payment_method="upi",
                error_source="unknown",
                error_step="unknown",
                error_reason="unknown",
            )
        )
        reader = RazorpayFreshProviderTruthReader(
            adapter_factory=lambda merchant_id, account_id: adapter,
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(
            AssessmentProviderTruthError,
            "^fresh_provider_truth_binding_mismatch$",
        ):
            reader.fetch_fresh_payment_truth(provider_query())
        self.assertTrue(adapter.closed)

    def test_method_health_returns_fresh_normal_or_exact_bound_incident(self) -> None:
        normal_cursor = _Cursor((NOW,))
        normal = PostgresFreshMethodHealthReader(
            connector=lambda: _Connection(normal_cursor),
        ).fetch_fresh_method_health(
            MethodHealthQuery(
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
                payment_method="upi",
                incident_id=None,
            )
        )
        self.assertEqual(IncidentState.NORMAL, normal.incident_state)

        incident_cursor = _Cursor(
            (NOW, INCIDENT_ID, "CONFIRMED", "detector-v1", "threshold-v1", NOW)
        )
        incident = PostgresFreshMethodHealthReader(
            connector=lambda: _Connection(incident_cursor),
        ).fetch_fresh_method_health(
            MethodHealthQuery(
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
                payment_method="upi",
                incident_id=INCIDENT_ID,
            )
        )
        self.assertEqual(IncidentState.CONFIRMED, incident.incident_state)
        self.assertEqual(INCIDENT_ID, incident.incident_id)

    def test_method_health_fails_closed_when_bound_incident_is_missing(self) -> None:
        reader = PostgresFreshMethodHealthReader(connector=lambda: _Connection(_Cursor(None)))
        with self.assertRaisesRegex(
            AssessmentMethodHealthError,
            "^fresh_method_health_unavailable$",
        ):
            reader.fetch_fresh_method_health(
                MethodHealthQuery(
                    merchant_id=MERCHANT_ID,
                    provider_account_id=PROVIDER_ACCOUNT_ID,
                    payment_method="upi",
                    incident_id=INCIDENT_ID,
                )
            )


if __name__ == "__main__":
    unittest.main()
