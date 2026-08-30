import json
import unittest

from retrywise.packages.razorpay import (
    AmbiguousCreateAction,
    PaymentLinkCustomer,
    PaymentLinkLookupResult,
    PaymentLinkValidationError,
    StandardPaymentLinkRequest,
    decide_ambiguous_create,
)

NOW = 1_725_000_000


def _request(**changes):
    values = {
        "amount_minor": 129_900,
        "currency": "INR",
        "reference_id": "rtw_case1_abcdefghijklmnopqrstuvwx",
        "description": "Retry payment for merchant order ORD-1042",
        "expire_by_epoch": NOW + 3_600,
        "notes": {
            "recovery_case_id": "case-1",
            "merchant_order_id": "ORD-1042",
        },
        "customer": PaymentLinkCustomer(
            "Test Customer", contact="+919876543210", email="test@example.com"
        ),
    }
    values.update(changes)
    return StandardPaymentLinkRequest(**values)


def _candidate(request=None, **changes):
    request = request or _request()
    values = {
        "id": "plink_123",
        "reference_id": request.reference_id,
        "amount": request.amount_minor,
        "currency": request.currency,
        "accept_partial": False,
        "upi_link": False,
        "status": "created",
    }
    values.update(changes)
    return values


class StandardPaymentLinkRequestTests(unittest.TestCase):
    def test_serialization_forces_safe_standard_link_options(self):
        request = _request()
        payload = request.to_payload(now_epoch=NOW)
        self.assertEqual(129_900, payload["amount"])
        self.assertIs(False, payload["accept_partial"])
        self.assertIs(False, payload["upi_link"])
        self.assertEqual({"sms": False, "email": False}, payload["notify"])
        self.assertIs(False, payload["reminder_enable"])
        self.assertEqual("Test Customer", payload["customer"]["name"])

        encoded = request.to_json_bytes(now_epoch=NOW)
        self.assertEqual(payload, json.loads(encoded))

    def test_amount_must_already_be_integer_minor_units(self):
        for invalid in (1299.0, True, 0, -1, "129900"):
            with self.subTest(invalid=invalid), self.assertRaises(PaymentLinkValidationError):
                _request(amount_minor=invalid)

    def test_reference_currency_notes_and_expiry_are_strict(self):
        with self.assertRaises(PaymentLinkValidationError):
            _request(currency="inr")
        with self.assertRaises(PaymentLinkValidationError):
            _request(reference_id="x" * 41)
        with self.assertRaises(PaymentLinkValidationError):
            _request(notes={str(i): "value" for i in range(16)})
        with self.assertRaises(PaymentLinkValidationError):
            _request(expire_by_epoch=NOW + 899).to_payload(now_epoch=NOW)

    def test_expiry_may_not_exceed_six_calendar_months(self):
        with self.assertRaises(PaymentLinkValidationError):
            _request(expire_by_epoch=NOW + 190 * 86_400).to_payload(now_epoch=NOW)

    def test_input_notes_are_copied_before_serialization(self):
        notes = {"case": "case-1"}
        request = _request(notes=notes)
        notes["case"] = "changed"
        self.assertEqual("case-1", request.to_payload()["notes"]["case"])


class AmbiguousCreateDecisionTests(unittest.TestCase):
    def test_incomplete_lookup_must_be_requeried_not_created(self):
        decision = decide_ambiguous_create(_request(), PaymentLinkLookupResult(completed=False))
        self.assertEqual(AmbiguousCreateAction.REQUERY, decision.action)

    def test_completed_empty_lookup_allows_same_reference_retry(self):
        decision = decide_ambiguous_create(_request(), PaymentLinkLookupResult(completed=True))
        self.assertEqual(AmbiguousCreateAction.RETRY_CREATE_SAME_REFERENCE, decision.action)

    def test_matching_candidate_is_adopted_even_when_terminal(self):
        request = _request()
        decision = decide_ambiguous_create(
            request,
            PaymentLinkLookupResult(
                completed=True, candidates=[_candidate(request, status="paid")]
            ),
        )
        self.assertEqual(AmbiguousCreateAction.ADOPT_EXISTING, decision.action)
        self.assertEqual("plink_123", decision.payment_link_id)

    def test_conflicting_money_or_link_mode_escalates(self):
        request = _request()
        for candidate in (
            _candidate(request, amount=request.amount_minor + 1),
            _candidate(request, accept_partial=True),
            _candidate(request, upi_link=True),
        ):
            with self.subTest(candidate=candidate):
                decision = decide_ambiguous_create(
                    request,
                    PaymentLinkLookupResult(completed=True, candidates=[candidate]),
                )
                self.assertEqual(AmbiguousCreateAction.ESCALATE, decision.action)

    def test_multiple_or_malformed_candidates_escalate(self):
        request = _request()
        multiple = decide_ambiguous_create(
            request,
            PaymentLinkLookupResult(
                completed=True, candidates=[_candidate(request), _candidate(request)]
            ),
        )
        malformed = decide_ambiguous_create(
            request,
            PaymentLinkLookupResult(completed=True, candidates=[{"id": "plink_1"}]),
        )
        self.assertEqual(AmbiguousCreateAction.ESCALATE, multiple.action)
        self.assertEqual(AmbiguousCreateAction.ESCALATE, malformed.action)

    def test_lookup_copies_provider_candidates_before_deciding(self):
        request = _request()
        candidate = _candidate(request)
        lookup = PaymentLinkLookupResult(completed=True, candidates=[candidate])
        candidate["amount"] += 1
        decision = decide_ambiguous_create(request, lookup)
        self.assertEqual(AmbiguousCreateAction.ADOPT_EXISTING, decision.action)


if __name__ == "__main__":
    unittest.main()
