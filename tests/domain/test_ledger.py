from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta

from retrywise.packages.domain import (
    DecisionLedger,
    InvalidValue,
    LedgerIntegrityError,
    LedgerVerificationReason,
    verify_ledger,
)
from tests.domain.helpers import NOW, context, gate, proposal


class DecisionLedgerTests(unittest.TestCase):
    def test_append_and_verify_domain_evidence(self) -> None:
        candidate = proposal()
        decision = gate().evaluate_policy(candidate, context())
        ledger = DecisionLedger("case_1")
        first = ledger.append(
            entry_type="ActionProposed",
            payload={"proposal": candidate},
            recorded_at=NOW,
        )
        second = ledger.append(
            entry_type="PolicyGateEvaluated",
            payload={"decision": decision},
            recorded_at=NOW + timedelta(seconds=1),
        )
        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.previous_hash, first.entry_hash)
        self.assertEqual(ledger.head_hash, second.entry_hash)
        verification = ledger.verify()
        self.assertTrue(verification.valid)
        self.assertEqual(verification.checked_entries, 2)

    def test_payload_key_order_produces_identical_genesis_hash(self) -> None:
        first = DecisionLedger("case_1")
        second = DecisionLedger("case_1")
        entry_a = first.append(
            entry_type="EvidenceRecorded",
            payload={"b": 2, "a": 1},
            recorded_at=NOW,
        )
        entry_b = second.append(
            entry_type="EvidenceRecorded",
            payload={"a": 1, "b": 2},
            recorded_at=NOW,
        )
        self.assertEqual(entry_a.payload_json, entry_b.payload_json)
        self.assertEqual(entry_a.entry_hash, entry_b.entry_hash)

    def test_payload_tampering_is_detected(self) -> None:
        ledger = DecisionLedger("case_1")
        entry = ledger.append(
            entry_type="EvidenceRecorded", payload={"amount": 100}, recorded_at=NOW
        )
        tampered = replace(entry, payload_json='{"amount":101}')
        result = verify_ledger((tampered,), expected_case_id="case_1")
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, LedgerVerificationReason.ENTRY_HASH_MISMATCH)

    def test_noncanonical_payload_is_rejected_before_hash_comparison(self) -> None:
        ledger = DecisionLedger("case_1")
        entry = ledger.append(
            entry_type="EvidenceRecorded", payload={"amount": 100}, recorded_at=NOW
        )
        tampered = replace(entry, payload_json='{ "amount": 100 }')
        result = verify_ledger((tampered,), expected_case_id="case_1")
        self.assertEqual(result.reason, LedgerVerificationReason.PAYLOAD_NOT_CANONICAL)

    def test_reordering_or_breaking_a_link_is_detected(self) -> None:
        ledger = DecisionLedger("case_1")
        first = ledger.append(entry_type="FirstEvent", payload={"n": 1}, recorded_at=NOW)
        second = ledger.append(
            entry_type="SecondEvent",
            payload={"n": 2},
            recorded_at=NOW + timedelta(seconds=1),
        )
        reordered = verify_ledger((second, first), expected_case_id="case_1")
        self.assertEqual(reordered.reason, LedgerVerificationReason.SEQUENCE_MISMATCH)
        broken = replace(second, previous_hash="f" * 64)
        result = verify_ledger((first, broken), expected_case_id="case_1")
        self.assertEqual(result.reason, LedgerVerificationReason.PREVIOUS_HASH_MISMATCH)

    def test_case_binding_and_entry_hash_shape_are_verified(self) -> None:
        ledger = DecisionLedger("case_1")
        entry = ledger.append(entry_type="EvidenceRecorded", payload={"ok": True}, recorded_at=NOW)
        wrong_case = replace(entry, case_id="case_2")
        result = verify_ledger((wrong_case,), expected_case_id="case_1")
        self.assertEqual(result.reason, LedgerVerificationReason.CASE_MISMATCH)
        bad_hash = replace(entry, entry_hash="not-a-hash")
        result = verify_ledger((bad_hash,), expected_case_id="case_1")
        self.assertEqual(result.reason, LedgerVerificationReason.ENTRY_HASH_INVALID)

    def test_case_binding_is_enforced_without_an_explicit_expected_case(self) -> None:
        first_ledger = DecisionLedger("case_1")
        first = first_ledger.append(
            entry_type="EvidenceRecorded", payload={"n": 1}, recorded_at=NOW
        )
        second = replace(
            first,
            sequence=2,
            case_id="case_2",
            previous_hash=first.entry_hash,
        )
        result = verify_ledger((first, second))
        self.assertEqual(result.reason, LedgerVerificationReason.CASE_MISMATCH)

    def test_float_payload_and_timestamp_regression_cannot_be_appended(self) -> None:
        ledger = DecisionLedger("case_1")
        with self.assertRaises(InvalidValue):
            ledger.append(entry_type="ModelScore", payload={"score": 0.9}, recorded_at=NOW)
        ledger.append(entry_type="FirstEvent", payload={"score": "0.9"}, recorded_at=NOW)
        with self.assertRaises(LedgerIntegrityError):
            ledger.append(
                entry_type="OldEvent",
                payload={"score": "0.9"},
                recorded_at=NOW - timedelta(seconds=1),
            )

    def test_invalid_existing_chain_cannot_be_loaded(self) -> None:
        ledger = DecisionLedger("case_1")
        entry = ledger.append(entry_type="EvidenceRecorded", payload={"ok": True}, recorded_at=NOW)
        tampered = replace(entry, entry_hash="f" * 64)
        with self.assertRaises(LedgerIntegrityError):
            DecisionLedger("case_1", (tampered,))


if __name__ == "__main__":
    unittest.main()
