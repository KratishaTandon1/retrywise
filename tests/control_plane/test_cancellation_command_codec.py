from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from retrywise.packages.domain import (
    ActionProposal,
    ActionType,
    GateDecision,
    GateStage,
)
from retrywise.packages.domain.canonical import canonical_json_bytes
from retrywise.packages.razorpay import make_recovery_reference_id
from retrywise.services.control_plane.cancellation import (
    CancellationTarget,
    CancelPaymentLinkCommand,
)
from retrywise.services.control_plane.cancellation_command_codec import (
    CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    CANCEL_PAYMENT_LINK_COMMAND_TYPE,
    EffectCommandBindingError,
    EffectCommandIntegrityError,
    EffectCommandPrivacyError,
    EffectCommandSchemaError,
    EffectCommandSizeError,
    decode_cancel_payment_link_command,
    encode_cancel_payment_link_command,
    encode_cancel_payment_link_command_json,
)
from retrywise.services.control_plane.effect_command_codec import MAX_EFFECT_COMMAND_BYTES

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
PROVIDER_ACCOUNT_ID = "provider_account_1"
PAYMENT_LINK_ID = "plink_ExjpAUN3gVHrPJ"


def plan_for(proposal: ActionProposal) -> GateDecision:
    return GateDecision(
        stage=GateStage.POLICY,
        policy_version="policy-v1",
        proposal_id=proposal.proposal_id,
        action_key=proposal.action_key,
        proposal_digest=proposal.proposal_digest,
        case_id=proposal.case_id,
        decision_version=proposal.decision_version,
        aggregate_version=8,
        evaluated_at=NOW + timedelta(seconds=1),
        reasons=(),
    )


def command() -> CancelPaymentLinkCommand:
    proposal = ActionProposal(
        proposal_id="proposal_cancel_1",
        merchant_id="merchant_1",
        case_id="case_1",
        decision_version=3,
        action_type=ActionType.CANCEL_PAYMENT_LINK,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        instrument_reference=PAYMENT_LINK_ID,
    )
    target = CancellationTarget(
        merchant_id=proposal.merchant_id,
        case_id=proposal.case_id,
        action_id="action_cancel_1",
        action_key=proposal.action_key,
        instrument_id="instrument_1",
        provider_account_id=PROVIDER_ACCOUNT_ID,
        payment_link_id=PAYMENT_LINK_ID,
        reference_id=make_recovery_reference_id(
            proposal.case_id,
            provider_account_id=PROVIDER_ACCOUNT_ID,
        ),
        amount_minor=129_900,
        currency="INR",
    )
    return CancelPaymentLinkCommand(proposal, plan_for(proposal), target)


def reseal(envelope: dict[str, object]) -> None:
    unsigned = {key: value for key, value in envelope.items() if key != "integrity"}
    integrity = envelope["integrity"]
    assert isinstance(integrity, dict)
    integrity["digest"] = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def jsonb_safe(value: object) -> bool:
    if value is None or type(value) in {str, int, bool}:
        return True
    if isinstance(value, list):
        return all(jsonb_safe(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and jsonb_safe(item) for key, item in value.items())
    return False


class CancelPaymentLinkCommandCodecTests(unittest.TestCase):
    def test_round_trip_mapping_and_canonical_json(self) -> None:
        original = command()

        envelope = encode_cancel_payment_link_command(original)
        canonical = encode_cancel_payment_link_command_json(original)

        self.assertEqual(original, decode_cancel_payment_link_command(envelope))
        self.assertEqual(original, decode_cancel_payment_link_command(canonical))
        self.assertEqual(canonical_json_bytes(envelope), canonical)
        self.assertTrue(jsonb_safe(envelope))
        self.assertLess(len(canonical), MAX_EFFECT_COMMAND_BYTES)
        self.assertEqual(CANCEL_PAYMENT_LINK_COMMAND_TYPE, envelope["command_type"])
        self.assertEqual(CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION, envelope["version"])

    def test_envelope_contains_every_immutable_cross_binding(self) -> None:
        original = command()
        envelope = encode_cancel_payment_link_command(original)
        bindings = envelope["bindings"]
        self.assertIsInstance(bindings, dict)
        assert isinstance(bindings, dict)

        self.assertEqual(original.proposal.action_key, bindings["action_key"])
        self.assertEqual(original.proposal.proposal_digest, bindings["proposal_sha256"])
        self.assertEqual(original.prior_plan.decision_digest, bindings["prior_plan_sha256"])
        self.assertEqual(original.target_digest, bindings["target_sha256"])
        self.assertEqual(original.payload_digest, bindings["executor_payload_sha256"])

    def test_unknown_missing_and_sensitive_fields_are_rejected(self) -> None:
        for mutation in ("unknown", "missing", "sensitive"):
            with self.subTest(mutation=mutation):
                envelope = encode_cancel_payment_link_command(command())
                command_value = envelope["command"]
                assert isinstance(command_value, dict)
                target = command_value["target"]
                assert isinstance(target, dict)
                expected_error: type[Exception] = EffectCommandSchemaError
                if mutation == "unknown":
                    target["benign_extension"] = "future"
                elif mutation == "missing":
                    del target["currency"]
                else:
                    target["api_secret"] = "must-not-cross-boundary"
                    expected_error = EffectCommandPrivacyError
                reseal(envelope)

                with self.assertRaises(expected_error):
                    decode_cancel_payment_link_command(envelope)

    def test_schema_and_external_metadata_mismatches_are_rejected(self) -> None:
        envelope = encode_cancel_payment_link_command(command())
        envelope["version"] = 2
        reseal(envelope)
        with self.assertRaises(EffectCommandSchemaError):
            decode_cancel_payment_link_command(envelope)

        valid = encode_cancel_payment_link_command(command())
        with self.assertRaises(EffectCommandSchemaError):
            decode_cancel_payment_link_command(valid, command_schema_version=2)
        with self.assertRaises(EffectCommandSchemaError):
            decode_cancel_payment_link_command(valid, command_type="SEND_EMAIL")

    def test_outer_integrity_and_duplicated_target_digest_are_verified(self) -> None:
        envelope = encode_cancel_payment_link_command(command())
        command_value = envelope["command"]
        assert isinstance(command_value, dict)
        target = command_value["target"]
        assert isinstance(target, dict)
        target["instrument_id"] = "instrument_other"
        with self.assertRaises(EffectCommandIntegrityError):
            decode_cancel_payment_link_command(envelope)

        reseal(envelope)
        with self.assertRaises(EffectCommandIntegrityError):
            decode_cancel_payment_link_command(envelope)

    def test_noncanonical_duplicate_and_oversized_payloads_are_rejected(self) -> None:
        envelope = encode_cancel_payment_link_command(command())
        with self.assertRaises(EffectCommandSchemaError):
            decode_cancel_payment_link_command(json.dumps(envelope).encode())

        canonical = encode_cancel_payment_link_command_json(command())
        duplicated = canonical.replace(b'{"bindings":', b'{"schema":"duplicate","bindings":', 1)
        with self.assertRaises(EffectCommandSchemaError):
            decode_cancel_payment_link_command(duplicated)

        oversized = encode_cancel_payment_link_command(command())
        oversized["padding"] = "x" * MAX_EFFECT_COMMAND_BYTES
        with self.assertRaises(EffectCommandSizeError):
            decode_cancel_payment_link_command(oversized)

    def test_constructor_rejects_wrong_action_and_target_binding(self) -> None:
        original = command()
        wrong_proposal = replace(
            original.proposal,
            action_type=ActionType.STOP,
            instrument_reference=None,
        )
        wrong_target = replace(original.target, action_key=wrong_proposal.action_key)
        with self.assertRaisesRegex(ValueError, "cancellation proposal"):
            CancelPaymentLinkCommand(
                wrong_proposal,
                plan_for(wrong_proposal),
                wrong_target,
            )

        other_case = "case_2"
        mismatched_target = replace(
            original.target,
            case_id=other_case,
            reference_id=make_recovery_reference_id(
                other_case,
                provider_account_id=original.target.provider_account_id,
            ),
        )
        with self.assertRaisesRegex(ValueError, "not bound"):
            CancelPaymentLinkCommand(
                original.proposal,
                original.prior_plan,
                mismatched_target,
            )

    def test_resealed_plan_or_target_mutation_fails_closed(self) -> None:
        plan_mismatch = encode_cancel_payment_link_command(command())
        command_value = plan_mismatch["command"]
        assert isinstance(command_value, dict)
        prior_plan = command_value["prior_plan"]
        assert isinstance(prior_plan, dict)
        prior_plan["case_id"] = "case_2"
        reseal(plan_mismatch)
        with self.assertRaises(EffectCommandBindingError):
            decode_cancel_payment_link_command(plan_mismatch)

        target_mismatch = encode_cancel_payment_link_command(command())
        command_value = target_mismatch["command"]
        assert isinstance(command_value, dict)
        target = command_value["target"]
        assert isinstance(target, dict)
        target["payment_link_id"] = "plink_other"
        reseal(target_mismatch)
        with self.assertRaises(EffectCommandBindingError):
            decode_cancel_payment_link_command(target_mismatch)


if __name__ == "__main__":
    unittest.main()
