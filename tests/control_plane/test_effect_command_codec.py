from __future__ import annotations

import hashlib
import json
import unittest
from datetime import UTC, datetime, timedelta

from retrywise.packages.domain import (
    ActionProposal,
    ActionType,
    GateDecision,
    GateReason,
    GateStage,
    Money,
    Probability,
)
from retrywise.packages.domain.canonical import canonical_json_bytes
from retrywise.packages.razorpay import (
    PaymentLinkCustomer,
    StandardPaymentLinkRequest,
    make_recovery_reference_id,
)
from retrywise.services.control_plane.effect_command_codec import (
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
    MAX_EFFECT_COMMAND_BYTES,
    EffectCommandBindingError,
    EffectCommandIntegrityError,
    EffectCommandPrivacyError,
    EffectCommandSchemaError,
    EffectCommandSizeError,
    decode_create_standard_payment_link_command,
    encode_create_standard_payment_link_command,
    encode_create_standard_payment_link_command_json,
)
from retrywise.services.control_plane.executor import CreatePaymentLinkCommand

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
PROVIDER_ACCOUNT_ID = "provider_account_test_1"
REFERENCE = make_recovery_reference_id("case_1", provider_account_id=PROVIDER_ACCOUNT_ID)


def command(
    *,
    request: StandardPaymentLinkRequest | None = None,
    action_type: ActionType = ActionType.CREATE_STANDARD_PAYMENT_LINK,
) -> CreatePaymentLinkCommand:
    proposal = ActionProposal(
        proposal_id="proposal_1",
        merchant_id="merchant_1",
        case_id="case_1",
        decision_version=3,
        action_type=action_type,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        attempt_ordinal=2,
        amount=Money(129_900, "INR"),
        payment_method="upi",
        expected_value_minor=30_000,
        model_confidence=Probability("0.90"),
    )
    plan = GateDecision(
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
    payment_request = request or StandardPaymentLinkRequest(
        amount_minor=129_900,
        currency="INR",
        reference_id=REFERENCE,
        description="Retry payment for order ORD-1042",
        expire_by_epoch=int((NOW + timedelta(minutes=50)).timestamp()),
        notes={"recovery_case_id": "case_1", "merchant_order_id": "ORD-1042"},
    )
    return CreatePaymentLinkCommand(
        proposal=proposal,
        prior_plan=plan,
        request=payment_request,
        provider_account_id=PROVIDER_ACCOUNT_ID,
    )


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


class EffectCommandCodecTests(unittest.TestCase):
    def test_round_trip_mapping_and_canonical_json(self) -> None:
        original = command()

        envelope = encode_create_standard_payment_link_command(original)
        canonical = encode_create_standard_payment_link_command_json(original)
        from_mapping = decode_create_standard_payment_link_command(envelope)
        from_bytes = decode_create_standard_payment_link_command(canonical)

        self.assertEqual(original, from_mapping)
        self.assertEqual(original, from_bytes)
        self.assertEqual(canonical_json_bytes(envelope), canonical)
        self.assertTrue(jsonb_safe(envelope))
        self.assertLess(len(canonical), MAX_EFFECT_COMMAND_BYTES)
        self.assertEqual(CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE, envelope["command_type"])
        self.assertEqual(
            CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
            envelope["version"],
        )

    def test_encoded_envelope_contains_all_cross_bindings(self) -> None:
        original = command()
        envelope = encode_create_standard_payment_link_command(original)
        bindings = envelope["bindings"]
        self.assertIsInstance(bindings, dict)
        assert isinstance(bindings, dict)

        self.assertEqual(original.proposal.action_key, bindings["action_key"])
        self.assertEqual(original.proposal.proposal_digest, bindings["proposal_sha256"])
        self.assertEqual(original.prior_plan.decision_digest, bindings["prior_plan_sha256"])
        self.assertEqual(original.request_digest, bindings["provider_request_sha256"])
        self.assertEqual(original.payload_digest, bindings["executor_payload_sha256"])

    def test_unknown_and_missing_fields_are_rejected_even_when_resealed(self) -> None:
        for mutation in ("unknown", "missing"):
            with self.subTest(mutation=mutation):
                envelope = encode_create_standard_payment_link_command(command())
                command_value = envelope["command"]
                assert isinstance(command_value, dict)
                request_value = command_value["request"]
                assert isinstance(request_value, dict)
                if mutation == "unknown":
                    request_value["benign_extension"] = "future"
                else:
                    del request_value["currency"]
                reseal(envelope)

                with self.assertRaises(EffectCommandSchemaError):
                    decode_create_standard_payment_link_command(envelope)

    def test_schema_version_and_external_metadata_mismatches_are_rejected(self) -> None:
        envelope = encode_create_standard_payment_link_command(command())
        envelope["version"] = 2
        reseal(envelope)
        with self.assertRaises(EffectCommandSchemaError):
            decode_create_standard_payment_link_command(envelope)

        envelope = encode_create_standard_payment_link_command(command())
        envelope["schema"] = "retrywise.future-command"
        reseal(envelope)
        with self.assertRaises(EffectCommandSchemaError):
            decode_create_standard_payment_link_command(envelope)

        valid = encode_create_standard_payment_link_command(command())
        with self.assertRaises(EffectCommandSchemaError):
            decode_create_standard_payment_link_command(valid, command_schema_version=2)
        with self.assertRaises(EffectCommandSchemaError):
            decode_create_standard_payment_link_command(valid, command_type="SEND_EMAIL")

    def test_noncanonical_timestamp_decimal_and_number_are_rejected(self) -> None:
        fixtures: list[tuple[str, object]] = [
            ("created_at", "2026-08-29T12:00:00Z"),
            ("model_confidence", "0.900"),
        ]
        for field, value in fixtures:
            with self.subTest(field=field):
                envelope = encode_create_standard_payment_link_command(command())
                command_value = envelope["command"]
                assert isinstance(command_value, dict)
                proposal_value = command_value["proposal"]
                assert isinstance(proposal_value, dict)
                proposal_value[field] = value
                reseal(envelope)
                with self.assertRaises(EffectCommandSchemaError):
                    decode_create_standard_payment_link_command(envelope)

        envelope = encode_create_standard_payment_link_command(command())
        command_value = envelope["command"]
        assert isinstance(command_value, dict)
        request_value = command_value["request"]
        assert isinstance(request_value, dict)
        request_value["amount_minor"] = 129_900.0
        with self.assertRaises(EffectCommandSchemaError):
            decode_create_standard_payment_link_command(envelope)

    def test_noncanonical_raw_json_duplicate_keys_and_negative_zero_are_rejected(self) -> None:
        envelope = encode_create_standard_payment_link_command(command())
        noncanonical = json.dumps(envelope).encode("utf-8")
        with self.assertRaises(EffectCommandSchemaError):
            decode_create_standard_payment_link_command(noncanonical)

        canonical = encode_create_standard_payment_link_command_json(command())
        duplicated = canonical.replace(b'{"bindings":', b'{"schema":"duplicate","bindings":', 1)
        with self.assertRaises(EffectCommandSchemaError):
            decode_create_standard_payment_link_command(duplicated)

        negative_zero = canonical.replace(b'"aggregate_version":8', b'"aggregate_version":-0')
        with self.assertRaises(EffectCommandSchemaError):
            decode_create_standard_payment_link_command(negative_zero)

    def test_envelope_integrity_and_all_domain_digests_are_verified(self) -> None:
        envelope = encode_create_standard_payment_link_command(command())
        command_value = envelope["command"]
        assert isinstance(command_value, dict)
        command_value["provider_account_id"] = "provider_account_test_2"
        with self.assertRaises(EffectCommandIntegrityError):
            decode_create_standard_payment_link_command(envelope)

        for field in (
            "proposal_sha256",
            "prior_plan_sha256",
            "provider_request_sha256",
            "executor_payload_sha256",
            "action_key",
        ):
            with self.subTest(field=field):
                envelope = encode_create_standard_payment_link_command(command())
                bindings = envelope["bindings"]
                assert isinstance(bindings, dict)
                bindings[field] = "0" * 64 if field != "action_key" else "act_" + "0" * 64
                reseal(envelope)
                with self.assertRaises(EffectCommandIntegrityError):
                    decode_create_standard_payment_link_command(envelope)

    def test_plan_and_request_must_remain_bound_to_the_proposal(self) -> None:
        plan_mismatch = encode_create_standard_payment_link_command(command())
        command_value = plan_mismatch["command"]
        assert isinstance(command_value, dict)
        prior_plan = command_value["prior_plan"]
        assert isinstance(prior_plan, dict)
        prior_plan["case_id"] = "case_2"
        reseal(plan_mismatch)
        with self.assertRaises(EffectCommandBindingError):
            decode_create_standard_payment_link_command(plan_mismatch)

        amount_mismatch = encode_create_standard_payment_link_command(command())
        command_value = amount_mismatch["command"]
        assert isinstance(command_value, dict)
        request_value = command_value["request"]
        assert isinstance(request_value, dict)
        request_value["amount_minor"] = 129_901
        reseal(amount_mismatch)
        with self.assertRaises(EffectCommandBindingError):
            decode_create_standard_payment_link_command(amount_mismatch)

        arbitrary_reference = StandardPaymentLinkRequest(
            amount_minor=129_900,
            currency="INR",
            reference_id="rtw_safe_but_not_case_bound",
            description="Retry payment for order ORD-1042",
            expire_by_epoch=int((NOW + timedelta(minutes=50)).timestamp()),
            notes={"recovery_case_id": "case_1", "merchant_order_id": "ORD-1042"},
        )
        with self.assertRaisesRegex(EffectCommandBindingError, "controller-derived"):
            encode_create_standard_payment_link_command(command(request=arbitrary_reference))

    def test_sensitive_customer_secret_and_pii_fields_are_rejected(self) -> None:
        customer_request = StandardPaymentLinkRequest(
            amount_minor=129_900,
            currency="INR",
            reference_id=REFERENCE,
            description="Retry payment for order ORD-1042",
            expire_by_epoch=int((NOW + timedelta(minutes=50)).timestamp()),
            customer=PaymentLinkCustomer(name="Private", email="private@example.test"),
        )
        with self.assertRaises(EffectCommandPrivacyError):
            encode_create_standard_payment_link_command(command(request=customer_request))

        secret_notes = StandardPaymentLinkRequest(
            amount_minor=129_900,
            currency="INR",
            reference_id=REFERENCE,
            description="Retry payment for order ORD-1042",
            expire_by_epoch=int((NOW + timedelta(minutes=50)).timestamp()),
            notes={"secret": "must-not-persist"},
        )
        with self.assertRaises(EffectCommandPrivacyError):
            encode_create_standard_payment_link_command(command(request=secret_notes))

        envelope = encode_create_standard_payment_link_command(command())
        command_value = envelope["command"]
        assert isinstance(command_value, dict)
        request_value = command_value["request"]
        assert isinstance(request_value, dict)
        request_value["customer_email"] = "private@example.test"
        reseal(envelope)
        with self.assertRaises(EffectCommandPrivacyError):
            decode_create_standard_payment_link_command(envelope)

    def test_free_form_pii_patterns_and_nonopaque_note_values_are_rejected(self) -> None:
        for description in (
            "Retry payment for private@example.test",
            "Retry payment for VPA private@bank",
            "Retry payment for phone 9876543210",
            "Retry card 4111111111111111",
            "Retry payment for John Doe, 12 Main Street",
        ):
            with self.subTest(description=description):
                request = StandardPaymentLinkRequest(
                    amount_minor=129_900,
                    currency="INR",
                    reference_id=REFERENCE,
                    description=description,
                    expire_by_epoch=int((NOW + timedelta(minutes=50)).timestamp()),
                    notes={"recovery_case_id": "case_1", "merchant_order_id": "ORD-1042"},
                )
                with self.assertRaises(EffectCommandPrivacyError):
                    encode_create_standard_payment_link_command(command(request=request))

        request = StandardPaymentLinkRequest(
            amount_minor=129_900,
            currency="INR",
            reference_id=REFERENCE,
            description="Retry payment for order ORD-1042",
            expire_by_epoch=int((NOW + timedelta(minutes=50)).timestamp()),
            notes={
                "recovery_case_id": "case_1",
                "merchant_order_id": "customer@example.test",
            },
        )
        with self.assertRaises(EffectCommandPrivacyError):
            encode_create_standard_payment_link_command(command(request=request))

    def test_description_and_recovery_case_are_bound_to_controller_notes(self) -> None:
        wrong_description = StandardPaymentLinkRequest(
            amount_minor=129_900,
            currency="INR",
            reference_id=REFERENCE,
            description="Please complete order ORD-1042",
            expire_by_epoch=int((NOW + timedelta(minutes=50)).timestamp()),
            notes={"recovery_case_id": "case_1", "merchant_order_id": "ORD-1042"},
        )
        with self.assertRaises(EffectCommandPrivacyError):
            encode_create_standard_payment_link_command(command(request=wrong_description))

        wrong_case = StandardPaymentLinkRequest(
            amount_minor=129_900,
            currency="INR",
            reference_id=REFERENCE,
            description="Retry payment for order ORD-1042",
            expire_by_epoch=int((NOW + timedelta(minutes=50)).timestamp()),
            notes={"recovery_case_id": "case_2", "merchant_order_id": "ORD-1042"},
        )
        with self.assertRaises(EffectCommandBindingError):
            encode_create_standard_payment_link_command(command(request=wrong_case))

    def test_payload_size_is_bounded_before_json_decode(self) -> None:
        oversized = b"{" + b" " * MAX_EFFECT_COMMAND_BYTES + b"}"
        with self.assertRaises(EffectCommandSizeError):
            decode_create_standard_payment_link_command(oversized)

        deeply_nested = b'{"nested":' + b"[" * 2_000 + b"]" * 2_000 + b"}"
        with self.assertRaises(EffectCommandSizeError):
            decode_create_standard_payment_link_command(deeply_nested)

        huge_integer = b"{" + b'"version":' + b"9" * 1_000 + b"}"
        with self.assertRaises(EffectCommandSchemaError):
            decode_create_standard_payment_link_command(huge_integer)

    def test_encode_rejects_non_create_action_and_non_policy_plan(self) -> None:
        with self.assertRaises(EffectCommandBindingError):
            encode_create_standard_payment_link_command(
                command(action_type=ActionType.NOTIFY_EXISTING_LINK)
            )

        original = command()
        effect_stage_plan = GateDecision(
            stage=GateStage.EFFECT,
            policy_version=original.prior_plan.policy_version,
            proposal_id=original.prior_plan.proposal_id,
            action_key=original.prior_plan.action_key,
            proposal_digest=original.prior_plan.proposal_digest,
            case_id=original.prior_plan.case_id,
            decision_version=original.prior_plan.decision_version,
            aggregate_version=original.prior_plan.aggregate_version,
            evaluated_at=original.prior_plan.evaluated_at,
            reasons=(),
        )
        wrong_stage = CreatePaymentLinkCommand(
            proposal=original.proposal,
            prior_plan=effect_stage_plan,
            request=original.request,
            provider_account_id=original.provider_account_id,
        )
        with self.assertRaises(EffectCommandBindingError):
            encode_create_standard_payment_link_command(wrong_stage)

        denied_plan = GateDecision(
            stage=GateStage.POLICY,
            policy_version=original.prior_plan.policy_version,
            proposal_id=original.prior_plan.proposal_id,
            action_key=original.prior_plan.action_key,
            proposal_digest=original.prior_plan.proposal_digest,
            case_id=original.prior_plan.case_id,
            decision_version=original.prior_plan.decision_version,
            aggregate_version=original.prior_plan.aggregate_version,
            evaluated_at=original.prior_plan.evaluated_at,
            reasons=(GateReason.GLOBAL_KILL_SWITCH_ACTIVE,),
        )
        denied = CreatePaymentLinkCommand(
            proposal=original.proposal,
            prior_plan=denied_plan,
            request=original.request,
            provider_account_id=original.provider_account_id,
        )
        with self.assertRaises(EffectCommandBindingError):
            encode_create_standard_payment_link_command(denied)


if __name__ == "__main__":
    unittest.main()
