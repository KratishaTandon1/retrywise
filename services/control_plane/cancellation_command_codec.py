"""Closed canonical codec for one durable Payment Link cancellation command.

The embedded SHA-256 digests detect accidental or malicious payload mutation;
they do not replace the executor's durable action/instrument-row lookup or the
fresh deterministic effect gate.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from copy import deepcopy
from typing import Final

from .cancellation import CancellationTarget, CancelPaymentLinkCommand
from .effect_command_codec import (
    EffectCommandBindingError,
    EffectCommandCodecError,
    EffectCommandIntegrityError,
    EffectCommandPrivacyError,
    EffectCommandSchemaError,
    EffectCommandSizeError,
    _bounded_canonical_bytes,
    _coerce_payload,
    _digest,
    _exact_object,
    _integer,
    _prior_plan,
    _proposal,
    _text,
)

CANCEL_PAYMENT_LINK_COMMAND_TYPE: Final = "CANCEL_PAYMENT_LINK"
CANCEL_PAYMENT_LINK_COMMAND_SCHEMA: Final = "retrywise.cancel-payment-link-command"
CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION: Final = 1

_ENVELOPE_FIELDS = frozenset(
    {"bindings", "command", "command_type", "integrity", "schema", "version"}
)
_COMMAND_FIELDS = frozenset({"prior_plan", "proposal", "target"})
_TARGET_FIELDS = frozenset(
    {
        "action_id",
        "action_key",
        "amount_minor",
        "case_id",
        "currency",
        "instrument_id",
        "merchant_id",
        "payment_link_id",
        "provider_account_id",
        "reference_id",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "action_key",
        "executor_payload_sha256",
        "prior_plan_sha256",
        "proposal_sha256",
        "target_sha256",
    }
)
_INTEGRITY_FIELDS = frozenset({"algorithm", "digest"})


def _target(value: object) -> CancellationTarget:
    item = _exact_object(value, fields=_TARGET_FIELDS, path="$.command.target")
    try:
        target = CancellationTarget(
            merchant_id=_text(item["merchant_id"], path="$.command.target.merchant_id"),
            case_id=_text(item["case_id"], path="$.command.target.case_id"),
            action_id=_text(item["action_id"], path="$.command.target.action_id"),
            action_key=_text(item["action_key"], path="$.command.target.action_key"),
            instrument_id=_text(item["instrument_id"], path="$.command.target.instrument_id"),
            provider_account_id=_text(
                item["provider_account_id"],
                path="$.command.target.provider_account_id",
            ),
            payment_link_id=_text(item["payment_link_id"], path="$.command.target.payment_link_id"),
            reference_id=_text(item["reference_id"], path="$.command.target.reference_id"),
            amount_minor=_integer(
                item["amount_minor"],
                path="$.command.target.amount_minor",
                minimum=1,
            ),
            currency=_text(item["currency"], path="$.command.target.currency"),
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, EffectCommandCodecError):
            raise
        raise EffectCommandSchemaError(
            "cancellation target violates its immutable contract"
        ) from exc
    if target.to_primitive() != item:
        raise EffectCommandBindingError(
            "cancellation target derived fields differ from their source"
        )
    return target


def _bindings(command: CancelPaymentLinkCommand) -> dict[str, object]:
    return {
        "action_key": command.proposal.action_key,
        "executor_payload_sha256": command.payload_digest,
        "prior_plan_sha256": command.prior_plan.decision_digest,
        "proposal_sha256": command.proposal.proposal_digest,
        "target_sha256": command.target_digest,
    }


def _unsigned_envelope(command: CancelPaymentLinkCommand) -> dict[str, object]:
    return {
        "bindings": _bindings(command),
        "command": {
            "prior_plan": command.prior_plan.to_primitive(),
            "proposal": command.proposal.to_primitive(),
            "target": command.target.to_primitive(),
        },
        "command_type": CANCEL_PAYMENT_LINK_COMMAND_TYPE,
        "schema": CANCEL_PAYMENT_LINK_COMMAND_SCHEMA,
        "version": CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    }


def _integrity_digest(unsigned: Mapping[str, object]) -> str:
    return hashlib.sha256(_bounded_canonical_bytes(unsigned)).hexdigest()


def encode_cancel_payment_link_command(
    command: CancelPaymentLinkCommand,
) -> dict[str, object]:
    """Return JSONB-compatible primitives for the unique version-one envelope."""

    if not isinstance(command, CancelPaymentLinkCommand):
        raise TypeError("command must be CancelPaymentLinkCommand")
    unsigned = _unsigned_envelope(command)
    envelope: dict[str, object] = {
        **unsigned,
        "integrity": {
            "algorithm": "sha256",
            "digest": _integrity_digest(unsigned),
        },
    }
    _bounded_canonical_bytes(envelope)
    return deepcopy(envelope)


def encode_cancel_payment_link_command_json(command: CancelPaymentLinkCommand) -> bytes:
    """Return the byte-for-byte canonical JSON representation."""

    return _bounded_canonical_bytes(encode_cancel_payment_link_command(command))


def decode_cancel_payment_link_command(
    payload: Mapping[str, object] | str | bytes | bytearray,
    *,
    command_type: str = CANCEL_PAYMENT_LINK_COMMAND_TYPE,
    command_schema_version: int = CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
) -> CancelPaymentLinkCommand:
    """Verify all schemas, duplicated bindings, and canonical integrity."""

    envelope = _exact_object(_coerce_payload(payload), fields=_ENVELOPE_FIELDS, path="$")
    if type(command_type) is not str or command_type != CANCEL_PAYMENT_LINK_COMMAND_TYPE:
        raise EffectCommandSchemaError("external cancellation command_type is unsupported")
    if (
        type(command_schema_version) is not int
        or command_schema_version != CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION
    ):
        raise EffectCommandSchemaError(
            "external cancellation command_schema_version is unsupported"
        )
    if envelope["schema"] != CANCEL_PAYMENT_LINK_COMMAND_SCHEMA:
        raise EffectCommandSchemaError("cancellation command schema is unsupported")
    if (
        type(envelope["version"]) is not int
        or envelope["version"] != CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION
    ):
        raise EffectCommandSchemaError("cancellation command schema version is unsupported")
    if envelope["command_type"] != command_type:
        raise EffectCommandSchemaError("embedded and external cancellation command types differ")

    integrity = _exact_object(
        envelope["integrity"],
        fields=_INTEGRITY_FIELDS,
        path="$.integrity",
    )
    if integrity["algorithm"] != "sha256":
        raise EffectCommandSchemaError("cancellation integrity algorithm is unsupported")
    supplied_integrity = _digest(integrity["digest"], path="$.integrity.digest")
    unsigned = {key: value for key, value in envelope.items() if key != "integrity"}
    if not hmac.compare_digest(supplied_integrity, _integrity_digest(unsigned)):
        raise EffectCommandIntegrityError("cancellation command integrity digest mismatch")

    command_value = _exact_object(
        envelope["command"],
        fields=_COMMAND_FIELDS,
        path="$.command",
    )
    proposal = _proposal(command_value["proposal"])
    prior_plan = _prior_plan(command_value["prior_plan"])
    target = _target(command_value["target"])
    try:
        command = CancelPaymentLinkCommand(
            proposal=proposal,
            prior_plan=prior_plan,
            target=target,
        )
    except (TypeError, ValueError) as exc:
        raise EffectCommandBindingError(
            "cancellation command violates proposal/plan/target binding"
        ) from exc

    supplied_bindings = _exact_object(
        envelope["bindings"],
        fields=_BINDING_FIELDS,
        path="$.bindings",
    )
    for field in _BINDING_FIELDS - {"action_key"}:
        _digest(supplied_bindings[field], path=f"$.bindings.{field}")
    expected_bindings = _bindings(command)
    for field, expected in expected_bindings.items():
        supplied = supplied_bindings[field]
        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, str(expected)):
            raise EffectCommandIntegrityError(f"cancellation command {field} binding mismatch")

    rebuilt = encode_cancel_payment_link_command(command)
    if not hmac.compare_digest(
        _bounded_canonical_bytes(envelope),
        _bounded_canonical_bytes(rebuilt),
    ):
        raise EffectCommandIntegrityError(
            "cancellation command is not its unique canonical envelope"
        )
    return command


__all__ = [
    "CANCEL_PAYMENT_LINK_COMMAND_SCHEMA",
    "CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION",
    "CANCEL_PAYMENT_LINK_COMMAND_TYPE",
    "EffectCommandBindingError",
    "EffectCommandCodecError",
    "EffectCommandIntegrityError",
    "EffectCommandPrivacyError",
    "EffectCommandSchemaError",
    "EffectCommandSizeError",
    "decode_cancel_payment_link_command",
    "encode_cancel_payment_link_command",
    "encode_cancel_payment_link_command_json",
]
