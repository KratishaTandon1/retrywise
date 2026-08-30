"""Strict JSONB-safe codec for the Standard Payment Link effect command.

The durable outbox stores an immutable command rather than an arbitrary provider
payload.  This module gives that command one closed, versioned wire format and
reconstructs the existing validated domain objects on read.  The embedded
SHA-256 is an integrity checksum, not an authenticity mechanism; authorization
still comes from the durable intent and the fresh deterministic effect gate.

Customer fields and credentials are deliberately outside the schema.  Only the
two controller-owned Payment Link note identifiers are serializable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime
from typing import Final

from ...packages.domain import (
    ActionProposal,
    ActionType,
    GateDecision,
    GateReason,
    GateStage,
    Money,
    Probability,
)
from ...packages.domain.canonical import (
    canonical_json_bytes,
    parse_canonical_timestamp,
)
from ...packages.domain.values import require_identifier
from ...packages.razorpay import (
    PaymentLinkValidationError,
    StandardPaymentLinkRequest,
    make_recovery_reference_id,
)
from .executor import CreatePaymentLinkCommand

CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE: Final = "CREATE_STANDARD_PAYMENT_LINK"
CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA: Final = (
    "retrywise.create-standard-payment-link-command"
)
CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION: Final = 1
MAX_EFFECT_COMMAND_BYTES: Final = 16 * 1024

_MAX_DEPTH = 12
_MAX_SIGNED_64 = (1 << 63) - 1
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_NOTE_KEYS = frozenset({"merchant_order_id", "recovery_case_id"})
_DESCRIPTION_PREFIX = "Retry payment for order "
_SENSITIVE_KEY_WORDS = frozenset(
    {
        "address",
        "authorization",
        "contact",
        "credential",
        "customer",
        "cvv",
        "email",
        "mobile",
        "pan",
        "password",
        "phone",
        "secret",
        "token",
        "vpa",
    }
)
_SENSITIVE_COMPOUND_KEYS = frozenset(
    {
        "api_key",
        "card_number",
        "key_secret",
        "private_key",
    }
)
_PII_NUMBER_RE = re.compile(r"(?<!\d)\d{10,19}(?!\d)")

_ENVELOPE_FIELDS = frozenset(
    {"bindings", "command", "command_type", "integrity", "schema", "version"}
)
_BINDING_FIELDS = frozenset(
    {
        "action_key",
        "executor_payload_sha256",
        "prior_plan_sha256",
        "proposal_sha256",
        "provider_request_sha256",
    }
)
_COMMAND_FIELDS = frozenset({"prior_plan", "proposal", "provider_account_id", "request"})
_INTEGRITY_FIELDS = frozenset({"algorithm", "digest"})
_PROPOSAL_FIELDS = frozenset(
    {
        "action_key",
        "action_type",
        "amount",
        "attempt_ordinal",
        "case_id",
        "created_at",
        "decision_version",
        "expected_value_minor",
        "expires_at",
        "instrument_reference",
        "merchant_id",
        "model_confidence",
        "payment_method",
        "proposal_id",
        "requires_approval",
    }
)
_MONEY_FIELDS = frozenset({"currency", "minor_units"})
_PLAN_FIELDS = frozenset(
    {
        "action_key",
        "aggregate_version",
        "allowed",
        "case_id",
        "decision_version",
        "evaluated_at",
        "policy_version",
        "proposal_digest",
        "proposal_id",
        "reasons",
        "stage",
    }
)
_REQUEST_FIELDS = frozenset(
    {
        "amount_minor",
        "currency",
        "description",
        "expire_by_epoch",
        "notes",
        "reference_id",
    }
)


class EffectCommandCodecError(ValueError):
    """Base class for fail-closed command decoding errors."""


class EffectCommandSizeError(EffectCommandCodecError):
    """The serialized command exceeds its bounded storage contract."""


class EffectCommandSchemaError(EffectCommandCodecError):
    """The command is not in the one supported canonical schema."""


class EffectCommandIntegrityError(EffectCommandCodecError):
    """A canonical checksum or duplicated digest does not match."""


class EffectCommandBindingError(EffectCommandCodecError):
    """The proposal, plan, provider request, or account binding disagrees."""


class EffectCommandPrivacyError(EffectCommandCodecError):
    """Secret-bearing or customer PII fields crossed the outbox boundary."""


def _exact_object(
    value: object,
    *,
    fields: frozenset[str],
    path: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise EffectCommandSchemaError(f"{path} must be a JSON object")
    copied = dict(value)
    present = frozenset(copied)
    if present != fields:
        missing = sorted(fields - present)
        unknown = sorted(present - fields)
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unknown:
            details.append(f"unknown={','.join(unknown)}")
        raise EffectCommandSchemaError(f"{path} has invalid fields ({'; '.join(details)})")
    return copied


def _text(value: object, *, path: str) -> str:
    if not isinstance(value, str):
        raise EffectCommandSchemaError(f"{path} must be a string")
    return value


def _boolean(value: object, *, path: str) -> bool:
    if type(value) is not bool:
        raise EffectCommandSchemaError(f"{path} must be a boolean")
    return value


def _integer(
    value: object,
    *,
    path: str,
    minimum: int | None = None,
    maximum: int = _MAX_SIGNED_64,
) -> int:
    if type(value) is not int:
        raise EffectCommandSchemaError(f"{path} must be a canonical JSON integer")
    if value < -_MAX_SIGNED_64 - 1 or value > maximum:
        raise EffectCommandSchemaError(f"{path} is outside the signed 64-bit boundary")
    if minimum is not None and value < minimum:
        raise EffectCommandSchemaError(f"{path} is below its minimum")
    return value


def _optional_integer(value: object, *, path: str) -> int | None:
    if value is None:
        return None
    return _integer(value, path=path)


def _optional_text(value: object, *, path: str) -> str | None:
    if value is None:
        return None
    return _text(value, path=path)


def _timestamp(value: object, *, path: str) -> datetime:
    rendered = _text(value, path=path)
    try:
        parsed = parse_canonical_timestamp(rendered)
    except ValueError as exc:
        raise EffectCommandSchemaError(f"{path} must use canonical UTC microseconds") from exc
    return parsed


def _digest(value: object, *, path: str) -> str:
    rendered = _text(value, path=path)
    if not _HEX_DIGEST_RE.fullmatch(rendered):
        raise EffectCommandSchemaError(f"{path} must be a lowercase SHA-256 digest")
    return rendered


def _sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    if normalized in _SENSITIVE_COMPOUND_KEYS:
        return True
    return bool(set(normalized.split("_")) & _SENSITIVE_KEY_WORDS)


def _walk_json(value: object, *, path: str = "$", depth: int = 0) -> int:
    """Reject non-JSONB values and cheaply bound hostile in-memory mappings."""

    if depth > _MAX_DEPTH:
        raise EffectCommandSizeError("effect command exceeds the maximum nesting depth")
    if value is None or type(value) is bool:
        return 4
    if type(value) is int:
        if value < -_MAX_SIGNED_64 - 1 or value > _MAX_SIGNED_64:
            raise EffectCommandSchemaError("effect command integer exceeds signed 64-bit range")
        return len(str(value))
    if isinstance(value, str):
        size = len(value.encode("utf-8")) + 2
        if size > MAX_EFFECT_COMMAND_BYTES:
            raise EffectCommandSizeError("effect command contains an oversized string")
        return size
    if isinstance(value, Mapping):
        total = 2
        for key, item in value.items():
            if not isinstance(key, str):
                raise EffectCommandSchemaError(f"{path} contains a non-string object key")
            key_size = len(key.encode("utf-8"))
            if key_size > MAX_EFFECT_COMMAND_BYTES:
                raise EffectCommandSizeError("effect command contains an oversized object key")
            if _sensitive_key(key):
                raise EffectCommandPrivacyError(f"{path} contains a prohibited sensitive field")
            total += key_size + 3
            total += _walk_json(item, path=f"{path}.{key}", depth=depth + 1)
            if total > MAX_EFFECT_COMMAND_BYTES:
                raise EffectCommandSizeError("effect command exceeds the serialized size cap")
        return total
    if isinstance(value, list):
        total = 2
        for index, item in enumerate(value):
            total += 1 + _walk_json(item, path=f"{path}[{index}]", depth=depth + 1)
            if total > MAX_EFFECT_COMMAND_BYTES:
                raise EffectCommandSizeError("effect command exceeds the serialized size cap")
        return total
    raise EffectCommandSchemaError(f"{path} contains a non-JSONB value")


def _bounded_canonical_bytes(value: object) -> bytes:
    _walk_json(value)
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise EffectCommandSchemaError("effect command is not canonical JSON") from exc
    if len(encoded) > MAX_EFFECT_COMMAND_BYTES:
        raise EffectCommandSizeError("effect command exceeds the serialized size cap")
    return encoded


def _parse_canonical_integer(token: str) -> int:
    if token == "-0":
        raise EffectCommandSchemaError("negative zero is not a canonical JSON integer")
    if len(token.lstrip("-")) > 19:
        raise EffectCommandSchemaError("JSON integer exceeds signed 64-bit range")
    parsed = int(token)
    if parsed < -_MAX_SIGNED_64 - 1 or parsed > _MAX_SIGNED_64:
        raise EffectCommandSchemaError("JSON integer exceeds signed 64-bit range")
    return parsed


def _reject_non_integer_number(token: str) -> object:
    del token
    raise EffectCommandSchemaError("non-integer JSON numbers are forbidden")


def _reject_json_constant(token: str) -> object:
    del token
    raise EffectCommandSchemaError("non-finite JSON numbers are forbidden")


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EffectCommandSchemaError("duplicate JSON object keys are forbidden")
        result[key] = value
    return result


def _coerce_payload(payload: Mapping[str, object] | str | bytes | bytearray) -> dict[str, object]:
    if isinstance(payload, Mapping):
        _walk_json(payload)
        canonical = _bounded_canonical_bytes(payload)
        try:
            copied: object = json.loads(canonical)
        except json.JSONDecodeError as exc:  # pragma: no cover - produced by our serializer
            raise AssertionError("canonical serializer produced invalid JSON") from exc
        if not isinstance(copied, dict):
            raise EffectCommandSchemaError("effect command payload must be a JSON object")
        return copied

    if isinstance(payload, str):
        try:
            raw = payload.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EffectCommandSchemaError("effect command must be valid UTF-8") from exc
    elif isinstance(payload, (bytes, bytearray)):
        raw = bytes(payload)
    else:
        raise TypeError("payload must be a JSON object, canonical JSON text, or bytes")
    if len(raw) > MAX_EFFECT_COMMAND_BYTES:
        raise EffectCommandSizeError("effect command exceeds the serialized size cap")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EffectCommandSchemaError("effect command must be valid UTF-8") from exc
    try:
        parsed: object = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicates,
            parse_int=_parse_canonical_integer,
            parse_float=_reject_non_integer_number,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise EffectCommandSchemaError("effect command is not valid JSON") from exc
    except RecursionError as exc:
        raise EffectCommandSizeError("effect command exceeds the maximum nesting depth") from exc
    if not isinstance(parsed, dict):
        raise EffectCommandSchemaError("effect command payload must be a JSON object")
    canonical = _bounded_canonical_bytes(parsed)
    if not hmac.compare_digest(raw, canonical):
        raise EffectCommandSchemaError("serialized effect command is not canonical JSON")
    return parsed


def _money(value: object, *, path: str) -> Money:
    item = _exact_object(value, fields=_MONEY_FIELDS, path=path)
    try:
        return Money(
            _integer(item["minor_units"], path=f"{path}.minor_units", minimum=0),
            _text(item["currency"], path=f"{path}.currency"),
        )
    except (TypeError, ValueError) as exc:
        raise EffectCommandSchemaError(f"{path} violates the Money contract") from exc


def _probability(value: object, *, path: str) -> Probability | None:
    if value is None:
        return None
    rendered = _text(value, path=path)
    try:
        probability = Probability(rendered)
    except (TypeError, ValueError) as exc:
        raise EffectCommandSchemaError(f"{path} violates the Probability contract") from exc
    if probability.to_primitive() != rendered:
        raise EffectCommandSchemaError(f"{path} is not a canonical decimal string")
    return probability


def _proposal(value: object) -> ActionProposal:
    item = _exact_object(value, fields=_PROPOSAL_FIELDS, path="$.command.proposal")
    amount_value = item["amount"]
    amount = (
        None if amount_value is None else _money(amount_value, path="$.command.proposal.amount")
    )
    action_type_value = _text(item["action_type"], path="$.command.proposal.action_type")
    try:
        action_type = ActionType(action_type_value)
        proposal = ActionProposal(
            proposal_id=_text(item["proposal_id"], path="$.command.proposal.proposal_id"),
            merchant_id=_text(item["merchant_id"], path="$.command.proposal.merchant_id"),
            case_id=_text(item["case_id"], path="$.command.proposal.case_id"),
            decision_version=_integer(
                item["decision_version"],
                path="$.command.proposal.decision_version",
                minimum=1,
            ),
            action_type=action_type,
            created_at=_timestamp(item["created_at"], path="$.command.proposal.created_at"),
            expires_at=_timestamp(item["expires_at"], path="$.command.proposal.expires_at"),
            attempt_ordinal=_integer(
                item["attempt_ordinal"],
                path="$.command.proposal.attempt_ordinal",
                minimum=1,
            ),
            amount=amount,
            payment_method=_optional_text(
                item["payment_method"], path="$.command.proposal.payment_method"
            ),
            expected_value_minor=_optional_integer(
                item["expected_value_minor"],
                path="$.command.proposal.expected_value_minor",
            ),
            model_confidence=_probability(
                item["model_confidence"], path="$.command.proposal.model_confidence"
            ),
            requires_approval=_boolean(
                item["requires_approval"], path="$.command.proposal.requires_approval"
            ),
            instrument_reference=_optional_text(
                item["instrument_reference"],
                path="$.command.proposal.instrument_reference",
            ),
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, EffectCommandCodecError):
            raise
        raise EffectCommandSchemaError("proposal violates the ActionProposal contract") from exc
    if proposal.to_primitive() != item:
        raise EffectCommandBindingError("proposal derived fields do not match their source fields")
    return proposal


def decode_action_proposal(value: object) -> ActionProposal:
    """Decode the exact canonical proposal primitive used in durable decisions."""

    return _proposal(value)


def _prior_plan(value: object) -> GateDecision:
    item = _exact_object(value, fields=_PLAN_FIELDS, path="$.command.prior_plan")
    reasons_value = item["reasons"]
    if not isinstance(reasons_value, list):
        raise EffectCommandSchemaError("$.command.prior_plan.reasons must be a JSON array")
    supplied_allowed = _boolean(item["allowed"], path="$.command.prior_plan.allowed")
    try:
        reasons = tuple(
            GateReason(_text(reason, path="$.command.prior_plan.reasons[]"))
            for reason in reasons_value
        )
        if len(reasons) != len(set(reasons)):
            raise EffectCommandSchemaError("prior plan reason codes must be unique")
        plan = GateDecision(
            stage=GateStage(_text(item["stage"], path="$.command.prior_plan.stage")),
            policy_version=_text(
                item["policy_version"], path="$.command.prior_plan.policy_version"
            ),
            proposal_id=_text(item["proposal_id"], path="$.command.prior_plan.proposal_id"),
            action_key=_text(item["action_key"], path="$.command.prior_plan.action_key"),
            proposal_digest=_digest(
                item["proposal_digest"], path="$.command.prior_plan.proposal_digest"
            ),
            case_id=_text(item["case_id"], path="$.command.prior_plan.case_id"),
            decision_version=_integer(
                item["decision_version"],
                path="$.command.prior_plan.decision_version",
                minimum=1,
            ),
            aggregate_version=_integer(
                item["aggregate_version"],
                path="$.command.prior_plan.aggregate_version",
                minimum=0,
            ),
            evaluated_at=_timestamp(item["evaluated_at"], path="$.command.prior_plan.evaluated_at"),
            reasons=reasons,
        )
        require_identifier(plan.policy_version, field="policy_version")
        require_identifier(plan.proposal_id, field="proposal_id")
        require_identifier(plan.case_id, field="case_id")
    except (TypeError, ValueError) as exc:
        if isinstance(exc, EffectCommandCodecError):
            raise
        raise EffectCommandSchemaError("prior plan violates the GateDecision contract") from exc
    if plan.allowed is not supplied_allowed or plan.to_primitive() != item:
        raise EffectCommandBindingError(
            "prior plan derived fields do not match their source fields"
        )
    return plan


def _reject_obvious_sensitive_description(value: str) -> None:
    if "@" in value or _PII_NUMBER_RE.search(value):
        raise EffectCommandPrivacyError(
            "Payment Link description contains an email, VPA, phone, or account-like number"
        )


def _validate_description_binding(value: str, *, merchant_order_id: str) -> None:
    _reject_obvious_sensitive_description(value)
    if value != f"{_DESCRIPTION_PREFIX}{merchant_order_id}":
        raise EffectCommandPrivacyError(
            "Payment Link description must use the controller-owned order template"
        )


def _notes(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise EffectCommandSchemaError("$.command.request.notes must be a JSON object")
    copied = dict(value)
    present = frozenset(copied)
    if present != _REQUIRED_NOTE_KEYS:
        if present - _REQUIRED_NOTE_KEYS:
            raise EffectCommandPrivacyError("Payment Link notes contain a non-controller field")
        raise EffectCommandSchemaError("Payment Link notes lack a required controller identifier")
    result: dict[str, str] = {}
    for key, candidate in copied.items():
        rendered = _text(candidate, path=f"$.command.request.notes.{key}")
        try:
            result[key] = require_identifier(rendered, field=f"notes.{key}")
        except ValueError as exc:
            raise EffectCommandPrivacyError(
                "Payment Link notes must contain opaque controller identifiers"
            ) from exc
    return result


def _request(value: object) -> StandardPaymentLinkRequest:
    item = _exact_object(value, fields=_REQUEST_FIELDS, path="$.command.request")
    description = _text(item["description"], path="$.command.request.description")
    _reject_obvious_sensitive_description(description)
    notes = _notes(item["notes"])
    _validate_description_binding(description, merchant_order_id=notes["merchant_order_id"])
    try:
        return StandardPaymentLinkRequest(
            amount_minor=_integer(
                item["amount_minor"], path="$.command.request.amount_minor", minimum=1
            ),
            currency=_text(item["currency"], path="$.command.request.currency"),
            reference_id=_text(item["reference_id"], path="$.command.request.reference_id"),
            description=description,
            expire_by_epoch=_integer(
                item["expire_by_epoch"],
                path="$.command.request.expire_by_epoch",
                minimum=1,
            ),
            notes=notes,
        )
    except PaymentLinkValidationError as exc:
        raise EffectCommandSchemaError(
            "provider request violates the StandardPaymentLinkRequest contract"
        ) from exc


def _request_primitive(request: StandardPaymentLinkRequest) -> dict[str, object]:
    if request.customer is not None:
        raise EffectCommandPrivacyError("customer PII must not be stored in an effect command")
    description = request.description
    _reject_obvious_sensitive_description(description)
    notes = _notes(request.notes)
    _validate_description_binding(description, merchant_order_id=notes["merchant_order_id"])
    return {
        "amount_minor": request.amount_minor,
        "currency": request.currency,
        "description": description,
        "expire_by_epoch": request.expire_by_epoch,
        "notes": notes,
        "reference_id": request.reference_id,
    }


def _validate_command_binding(command: CreatePaymentLinkCommand) -> None:
    proposal = command.proposal
    plan = command.prior_plan
    request = command.request
    try:
        require_identifier(command.provider_account_id, field="provider_account_id")
    except ValueError as exc:
        raise EffectCommandBindingError(
            "provider account binding is not an opaque identifier"
        ) from exc
    if proposal.action_type is not ActionType.CREATE_STANDARD_PAYMENT_LINK:
        raise EffectCommandBindingError("proposal is not a Standard Payment Link action")
    if plan.stage is not GateStage.POLICY or not plan.allowed:
        raise EffectCommandBindingError("effect command requires an allowed policy-stage plan")
    expected_plan_fields = (
        (plan.proposal_id, proposal.proposal_id),
        (plan.action_key, proposal.action_key),
        (plan.proposal_digest, proposal.proposal_digest),
        (plan.case_id, proposal.case_id),
        (plan.decision_version, proposal.decision_version),
    )
    if any(actual != expected for actual, expected in expected_plan_fields):
        raise EffectCommandBindingError("prior plan is not bound to the proposal")
    if proposal.amount is None:
        raise EffectCommandBindingError("collection proposal has no amount")
    if proposal.amount.minor_units != request.amount_minor:
        raise EffectCommandBindingError("provider request amount is not bound to the proposal")
    if proposal.amount.currency != request.currency:
        raise EffectCommandBindingError("provider request currency is not bound to the proposal")
    expected_reference_id = make_recovery_reference_id(
        proposal.case_id,
        provider_account_id=command.provider_account_id,
    )
    if request.reference_id != expected_reference_id:
        raise EffectCommandBindingError(
            "provider request reference is not controller-derived from case and account"
        )
    recovery_case_id = request.notes.get("recovery_case_id")
    if recovery_case_id != proposal.case_id:
        raise EffectCommandBindingError(
            "provider request recovery case is not bound to the proposal"
        )


def _bindings(command: CreatePaymentLinkCommand) -> dict[str, object]:
    return {
        "action_key": command.proposal.action_key,
        "executor_payload_sha256": command.payload_digest,
        "prior_plan_sha256": command.prior_plan.decision_digest,
        "proposal_sha256": command.proposal.proposal_digest,
        "provider_request_sha256": command.request_digest,
    }


def _unsigned_envelope(command: CreatePaymentLinkCommand) -> dict[str, object]:
    return {
        "bindings": _bindings(command),
        "command": {
            "prior_plan": command.prior_plan.to_primitive(),
            "proposal": command.proposal.to_primitive(),
            "provider_account_id": command.provider_account_id,
            "request": _request_primitive(command.request),
        },
        "command_type": CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
        "schema": CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA,
        "version": CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    }


def _integrity_digest(unsigned: Mapping[str, object]) -> str:
    return hashlib.sha256(_bounded_canonical_bytes(unsigned)).hexdigest()


def encode_create_standard_payment_link_command(
    command: CreatePaymentLinkCommand,
) -> dict[str, object]:
    """Return the closed command envelope as JSONB-compatible primitives."""

    if not isinstance(command, CreatePaymentLinkCommand):
        raise TypeError("command must be CreatePaymentLinkCommand")
    unsigned = _unsigned_envelope(command)
    _validate_command_binding(command)
    envelope: dict[str, object] = {
        **unsigned,
        "integrity": {
            "algorithm": "sha256",
            "digest": _integrity_digest(unsigned),
        },
    }
    _bounded_canonical_bytes(envelope)
    return deepcopy(envelope)


def encode_create_standard_payment_link_command_json(
    command: CreatePaymentLinkCommand,
) -> bytes:
    """Return the byte-for-byte canonical JSON representation of the envelope."""

    return _bounded_canonical_bytes(encode_create_standard_payment_link_command(command))


def decode_create_standard_payment_link_command(
    payload: Mapping[str, object] | str | bytes | bytearray,
    *,
    command_type: str = CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
    command_schema_version: int = CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
) -> CreatePaymentLinkCommand:
    """Verify and reconstruct one durable Standard Payment Link command.

    ``command_type`` and ``command_schema_version`` are the independently stored
    outbox columns.  Passing them binds that metadata to the envelope rather than
    trusting either copy alone.
    """

    envelope = _exact_object(
        _coerce_payload(payload),
        fields=_ENVELOPE_FIELDS,
        path="$",
    )
    if type(command_type) is not str or command_type != CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE:
        raise EffectCommandSchemaError("external command_type is unsupported")
    if (
        type(command_schema_version) is not int
        or command_schema_version != CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION
    ):
        raise EffectCommandSchemaError("external command_schema_version is unsupported")
    if envelope["schema"] != CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA:
        raise EffectCommandSchemaError("effect command schema is unsupported")
    if (
        envelope["version"] != CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION
        or type(envelope["version"]) is not int
    ):
        raise EffectCommandSchemaError("effect command schema version is unsupported")
    if envelope["command_type"] != command_type:
        raise EffectCommandSchemaError("embedded and external command types differ")

    integrity = _exact_object(
        envelope["integrity"],
        fields=_INTEGRITY_FIELDS,
        path="$.integrity",
    )
    if integrity["algorithm"] != "sha256":
        raise EffectCommandSchemaError("effect command integrity algorithm is unsupported")
    supplied_integrity = _digest(integrity["digest"], path="$.integrity.digest")
    unsigned = {key: value for key, value in envelope.items() if key != "integrity"}
    expected_integrity = _integrity_digest(unsigned)
    if not hmac.compare_digest(supplied_integrity, expected_integrity):
        raise EffectCommandIntegrityError("effect command integrity digest mismatch")

    command_value = _exact_object(
        envelope["command"],
        fields=_COMMAND_FIELDS,
        path="$.command",
    )
    proposal = _proposal(command_value["proposal"])
    prior_plan = _prior_plan(command_value["prior_plan"])
    request = _request(command_value["request"])
    try:
        command = CreatePaymentLinkCommand(
            proposal=proposal,
            prior_plan=prior_plan,
            request=request,
            provider_account_id=_text(
                command_value["provider_account_id"],
                path="$.command.provider_account_id",
            ),
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, EffectCommandCodecError):
            raise
        raise EffectCommandSchemaError("effect command violates the executor contract") from exc
    _validate_command_binding(command)

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
            raise EffectCommandIntegrityError(f"effect command {field} binding mismatch")

    rebuilt = encode_create_standard_payment_link_command(command)
    if not hmac.compare_digest(
        _bounded_canonical_bytes(envelope),
        _bounded_canonical_bytes(rebuilt),
    ):
        raise EffectCommandIntegrityError("effect command is not its unique canonical envelope")
    return command


__all__ = [
    "CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA",
    "CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION",
    "CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE",
    "MAX_EFFECT_COMMAND_BYTES",
    "EffectCommandBindingError",
    "EffectCommandCodecError",
    "EffectCommandIntegrityError",
    "EffectCommandPrivacyError",
    "EffectCommandSchemaError",
    "EffectCommandSizeError",
    "decode_action_proposal",
    "decode_create_standard_payment_link_command",
    "encode_create_standard_payment_link_command",
    "encode_create_standard_payment_link_command_json",
]
