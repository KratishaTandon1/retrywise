"""Closed recovery action catalog and immutable proposals/approvals."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .canonical import canonical_json_bytes, canonical_timestamp, require_utc
from .errors import InvalidValue
from .values import Money, Probability, require_identifier, require_payment_method

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ActionType(StrEnum):
    WAIT = "wait"
    CREATE_STANDARD_PAYMENT_LINK = "create_standard_payment_link"
    NOTIFY_EXISTING_LINK = "notify_existing_link"
    CANCEL_PAYMENT_LINK = "cancel_payment_link"
    ESCALATE = "escalate"
    STOP = "stop"


COLLECTION_ACTIONS = frozenset(
    {
        ActionType.CREATE_STANDARD_PAYMENT_LINK,
        ActionType.NOTIFY_EXISTING_LINK,
    }
)
CONTACT_ACTIONS = frozenset({ActionType.NOTIFY_EXISTING_LINK})
PROTECTIVE_ACTIONS = frozenset({ActionType.CANCEL_PAYMENT_LINK})
INTERNAL_ACTIONS = frozenset({ActionType.WAIT, ActionType.ESCALATE, ActionType.STOP})
EXTERNAL_ACTIONS = COLLECTION_ACTIONS | PROTECTIVE_ACTIONS


@dataclass(frozen=True, slots=True)
class ActionProposal:
    proposal_id: str
    merchant_id: str
    case_id: str
    decision_version: int
    action_type: ActionType
    created_at: datetime
    expires_at: datetime
    attempt_ordinal: int = 1
    amount: Money | None = None
    payment_method: str | None = None
    expected_value_minor: int | None = None
    model_confidence: Probability | None = None
    requires_approval: bool = False
    instrument_reference: str | None = None

    def __post_init__(self) -> None:
        require_identifier(self.proposal_id, field="proposal_id")
        require_identifier(self.merchant_id, field="merchant_id")
        require_identifier(self.case_id, field="case_id")
        if not isinstance(self.action_type, ActionType):
            raise InvalidValue("action_type must be a closed ActionType value")
        if (
            isinstance(self.decision_version, bool)
            or not isinstance(self.decision_version, int)
            or self.decision_version < 1
        ):
            raise InvalidValue("decision_version must be a positive integer")
        if (
            isinstance(self.attempt_ordinal, bool)
            or not isinstance(self.attempt_ordinal, int)
            or self.attempt_ordinal < 1
        ):
            raise InvalidValue("attempt_ordinal must be a positive integer")
        created_at = require_utc(self.created_at, field="created_at")
        expires_at = require_utc(self.expires_at, field="expires_at")
        if expires_at <= created_at:
            raise InvalidValue("proposal expires_at must be after created_at")
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "expires_at", expires_at)

        if self.expected_value_minor is not None and (
            isinstance(self.expected_value_minor, bool)
            or not isinstance(self.expected_value_minor, int)
        ):
            raise InvalidValue("expected_value_minor must be an integer")
        if self.amount is not None and not isinstance(self.amount, Money):
            raise InvalidValue("amount must be a Money value")
        if self.model_confidence is not None and not isinstance(self.model_confidence, Probability):
            raise InvalidValue("model_confidence must be a Probability value")
        if not isinstance(self.requires_approval, bool):
            raise InvalidValue("requires_approval must be boolean")
        if self.payment_method is not None:
            require_payment_method(self.payment_method)
        if self.instrument_reference is not None:
            require_identifier(self.instrument_reference, field="instrument_reference")

        if self.action_type in COLLECTION_ACTIONS:
            if self.amount is None or self.amount.minor_units == 0:
                raise InvalidValue("collection proposals require a positive amount")
            if self.payment_method is None:
                raise InvalidValue("collection proposals require a payment method")
        elif self.amount is not None or self.payment_method is not None:
            raise InvalidValue("non-collection proposals cannot carry amount or payment method")

        if self.action_type is ActionType.CANCEL_PAYMENT_LINK:
            if self.instrument_reference is None:
                raise InvalidValue("cancellation requires an instrument reference")
        elif self.instrument_reference is not None:
            raise InvalidValue("only cancellation proposals carry an instrument reference")

    @property
    def action_key(self) -> str:
        material = {
            "action_type": self.action_type.value,
            "attempt_ordinal": self.attempt_ordinal,
            "case_id": self.case_id,
            "decision_version": self.decision_version,
            "merchant_id": self.merchant_id,
            "schema": "retrywise-action-key-v1",
        }
        return "act_" + hashlib.sha256(canonical_json_bytes(material)).hexdigest()

    @property
    def proposal_digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_primitive())).hexdigest()

    def to_primitive(self) -> dict[str, Any]:
        return {
            "action_key": self.action_key,
            "action_type": self.action_type.value,
            "amount": None if self.amount is None else self.amount.to_primitive(),
            "attempt_ordinal": self.attempt_ordinal,
            "case_id": self.case_id,
            "created_at": canonical_timestamp(self.created_at),
            "decision_version": self.decision_version,
            "expected_value_minor": self.expected_value_minor,
            "expires_at": canonical_timestamp(self.expires_at),
            "instrument_reference": self.instrument_reference,
            "merchant_id": self.merchant_id,
            "model_confidence": (
                None if self.model_confidence is None else self.model_confidence.to_primitive()
            ),
            "payment_method": self.payment_method,
            "proposal_id": self.proposal_id,
            "requires_approval": self.requires_approval,
        }


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    merchant_id: str
    case_id: str
    action_key: str
    proposal_digest: str
    decision_version: int
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    granted: bool = True

    def __post_init__(self) -> None:
        require_identifier(self.approval_id, field="approval_id")
        require_identifier(self.merchant_id, field="merchant_id")
        require_identifier(self.case_id, field="case_id")
        require_identifier(self.approved_by, field="approved_by")
        if not isinstance(self.action_key, str) or not self.action_key.startswith("act_"):
            raise InvalidValue("approval action_key is invalid")
        if not isinstance(self.proposal_digest, str) or not _DIGEST_PATTERN.fullmatch(
            self.proposal_digest
        ):
            raise InvalidValue("approval proposal_digest is invalid")
        if (
            isinstance(self.decision_version, bool)
            or not isinstance(self.decision_version, int)
            or self.decision_version < 1
        ):
            raise InvalidValue("approval decision_version must be positive")
        approved_at = require_utc(self.approved_at, field="approved_at")
        expires_at = require_utc(self.expires_at, field="expires_at")
        if expires_at <= approved_at:
            raise InvalidValue("approval expires_at must be after approved_at")
        if not isinstance(self.granted, bool):
            raise InvalidValue("approval granted must be boolean")
        object.__setattr__(self, "approved_at", approved_at)
        object.__setattr__(self, "expires_at", expires_at)

    def to_primitive(self) -> dict[str, Any]:
        return {
            "action_key": self.action_key,
            "approval_id": self.approval_id,
            "approved_at": canonical_timestamp(self.approved_at),
            "approved_by": self.approved_by,
            "case_id": self.case_id,
            "decision_version": self.decision_version,
            "expires_at": canonical_timestamp(self.expires_at),
            "granted": self.granted,
            "merchant_id": self.merchant_id,
            "proposal_digest": self.proposal_digest,
        }
