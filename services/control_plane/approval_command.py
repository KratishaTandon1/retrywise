"""Exact durable command envelope for worker-side approval materialization."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from ...packages.domain.canonical import canonical_json_bytes

MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE = "MATERIALIZE_APPROVED_ACTION"
MATERIALIZE_APPROVED_ACTION_SCHEMA_VERSION = 1

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_SUBJECT_RE = re.compile(r"^operator:[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,99}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class ApprovalCommandCodecError(ValueError):
    pass


def _ulid(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _ULID_RE.fullmatch(value) is None:
        raise ApprovalCommandCodecError(f"{field} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class MaterializeApprovedActionCommand:
    merchant_id: str
    approval_id: str
    operator_subject: str
    reason_code: str
    request_idempotency_sha256: str

    def __post_init__(self) -> None:
        _ulid(self.merchant_id, field="merchant_id")
        _ulid(self.approval_id, field="approval_id")
        if _SUBJECT_RE.fullmatch(self.operator_subject) is None:
            raise ApprovalCommandCodecError("operator_subject is invalid")
        if _REASON_RE.fullmatch(self.reason_code) is None:
            raise ApprovalCommandCodecError("reason_code is invalid")
        if _DIGEST_RE.fullmatch(self.request_idempotency_sha256) is None:
            raise ApprovalCommandCodecError("request idempotency digest is invalid")

    def to_primitive(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "merchant_id": self.merchant_id,
            "operator_subject": self.operator_subject,
            "reason_code": self.reason_code,
            "request_idempotency_sha256": self.request_idempotency_sha256,
            "schema": "retrywise-materialize-approved-action",
            "schema_version": MATERIALIZE_APPROVED_ACTION_SCHEMA_VERSION,
        }

    @property
    def payload_digest(self) -> str:
        import hashlib

        return hashlib.sha256(canonical_json_bytes(self.to_primitive())).hexdigest()


def decode_materialize_approved_action_command(
    value: object,
    *,
    command_type: str,
    command_schema_version: int,
) -> MaterializeApprovedActionCommand:
    if command_type != MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE:
        raise ApprovalCommandCodecError("command type is invalid")
    if command_schema_version != MATERIALIZE_APPROVED_ACTION_SCHEMA_VERSION:
        raise ApprovalCommandCodecError("command schema version is invalid")
    if not isinstance(value, Mapping):
        raise ApprovalCommandCodecError("command payload must be an object")
    expected = {
        "approval_id",
        "merchant_id",
        "operator_subject",
        "reason_code",
        "request_idempotency_sha256",
        "schema",
        "schema_version",
    }
    if set(value) != expected:
        raise ApprovalCommandCodecError("command payload fields are invalid")
    if (
        value["schema"] != "retrywise-materialize-approved-action"
        or value["schema_version"] != MATERIALIZE_APPROVED_ACTION_SCHEMA_VERSION
    ):
        raise ApprovalCommandCodecError("command payload schema is invalid")
    return MaterializeApprovedActionCommand(
        merchant_id=_ulid(value["merchant_id"], field="merchant_id"),
        approval_id=_ulid(value["approval_id"], field="approval_id"),
        operator_subject=(
            value["operator_subject"] if isinstance(value["operator_subject"], str) else ""
        ),
        reason_code=value["reason_code"] if isinstance(value["reason_code"], str) else "",
        request_idempotency_sha256=(
            value["request_idempotency_sha256"]
            if isinstance(value["request_idempotency_sha256"], str)
            else ""
        ),
    )


__all__ = [
    "MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE",
    "MATERIALIZE_APPROVED_ACTION_SCHEMA_VERSION",
    "ApprovalCommandCodecError",
    "MaterializeApprovedActionCommand",
    "decode_materialize_approved_action_command",
]
