"""Append-only, canonical-JSON, hash-chained decision ledger."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .canonical import (
    canonical_json,
    canonical_json_bytes,
    canonical_timestamp,
    parse_canonical_timestamp,
    require_utc,
)
from .errors import InvalidValue, LedgerIntegrityError
from .values import require_identifier

GENESIS_HASH = "0" * 64
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class LedgerVerificationReason(StrEnum):
    OK = "OK"
    ENTRY_INVALID = "ENTRY_INVALID"
    SEQUENCE_MISMATCH = "SEQUENCE_MISMATCH"
    CASE_MISMATCH = "CASE_MISMATCH"
    PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
    TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
    TIMESTAMP_REGRESSION = "TIMESTAMP_REGRESSION"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    PAYLOAD_NOT_CANONICAL = "PAYLOAD_NOT_CANONICAL"
    ENTRY_HASH_INVALID = "ENTRY_HASH_INVALID"
    ENTRY_HASH_MISMATCH = "ENTRY_HASH_MISMATCH"


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    sequence: int
    case_id: str
    recorded_at: str
    entry_type: str
    payload_json: str
    previous_hash: str
    entry_hash: str

    @property
    def payload(self) -> Any:
        return json.loads(self.payload_json)

    def hash_document(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "entry_type": self.entry_type,
            "payload": self.payload,
            "recorded_at": self.recorded_at,
            "sequence": self.sequence,
        }

    def to_primitive(self) -> dict[str, Any]:
        return {
            **self.hash_document(),
            "entry_hash": self.entry_hash,
            "previous_hash": self.previous_hash,
        }


@dataclass(frozen=True, slots=True)
class LedgerVerification:
    valid: bool
    reason: LedgerVerificationReason
    checked_entries: int
    error_index: int | None = None
    expected_hash: str | None = None
    actual_hash: str | None = None


def _entry_hash(entry: LedgerEntry) -> str:
    material = canonical_json_bytes(entry.hash_document()) + entry.previous_hash.encode("ascii")
    return hashlib.sha256(material).hexdigest()


def verify_ledger(
    entries: Sequence[LedgerEntry], *, expected_case_id: str | None = None
) -> LedgerVerification:
    """Verify sequence, case binding, canonical evidence, and every hash link."""

    if expected_case_id is not None:
        require_identifier(expected_case_id, field="expected_case_id")
    chain_case_id = expected_case_id
    previous_hash = GENESIS_HASH
    previous_time: datetime | None = None

    for index, entry in enumerate(entries):
        if not isinstance(entry, LedgerEntry):
            return LedgerVerification(
                False,
                LedgerVerificationReason.ENTRY_INVALID,
                index,
                error_index=index,
            )
        if entry.sequence != index + 1:
            return LedgerVerification(
                False,
                LedgerVerificationReason.SEQUENCE_MISMATCH,
                index,
                error_index=index,
            )
        try:
            require_identifier(entry.case_id, field="entry case_id")
            require_identifier(entry.entry_type, field="entry_type")
        except InvalidValue:
            return LedgerVerification(
                False,
                LedgerVerificationReason.ENTRY_INVALID,
                index,
                error_index=index,
            )
        if chain_case_id is None:
            chain_case_id = entry.case_id
        if entry.case_id != chain_case_id:
            return LedgerVerification(
                False,
                LedgerVerificationReason.CASE_MISMATCH,
                index,
                error_index=index,
            )
        if entry.previous_hash != previous_hash:
            return LedgerVerification(
                False,
                LedgerVerificationReason.PREVIOUS_HASH_MISMATCH,
                index,
                error_index=index,
                expected_hash=previous_hash,
                actual_hash=entry.previous_hash,
            )
        try:
            recorded_at = parse_canonical_timestamp(entry.recorded_at)
        except InvalidValue:
            return LedgerVerification(
                False,
                LedgerVerificationReason.TIMESTAMP_INVALID,
                index,
                error_index=index,
            )
        if previous_time is not None and recorded_at < previous_time:
            return LedgerVerification(
                False,
                LedgerVerificationReason.TIMESTAMP_REGRESSION,
                index,
                error_index=index,
            )
        try:
            payload = json.loads(entry.payload_json)
        except (json.JSONDecodeError, TypeError):
            return LedgerVerification(
                False,
                LedgerVerificationReason.PAYLOAD_INVALID,
                index,
                error_index=index,
            )
        try:
            if canonical_json(payload) != entry.payload_json:
                return LedgerVerification(
                    False,
                    LedgerVerificationReason.PAYLOAD_NOT_CANONICAL,
                    index,
                    error_index=index,
                )
        except InvalidValue:
            return LedgerVerification(
                False,
                LedgerVerificationReason.PAYLOAD_INVALID,
                index,
                error_index=index,
            )
        if not isinstance(entry.entry_hash, str) or not _HASH_PATTERN.fullmatch(entry.entry_hash):
            return LedgerVerification(
                False,
                LedgerVerificationReason.ENTRY_HASH_INVALID,
                index,
                error_index=index,
            )
        try:
            computed_hash = _entry_hash(entry)
        except (InvalidValue, UnicodeEncodeError, json.JSONDecodeError):
            return LedgerVerification(
                False,
                LedgerVerificationReason.PAYLOAD_INVALID,
                index,
                error_index=index,
            )
        if entry.entry_hash != computed_hash:
            return LedgerVerification(
                False,
                LedgerVerificationReason.ENTRY_HASH_MISMATCH,
                index,
                error_index=index,
                expected_hash=computed_hash,
                actual_hash=entry.entry_hash,
            )
        previous_hash = entry.entry_hash
        previous_time = recorded_at

    return LedgerVerification(True, LedgerVerificationReason.OK, checked_entries=len(entries))


class DecisionLedger:
    """A per-case ledger exposing append but no update or delete operation."""

    def __init__(self, case_id: str, entries: Sequence[LedgerEntry] = ()) -> None:
        self._case_id = require_identifier(case_id, field="case_id")
        verification = verify_ledger(entries, expected_case_id=case_id)
        if not verification.valid:
            raise LedgerIntegrityError(f"cannot load invalid ledger: {verification.reason.value}")
        self._entries = list(entries)

    @property
    def case_id(self) -> str:
        return self._case_id

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def append(
        self,
        *,
        entry_type: str,
        payload: Mapping[str, Any],
        recorded_at: datetime,
    ) -> LedgerEntry:
        require_identifier(entry_type, field="entry_type")
        if not isinstance(payload, Mapping):
            raise InvalidValue("ledger payload must be a mapping")
        timestamp = require_utc(recorded_at, field="recorded_at")
        if self._entries:
            previous_time = parse_canonical_timestamp(self._entries[-1].recorded_at)
            if timestamp < previous_time:
                raise LedgerIntegrityError("ledger timestamps cannot move backwards")
        payload_json = canonical_json(payload)
        provisional = LedgerEntry(
            sequence=len(self._entries) + 1,
            case_id=self._case_id,
            recorded_at=canonical_timestamp(timestamp),
            entry_type=entry_type,
            payload_json=payload_json,
            previous_hash=self.head_hash,
            entry_hash=GENESIS_HASH,
        )
        entry = LedgerEntry(
            sequence=provisional.sequence,
            case_id=provisional.case_id,
            recorded_at=provisional.recorded_at,
            entry_type=provisional.entry_type,
            payload_json=provisional.payload_json,
            previous_hash=provisional.previous_hash,
            entry_hash=_entry_hash(provisional),
        )
        self._entries.append(entry)
        return entry

    def verify(self) -> LedgerVerification:
        return verify_ledger(self.entries, expected_case_id=self.case_id)
