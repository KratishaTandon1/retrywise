"""Tenant-scoped diagnosis routing controls with immutable change evidence."""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from retrywise.packages.diagnosis.provenance import DiagnosisMode

from .postgres_connection import PostgresConnectionPolicy

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_REASONS = {
    DiagnosisMode.LOCAL_ML: "operator_selected_local_ml",
    DiagnosisMode.HYBRID_GEMINI: "operator_selected_hybrid_gemini",
    DiagnosisMode.SHADOW: "operator_selected_shadow",
}


class DiagnosisControlNotFound(RuntimeError):
    pass


class DiagnosisControlConflict(RuntimeError):
    pass


def _new_ulid() -> str:
    value = ((time.time_ns() // 1_000_000) << 80) | secrets.randbits(80)
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = _CROCKFORD_BASE32[value & 31]
        value >>= 5
    return "".join(characters)


def _clean(value: object, *, field: str, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not minimum <= len(value) <= maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{field} is invalid")
    return value


def _ulid(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _ULID_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a RetryWise ULID")
    return value


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _bytes(value: object) -> bytes:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if not isinstance(value, bytes) or len(value) != 32:
        raise RuntimeError("persisted digest is malformed")
    return value


def _mode(value: object) -> DiagnosisMode:
    if not isinstance(value, str):
        raise RuntimeError("persisted diagnosis mode is malformed")
    try:
        return DiagnosisMode(value)
    except ValueError:
        raise RuntimeError("persisted diagnosis mode is malformed") from None


@dataclass(frozen=True, slots=True)
class DiagnosisControlState:
    merchant_id: str
    mode: DiagnosisMode
    gemini_configured: bool
    event_id: str | None = None
    sequence_number: int | None = None
    reason_code: str | None = None
    changed_at: datetime | None = None
    idempotent_replay: bool = False

    def __post_init__(self) -> None:
        _ulid(self.merchant_id, field="merchant_id")
        if not isinstance(self.mode, DiagnosisMode):
            raise TypeError("mode must be DiagnosisMode")
        if type(self.gemini_configured) is not bool:
            raise TypeError("gemini_configured must be boolean")
        optional = (self.event_id, self.sequence_number, self.reason_code, self.changed_at)
        if any(value is None for value in optional) and any(
            value is not None for value in optional
        ):
            raise ValueError("last diagnosis control event fields must be present together")
        if self.event_id is not None:
            _ulid(self.event_id, field="event_id")
            if type(self.sequence_number) is not int or self.sequence_number <= 0:
                raise ValueError("sequence_number must be positive")
            if self.reason_code not in _REASONS.values():
                raise ValueError("reason_code is invalid")
            if (
                not isinstance(self.changed_at, datetime)
                or self.changed_at.tzinfo is None
                or self.changed_at.utcoffset() is None
            ):
                raise ValueError("changed_at must be timezone-aware")
        if type(self.idempotent_replay) is not bool:
            raise TypeError("idempotent_replay must be boolean")

    def to_primitive(self) -> dict[str, object]:
        return {
            "environment": "RAZORPAY_TEST_MODE",
            "merchant_id": self.merchant_id,
            "mode": self.mode.value,
            "gemini_configured": self.gemini_configured,
            "effective_for": "future_assessments",
            "local_fallback_enabled": True,
            "policy_authority": "DETERMINISTIC",
            "last_event": (
                None
                if self.event_id is None
                else {
                    "id": self.event_id,
                    "sequence_number": self.sequence_number,
                    "reason_code": self.reason_code,
                    "changed_at": self.changed_at.astimezone(UTC).isoformat(),  # type: ignore[union-attr]
                }
            ),
            "idempotent_replay": self.idempotent_replay,
        }


_STATE = """
SELECT merchant.id::text, merchant.diagnosis_mode,
       event.id::text, event.sequence_number, event.reason_code, event.created_at
FROM retrywise.merchants AS merchant
LEFT JOIN LATERAL (
    SELECT candidate.id, candidate.sequence_number, candidate.reason_code,
           candidate.created_at
    FROM retrywise.diagnosis_mode_events AS candidate
    WHERE candidate.merchant_id = merchant.id
    ORDER BY candidate.sequence_number DESC
    LIMIT 1
) AS event ON TRUE
WHERE merchant.id = %(merchant_id)s
  AND merchant.status = 'ACTIVE'
"""

_LOCK = """
SELECT id::text, diagnosis_mode
FROM retrywise.merchants
WHERE id = %(merchant_id)s AND status = 'ACTIVE'
FOR UPDATE
"""

_PREVIOUS = """
SELECT id::text, sequence_number, diagnosis_mode, reason_code,
       actor_subject_sha256, created_at
FROM retrywise.diagnosis_mode_events
WHERE merchant_id = %(merchant_id)s
  AND idempotency_key_sha256 = %(idempotency_key_sha256)s
FOR SHARE
"""

_UPDATE = """
UPDATE retrywise.merchants
SET diagnosis_mode = %(mode)s, updated_at = clock_timestamp()
WHERE id = %(merchant_id)s AND status = 'ACTIVE'
RETURNING diagnosis_mode
"""

_INSERT = """
INSERT INTO retrywise.diagnosis_mode_events (
    id, merchant_id, sequence_number, diagnosis_mode, reason_code,
    actor_subject_sha256, idempotency_key_sha256
) SELECT
    %(event_id)s, %(merchant_id)s::retrywise.ulid,
    COALESCE(max(sequence_number), 0) + 1,
    %(mode)s, %(reason_code)s, %(actor_subject_sha256)s,
    %(idempotency_key_sha256)s
FROM retrywise.diagnosis_mode_events
WHERE merchant_id = %(merchant_id)s::retrywise.ulid
RETURNING id::text, sequence_number, reason_code, created_at
"""


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def __enter__(self) -> _Cursor: ...

    def __exit__(self, *args: object) -> bool | None: ...


class _Transaction(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(self, *args: object) -> bool | None: ...


class _Connection(Protocol):
    def transaction(self) -> _Transaction: ...

    def cursor(self) -> _Cursor: ...


class _ConnectionContext(Protocol):
    def __enter__(self) -> _Connection: ...

    def __exit__(self, *args: object) -> bool | None: ...


ConnectionFactory = Callable[[], _ConnectionContext]


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresDiagnosisControlService"),
        )

    return connect


class PostgresDiagnosisControlService:
    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        gemini_configured: bool = False,
        id_factory: Callable[[], str] = _new_ulid,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if type(gemini_configured) is not bool:
            raise TypeError("gemini_configured must be boolean")
        if not callable(id_factory):
            raise TypeError("id_factory must be callable")
        self._connector = (
            _dsn_factory(dsn, require_tls=require_tls)
            if dsn is not None
            else cast(ConnectionFactory, connector)
        )
        self._gemini_configured = gemini_configured
        self._id_factory = id_factory

    def _state(
        self, row: Sequence[object] | None, *, idempotent_replay: bool = False
    ) -> DiagnosisControlState:
        if row is None or len(row) != 6:
            raise DiagnosisControlNotFound("diagnosis_control_not_found")
        merchant_id, raw_mode, event_id, sequence, reason, changed_at = row
        return DiagnosisControlState(
            merchant_id=_ulid(merchant_id, field="merchant_id"),
            mode=_mode(raw_mode),
            gemini_configured=self._gemini_configured,
            event_id=cast(str | None, event_id),
            sequence_number=cast(int | None, sequence),
            reason_code=cast(str | None, reason),
            changed_at=cast(datetime | None, changed_at),
            idempotent_replay=idempotent_replay,
        )

    def get(self, *, merchant_id: str) -> DiagnosisControlState:
        merchant_id = _ulid(merchant_id, field="merchant_id")
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(_STATE, {"merchant_id": merchant_id})
            return self._state(cursor.fetchone())

    def diagnosis_mode(self, *, merchant_id: str) -> DiagnosisMode:
        return self.get(merchant_id=merchant_id).mode

    def set_mode(
        self,
        *,
        merchant_id: str,
        mode: DiagnosisMode,
        operator_subject: str,
        idempotency_key: str,
    ) -> DiagnosisControlState:
        merchant_id = _ulid(merchant_id, field="merchant_id")
        if not isinstance(mode, DiagnosisMode):
            raise TypeError("mode must be DiagnosisMode")
        operator_subject = _clean(
            operator_subject, field="operator_subject", minimum=1, maximum=200
        )
        idempotency_key = _clean(idempotency_key, field="idempotency_key", minimum=16, maximum=128)
        actor_digest = _digest(operator_subject)
        key_digest = _digest(idempotency_key)
        reason_code = _REASONS[mode]
        params: dict[str, object] = {
            "merchant_id": merchant_id,
            "mode": mode.value,
            "reason_code": reason_code,
            "actor_subject_sha256": actor_digest,
            "idempotency_key_sha256": key_digest,
            "event_id": _ulid(self._id_factory(), field="id_factory result"),
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_LOCK, params)
            merchant = cursor.fetchone()
            if merchant is None or len(merchant) != 2 or merchant[0] != merchant_id:
                raise DiagnosisControlNotFound("diagnosis_control_not_found")
            cursor.execute(_PREVIOUS, params)
            previous = cursor.fetchone()
            if previous is not None:
                if len(previous) != 6:
                    raise RuntimeError("diagnosis mode event is malformed")
                (
                    event_id,
                    sequence,
                    previous_mode,
                    previous_reason,
                    actor_hash,
                    created_at,
                ) = previous
                if (
                    previous_mode != mode.value
                    or previous_reason != reason_code
                    or not secrets.compare_digest(_bytes(actor_hash), actor_digest)
                ):
                    raise DiagnosisControlConflict("idempotency_key_conflict")
                return DiagnosisControlState(
                    merchant_id=merchant_id,
                    mode=_mode(merchant[1]),
                    gemini_configured=self._gemini_configured,
                    event_id=cast(str, event_id),
                    sequence_number=cast(int, sequence),
                    reason_code=previous_reason,
                    changed_at=cast(datetime, created_at),
                    idempotent_replay=True,
                )
            cursor.execute(_UPDATE, params)
            if cursor.fetchone() != (mode.value,):
                raise RuntimeError("diagnosis mode update was not persisted")
            cursor.execute(_INSERT, params)
            event = cursor.fetchone()
            if event is None or len(event) != 4:
                raise RuntimeError("diagnosis mode event was not persisted")
            return DiagnosisControlState(
                merchant_id=merchant_id,
                mode=mode,
                gemini_configured=self._gemini_configured,
                event_id=cast(str, event[0]),
                sequence_number=cast(int, event[1]),
                reason_code=cast(str, event[2]),
                changed_at=cast(datetime, event[3]),
            )


__all__ = [
    "DiagnosisControlConflict",
    "DiagnosisControlNotFound",
    "DiagnosisControlState",
    "PostgresDiagnosisControlService",
]
