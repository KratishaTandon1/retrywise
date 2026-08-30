"""Tenant-scoped, idempotent merchant effect controls with immutable evidence."""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from .postgres_connection import PostgresConnectionPolicy

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{2,99}$")
_ENABLE_REASONS = frozenset({"emergency_stop", "operator_safety_hold", "test_mode_hold"})
_DISABLE_REASONS = frozenset({"resume_after_verification", "enable_test_mode_effects"})
_CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class MerchantControlNotFound(RuntimeError):
    """The authenticated tenant does not resolve to an active merchant."""


class MerchantControlConflict(RuntimeError):
    """An idempotency key is already bound to another control request."""


def _new_ulid() -> str:
    timestamp_ms = time.time_ns() // 1_000_000
    if not 0 <= timestamp_ms < 1 << 48:
        raise RuntimeError("system clock is outside the ULID timestamp range")
    value = (timestamp_ms << 80) | secrets.randbits(80)
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = _CROCKFORD_BASE32[value & 31]
        value >>= 5
    return "".join(characters)


def _ulid(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _ULID_RE.fullmatch(value):
        raise ValueError(f"{field} must be a RetryWise ULID")
    return value


def _clean(value: object, *, field: str, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not minimum <= len(value) <= maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{field} is invalid")
    return value


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _bytes(value: object, *, field: str) -> bytes:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if not isinstance(value, bytes) or len(value) != 32:
        raise RuntimeError(f"{field} is not a SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class MerchantControlState:
    merchant_id: str
    kill_switch_enabled: bool
    policy_version: str
    event_id: str | None = None
    sequence_number: int | None = None
    reason_code: str | None = None
    changed_at: datetime | None = None
    idempotent_replay: bool = False

    def __post_init__(self) -> None:
        _ulid(self.merchant_id, field="merchant_id")
        if type(self.kill_switch_enabled) is not bool:
            raise TypeError("kill_switch_enabled must be boolean")
        _clean(self.policy_version, field="policy_version", minimum=1, maximum=100)
        optional = (self.event_id, self.sequence_number, self.reason_code, self.changed_at)
        if any(value is None for value in optional) and any(
            value is not None for value in optional
        ):
            raise ValueError("last control event fields must be present together")
        if self.event_id is not None:
            _ulid(self.event_id, field="event_id")
            if type(self.sequence_number) is not int or self.sequence_number <= 0:
                raise ValueError("sequence_number must be positive")
            if self.reason_code is None or not _REASON_RE.fullmatch(self.reason_code):
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
            "kill_switch_enabled": self.kill_switch_enabled,
            "collection_effects_enabled": not self.kill_switch_enabled,
            "policy_version": self.policy_version,
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
SELECT merchant.id::text, merchant.kill_switch_enabled,
       merchant.default_policy_version, event.id::text, event.sequence_number,
       event.reason_code, event.created_at
FROM retrywise.merchants AS merchant
LEFT JOIN LATERAL (
    SELECT candidate.id, candidate.sequence_number, candidate.reason_code,
           candidate.created_at
    FROM retrywise.merchant_control_events AS candidate
    WHERE candidate.merchant_id = merchant.id
      AND candidate.control_type = 'MERCHANT_KILL_SWITCH'
    ORDER BY candidate.sequence_number DESC
    LIMIT 1
) AS event ON TRUE
WHERE merchant.id = %(merchant_id)s
  AND merchant.status = 'ACTIVE'
"""

_LOCK_MERCHANT = """
SELECT id::text, kill_switch_enabled, default_policy_version
FROM retrywise.merchants
WHERE id = %(merchant_id)s
  AND status = 'ACTIVE'
FOR UPDATE
"""

_IDEMPOTENT_EVENT = """
SELECT id::text, sequence_number, enabled, reason_code,
       actor_subject_sha256, created_at
FROM retrywise.merchant_control_events
WHERE merchant_id = %(merchant_id)s
  AND idempotency_key_sha256 = %(idempotency_key_sha256)s
FOR SHARE
"""

_UPDATE_MERCHANT = """
UPDATE retrywise.merchants
SET kill_switch_enabled = %(enabled)s,
    updated_at = clock_timestamp()
WHERE id = %(merchant_id)s
  AND status = 'ACTIVE'
RETURNING kill_switch_enabled
"""

_INSERT_EVENT = """
INSERT INTO retrywise.merchant_control_events (
    id, merchant_id, sequence_number, control_type, enabled, reason_code,
    actor_subject_sha256, idempotency_key_sha256
) SELECT
    %(event_id)s, %(merchant_id)s::retrywise.ulid,
    COALESCE(max(sequence_number), 0) + 1,
    'MERCHANT_KILL_SWITCH', %(enabled)s, %(reason_code)s,
    %(actor_subject_sha256)s, %(idempotency_key_sha256)s
FROM retrywise.merchant_control_events
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
            policy.connect(dsn, component="PostgresMerchantControlService"),
        )

    return connect


def _state(
    row: Sequence[object] | None, *, idempotent_replay: bool = False
) -> MerchantControlState:
    if row is None or len(row) != 7:
        raise MerchantControlNotFound("merchant_control_not_found")
    merchant_id, enabled, policy, event_id, sequence, reason, changed_at = row
    if not isinstance(merchant_id, str) or type(enabled) is not bool or not isinstance(policy, str):
        raise RuntimeError("merchant control state is malformed")
    return MerchantControlState(
        merchant_id=merchant_id,
        kill_switch_enabled=enabled,
        policy_version=policy,
        event_id=cast(str | None, event_id),
        sequence_number=cast(int | None, sequence),
        reason_code=cast(str | None, reason),
        changed_at=cast(datetime | None, changed_at),
        idempotent_replay=idempotent_replay,
    )


class PostgresMerchantControlService:
    """Read and mutate the merchant kill switch under one database authority."""

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        id_factory: Callable[[], str] = _new_ulid,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if not callable(id_factory):
            raise TypeError("id_factory must be callable")
        self._connector = (
            _dsn_factory(dsn, require_tls=require_tls)
            if dsn is not None
            else cast(ConnectionFactory, connector)
        )
        self._id_factory = id_factory

    def get(self, *, merchant_id: str) -> MerchantControlState:
        merchant_id = _ulid(merchant_id, field="merchant_id")
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(_STATE, {"merchant_id": merchant_id})
            return _state(cursor.fetchone())

    def set_kill_switch(
        self,
        *,
        merchant_id: str,
        enabled: bool,
        reason_code: str,
        operator_subject: str,
        idempotency_key: str,
    ) -> MerchantControlState:
        merchant_id = _ulid(merchant_id, field="merchant_id")
        if type(enabled) is not bool:
            raise TypeError("enabled must be boolean")
        reason_code = _clean(reason_code, field="reason_code", minimum=3, maximum=100)
        allowed = _ENABLE_REASONS if enabled else _DISABLE_REASONS
        if reason_code not in allowed:
            raise ValueError("reason_code is not allowed for the requested state")
        operator_subject = _clean(
            operator_subject, field="operator_subject", minimum=1, maximum=200
        )
        idempotency_key = _clean(idempotency_key, field="idempotency_key", minimum=16, maximum=128)
        actor_digest = _digest(operator_subject)
        key_digest = _digest(idempotency_key)
        params: dict[str, object] = {
            "merchant_id": merchant_id,
            "enabled": enabled,
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
            cursor.execute(_LOCK_MERCHANT, params)
            merchant = cursor.fetchone()
            if (
                merchant is None
                or len(merchant) != 3
                or merchant[0] != merchant_id
                or type(merchant[1]) is not bool
                or not isinstance(merchant[2], str)
            ):
                raise MerchantControlNotFound("merchant_control_not_found")
            current_enabled = merchant[1]
            policy_version = merchant[2]

            cursor.execute(_IDEMPOTENT_EVENT, params)
            previous = cursor.fetchone()
            if previous is not None:
                if len(previous) != 6:
                    raise RuntimeError("merchant control event is malformed")
                event_id, sequence, previous_enabled, previous_reason, actor_hash, created_at = (
                    previous
                )
                if (
                    previous_enabled is not enabled
                    or previous_reason != reason_code
                    or not secrets.compare_digest(
                        _bytes(actor_hash, field="actor_subject_sha256"), actor_digest
                    )
                ):
                    raise MerchantControlConflict("idempotency_key_conflict")
                return MerchantControlState(
                    merchant_id=merchant_id,
                    kill_switch_enabled=current_enabled,
                    policy_version=policy_version,
                    event_id=cast(str, event_id),
                    sequence_number=cast(int, sequence),
                    reason_code=previous_reason,
                    changed_at=cast(datetime, created_at),
                    idempotent_replay=True,
                )

            cursor.execute(_UPDATE_MERCHANT, params)
            if cursor.fetchone() != (enabled,):
                raise RuntimeError("merchant kill switch update was not persisted")
            cursor.execute(_INSERT_EVENT, params)
            event = cursor.fetchone()
            if event is None or len(event) != 4:
                raise RuntimeError("merchant control event was not persisted")
            event_id, sequence, persisted_reason, created_at = event
            return MerchantControlState(
                merchant_id=merchant_id,
                kill_switch_enabled=enabled,
                policy_version=policy_version,
                event_id=cast(str, event_id),
                sequence_number=cast(int, sequence),
                reason_code=cast(str, persisted_reason),
                changed_at=cast(datetime, created_at),
            )


__all__ = [
    "MerchantControlConflict",
    "MerchantControlNotFound",
    "MerchantControlState",
    "PostgresMerchantControlService",
]
