"""PostgreSQL persistence and verification for the production audit chain.

This boundary is deliberately separate from :mod:`packages.domain.ledger`.
The domain ledger is useful deterministic decision evidence, including in
simulator fixtures.  A successful :class:`PostgresAuditVerification` from this
module instead proves that rows read from ``retrywise.audit_entries`` satisfy
the PostgreSQL audit-chain v1 profile.

The v1 profile hashes tenant and case identity, the database row identity,
actor metadata, a constrained non-PII fact envelope, and the canonical UTC
timestamp.  It retains the domain ledger's canonical-JSON-plus-previous-hash
construction, but is explicitly versioned because its hash document is wider.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, NoReturn, Protocol, cast

from ...packages.domain.canonical import canonical_json, canonical_json_bytes, canonical_timestamp
from ...packages.domain.errors import InvalidValue
from ...packages.domain.ledger import GENESIS_HASH
from .postgres_connection import PostgresConnectionPolicy

AUDIT_HASH_SCHEMA_VERSION = 1
POSTGRES_AUDIT_VERIFICATION_PROFILE = "POSTGRES_AUDIT_CHAIN_V1"
MAX_AUDIT_FACT_BYTES = 16_384
MAX_AUDIT_PAGE_SIZE = 250
MAX_AUDIT_VERIFY_ENTRIES = 5_000

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_ENTRY_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,99}$")
_FACT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MACHINE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_MACHINE_ID_RE = re.compile(r"^[a-z][a-z0-9]{0,31}[_:][A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_SUBJECT_RE = re.compile(
    r"^(system|worker|operator|model|provider):"
    r"([0-9A-HJKMNP-TV-Z]{26}|[0-9a-f]{64})$"
)
_FORBIDDEN_FACT_KEY_PARTS = frozenset(
    {
        "address",
        "alias",
        "birth",
        "body",
        "card",
        "contact",
        "comment",
        "credential",
        "customer",
        "cvv",
        "description",
        "detail",
        "dob",
        "email",
        "ip",
        "message",
        "name",
        "note",
        "pan",
        "password",
        "payer",
        "phone",
        "raw",
        "secret",
        "tax",
        "text",
        "title",
        "token",
        "upi",
        "user",
        "vpa",
    }
)

_LOCK_CHAIN = """
SELECT pg_advisory_xact_lock(
    hashtextextended(
        %(merchant_id)s::text || ':' || %(recovery_case_id)s::text,
        0
    )
)
"""

_LOCK_CASE_BINDING = """
SELECT TRUE
FROM retrywise.recovery_cases
WHERE merchant_id = %(merchant_id)s
  AND id = %(recovery_case_id)s
FOR SHARE
"""

_SELECT_CHAIN_HEAD = """
SELECT sequence_number, entry_hash, created_at
FROM retrywise.audit_entries
WHERE merchant_id = %(merchant_id)s
  AND recovery_case_id = %(recovery_case_id)s
ORDER BY sequence_number DESC
LIMIT 1
"""

_INSERT_AUDIT_ENTRY = """
INSERT INTO retrywise.audit_entries (
    id,
    merchant_id,
    recovery_case_id,
    sequence_number,
    entry_type,
    actor_type,
    actor_subject,
    payload,
    previous_entry_hash,
    entry_hash,
    created_at
) VALUES (
    %(audit_entry_id)s,
    %(merchant_id)s,
    %(recovery_case_id)s,
    %(sequence_number)s,
    %(entry_type)s,
    %(actor_type)s,
    %(actor_subject)s,
    %(payload_json)s::jsonb,
    %(previous_entry_hash)s,
    %(entry_hash)s,
    %(created_at)s
)
RETURNING id, sequence_number, entry_hash, created_at
"""

_SELECT_AUDIT_PAGE = """
SELECT
    id,
    merchant_id,
    recovery_case_id,
    sequence_number,
    entry_type,
    actor_type::text,
    actor_subject,
    payload,
    previous_entry_hash,
    entry_hash,
    created_at
FROM retrywise.audit_entries
WHERE merchant_id = %(merchant_id)s
  AND recovery_case_id = %(recovery_case_id)s
  AND sequence_number > %(after_sequence)s
ORDER BY sequence_number ASC
LIMIT %(fetch_limit)s
"""


class AuditActorType(StrEnum):
    """Values admitted by the PostgreSQL ``audit_actor_type`` enum."""

    SYSTEM = "SYSTEM"
    WORKER = "WORKER"
    OPERATOR = "OPERATOR"
    MODEL = "MODEL"
    PROVIDER = "PROVIDER"


class AuditRepositoryErrorCode(StrEnum):
    """Stable, non-sensitive operational failures exposed by this boundary."""

    CASE_NOT_FOUND = "AUDIT_CASE_NOT_FOUND"
    CHAIN_HEAD_CORRUPT = "AUDIT_CHAIN_HEAD_CORRUPT"
    TIMESTAMP_REGRESSION = "AUDIT_TIMESTAMP_REGRESSION"
    STORAGE_FAILURE = "AUDIT_STORAGE_FAILURE"


class AuditRepositoryError(RuntimeError):
    """An append/read operation could not safely complete."""

    def __init__(self, code: AuditRepositoryErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


class AuditInputError(ValueError):
    """A caller supplied a value outside the non-PII audit contract."""

    code = "AUDIT_INVALID_ARGUMENT"

    def __init__(self) -> None:
        super().__init__(self.code)


class AuditVerificationReason(StrEnum):
    """Stable, fail-closed outcomes for PostgreSQL chain verification."""

    OK = "OK"
    CASE_NOT_FOUND = "CASE_NOT_FOUND"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    ROW_INVALID = "ROW_INVALID"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    CASE_MISMATCH = "CASE_MISMATCH"
    SEQUENCE_MISMATCH = "SEQUENCE_MISMATCH"
    PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
    TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
    TIMESTAMP_REGRESSION = "TIMESTAMP_REGRESSION"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    HASH_SCHEMA_UNSUPPORTED = "HASH_SCHEMA_UNSUPPORTED"
    ENTRY_HASH_INVALID = "ENTRY_HASH_INVALID"
    ENTRY_HASH_MISMATCH = "ENTRY_HASH_MISMATCH"


@dataclass(frozen=True, slots=True)
class PersistedAuditEntry:
    """One sanitized row that passed the PostgreSQL audit-chain v1 profile."""

    audit_entry_id: str
    merchant_id: str
    recovery_case_id: str
    sequence_number: int
    entry_type: str
    actor_type: AuditActorType
    actor_subject: str | None
    facts: Mapping[str, Any]
    previous_entry_hash: str | None
    entry_hash: str
    created_at: datetime
    hash_schema_version: int = AUDIT_HASH_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class PostgresAuditVerification:
    """Result of bounded verification against PostgreSQL audit rows.

    ``entries`` is populated only for a complete valid chain.  Callers can
    therefore never mistake a verified prefix for verified PostgreSQL evidence.
    ``profile`` intentionally prevents simulator/domain-ledger results from
    being relabelled as this persistence proof.
    """

    valid: bool
    reason: AuditVerificationReason
    checked_entries: int
    entries: tuple[PersistedAuditEntry, ...]
    error_sequence: int | None
    head_hash: str | None
    profile: str = POSTGRES_AUDIT_VERIFICATION_PROFILE

    def __post_init__(self) -> None:
        if self.valid:
            if self.reason is not AuditVerificationReason.OK:
                raise ValueError("valid audit verification must have reason OK")
            if self.checked_entries != len(self.entries):
                raise ValueError("valid audit verification must expose its complete chain")
            expected_head = self.entries[-1].entry_hash if self.entries else GENESIS_HASH
            if self.head_hash != expected_head or self.error_sequence is not None:
                raise ValueError("valid audit verification has inconsistent result metadata")
        elif self.entries or self.head_hash is not None:
            raise ValueError("invalid audit verification cannot expose partially trusted entries")


class AuditWriteCursor(Protocol):
    """Minimal cursor surface required by a transactional audit append.

    The cursor must belong to an already-open PostgreSQL transaction.  The
    appender deliberately has no connector, transaction, commit, or rollback
    capability; ownership of those boundaries stays with the business
    repository coordinating the state change and its audit evidence.
    """

    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...


class TransactionalAuditAppender(Protocol):
    """Dependency-injection contract for an append in the caller's transaction."""

    def append(
        self,
        *,
        cursor: AuditWriteCursor,
        audit_entry_id: str,
        merchant_id: str,
        recovery_case_id: str,
        entry_type: str,
        actor_type: AuditActorType | str,
        actor_subject: str | None,
        facts: Mapping[str, Any],
        created_at: datetime,
    ) -> PersistedAuditEntry: ...


class _Cursor(AuditWriteCursor, Protocol):
    def fetchall(self) -> Sequence[Sequence[object]]: ...

    def __enter__(self) -> _Cursor: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class _Transaction(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...

    def transaction(self) -> _Transaction: ...


class _ConnectionContext(Protocol):
    def __enter__(self) -> _Connection: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


ConnectionFactory = Callable[[], _ConnectionContext]


def _invalid_input() -> NoReturn:
    raise AuditInputError


def _require_ulid(value: object) -> str:
    if not isinstance(value, str) or not _ULID_RE.fullmatch(value):
        _invalid_input()
    return value


def _require_entry_type(value: object) -> str:
    if not isinstance(value, str) or not _ENTRY_TYPE_RE.fullmatch(value):
        _invalid_input()
    return value


def _require_actor_type(value: object) -> AuditActorType:
    if not isinstance(value, str):
        _invalid_input()
    try:
        return AuditActorType(value)
    except (TypeError, ValueError) as exc:
        raise AuditInputError from exc


def _require_actor_subject(value: object, *, actor_type: AuditActorType) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        _invalid_input()
    match = _OPAQUE_SUBJECT_RE.fullmatch(value)
    if match is None or match.group(1) != actor_type.value.lower():
        _invalid_input()
    return value


def _require_timestamp(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _invalid_input()
    return value.astimezone(UTC)


def _looks_like_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _normalize_fact_value(value: object, *, depth: int) -> Any:
    if depth > 4:
        _invalid_input()
    if value is None or isinstance(value, bool):
        return value
    if type(value) is int:
        if not -(2**63) <= value < 2**63:
            _invalid_input()
        return value
    if isinstance(value, str):
        if (
            not (
                _MACHINE_CODE_RE.fullmatch(value)
                or _MACHINE_ID_RE.fullmatch(value)
                or _ULID_RE.fullmatch(value)
                or _HASH_RE.fullmatch(value)
            )
            or "://" in value
            or (value.isdigit() and len(value) >= 7)
            or _looks_like_ip_address(value)
        ):
            _invalid_input()
        return value
    if isinstance(value, Mapping):
        if len(value) > 64:
            _invalid_input()
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not _FACT_KEY_RE.fullmatch(key):
                _invalid_input()
            if _FORBIDDEN_FACT_KEY_PARTS.intersection(key.split("_")):
                _invalid_input()
            if key.endswith("_code") and (
                not isinstance(item, str) or not _MACHINE_CODE_RE.fullmatch(item)
            ):
                _invalid_input()
            normalized[key] = _normalize_fact_value(item, depth=depth + 1)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > 32:
            _invalid_input()
        return [_normalize_fact_value(item, depth=depth + 1) for item in value]
    _invalid_input()


def _normalize_facts(facts: object) -> dict[str, Any]:
    if not isinstance(facts, Mapping):
        _invalid_input()
    normalized = cast(dict[str, Any], _normalize_fact_value(facts, depth=0))
    rendered = canonical_json(normalized)
    if len(rendered.encode("utf-8")) > MAX_AUDIT_FACT_BYTES:
        _invalid_input()
    return cast(dict[str, Any], json.loads(rendered))


def _payload_envelope(facts: object) -> dict[str, Any]:
    return {
        "audit_hash_schema_version": AUDIT_HASH_SCHEMA_VERSION,
        "facts": _normalize_facts(facts),
    }


def _freeze_fact_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_fact_value(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_fact_value(item) for item in value)
    return value


def _require_previous_hash(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        _invalid_input()
    return value


def _hash_document(
    *,
    audit_entry_id: str,
    merchant_id: str,
    recovery_case_id: str,
    sequence_number: int,
    entry_type: str,
    actor_type: AuditActorType,
    actor_subject: str | None,
    payload: Mapping[str, Any],
    created_at: datetime,
) -> dict[str, Any]:
    return {
        "actor_subject": actor_subject,
        "actor_type": actor_type.value,
        "audit_entry_id": audit_entry_id,
        "created_at": canonical_timestamp(created_at),
        "entry_type": entry_type,
        "hash_schema_version": AUDIT_HASH_SCHEMA_VERSION,
        "merchant_id": merchant_id,
        "payload": payload,
        "recovery_case_id": recovery_case_id,
        "sequence_number": sequence_number,
    }


def audit_entry_hash_v1(
    *,
    audit_entry_id: str,
    merchant_id: str,
    recovery_case_id: str,
    sequence_number: int,
    entry_type: str,
    actor_type: AuditActorType | str,
    actor_subject: str | None,
    facts: Mapping[str, Any],
    previous_entry_hash: str | None,
    created_at: datetime,
) -> str:
    """Return the explicit PostgreSQL audit v1 application hash."""

    audit_entry_id = _require_ulid(audit_entry_id)
    merchant_id = _require_ulid(merchant_id)
    recovery_case_id = _require_ulid(recovery_case_id)
    if type(sequence_number) is not int or sequence_number <= 0:
        _invalid_input()
    entry_type = _require_entry_type(entry_type)
    parsed_actor_type = _require_actor_type(actor_type)
    actor_subject = _require_actor_subject(actor_subject, actor_type=parsed_actor_type)
    payload = _payload_envelope(facts)
    previous_hash = _require_previous_hash(previous_entry_hash) or GENESIS_HASH
    created_at = _require_timestamp(created_at)
    document = _hash_document(
        audit_entry_id=audit_entry_id,
        merchant_id=merchant_id,
        recovery_case_id=recovery_case_id,
        sequence_number=sequence_number,
        entry_type=entry_type,
        actor_type=parsed_actor_type,
        actor_subject=actor_subject,
        payload=payload,
        created_at=created_at,
    )
    material = canonical_json_bytes(document) + previous_hash.encode("ascii")
    return hashlib.sha256(material).hexdigest()


def _database_digest(value: object) -> bytes:
    if isinstance(value, memoryview):
        result = value.tobytes()
    elif isinstance(value, (bytes, bytearray)):
        result = bytes(value)
    else:
        raise AuditRepositoryError(AuditRepositoryErrorCode.CHAIN_HEAD_CORRUPT)
    if len(result) != 32:
        raise AuditRepositoryError(AuditRepositoryErrorCode.CHAIN_HEAD_CORRUPT)
    return result


def _first_column(row: Sequence[object] | None) -> object | None:
    if row is None:
        return None
    if len(row) != 1:
        raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE)
    return row[0]


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresAuditRepository"),
        )

    return connect


def _verification_failure(
    reason: AuditVerificationReason,
    *,
    checked_entries: int,
    error_sequence: int | None,
) -> PostgresAuditVerification:
    return PostgresAuditVerification(
        valid=False,
        reason=reason,
        checked_entries=checked_entries,
        entries=(),
        error_sequence=error_sequence,
        head_hash=None,
    )


class PostgresAuditAppender:
    """Append audit evidence through a caller-owned PostgreSQL transaction.

    Each call takes the same tenant/case advisory lock as the immutable
    database trigger, validates the case binding and current head, computes the
    v1 application hash, and validates PostgreSQL's ``RETURNING`` row.  It
    never opens a connection or transaction and never commits or rolls back.
    """

    durable = True

    def append(
        self,
        *,
        cursor: AuditWriteCursor,
        audit_entry_id: str,
        merchant_id: str,
        recovery_case_id: str,
        entry_type: str,
        actor_type: AuditActorType | str,
        actor_subject: str | None,
        facts: Mapping[str, Any],
        created_at: datetime,
    ) -> PersistedAuditEntry:
        """Append one row without taking ownership of the surrounding transaction."""

        audit_entry_id = _require_ulid(audit_entry_id)
        merchant_id = _require_ulid(merchant_id)
        recovery_case_id = _require_ulid(recovery_case_id)
        entry_type = _require_entry_type(entry_type)
        parsed_actor_type = _require_actor_type(actor_type)
        actor_subject = _require_actor_subject(actor_subject, actor_type=parsed_actor_type)
        normalized_facts = _normalize_facts(facts)
        payload = _payload_envelope(normalized_facts)
        created_at = _require_timestamp(created_at)
        chain_params: dict[str, object] = {
            "merchant_id": merchant_id,
            "recovery_case_id": recovery_case_id,
        }

        try:
            cursor.execute(_LOCK_CHAIN, chain_params)
            lock_row = cursor.fetchone()
            if lock_row is None or len(lock_row) != 1:
                raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE)

            cursor.execute(_LOCK_CASE_BINDING, chain_params)
            if _first_column(cursor.fetchone()) is not True:
                raise AuditRepositoryError(AuditRepositoryErrorCode.CASE_NOT_FOUND)

            cursor.execute(_SELECT_CHAIN_HEAD, chain_params)
            head = cursor.fetchone()
            if head is None:
                sequence_number = 1
                previous_hash_bytes: bytes | None = None
                previous_hash_hex: str | None = None
            else:
                if (
                    len(head) != 3
                    or type(head[0]) is not int
                    or head[0] <= 0
                    or not isinstance(head[2], datetime)
                    or head[2].tzinfo is None
                    or head[2].utcoffset() is None
                ):
                    raise AuditRepositoryError(AuditRepositoryErrorCode.CHAIN_HEAD_CORRUPT)
                previous_hash_bytes = _database_digest(head[1])
                previous_hash_hex = previous_hash_bytes.hex()
                sequence_number = head[0] + 1
                if created_at < head[2].astimezone(created_at.tzinfo):
                    raise AuditRepositoryError(AuditRepositoryErrorCode.TIMESTAMP_REGRESSION)

            entry_hash_hex = audit_entry_hash_v1(
                audit_entry_id=audit_entry_id,
                merchant_id=merchant_id,
                recovery_case_id=recovery_case_id,
                sequence_number=sequence_number,
                entry_type=entry_type,
                actor_type=parsed_actor_type,
                actor_subject=actor_subject,
                facts=normalized_facts,
                previous_entry_hash=previous_hash_hex,
                created_at=created_at,
            )
            entry_hash_bytes = bytes.fromhex(entry_hash_hex)
            insert_params = {
                **chain_params,
                "audit_entry_id": audit_entry_id,
                "sequence_number": sequence_number,
                "entry_type": entry_type,
                "actor_type": parsed_actor_type.value,
                "actor_subject": actor_subject,
                "payload_json": canonical_json(payload),
                "previous_entry_hash": previous_hash_bytes,
                "entry_hash": entry_hash_bytes,
                "created_at": created_at,
            }
            cursor.execute(_INSERT_AUDIT_ENTRY, insert_params)
            inserted = cursor.fetchone()
            if (
                inserted is None
                or len(inserted) != 4
                or inserted[0] != audit_entry_id
                or type(inserted[1]) is not int
                or inserted[1] != sequence_number
                or not isinstance(inserted[3], datetime)
                or inserted[3].tzinfo is None
            ):
                raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE)
            try:
                returned_entry_hash = _database_digest(inserted[2])
            except AuditRepositoryError:
                raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE) from None
            if returned_entry_hash != entry_hash_bytes or canonical_timestamp(
                inserted[3]
            ) != canonical_timestamp(created_at):
                raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE)

            return PersistedAuditEntry(
                audit_entry_id=audit_entry_id,
                merchant_id=merchant_id,
                recovery_case_id=recovery_case_id,
                sequence_number=sequence_number,
                entry_type=entry_type,
                actor_type=parsed_actor_type,
                actor_subject=actor_subject,
                facts=cast(Mapping[str, Any], _freeze_fact_value(normalized_facts)),
                previous_entry_hash=previous_hash_hex,
                entry_hash=entry_hash_hex,
                created_at=created_at,
            )
        except (AuditRepositoryError, AuditInputError):
            raise
        except Exception:
            raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE) from None


class PostgresAuditRepository:
    """Append and verify tenant-bound PostgreSQL audit chains."""

    durable = True

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if not isinstance(require_tls, bool):
            raise TypeError("require_tls must be boolean")
        if dsn is not None:
            self._connector = _dsn_factory(dsn, require_tls=require_tls)
        else:
            if require_tls:
                raise ValueError(
                    "require_tls needs the built-in DSN connector so its policy is verifiable"
                )
            if not callable(connector):
                raise TypeError("connector must be callable")
            self._connector = connector
        self._appender: TransactionalAuditAppender = PostgresAuditAppender()

    def append(
        self,
        *,
        audit_entry_id: str,
        merchant_id: str,
        recovery_case_id: str,
        entry_type: str,
        actor_type: AuditActorType | str,
        actor_subject: str | None,
        facts: Mapping[str, Any],
        created_at: datetime,
    ) -> PersistedAuditEntry:
        """Open one transaction and delegate the write to the scoped appender."""

        try:
            with (
                self._connector() as connection,
                connection.transaction(),
                connection.cursor() as cursor,
            ):
                entry = self._appender.append(
                    cursor=cursor,
                    audit_entry_id=audit_entry_id,
                    merchant_id=merchant_id,
                    recovery_case_id=recovery_case_id,
                    entry_type=entry_type,
                    actor_type=actor_type,
                    actor_subject=actor_subject,
                    facts=facts,
                    created_at=created_at,
                )
            return entry
        except (AuditRepositoryError, AuditInputError):
            raise
        except Exception:
            raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE) from None

    def verify_chain(
        self,
        *,
        merchant_id: str,
        recovery_case_id: str,
        page_size: int = 100,
        max_entries: int = 1_000,
    ) -> PostgresAuditVerification:
        """Read and verify a complete chain under one bounded transaction lock."""

        merchant_id = _require_ulid(merchant_id)
        recovery_case_id = _require_ulid(recovery_case_id)
        if (
            type(page_size) is not int
            or not 1 <= page_size <= MAX_AUDIT_PAGE_SIZE
            or type(max_entries) is not int
            or not 1 <= max_entries <= MAX_AUDIT_VERIFY_ENTRIES
        ):
            _invalid_input()
        chain_params: dict[str, object] = {
            "merchant_id": merchant_id,
            "recovery_case_id": recovery_case_id,
        }
        verified: list[PersistedAuditEntry] = []
        previous_hash: bytes | None = None
        previous_time: datetime | None = None

        try:
            with (
                self._connector() as connection,
                connection.transaction(),
                connection.cursor() as cursor,
            ):
                cursor.execute(_LOCK_CHAIN, chain_params)
                lock_row = cursor.fetchone()
                if lock_row is None or len(lock_row) != 1:
                    raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE)

                cursor.execute(_LOCK_CASE_BINDING, chain_params)
                if _first_column(cursor.fetchone()) is not True:
                    return _verification_failure(
                        AuditVerificationReason.CASE_NOT_FOUND,
                        checked_entries=0,
                        error_sequence=None,
                    )

                after_sequence = 0
                while True:
                    remaining = max_entries - len(verified)
                    probing_limit = remaining == 0
                    requested = 1 if probing_limit else min(page_size, remaining)
                    page_params = {
                        **chain_params,
                        "after_sequence": after_sequence,
                        "fetch_limit": requested,
                    }
                    cursor.execute(_SELECT_AUDIT_PAGE, page_params)
                    rows = cursor.fetchall()
                    if probing_limit:
                        if rows:
                            return _verification_failure(
                                AuditVerificationReason.LIMIT_EXCEEDED,
                                checked_entries=len(verified),
                                error_sequence=len(verified) + 1,
                            )
                        break
                    if len(rows) > requested:
                        raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE)
                    for row in rows:
                        expected_sequence = len(verified) + 1
                        entry, reason = self._verify_row(
                            row,
                            merchant_id=merchant_id,
                            recovery_case_id=recovery_case_id,
                            expected_sequence=expected_sequence,
                            previous_hash=previous_hash,
                            previous_time=previous_time,
                        )
                        if entry is None:
                            return _verification_failure(
                                reason,
                                checked_entries=len(verified),
                                error_sequence=expected_sequence,
                            )
                        verified.append(entry)
                        previous_hash = bytes.fromhex(entry.entry_hash)
                        previous_time = entry.created_at
                        after_sequence = entry.sequence_number

                    if len(rows) < requested:
                        break
                    if not rows:
                        break

            entries = tuple(verified)
            return PostgresAuditVerification(
                valid=True,
                reason=AuditVerificationReason.OK,
                checked_entries=len(entries),
                entries=entries,
                error_sequence=None,
                head_hash=entries[-1].entry_hash if entries else GENESIS_HASH,
            )
        except AuditRepositoryError:
            raise
        except Exception:
            raise AuditRepositoryError(AuditRepositoryErrorCode.STORAGE_FAILURE) from None

    @staticmethod
    def _verify_row(
        row: Sequence[object],
        *,
        merchant_id: str,
        recovery_case_id: str,
        expected_sequence: int,
        previous_hash: bytes | None,
        previous_time: datetime | None,
    ) -> tuple[PersistedAuditEntry | None, AuditVerificationReason]:
        if len(row) != 11:
            return None, AuditVerificationReason.ROW_INVALID
        (
            audit_entry_id,
            row_merchant_id,
            row_case_id,
            sequence_number,
            entry_type,
            actor_type,
            actor_subject,
            payload,
            previous_entry_hash,
            entry_hash,
            created_at,
        ) = row
        if row_merchant_id != merchant_id:
            return None, AuditVerificationReason.TENANT_MISMATCH
        if row_case_id != recovery_case_id:
            return None, AuditVerificationReason.CASE_MISMATCH
        if type(sequence_number) is not int or sequence_number != expected_sequence:
            return None, AuditVerificationReason.SEQUENCE_MISMATCH
        try:
            parsed_id = _require_ulid(audit_entry_id)
            parsed_entry_type = _require_entry_type(entry_type)
            parsed_actor_type = _require_actor_type(actor_type)
            parsed_actor_subject = _require_actor_subject(
                actor_subject, actor_type=parsed_actor_type
            )
        except AuditInputError:
            return None, AuditVerificationReason.ROW_INVALID

        if not isinstance(payload, Mapping):
            return None, AuditVerificationReason.PAYLOAD_INVALID
        if set(payload) != {"audit_hash_schema_version", "facts"}:
            return None, AuditVerificationReason.PAYLOAD_INVALID
        if (
            type(payload.get("audit_hash_schema_version")) is not int
            or payload.get("audit_hash_schema_version") != AUDIT_HASH_SCHEMA_VERSION
        ):
            return None, AuditVerificationReason.HASH_SCHEMA_UNSUPPORTED
        try:
            normalized_facts = _normalize_facts(payload.get("facts"))
        except (AuditInputError, InvalidValue, TypeError, ValueError):
            return None, AuditVerificationReason.PAYLOAD_INVALID
        normalized_payload = _payload_envelope(normalized_facts)

        if expected_sequence == 1:
            if previous_entry_hash is not None or previous_hash is not None:
                return None, AuditVerificationReason.PREVIOUS_HASH_MISMATCH
            previous_hash_hex: str | None = None
        else:
            try:
                stored_previous = _database_digest(previous_entry_hash)
            except AuditRepositoryError:
                return None, AuditVerificationReason.PREVIOUS_HASH_MISMATCH
            if previous_hash is None or stored_previous != previous_hash:
                return None, AuditVerificationReason.PREVIOUS_HASH_MISMATCH
            previous_hash_hex = stored_previous.hex()

        if (
            not isinstance(created_at, datetime)
            or created_at.tzinfo is None
            or created_at.utcoffset() is None
        ):
            return None, AuditVerificationReason.TIMESTAMP_INVALID
        created_at = created_at.astimezone(previous_time.tzinfo) if previous_time else created_at
        if previous_time is not None and created_at < previous_time:
            return None, AuditVerificationReason.TIMESTAMP_REGRESSION

        try:
            stored_entry_hash = _database_digest(entry_hash)
        except AuditRepositoryError:
            return None, AuditVerificationReason.ENTRY_HASH_INVALID
        try:
            computed_hash = audit_entry_hash_v1(
                audit_entry_id=parsed_id,
                merchant_id=merchant_id,
                recovery_case_id=recovery_case_id,
                sequence_number=expected_sequence,
                entry_type=parsed_entry_type,
                actor_type=parsed_actor_type,
                actor_subject=parsed_actor_subject,
                facts=normalized_facts,
                previous_entry_hash=previous_hash_hex,
                created_at=created_at,
            )
        except AuditInputError:
            return None, AuditVerificationReason.PAYLOAD_INVALID
        if stored_entry_hash.hex() != computed_hash:
            return None, AuditVerificationReason.ENTRY_HASH_MISMATCH

        return (
            PersistedAuditEntry(
                audit_entry_id=parsed_id,
                merchant_id=merchant_id,
                recovery_case_id=recovery_case_id,
                sequence_number=expected_sequence,
                entry_type=parsed_entry_type,
                actor_type=parsed_actor_type,
                actor_subject=parsed_actor_subject,
                facts=cast(
                    Mapping[str, Any],
                    _freeze_fact_value(normalized_payload["facts"]),
                ),
                previous_entry_hash=previous_hash_hex,
                entry_hash=computed_hash,
                created_at=created_at,
            ),
            AuditVerificationReason.OK,
        )


__all__ = [
    "AUDIT_HASH_SCHEMA_VERSION",
    "MAX_AUDIT_PAGE_SIZE",
    "MAX_AUDIT_VERIFY_ENTRIES",
    "POSTGRES_AUDIT_VERIFICATION_PROFILE",
    "AuditActorType",
    "AuditInputError",
    "AuditRepositoryError",
    "AuditRepositoryErrorCode",
    "AuditVerificationReason",
    "AuditWriteCursor",
    "PersistedAuditEntry",
    "PostgresAuditAppender",
    "PostgresAuditRepository",
    "PostgresAuditVerification",
    "TransactionalAuditAppender",
    "audit_entry_hash_v1",
]
