"""Secret-free operator approval capture and durable worker dispatch."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, cast

from .approval_command import (
    MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE,
    MATERIALIZE_APPROVED_ACTION_SCHEMA_VERSION,
    MaterializeApprovedActionCommand,
)
from .postgres_audit import AuditActorType, TransactionalAuditAppender
from .postgres_connection import PostgresConnectionPolicy

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,99}$")

_LOCK_APPROVAL = """
SELECT
    approval.verdict::text,
    approval.recovery_case_id::text,
    approval.expires_at,
    recovery_case.state::text,
    recovery_case.version,
    clock_timestamp()
FROM retrywise.approvals AS approval
JOIN retrywise.recovery_cases AS recovery_case
  ON recovery_case.merchant_id = approval.merchant_id
 AND recovery_case.id = approval.recovery_case_id
WHERE approval.merchant_id = %(merchant_id)s
  AND approval.id = %(approval_id)s
FOR UPDATE OF approval, recovery_case
"""

_EXISTING_COMMAND = """
SELECT id::text, status::text, command_payload
FROM retrywise.outbox_jobs
WHERE merchant_id = %(merchant_id)s
  AND idempotency_key = %(approval_idempotency_key)s
"""

_INSERT_COMMAND = """
INSERT INTO retrywise.outbox_jobs (
    id, merchant_id, aggregate_type, aggregate_id, command_type,
    command_schema_version, command_payload, idempotency_key, status,
    max_attempts, next_attempt_at, created_at, updated_at
) VALUES (
    %(outbox_job_id)s, %(merchant_id)s, 'APPROVAL', %(approval_id)s,
    %(command_type)s, %(command_schema_version)s, %(command_payload)s::jsonb,
    %(approval_idempotency_key)s, 'PENDING', 8,
    %(acted_at)s, %(acted_at)s, %(acted_at)s
)
RETURNING id::text, status::text
"""

_REJECT_APPROVAL = """
UPDATE retrywise.approvals
SET verdict = 'REJECTED',
    approver_subject = %(operator_subject)s,
    reason_code = %(reason_code)s,
    acted_at = %(acted_at)s
WHERE merchant_id = %(merchant_id)s
  AND id = %(approval_id)s
  AND verdict = 'PENDING'
RETURNING verdict::text
"""

_EXPIRE_APPROVAL = """
UPDATE retrywise.approvals
SET verdict = 'EXPIRED',
    reason_code = 'approval_expired',
    acted_at = %(acted_at)s
WHERE merchant_id = %(merchant_id)s
  AND id = %(approval_id)s
  AND verdict = 'PENDING'
RETURNING verdict::text
"""

_SUPPRESS_CASE = """
UPDATE retrywise.recovery_cases
SET state = 'SUPPRESSED_POLICY',
    version = version + 1,
    terminal_reason_code = %(terminal_reason_code)s,
    terminal_at = %(acted_at)s,
    updated_at = clock_timestamp()
WHERE merchant_id = %(merchant_id)s
  AND id = %(recovery_case_id)s
  AND state = 'APPROVAL_REQUIRED'
  AND version = %(case_version)s
RETURNING version
"""


class ApprovalRequestError(RuntimeError):
    pass


class ApprovalRequestNotFound(ApprovalRequestError):
    pass


class ApprovalRequestConflict(ApprovalRequestError):
    pass


@dataclass(frozen=True, slots=True)
class ApprovalRequestResult:
    approval_id: str
    verdict: str
    recovery_case_id: str
    case_version: int
    outbox_job_id: str | None = None
    command_status: str | None = None


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
            policy.connect(dsn, component="PostgresApprovalRequestService"),
        )

    return connect


def _new_ulid() -> str:
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = ((time.time_ns() // 1_000_000) << 80) | secrets.randbits(80)
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = alphabet[value & 31]
        value >>= 5
    return "".join(characters)


def _ulid(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _ULID_RE.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")
    return value


class PostgresApprovalRequestService:
    """Capture human intent without loading or possessing provider credentials."""

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        audit_appender: TransactionalAuditAppender | None = None,
        id_factory: Callable[[], str] = _new_ulid,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        self._connector = (
            _dsn_factory(dsn, require_tls=require_tls)
            if dsn is not None
            else cast(ConnectionFactory, connector)
        )
        self._audit_appender = audit_appender
        self._id_factory = id_factory

    def act(
        self,
        *,
        merchant_id: str,
        approval_id: str,
        operator_subject: str,
        verdict: str,
        reason_code: str,
        idempotency_key: str,
    ) -> ApprovalRequestResult:
        merchant_id = _ulid(merchant_id, field="merchant_id")
        approval_id = _ulid(approval_id, field="approval_id")
        if verdict not in {"APPROVED", "REJECTED"}:
            raise ValueError("verdict must be APPROVED or REJECTED")
        if _REASON_RE.fullmatch(reason_code) is None:
            raise ValueError("reason_code is invalid")
        if (
            not isinstance(operator_subject, str)
            or not operator_subject
            or len(operator_subject) > 200
        ):
            raise ValueError("operator_subject is invalid")
        if (
            not isinstance(idempotency_key, str)
            or idempotency_key != idempotency_key.strip()
            or not 16 <= len(idempotency_key) <= 128
        ):
            raise ValueError("idempotency_key is invalid")
        idempotency_digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        derived_subject = "operator:" + hashlib.sha256(operator_subject.encode("utf-8")).hexdigest()
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            params: dict[str, object] = {
                "merchant_id": merchant_id,
                "approval_id": approval_id,
            }
            cursor.execute(_LOCK_APPROVAL, params)
            row = cursor.fetchone()
            if row is None:
                raise ApprovalRequestNotFound("approval_not_found")
            if (
                len(row) != 6
                or not isinstance(row[0], str)
                or not isinstance(row[1], str)
                or not isinstance(row[2], datetime)
                or not isinstance(row[3], str)
                or type(row[4]) is not int
                or not isinstance(row[5], datetime)
            ):
                raise ApprovalRequestConflict("approval_snapshot_unsafe")
            current_verdict = row[0]
            recovery_case_id = row[1]
            expires_at = row[2]
            case_state = row[3]
            case_version = row[4]
            acted_at = row[5]
            recovery_case_id = _ulid(recovery_case_id, field="recovery_case_id")
            params.update(
                {
                    "acted_at": acted_at,
                    "case_version": case_version,
                    "operator_subject": derived_subject,
                    "reason_code": reason_code,
                    "recovery_case_id": recovery_case_id,
                }
            )
            if current_verdict != "PENDING":
                if current_verdict == verdict:
                    return ApprovalRequestResult(
                        approval_id,
                        current_verdict,
                        recovery_case_id,
                        case_version,
                    )
                raise ApprovalRequestConflict("approval_already_final")
            if case_state != "APPROVAL_REQUIRED":
                raise ApprovalRequestConflict("approval_case_not_actionable")
            if acted_at >= expires_at:
                cursor.execute(_EXPIRE_APPROVAL, params)
                self._one(cursor.fetchone(), "EXPIRED", "approval_expiry_failed")
                params["terminal_reason_code"] = "approval_expired"
                cursor.execute(_SUPPRESS_CASE, params)
                self._one(cursor.fetchone(), case_version + 1, "approval_case_expiry_failed")
                self._audit(
                    cursor,
                    params=params,
                    verdict="EXPIRED",
                    reason_code="approval_expired",
                )
                return ApprovalRequestResult(
                    approval_id,
                    "EXPIRED",
                    recovery_case_id,
                    case_version + 1,
                )
            if verdict == "REJECTED":
                cursor.execute(
                    _EXISTING_COMMAND,
                    {
                        **params,
                        "approval_idempotency_key": f"materialize-approved-action:{approval_id}",
                    },
                )
                if cursor.fetchone() is not None:
                    raise ApprovalRequestConflict("approval_materialization_already_queued")
                cursor.execute(_REJECT_APPROVAL, params)
                self._one(cursor.fetchone(), "REJECTED", "approval_rejection_failed")
                params["terminal_reason_code"] = reason_code
                cursor.execute(_SUPPRESS_CASE, params)
                self._one(cursor.fetchone(), case_version + 1, "approval_case_rejection_failed")
                self._audit(cursor, params=params, verdict="REJECTED", reason_code=reason_code)
                return ApprovalRequestResult(
                    approval_id,
                    "REJECTED",
                    recovery_case_id,
                    case_version + 1,
                )
            command = MaterializeApprovedActionCommand(
                merchant_id=merchant_id,
                approval_id=approval_id,
                operator_subject=derived_subject,
                reason_code=reason_code,
                request_idempotency_sha256=idempotency_digest,
            )
            command_payload = command.to_primitive()
            idempotency_key = f"materialize-approved-action:{approval_id}"
            params.update(
                {
                    "approval_idempotency_key": idempotency_key,
                    "command_payload": json.dumps(
                        command_payload, sort_keys=True, separators=(",", ":")
                    ),
                    "command_schema_version": MATERIALIZE_APPROVED_ACTION_SCHEMA_VERSION,
                    "command_type": MATERIALIZE_APPROVED_ACTION_COMMAND_TYPE,
                    "outbox_job_id": _ulid(self._id_factory(), field="outbox_job_id"),
                }
            )
            cursor.execute(_EXISTING_COMMAND, params)
            existing = cursor.fetchone()
            if existing is not None:
                if (
                    len(existing) != 3
                    or not isinstance(existing[0], str)
                    or not isinstance(existing[1], str)
                    or existing[2] != command_payload
                ):
                    raise ApprovalRequestConflict("approval_command_conflict")
                return ApprovalRequestResult(
                    approval_id,
                    "APPROVAL_QUEUED",
                    recovery_case_id,
                    case_version,
                    existing[0],
                    existing[1],
                )
            cursor.execute(_INSERT_COMMAND, params)
            inserted = cursor.fetchone()
            if (
                inserted is None
                or len(inserted) != 2
                or not isinstance(inserted[0], str)
                or not isinstance(inserted[1], str)
                or inserted[0] != params["outbox_job_id"]
                or inserted[1] != "PENDING"
            ):
                raise ApprovalRequestConflict("approval_command_insert_failed")
            self._audit(
                cursor,
                params=params,
                verdict="APPROVAL_QUEUED",
                reason_code=reason_code,
            )
            return ApprovalRequestResult(
                approval_id,
                "APPROVAL_QUEUED",
                recovery_case_id,
                case_version,
                inserted[0],
                inserted[1],
            )

    @staticmethod
    def _one(row: Sequence[object] | None, expected: object, operation: str) -> None:
        if row is None or len(row) != 1 or row[0] != expected:
            raise ApprovalRequestConflict(operation)

    def _audit(
        self,
        cursor: _Cursor,
        *,
        params: Mapping[str, object],
        verdict: str,
        reason_code: str,
    ) -> None:
        if self._audit_appender is None:
            return
        self._audit_appender.append(
            cursor=cursor,
            audit_entry_id=_ulid(self._id_factory(), field="audit_entry_id"),
            merchant_id=cast(str, params["merchant_id"]),
            recovery_case_id=cast(str, params["recovery_case_id"]),
            entry_type="APPROVAL_ACTED" if verdict == "REJECTED" else "APPROVAL_REQUESTED",
            actor_type=AuditActorType.OPERATOR,
            actor_subject=cast(str, params["operator_subject"]),
            facts={
                "approval_id": params["approval_id"],
                "approval_verdict": verdict,
                "reason_code": reason_code.upper(),
            },
            created_at=cast(datetime, params["acted_at"]),
        )


__all__ = [
    "ApprovalRequestConflict",
    "ApprovalRequestError",
    "ApprovalRequestNotFound",
    "ApprovalRequestResult",
    "PostgresApprovalRequestService",
]
