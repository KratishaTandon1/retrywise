"""Durable assessment scheduling, command decoding, and worker dispatch."""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol, cast

from .assessment_intent import (
    AssessmentAuthorizationError,
    AssessmentError,
    AssessmentMethodHealthError,
    AssessmentNotEligibleError,
    AssessmentPersistenceError,
    AssessmentProviderTruthError,
    AssessmentResult,
    AssessmentSource,
    AssessmentStateChangedError,
    AssessmentToIntentService,
    AssessRecoveryCaseCommand,
)
from .outbox import RetryMode
from .outbox_worker import HandlerResult
from .postgres_connection import PostgresConnectionPolicy
from .postgres_outbox import ClaimedOutboxCommand

ASSESS_RECOVERY_CASE_COMMAND_TYPE: Final = "ASSESS_RECOVERY_CASE"
ASSESS_RECOVERY_CASE_SCHEMA_VERSION: Final = 1
MAX_ASSESSMENT_COMMAND_BYTES: Final = 4 * 1024

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_MAX_ULID_TIMESTAMP = (1 << 48) - 1
_FIELDS = frozenset(
    {
        "expected_case_version",
        "logical_order_id",
        "merchant_id",
        "payment_record_id",
        "provider_account_id",
        "recovery_case_id",
        "schema_version",
        "source",
    }
)


class AssessmentCommandError(ValueError):
    """An outbox delivery is not the exact assessment command contract."""


def _new_ulid() -> str:
    timestamp_ms = time.time_ns() // 1_000_000
    if not 0 <= timestamp_ms <= _MAX_ULID_TIMESTAMP:
        raise RuntimeError("system clock is outside the ULID timestamp range")
    value = (timestamp_ms << 80) | secrets.randbits(80)
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = _CROCKFORD_BASE32[value & 31]
        value >>= 5
    return "".join(characters)


def encode_assess_recovery_case_command(command: AssessRecoveryCaseCommand) -> dict[str, object]:
    if not isinstance(command, AssessRecoveryCaseCommand):
        raise TypeError("command must be AssessRecoveryCaseCommand")
    return {
        "expected_case_version": command.expected_case_version,
        "logical_order_id": command.logical_order_id,
        "merchant_id": command.merchant_id,
        "payment_record_id": command.payment_record_id,
        "provider_account_id": command.provider_account_id,
        "recovery_case_id": command.recovery_case_id,
        "schema_version": ASSESS_RECOVERY_CASE_SCHEMA_VERSION,
        "source": command.source.value,
    }


def _canonical_payload(payload: Mapping[str, object]) -> bytes:
    try:
        rendered = json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise AssessmentCommandError("assessment payload must contain JSON values") from exc
    if len(rendered) > MAX_ASSESSMENT_COMMAND_BYTES:
        raise AssessmentCommandError("assessment payload exceeds its boundary")
    return rendered


def decode_assess_recovery_case_command(
    claimed: ClaimedOutboxCommand,
) -> AssessRecoveryCaseCommand:
    if not isinstance(claimed, ClaimedOutboxCommand):
        raise TypeError("claimed must be ClaimedOutboxCommand")
    if (
        claimed.command_type != ASSESS_RECOVERY_CASE_COMMAND_TYPE
        or claimed.command_schema_version != ASSESS_RECOVERY_CASE_SCHEMA_VERSION
        or claimed.aggregate_type != "RECOVERY_CASE"
    ):
        raise AssessmentCommandError("unexpected assessment envelope")
    payload = claimed.command_payload
    if not isinstance(payload, Mapping) or set(payload) != _FIELDS:
        raise AssessmentCommandError("assessment payload fields disagree")
    _canonical_payload(payload)
    if payload["schema_version"] != ASSESS_RECOVERY_CASE_SCHEMA_VERSION:
        raise AssessmentCommandError("assessment schema version is invalid")
    try:
        command = AssessRecoveryCaseCommand(
            merchant_id=cast(str, payload["merchant_id"]),
            provider_account_id=cast(str, payload["provider_account_id"]),
            logical_order_id=cast(str, payload["logical_order_id"]),
            payment_record_id=cast(str, payload["payment_record_id"]),
            recovery_case_id=cast(str, payload["recovery_case_id"]),
            expected_case_version=cast(int, payload["expected_case_version"]),
            source=AssessmentSource(cast(str, payload["source"])),
        )
    except (TypeError, ValueError):
        raise AssessmentCommandError("assessment payload is invalid") from None
    if (
        command.merchant_id != claimed.merchant_id
        or command.recovery_case_id != claimed.aggregate_id
        or claimed.idempotency_key
        != f"assess-recovery-case:{command.recovery_case_id}:v{command.expected_case_version}"
    ):
        raise AssessmentCommandError("assessment envelope binding mismatch")
    return command


@dataclass(frozen=True, slots=True)
class AssessmentScheduleResult:
    selected: int
    scheduled: int
    already_scheduled: int


_SELECT_DUE = """
SELECT
    recovery_case.id::text,
    recovery_case.merchant_id::text,
    recovery_case.provider_account_id::text,
    recovery_case.logical_order_id::text,
    recovery_case.version,
    payment.id::text
FROM retrywise.recovery_cases AS recovery_case
JOIN LATERAL (
    SELECT candidate.id
    FROM retrywise.provider_payments AS candidate
    WHERE candidate.merchant_id = recovery_case.merchant_id
      AND candidate.provider_account_id = recovery_case.provider_account_id
      AND candidate.logical_order_id = recovery_case.logical_order_id
      AND candidate.currency = recovery_case.currency
      AND candidate.status = 'FAILED'
    ORDER BY candidate.provider_snapshot_at DESC, candidate.id
    LIMIT 1
) AS payment ON TRUE
WHERE recovery_case.state IN ('OBSERVING', 'WAITING')
  AND recovery_case.observation_contract_version = 1
  AND (
      (recovery_case.state = 'OBSERVING'
       AND recovery_case.observation_deadline_at <= clock_timestamp())
      OR
      (recovery_case.state = 'WAITING'
       AND recovery_case.evaluation_deadline_at <= clock_timestamp())
  )
ORDER BY
    CASE
        WHEN recovery_case.state = 'OBSERVING' THEN recovery_case.observation_deadline_at
        ELSE recovery_case.evaluation_deadline_at
    END,
    recovery_case.id
FOR UPDATE OF recovery_case SKIP LOCKED
LIMIT %(batch_size)s
"""

_INSERT_ASSESSMENT = """
INSERT INTO retrywise.outbox_jobs (
    id,
    merchant_id,
    aggregate_type,
    aggregate_id,
    command_type,
    command_schema_version,
    command_payload,
    idempotency_key,
    status,
    max_attempts,
    next_attempt_at
) VALUES (
    %(outbox_job_id)s,
    %(merchant_id)s,
    'RECOVERY_CASE',
    %(recovery_case_id)s,
    'ASSESS_RECOVERY_CASE',
    1,
    %(command_payload)s::jsonb,
    %(idempotency_key)s,
    'PENDING',
    %(max_attempts)s,
    clock_timestamp()
)
ON CONFLICT (merchant_id, idempotency_key) DO NOTHING
RETURNING id::text
"""


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def fetchall(self) -> Sequence[Sequence[object]]: ...

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
            policy.connect(dsn, component="PostgresAssessmentScheduler"),
        )

    return connect


class PostgresAssessmentScheduler:
    """Materialize due observation deadlines into idempotent outbox commands."""

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        batch_size: int = 50,
        max_attempts: int = 12,
        id_factory: Callable[[], str] = _new_ulid,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if not 1 <= batch_size <= 100 or not 1 <= max_attempts <= 100:
            raise ValueError("scheduler bounds are invalid")
        if not callable(id_factory):
            raise TypeError("id_factory must be callable")
        if dsn is not None:
            self._connector = _dsn_factory(dsn, require_tls=require_tls)
        else:
            if require_tls or not callable(connector):
                raise ValueError("custom connectors cannot attest TLS")
            self._connector = connector
        self._batch_size = batch_size
        self._max_attempts = max_attempts
        self._id_factory = id_factory

    def schedule_due(self) -> AssessmentScheduleResult:
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_SELECT_DUE, {"batch_size": self._batch_size})
            rows = cursor.fetchall()
            scheduled = 0
            for row in rows:
                if len(row) != 6:
                    raise RuntimeError("assessment scheduler row is malformed")
                case_id, merchant_id, account_id, order_id, version, payment_id = row
                if (
                    any(
                        type(value) is not str or not _ULID_RE.fullmatch(value)
                        for value in (
                            case_id,
                            merchant_id,
                            account_id,
                            order_id,
                            payment_id,
                        )
                    )
                    or type(version) is not int
                    or version < 0
                ):
                    raise RuntimeError("assessment scheduler row is unsafe")
                command = AssessRecoveryCaseCommand(
                    merchant_id=cast(str, merchant_id),
                    provider_account_id=cast(str, account_id),
                    logical_order_id=cast(str, order_id),
                    payment_record_id=cast(str, payment_id),
                    recovery_case_id=cast(str, case_id),
                    expected_case_version=version,
                )
                outbox_job_id = self._id_factory()
                if type(outbox_job_id) is not str or not _ULID_RE.fullmatch(outbox_job_id):
                    raise RuntimeError("assessment scheduler id factory is unsafe")
                idempotency_key = f"assess-recovery-case:{case_id}:v{version}"
                cursor.execute(
                    _INSERT_ASSESSMENT,
                    {
                        "outbox_job_id": outbox_job_id,
                        "merchant_id": merchant_id,
                        "recovery_case_id": case_id,
                        "command_payload": _canonical_payload(
                            encode_assess_recovery_case_command(command)
                        ).decode("ascii"),
                        "idempotency_key": idempotency_key,
                        "max_attempts": self._max_attempts,
                    },
                )
                if cursor.fetchone() is not None:
                    scheduled += 1
            return AssessmentScheduleResult(
                selected=len(rows),
                scheduled=scheduled,
                already_scheduled=len(rows) - scheduled,
            )


class AssessmentCompletionProbe(Protocol):
    def already_applied(self, command: AssessRecoveryCaseCommand) -> bool: ...


_ASSESSMENT_ALREADY_APPLIED = """
SELECT EXISTS (
    SELECT 1
    FROM retrywise.recovery_cases
    WHERE id = %(recovery_case_id)s
      AND merchant_id = %(merchant_id)s
      AND provider_account_id = %(provider_account_id)s
      AND logical_order_id = %(logical_order_id)s
      AND version >= %(expected_case_version)s + 2
      AND last_decision_id IS NOT NULL
)
"""


class PostgresAssessmentCompletionProbe:
    def __init__(self, *, connector: ConnectionFactory) -> None:
        if not callable(connector):
            raise TypeError("connector must be callable")
        self._connector = connector

    def already_applied(self, command: AssessRecoveryCaseCommand) -> bool:
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(
                _ASSESSMENT_ALREADY_APPLIED,
                {
                    "recovery_case_id": command.recovery_case_id,
                    "merchant_id": command.merchant_id,
                    "provider_account_id": command.provider_account_id,
                    "logical_order_id": command.logical_order_id,
                    "expected_case_version": command.expected_case_version,
                },
            )
            row = cursor.fetchone()
            return row == (True,)


class AssessRecoveryCaseHandler:
    """Outbox handler for fresh-read assessment and atomic durable intent."""

    def __init__(
        self,
        *,
        service: AssessmentToIntentService,
        completion_probe: AssessmentCompletionProbe,
    ) -> None:
        if not isinstance(service, AssessmentToIntentService):
            raise TypeError("service must be AssessmentToIntentService")
        if not callable(getattr(completion_probe, "already_applied", None)):
            raise TypeError("completion_probe must provide already_applied")
        self._service = service
        self._completion_probe = completion_probe

    def __call__(self, claimed: ClaimedOutboxCommand) -> HandlerResult:
        try:
            command = decode_assess_recovery_case_command(claimed)
        except (AssessmentCommandError, TypeError):
            return HandlerResult.dead_letter("invalid_assessment_command")
        try:
            result = self._service.assess(command)
        except AssessmentAuthorizationError:
            return HandlerResult.retry_safely(
                "assessment_outcome_not_persisted",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        except AssessmentStateChangedError:
            if self._completion_probe.already_applied(command):
                return HandlerResult.succeeded(
                    f"assessment:{command.recovery_case_id}:already-applied"
                )
            return HandlerResult.retry_safely(
                "assessment_state_changed",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        except AssessmentNotEligibleError:
            return HandlerResult.dead_letter("assessment_not_eligible")
        except (AssessmentProviderTruthError, AssessmentMethodHealthError):
            return HandlerResult.retry_safely(
                "assessment_fresh_truth_unavailable",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        except (AssessmentPersistenceError, AssessmentError):
            return HandlerResult.retry_safely(
                "assessment_persistence_failed",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        if not isinstance(result, AssessmentResult):
            return HandlerResult.dead_letter("invalid_assessment_result")
        return HandlerResult.succeeded(
            f"assessment:{result.recovery_case_id}:{result.disposition.value.lower()}"
        )


__all__ = [
    "ASSESS_RECOVERY_CASE_COMMAND_TYPE",
    "ASSESS_RECOVERY_CASE_SCHEMA_VERSION",
    "AssessRecoveryCaseHandler",
    "AssessmentCommandError",
    "AssessmentScheduleResult",
    "PostgresAssessmentCompletionProbe",
    "PostgresAssessmentScheduler",
    "decode_assess_recovery_case_command",
    "encode_assess_recovery_case_command",
]
