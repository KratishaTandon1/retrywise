"""Durable scheduling and execution of protective Payment Link cancellation."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, cast

from ...packages.domain import (
    ActionProposal,
    ActionType,
    CanonicalPaymentState,
    DeterministicGate,
    GateContext,
    GateDecision,
    IncidentState,
    Money,
    ProviderSnapshot,
    RecoveryState,
)
from ...packages.domain.canonical import canonical_json_bytes
from .cancellation import (
    CancellationDisposition,
    CancellationExecutionResult,
    CancellationTarget,
    CancelPaymentLinkCommand,
    CancelPaymentLinkExecutor,
    DurableInstrumentBinding,
    DurableInstrumentStatus,
    PaymentLinkCancellationProvider,
)
from .cancellation_command_codec import (
    CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    EffectCommandCodecError,
    decode_cancel_payment_link_command,
    encode_cancel_payment_link_command,
)
from .outbox import OutboxJob, OutboxState, RetryMode
from .outbox_worker import HandlerResult
from .postgres_audit import AuditActorType, TransactionalAuditAppender
from .postgres_connection import PostgresConnectionPolicy
from .postgres_outbox import ClaimedOutboxCommand

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")

_SELECT_DUE = """
SELECT
    recovery_case.id::text,
    recovery_case.merchant_id::text,
    recovery_case.logical_order_id::text,
    recovery_case.provider_account_id::text,
    recovery_case.state::text,
    recovery_case.version,
    recovery_case.attempt_count,
    instrument.id::text,
    instrument.status::text,
    instrument.provider_payment_link_id,
    instrument.reference_id,
    instrument.amount_minor,
    instrument.currency::text,
    merchant.status::text,
    merchant.kill_switch_enabled,
    account.environment::text,
    account.enabled,
    logical_order.canonical_truth::text,
    COALESCE(payment.payment_method, 'unknown'),
    clock_timestamp()
FROM retrywise.recovery_cases AS recovery_case
JOIN retrywise.recovery_instruments AS instrument
  ON instrument.merchant_id = recovery_case.merchant_id
 AND instrument.recovery_case_id = recovery_case.id
 AND instrument.logical_order_id = recovery_case.logical_order_id
 AND instrument.provider_account_id = recovery_case.provider_account_id
 AND instrument.currency = recovery_case.currency
JOIN retrywise.merchants AS merchant ON merchant.id = recovery_case.merchant_id
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = recovery_case.merchant_id
 AND account.id = recovery_case.provider_account_id
JOIN retrywise.logical_orders AS logical_order
  ON logical_order.merchant_id = recovery_case.merchant_id
 AND logical_order.id = recovery_case.logical_order_id
LEFT JOIN LATERAL (
    SELECT candidate.payment_method
    FROM retrywise.provider_payments AS candidate
    WHERE candidate.merchant_id = recovery_case.merchant_id
      AND candidate.provider_account_id = recovery_case.provider_account_id
      AND candidate.logical_order_id = recovery_case.logical_order_id
    ORDER BY candidate.provider_snapshot_at DESC, candidate.id
    LIMIT 1
) AS payment ON TRUE
WHERE recovery_case.state IN ('SUPPRESSED_PAID', 'DUPLICATE_REVIEW')
  AND merchant.status = 'ACTIVE'
  AND account.environment = 'TEST'
  AND account.enabled = TRUE
  AND instrument.status IN ('UNCERTAIN', 'ISSUED', 'ACTIVE', 'CANCEL_PENDING')
  AND instrument.provider_payment_link_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM retrywise.actions AS action
      WHERE action.merchant_id = recovery_case.merchant_id
        AND action.recovery_case_id = recovery_case.id
        AND action.action_type = 'CANCEL_PAYMENT_LINK'
        AND action.external_reference_id = instrument.provider_payment_link_id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM retrywise.decisions AS decision
      WHERE decision.merchant_id = recovery_case.merchant_id
        AND decision.recovery_case_id = recovery_case.id
        AND decision.aggregate_version = recovery_case.version
  )
ORDER BY recovery_case.updated_at, recovery_case.id
LIMIT %(batch_size)s
FOR UPDATE OF recovery_case, instrument SKIP LOCKED
"""

_INSERT_DECISION = """
INSERT INTO retrywise.decisions (
    id, merchant_id, recovery_case_id, logical_order_id, aggregate_version,
    feature_schema_version, feature_snapshot, feature_snapshot_sha256,
    model_name, model_version, class_probabilities, abstained,
    out_of_distribution, policy_name, policy_version, candidates,
    selected_action, planning_gate_verdict, planning_gate_reason_codes,
    expected_value_inputs, expected_value_minor, source_label, created_at
) VALUES (
    %(decision_id)s, %(merchant_id)s, %(recovery_case_id)s,
    %(logical_order_id)s, %(case_version)s, 1, %(feature_snapshot)s::jsonb,
    %(feature_snapshot_sha256)s, 'terminal-protection', 'v1', '{}'::jsonb,
    FALSE, FALSE, 'retrywise_protective_cancellation', %(policy_version)s,
    %(candidates)s::jsonb, 'CANCEL_PAYMENT_LINK', 'ALLOWED', '{}'::text[],
    '{}'::jsonb, NULL, 'RAZORPAY_TEST_MODE', %(evaluated_at)s
)
RETURNING id::text
"""

_INSERT_ACTION = """
INSERT INTO retrywise.actions (
    id, merchant_id, recovery_case_id, decision_id, aggregate_version,
    action_key, action_type, source_label, status, max_attempts,
    request_metadata, external_reference_id, scheduled_at, created_at, updated_at
) VALUES (
    %(action_id)s, %(merchant_id)s, %(recovery_case_id)s, %(decision_id)s,
    %(case_version)s, %(action_key)s, 'CANCEL_PAYMENT_LINK',
    'RAZORPAY_TEST_MODE', 'PLANNED', 8, %(request_metadata)s::jsonb,
    %(payment_link_id)s, %(evaluated_at)s, %(evaluated_at)s, %(evaluated_at)s
)
RETURNING id::text
"""

_QUEUE_ACTION = """
UPDATE retrywise.actions
SET status = 'QUEUED'
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'PLANNED'
RETURNING status::text
"""

_MARK_CANCEL_PENDING = """
UPDATE retrywise.recovery_instruments
SET status = 'CANCEL_PENDING',
    reconciliation_status = 'PENDING',
    updated_at = clock_timestamp()
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND status IN ('UNCERTAIN', 'ISSUED', 'ACTIVE')
RETURNING status::text
"""

_INSERT_OUTBOX = """
INSERT INTO retrywise.outbox_jobs (
    id, merchant_id, aggregate_type, aggregate_id, command_type,
    command_schema_version, command_payload, idempotency_key, status,
    max_attempts, next_attempt_at, created_at, updated_at
) VALUES (
    %(outbox_job_id)s, %(merchant_id)s, 'ACTION', %(action_id)s,
    'CANCEL_PAYMENT_LINK', %(command_schema_version)s,
    %(command_payload)s::jsonb, %(idempotency_key)s, 'PENDING', 12,
    %(evaluated_at)s, %(evaluated_at)s, %(evaluated_at)s
)
RETURNING id::text
"""

_LOAD_BINDING = """
SELECT
    action.request_metadata,
    action.created_at,
    action.status::text,
    instrument.status::text,
    instrument.reference_id,
    instrument.amount_minor,
    instrument.currency::text,
    instrument.provider_payment_link_id
FROM retrywise.actions AS action
JOIN retrywise.recovery_cases AS recovery_case
  ON recovery_case.merchant_id = action.merchant_id
 AND recovery_case.id = action.recovery_case_id
JOIN retrywise.recovery_instruments AS instrument
  ON instrument.merchant_id = recovery_case.merchant_id
 AND instrument.recovery_case_id = recovery_case.id
WHERE action.merchant_id = %(merchant_id)s
  AND action.recovery_case_id = %(case_id)s
  AND action.id = %(action_id)s
  AND action.action_key = %(action_key)s
  AND action.action_type = 'CANCEL_PAYMENT_LINK'
  AND recovery_case.provider_account_id = %(provider_account_id)s
  AND instrument.id = %(instrument_id)s
  AND instrument.provider_payment_link_id = %(payment_link_id)s
"""

_LOAD_CONTEXT = """
SELECT
    recovery_case.state::text,
    recovery_case.version,
    recovery_case.amount_due_snapshot_minor,
    recovery_case.currency::text,
    recovery_case.observation_deadline_at,
    recovery_case.attempt_count,
    recovery_case.contact_count,
    merchant.status::text,
    merchant.kill_switch_enabled,
    account.environment::text,
    account.enabled,
    logical_order.canonical_truth::text,
    COALESCE(payment.payment_method, 'unknown'),
    (
        SELECT count(*)
        FROM retrywise.recovery_instruments AS active
        WHERE active.merchant_id = recovery_case.merchant_id
          AND active.logical_order_id = recovery_case.logical_order_id
          AND active.currency = recovery_case.currency
          AND active.status IN (
              'CREATING', 'UNCERTAIN', 'ISSUED', 'ACTIVE', 'CANCEL_PENDING'
          )
    )
FROM retrywise.recovery_cases AS recovery_case
JOIN retrywise.merchants AS merchant ON merchant.id = recovery_case.merchant_id
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = recovery_case.merchant_id
 AND account.id = recovery_case.provider_account_id
JOIN retrywise.logical_orders AS logical_order
  ON logical_order.merchant_id = recovery_case.merchant_id
 AND logical_order.id = recovery_case.logical_order_id
LEFT JOIN LATERAL (
    SELECT candidate.payment_method
    FROM retrywise.provider_payments AS candidate
    WHERE candidate.merchant_id = recovery_case.merchant_id
      AND candidate.logical_order_id = recovery_case.logical_order_id
    ORDER BY candidate.provider_snapshot_at DESC, candidate.id
    LIMIT 1
) AS payment ON TRUE
WHERE recovery_case.merchant_id = %(merchant_id)s
  AND recovery_case.id = %(case_id)s
  AND recovery_case.provider_account_id = %(provider_account_id)s
"""

_LOCK_FENCE = """
SELECT TRUE
FROM retrywise.outbox_jobs
WHERE id = %(job_id)s
  AND merchant_id = %(merchant_id)s
  AND aggregate_type = 'ACTION'
  AND aggregate_id = %(action_id)s
  AND command_type = 'CANCEL_PAYMENT_LINK'
  AND status = 'IN_PROGRESS'
  AND delivery_version = %(delivery_version)s
  AND lease_owner = %(worker_id)s
  AND lease_token = %(lease_token)s
  AND lease_expires_at > clock_timestamp()
FOR UPDATE
"""

_LOCK_ACTION_INSTRUMENT = """
SELECT action.status::text, instrument.status::text
FROM retrywise.actions AS action
JOIN retrywise.recovery_instruments AS instrument
  ON instrument.merchant_id = action.merchant_id
 AND instrument.recovery_case_id = action.recovery_case_id
WHERE action.id = %(action_id)s
  AND action.merchant_id = %(merchant_id)s
  AND action.action_key = %(action_key)s
  AND instrument.id = %(instrument_id)s
  AND instrument.provider_payment_link_id = %(payment_link_id)s
FOR UPDATE OF action, instrument
"""

_AUTHORIZE = """
UPDATE retrywise.actions
SET status = 'EXECUTING',
    attempt_number = attempt_number + 1,
    lease_owner = %(worker_id)s,
    lease_expires_at = %(lease_expires_at)s,
    effect_gate_snapshot = %(gate_snapshot)s::jsonb,
    effect_gate_verdict = 'ALLOWED',
    effect_gate_reason_codes = '{}'::text[],
    first_attempted_at = COALESCE(first_attempted_at, %(evaluated_at)s),
    last_attempted_at = %(evaluated_at)s
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'QUEUED'
RETURNING status::text
"""

_ACTION_TO_RECONCILING = """
UPDATE retrywise.actions
SET status = 'RECONCILING',
    lease_owner = %(worker_id)s,
    lease_expires_at = %(lease_expires_at)s,
    last_attempted_at = %(completed_at)s
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'UNCERTAIN'
RETURNING status::text
"""

_COMPLETE_ACTION = """
UPDATE retrywise.actions
SET status = %(new_status)s::retrywise.action_status,
    lease_owner = NULL,
    lease_expires_at = NULL,
    response_metadata = %(response_metadata)s::jsonb,
    provider_status = %(provider_status)s,
    reconciliation_status = 'CONFIRMED',
    provider_resource_id = %(payment_link_id)s,
    completed_at = %(completed_at)s,
    last_error_code = NULL
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = %(expected_status)s::retrywise.action_status
RETURNING status::text
"""

_CANCEL_QUEUED_ACTION = """
UPDATE retrywise.actions
SET status = 'CANCELLED',
    lease_owner = NULL,
    lease_expires_at = NULL,
    response_metadata = %(response_metadata)s::jsonb,
    provider_status = %(provider_status)s,
    reconciliation_status = 'CONFIRMED',
    provider_resource_id = %(payment_link_id)s,
    completed_at = %(completed_at)s,
    last_error_code = NULL
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'QUEUED'
RETURNING status::text
"""

_COMPLETE_INSTRUMENT = """
UPDATE retrywise.recovery_instruments
SET status = %(instrument_status)s::retrywise.recovery_instrument_status,
    last_provider_status = %(provider_status)s,
    reconciliation_status = 'CONFIRMED',
    last_reconciled_at = %(completed_at)s,
    updated_at = clock_timestamp()
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND status IN ('UNCERTAIN', 'ISSUED', 'ACTIVE', 'CANCEL_PENDING')
RETURNING status::text
"""

_MARK_ACTION_UNCERTAIN = """
UPDATE retrywise.actions
SET status = 'UNCERTAIN',
    lease_owner = NULL,
    lease_expires_at = NULL,
    reconciliation_status = 'PENDING',
    last_error_code = %(reason_code)s
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'EXECUTING'
RETURNING status::text
"""

_QUEUE_RECONCILING_ACTION = """
UPDATE retrywise.actions
SET status = 'QUEUED',
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error_code = %(reason_code)s
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'RECONCILING'
RETURNING status::text
"""

_FAIL_ACTION = """
UPDATE retrywise.actions
SET status = CASE
        WHEN status = 'EXECUTING' THEN 'FAILED_SAFE'::retrywise.action_status
        ELSE 'DEAD_LETTER'::retrywise.action_status
    END,
    lease_owner = NULL,
    lease_expires_at = NULL,
    completed_at = %(completed_at)s,
    last_error_code = %(reason_code)s,
    dead_lettered_at = CASE WHEN status <> 'EXECUTING' THEN %(completed_at)s END,
    dead_letter_reason = CASE WHEN status <> 'EXECUTING' THEN %(reason_code)s END
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status IN ('QUEUED', 'EXECUTING', 'UNCERTAIN', 'RECONCILING')
RETURNING status::text
"""

_RESTORE_INSTRUMENT = """
UPDATE retrywise.recovery_instruments
SET status = 'ACTIVE',
    reconciliation_status = 'CONFLICT',
    last_reconciled_at = %(completed_at)s,
    updated_at = clock_timestamp()
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'CANCEL_PENDING'
RETURNING status::text
"""

_MARK_DUPLICATE_REVIEW = """
UPDATE retrywise.recovery_cases
SET state = 'DUPLICATE_REVIEW',
    version = version + 1,
    terminal_reason_code = %(reason_code)s,
    terminal_at = %(completed_at)s,
    updated_at = clock_timestamp()
WHERE id = %(case_id)s
  AND merchant_id = %(merchant_id)s
  AND state <> 'DUPLICATE_REVIEW'
RETURNING state::text
"""


class CancellationPersistenceError(RuntimeError):
    pass


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


class CancellationAdapter(PaymentLinkCancellationProvider, Protocol):
    def close(self) -> None: ...


CancellationAdapterFactory = Callable[[str, str], CancellationAdapter]


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresCancellationWorker"),
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


def _ulid(value: object) -> str:
    if type(value) is not str or not _ULID_RE.fullmatch(value):
        raise CancellationPersistenceError("cancellation_identifier_invalid")
    return value


def _one(row: Sequence[object] | None, expected: object, operation: str) -> None:
    if row is None or len(row) != 1 or row[0] != expected:
        raise CancellationPersistenceError(operation)


def _job(claimed: ClaimedOutboxCommand, command: CancelPaymentLinkCommand) -> OutboxJob:
    return OutboxJob(
        job_id=claimed.job_id,
        action_key=command.proposal.action_key,
        payload_digest=command.payload_digest,
        state=OutboxState.LEASED,
        version=claimed.delivery_version,
        attempts=claimed.attempt_count,
        max_attempts=claimed.max_attempts,
        created_at=claimed.created_at,
        updated_at=claimed.claimed_at,
        available_at=None,
        retry_mode=claimed.retry_mode,
        lease_owner=claimed.worker_id,
        lease_token=claimed.lease_token,
        lease_expires_at=claimed.lease_expires_at,
    )


@dataclass(frozen=True, slots=True)
class CancellationScheduleResult:
    selected: int
    scheduled: int


class PostgresCancellationScheduler:
    """Continuously repairs terminal cases that still have a collectible link."""

    def __init__(
        self,
        *,
        gate: DeterministicGate,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        batch_size: int = 25,
        id_factory: Callable[[], str] = _new_ulid,
        audit_appender: TransactionalAuditAppender | None = None,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if not 1 <= batch_size <= 100:
            raise ValueError("batch_size is invalid")
        self._connector = (
            _dsn_factory(dsn, require_tls=require_tls)
            if dsn is not None
            else cast(ConnectionFactory, connector)
        )
        self._gate = gate
        self._batch_size = batch_size
        self._id_factory = id_factory
        self._audit_appender = audit_appender

    def schedule_due(self) -> CancellationScheduleResult:
        scheduled = 0
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_SELECT_DUE, {"batch_size": self._batch_size})
            rows = cursor.fetchall()
            for row in rows:
                self._schedule(cursor, row)
                scheduled += 1
        return CancellationScheduleResult(len(rows), scheduled)

    def _schedule(self, cursor: _Cursor, row: Sequence[object]) -> None:
        if len(row) != 20:
            raise CancellationPersistenceError("cancellation_schedule_row_unsafe")
        (
            case_id,
            merchant_id,
            order_id,
            account_id,
            case_state,
            case_version,
            attempt_count,
            instrument_id,
            instrument_status,
            payment_link_id,
            reference_id,
            amount_minor,
            currency,
            merchant_status,
            merchant_kill_switch,
            account_environment,
            account_enabled,
            canonical_truth,
            payment_method,
            evaluated_at,
        ) = row
        case_id = _ulid(case_id)
        merchant_id = _ulid(merchant_id)
        order_id = _ulid(order_id)
        account_id = _ulid(account_id)
        instrument_id = _ulid(instrument_id)
        if (
            type(case_version) is not int
            or case_version < 1
            or type(attempt_count) is not int
            or type(amount_minor) is not int
            or not isinstance(evaluated_at, datetime)
            or not isinstance(payment_link_id, str)
            or not isinstance(reference_id, str)
            or not isinstance(currency, str)
            or not isinstance(payment_method, str)
        ):
            raise CancellationPersistenceError("cancellation_schedule_row_unsafe")
        proposal = ActionProposal(
            proposal_id=f"proposal:cancel:{case_id}:{case_version}",
            merchant_id=merchant_id,
            case_id=case_id,
            decision_version=case_version,
            action_type=ActionType.CANCEL_PAYMENT_LINK,
            created_at=evaluated_at,
            expires_at=evaluated_at + timedelta(minutes=5),
            attempt_ordinal=attempt_count + 1,
            instrument_reference=payment_link_id,
        )
        decision = self._gate.evaluate_policy(
            proposal,
            GateContext(
                merchant_id=merchant_id,
                case_id=case_id,
                evaluated_at=evaluated_at,
                aggregate_version=case_version,
                expected_aggregate_version=case_version,
                recovery_state=RecoveryState(cast(str, case_state).lower()),
                snapshot=ProviderSnapshot(
                    payment_state=CanonicalPaymentState(cast(str, canonical_truth).lower()),
                    amount_due=Money(amount_minor, currency),
                    payment_method=payment_method,
                    observed_at=evaluated_at,
                    active_instrument_count=1,
                    incident_state=IncidentState.NORMAL,
                    method_health_observed_at=evaluated_at,
                ),
                environment_effects_enabled=(
                    merchant_status == "ACTIVE"
                    and account_environment == "TEST"
                    and account_enabled is True
                ),
                global_kill_switch=True,
                merchant_kill_switch=cast(bool, merchant_kill_switch),
            ),
        )
        if not decision.allowed:
            raise CancellationPersistenceError("protective_cancellation_not_authorized")
        action_id, decision_id, outbox_job_id = (
            _ulid(self._id_factory()),
            _ulid(self._id_factory()),
            _ulid(self._id_factory()),
        )
        target = CancellationTarget(
            merchant_id=merchant_id,
            case_id=case_id,
            action_id=action_id,
            action_key=proposal.action_key,
            instrument_id=instrument_id,
            provider_account_id=account_id,
            payment_link_id=payment_link_id,
            reference_id=reference_id,
            amount_minor=amount_minor,
            currency=currency,
        )
        command = CancelPaymentLinkCommand(proposal=proposal, prior_plan=decision, target=target)
        feature_snapshot = {
            "canonical_truth": canonical_truth,
            "instrument_id": instrument_id,
            "instrument_status": instrument_status,
            "reason_code": "terminal_case_has_collectible_link",
        }
        params: dict[str, object] = {
            "merchant_id": merchant_id,
            "recovery_case_id": case_id,
            "logical_order_id": order_id,
            "provider_account_id": account_id,
            "case_version": case_version,
            "instrument_id": instrument_id,
            "payment_link_id": payment_link_id,
            "decision_id": decision_id,
            "action_id": action_id,
            "outbox_job_id": outbox_job_id,
            "action_key": proposal.action_key,
            "policy_version": decision.policy_version,
            "evaluated_at": evaluated_at,
            "feature_snapshot": json.dumps(feature_snapshot, sort_keys=True, separators=(",", ":")),
            "feature_snapshot_sha256": hashlib.sha256(
                canonical_json_bytes(feature_snapshot)
            ).digest(),
            "candidates": json.dumps(
                [proposal.to_primitive()], sort_keys=True, separators=(",", ":")
            ),
            "request_metadata": json.dumps(
                {
                    "recorded_at": evaluated_at.isoformat().replace("+00:00", "Z"),
                    "schema": "retrywise-durable-cancellation-binding",
                    "schema_version": 1,
                    "target_sha256": target.target_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            "command_schema_version": CANCEL_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
            "command_payload": json.dumps(
                encode_cancel_payment_link_command(command),
                sort_keys=True,
                separators=(",", ":"),
            ),
            "idempotency_key": f"cancel-payment-link:{proposal.action_key}",
        }
        cursor.execute(_INSERT_DECISION, params)
        _one(cursor.fetchone(), decision_id, "cancellation_decision_insert_failed")
        cursor.execute(_INSERT_ACTION, params)
        _one(cursor.fetchone(), action_id, "cancellation_action_insert_failed")
        cursor.execute(_QUEUE_ACTION, params)
        _one(cursor.fetchone(), "QUEUED", "cancellation_action_queue_failed")
        if instrument_status != "CANCEL_PENDING":
            cursor.execute(_MARK_CANCEL_PENDING, params)
            _one(cursor.fetchone(), "CANCEL_PENDING", "instrument_cancel_pending_failed")
        cursor.execute(_INSERT_OUTBOX, params)
        _one(cursor.fetchone(), outbox_job_id, "cancellation_outbox_insert_failed")
        if self._audit_appender is not None:
            self._audit_appender.append(
                cursor=cursor,
                audit_entry_id=_ulid(self._id_factory()),
                merchant_id=merchant_id,
                recovery_case_id=case_id,
                entry_type="CANCELLATION_SCHEDULED",
                actor_type=AuditActorType.WORKER,
                actor_subject=(
                    "worker:" + hashlib.sha256(b"retrywise-cancellation-scheduler").hexdigest()
                ),
                facts={"action_id": action_id, "instrument_id": instrument_id},
                created_at=evaluated_at,
            )


class PostgresCancellationRepository:
    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        global_kill_switch: bool = False,
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
        self._global_kill_switch = global_kill_switch
        self._audit_appender = audit_appender
        self._id_factory = id_factory

    def load_cancellation_binding(self, **values: str) -> DurableInstrumentBinding | None:
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(_LOAD_BINDING, values)
            row = cursor.fetchone()
        if row is None:
            return None
        if (
            len(row) != 8
            or not isinstance(row[0], Mapping)
            or not isinstance(row[1], datetime)
            or not isinstance(row[2], str)
            or not isinstance(row[3], str)
            or not isinstance(row[4], str)
            or type(row[5]) is not int
            or not isinstance(row[6], str)
            or not isinstance(row[7], str)
        ):
            raise CancellationPersistenceError("cancellation_binding_unsafe")
        metadata = row[0]
        if (
            set(metadata) != {"recorded_at", "schema", "schema_version", "target_sha256"}
            or metadata["schema"] != "retrywise-durable-cancellation-binding"
            or metadata["schema_version"] != 1
            or metadata["target_sha256"] != values["target_digest"]
        ):
            raise CancellationPersistenceError("cancellation_binding_unsafe")
        target = CancellationTarget(
            merchant_id=values["merchant_id"],
            case_id=values["case_id"],
            action_id=values["action_id"],
            action_key=values["action_key"],
            instrument_id=values["instrument_id"],
            provider_account_id=values["provider_account_id"],
            payment_link_id=values["payment_link_id"],
            reference_id=row[4],
            amount_minor=row[5],
            currency=row[6],
        )
        if row[7] != target.payment_link_id or target.target_digest != values["target_digest"]:
            raise CancellationPersistenceError("cancellation_binding_mismatch")
        return DurableInstrumentBinding(
            target=target,
            persisted_target_digest=values["target_digest"],
            instrument_status=DurableInstrumentStatus(row[3]),
            recorded_at=row[1],
        )

    def load_fresh_gate_context(
        self,
        *,
        proposal: ActionProposal,
        provider_account_id: str,
        evaluated_at: datetime,
    ) -> GateContext:
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(
                _LOAD_CONTEXT,
                {
                    "merchant_id": proposal.merchant_id,
                    "case_id": proposal.case_id,
                    "provider_account_id": provider_account_id,
                },
            )
            row = cursor.fetchone()
        if row is None or len(row) != 14:
            raise CancellationPersistenceError("cancellation_context_unavailable")
        return GateContext(
            merchant_id=proposal.merchant_id,
            case_id=proposal.case_id,
            evaluated_at=evaluated_at,
            aggregate_version=cast(int, row[1]),
            expected_aggregate_version=cast(int, row[1]),
            recovery_state=RecoveryState(cast(str, row[0]).lower()),
            snapshot=ProviderSnapshot(
                payment_state=CanonicalPaymentState(cast(str, row[11]).lower()),
                amount_due=Money(cast(int, row[2]), cast(str, row[3])),
                payment_method=cast(str, row[12]),
                observed_at=evaluated_at,
                active_instrument_count=cast(int, row[13]),
                incident_state=IncidentState.NORMAL,
                method_health_observed_at=evaluated_at,
            ),
            environment_effects_enabled=(
                row[7] == "ACTIVE" and row[9] == "TEST" and row[10] is True
            ),
            observation_deadline=cast(datetime | None, row[4]),
            global_kill_switch=self._global_kill_switch,
            merchant_kill_switch=cast(bool, row[8]),
            contacts_in_window=cast(int, row[6]),
            attempts_used=cast(int, row[5]),
        )

    def record_cancellation_authorization(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        decision: GateDecision,
        context: GateContext,
        worker_id: str,
    ) -> None:
        params = self._params(job, command, completed_at=decision.evaluated_at)
        params.update(
            {
                "worker_id": worker_id,
                "lease_expires_at": job.lease_expires_at,
                "evaluated_at": decision.evaluated_at,
                "gate_snapshot": json.dumps(
                    decision.to_primitive(), sort_keys=True, separators=(",", ":")
                ),
            }
        )
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            self._lock(cursor, params)
            cursor.execute(_AUTHORIZE, params)
            _one(cursor.fetchone(), "EXECUTING", "cancellation_authorization_failed")
            self._audit(
                cursor,
                command,
                entry_type="CANCELLATION_AUTHORIZED",
                facts={"decision_digest": decision.decision_digest},
                created_at=decision.evaluated_at,
            )

    def persist_result(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        result: CancellationExecutionResult,
        completed_at: datetime,
    ) -> None:
        params = self._params(job, command, completed_at=completed_at)
        params.update(
            {
                "reason_code": result.reason_code[:500],
                "provider_status": (
                    None if result.provider_status is None else result.provider_status.value
                ),
                "response_metadata": json.dumps(
                    {
                        "cancel_attempted": result.cancel_attempted,
                        "disposition": result.disposition.value,
                        "reason_code": result.reason_code,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
        )
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            action_status, instrument_status = self._lock(cursor, params)
            if result.disposition in {
                CancellationDisposition.CANCELLED,
                CancellationDisposition.ALREADY_CANCELLED,
                CancellationDisposition.EXPIRED,
            }:
                expected = action_status
                if action_status == "QUEUED":
                    cursor.execute(_CANCEL_QUEUED_ACTION, params)
                    _one(cursor.fetchone(), "CANCELLED", "cancel_action_completion_failed")
                    expected = "CANCELLED"
                elif action_status == "UNCERTAIN":
                    params.update(
                        {
                            "worker_id": job.lease_owner or "",
                            "lease_expires_at": job.lease_expires_at,
                        }
                    )
                    cursor.execute(_ACTION_TO_RECONCILING, params)
                    _one(cursor.fetchone(), "RECONCILING", "cancel_reconciliation_start_failed")
                    expected = "RECONCILING"
                if expected != "CANCELLED":
                    params.update(
                        {
                            "expected_status": expected,
                            "new_status": (
                                "SUCCEEDED" if expected == "EXECUTING" else "RECONCILED"
                            ),
                        }
                    )
                    cursor.execute(_COMPLETE_ACTION, params)
                    _one(
                        cursor.fetchone(),
                        params["new_status"],
                        "cancel_action_completion_failed",
                    )
                params["instrument_status"] = (
                    "EXPIRED"
                    if result.disposition is CancellationDisposition.EXPIRED
                    else "CANCELLED"
                )
                if instrument_status != params["instrument_status"]:
                    cursor.execute(_COMPLETE_INSTRUMENT, params)
                    _one(
                        cursor.fetchone(),
                        params["instrument_status"],
                        "cancel_instrument_completion_failed",
                    )
            elif result.disposition is CancellationDisposition.RECONCILE_REQUIRED:
                if result.cancel_attempted and action_status == "EXECUTING":
                    cursor.execute(_MARK_ACTION_UNCERTAIN, params)
                    _one(cursor.fetchone(), "UNCERTAIN", "cancel_action_uncertain_failed")
                elif not result.cancel_attempted and action_status == "UNCERTAIN":
                    params.update(
                        {
                            "worker_id": job.lease_owner or "",
                            "lease_expires_at": job.lease_expires_at,
                        }
                    )
                    cursor.execute(_ACTION_TO_RECONCILING, params)
                    _one(cursor.fetchone(), "RECONCILING", "cancel_reconciliation_start_failed")
                    cursor.execute(_QUEUE_RECONCILING_ACTION, params)
                    _one(cursor.fetchone(), "QUEUED", "cancel_action_requeue_failed")
            else:
                cursor.execute(_FAIL_ACTION, params)
                if cursor.fetchone() is None:
                    raise CancellationPersistenceError("cancel_action_failure_failed")
                if result.disposition is CancellationDisposition.REVIEW_REQUIRED:
                    cursor.execute(_MARK_DUPLICATE_REVIEW, params)
                    cursor.fetchone()  # An already-DUPLICATE_REVIEW case needs no mutation.
                elif instrument_status == "CANCEL_PENDING":
                    cursor.execute(_RESTORE_INSTRUMENT, params)
                    _one(cursor.fetchone(), "ACTIVE", "cancel_instrument_restore_failed")
            self._audit(
                cursor,
                command,
                entry_type="CANCELLATION_RESULT_COMMITTED",
                facts={
                    "cancel_attempted": result.cancel_attempted,
                    "disposition": result.disposition.value,
                },
                created_at=completed_at,
            )

    def _params(
        self,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        *,
        completed_at: datetime,
    ) -> dict[str, object]:
        target = command.target
        return {
            "job_id": job.job_id,
            "merchant_id": target.merchant_id,
            "case_id": target.case_id,
            "action_id": target.action_id,
            "action_key": target.action_key,
            "instrument_id": target.instrument_id,
            "payment_link_id": target.payment_link_id,
            "delivery_version": job.version,
            "worker_id": job.lease_owner or "",
            "lease_token": job.lease_token or "",
            "completed_at": completed_at,
        }

    def _lock(self, cursor: _Cursor, params: Mapping[str, object]) -> tuple[str, str]:
        cursor.execute(_LOCK_FENCE, params)
        _one(cursor.fetchone(), True, "cancellation_fence_lost")
        cursor.execute(_LOCK_ACTION_INSTRUMENT, params)
        row = cursor.fetchone()
        if row is None or len(row) != 2 or not all(isinstance(value, str) for value in row):
            raise CancellationPersistenceError("cancellation_path_missing")
        return cast(str, row[0]), cast(str, row[1])

    def _audit(
        self,
        cursor: _Cursor,
        command: CancelPaymentLinkCommand,
        *,
        entry_type: str,
        facts: Mapping[str, object],
        created_at: datetime,
    ) -> None:
        if self._audit_appender is None:
            return
        self._audit_appender.append(
            cursor=cursor,
            audit_entry_id=_ulid(self._id_factory()),
            merchant_id=command.target.merchant_id,
            recovery_case_id=command.target.case_id,
            entry_type=entry_type,
            actor_type=AuditActorType.WORKER,
            actor_subject=(
                "worker:" + hashlib.sha256(b"retrywise-cancellation-worker").hexdigest()
            ),
            facts=facts,
            created_at=created_at,
        )


class CancelPaymentLinkHandler:
    def __init__(
        self,
        *,
        gate: DeterministicGate,
        repository: PostgresCancellationRepository,
        adapter_factory: CancellationAdapterFactory,
        clock: Callable[[], datetime],
    ) -> None:
        self._gate = gate
        self._repository = repository
        self._adapter_factory = adapter_factory
        self._clock = clock

    def __call__(self, claimed: ClaimedOutboxCommand) -> HandlerResult:
        try:
            command = decode_cancel_payment_link_command(
                claimed.command_payload,
                command_type=claimed.command_type,
                command_schema_version=claimed.command_schema_version,
            )
        except (EffectCommandCodecError, TypeError, ValueError):
            return HandlerResult.dead_letter("invalid_cancel_payment_link_command")
        if (
            claimed.aggregate_type != "ACTION"
            or claimed.aggregate_id != command.target.action_id
            or claimed.merchant_id != command.target.merchant_id
            or claimed.idempotency_key != f"cancel-payment-link:{command.proposal.action_key}"
        ):
            return HandlerResult.dead_letter("invalid_cancel_payment_link_command")
        adapter: CancellationAdapter | None = None
        try:
            adapter = self._adapter_factory(
                command.target.merchant_id,
                command.target.provider_account_id,
            )
            job = _job(claimed, command)
            result = CancelPaymentLinkExecutor(
                gate=self._gate,
                bindings=self._repository,
                contexts=self._repository,
                provider=adapter,
                clock=self._clock,
                authorization_recorder=self._repository,
            ).execute(job=job, command=command, worker_id=claimed.worker_id)
            self._repository.persist_result(
                job=job,
                command=command,
                result=result,
                completed_at=self._clock(),
            )
        except CancellationPersistenceError:
            return HandlerResult.retry_safely(
                "cancellation_persistence_unavailable",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        except Exception:
            return HandlerResult.retry_safely(
                "cancellation_execution_unavailable",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        finally:
            if adapter is not None:
                with suppress(Exception):
                    adapter.close()
        if result.disposition in {
            CancellationDisposition.CANCELLED,
            CancellationDisposition.ALREADY_CANCELLED,
            CancellationDisposition.EXPIRED,
        }:
            return HandlerResult.succeeded(f"{result.disposition.value}:{result.payment_link_id}")
        if result.disposition is CancellationDisposition.RECONCILE_REQUIRED:
            return HandlerResult.retry_safely(
                result.reason_code,
                retry_mode=result.job.retry_mode,
            )
        return HandlerResult.dead_letter(result.reason_code)


__all__ = [
    "CancelPaymentLinkHandler",
    "CancellationAdapter",
    "CancellationAdapterFactory",
    "CancellationPersistenceError",
    "CancellationScheduleResult",
    "PostgresCancellationRepository",
    "PostgresCancellationScheduler",
]
