"""Tenant-bound human approval that materializes an effect only after fresh reads."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast

from ...packages.domain import (
    Approval,
    DeterministicGate,
    GateContext,
    Money,
    ProviderSnapshot,
    RecoveryState,
)
from ...packages.razorpay import StandardPaymentLinkRequest, make_recovery_reference_id
from .assessment_intent import (
    FreshMethodHealthReader,
    FreshProviderTruthReader,
    MethodHealthQuery,
    ProviderTruthQuery,
)
from .effect_command_codec import (
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
    decode_action_proposal,
    encode_create_standard_payment_link_command,
)
from .executor import CreatePaymentLinkCommand, DurableActionIntent
from .postgres_audit import AuditActorType, TransactionalAuditAppender
from .postgres_connection import PostgresConnectionPolicy

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,99}$")

_LOAD_PENDING = """
SELECT
    approval.id::text,
    approval.decision_id::text,
    approval.aggregate_version,
    approval.requested_at,
    approval.expires_at,
    decision.candidates,
    decision.policy_version,
    recovery_case.id::text,
    recovery_case.logical_order_id::text,
    recovery_case.provider_account_id::text,
    recovery_case.currency::text,
    recovery_case.amount_due_snapshot_minor,
    recovery_case.state::text,
    recovery_case.version,
    recovery_case.observation_deadline_at,
    recovery_case.attempt_count,
    recovery_case.contact_count,
    recovery_case.incident_id::text,
    merchant.status::text,
    merchant.kill_switch_enabled,
    account.provider_account_identifier,
    account.environment::text,
    account.enabled,
    account.credential_binding_version,
    logical_order.canonical_truth::text,
    payment.id::text,
    payment.provider_payment_id,
    payment.provider_order_id,
    payment.payment_method,
    (
        SELECT count(*)
        FROM retrywise.recovery_instruments AS instrument
        WHERE instrument.merchant_id = recovery_case.merchant_id
          AND instrument.logical_order_id = recovery_case.logical_order_id
          AND instrument.currency = recovery_case.currency
          AND instrument.status IN (
              'CREATING', 'UNCERTAIN', 'ISSUED', 'ACTIVE', 'CANCEL_PENDING'
          )
    ),
    clock_timestamp()
FROM retrywise.approvals AS approval
JOIN retrywise.decisions AS decision
  ON decision.merchant_id = approval.merchant_id
 AND decision.id = approval.decision_id
 AND decision.recovery_case_id = approval.recovery_case_id
 AND decision.aggregate_version = approval.aggregate_version
JOIN retrywise.recovery_cases AS recovery_case
  ON recovery_case.merchant_id = approval.merchant_id
 AND recovery_case.id = approval.recovery_case_id
JOIN retrywise.merchants AS merchant ON merchant.id = approval.merchant_id
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = recovery_case.merchant_id
 AND account.id = recovery_case.provider_account_id
JOIN retrywise.logical_orders AS logical_order
  ON logical_order.merchant_id = recovery_case.merchant_id
 AND logical_order.id = recovery_case.logical_order_id
 AND logical_order.provider_account_id = recovery_case.provider_account_id
 AND logical_order.currency = recovery_case.currency
JOIN LATERAL (
    SELECT candidate.*
    FROM retrywise.provider_payments AS candidate
    WHERE candidate.merchant_id = recovery_case.merchant_id
      AND candidate.provider_account_id = recovery_case.provider_account_id
      AND candidate.logical_order_id = recovery_case.logical_order_id
      AND candidate.currency = recovery_case.currency
    ORDER BY candidate.provider_snapshot_at DESC, candidate.id
    LIMIT 1
) AS payment ON TRUE
WHERE approval.merchant_id = %(merchant_id)s
  AND approval.id = %(approval_id)s
  AND approval.verdict = 'PENDING'
  AND recovery_case.state = 'APPROVAL_REQUIRED'
"""

_LOCK_PENDING = _LOAD_PENDING + "\nFOR UPDATE OF approval, recovery_case\n"

_APPROVE = """
UPDATE retrywise.approvals
SET verdict = 'APPROVED',
    approver_subject = %(operator_subject)s,
    reason_code = %(reason_code)s,
    acted_at = %(acted_at)s
WHERE id = %(approval_id)s
  AND merchant_id = %(merchant_id)s
  AND verdict = 'PENDING'
  AND %(acted_at)s <= expires_at
RETURNING verdict::text
"""

_REJECT = """
UPDATE retrywise.approvals
SET verdict = 'REJECTED',
    approver_subject = %(operator_subject)s,
    reason_code = %(reason_code)s,
    acted_at = %(acted_at)s
WHERE id = %(approval_id)s
  AND merchant_id = %(merchant_id)s
  AND verdict = 'PENDING'
RETURNING verdict::text
"""

_CANCEL = """
UPDATE retrywise.approvals
SET verdict = %(verdict)s::retrywise.approval_verdict,
    approver_subject = %(operator_subject)s,
    reason_code = %(reason_code)s,
    acted_at = %(acted_at)s
WHERE id = %(approval_id)s
  AND merchant_id = %(merchant_id)s
  AND verdict = 'PENDING'
RETURNING verdict::text
"""

_INSERT_ACTION = """
INSERT INTO retrywise.actions (
    id, merchant_id, recovery_case_id, decision_id, aggregate_version,
    approval_id, action_key, action_type, source_label, status, max_attempts,
    request_metadata, external_reference_id, scheduled_at, created_at, updated_at
) VALUES (
    %(action_id)s, %(merchant_id)s, %(recovery_case_id)s, %(decision_id)s,
    %(decision_version)s, %(approval_id)s, %(action_key)s,
    'CREATE_STANDARD_PAYMENT_LINK', 'RAZORPAY_TEST_MODE', 'PLANNED',
    %(action_max_attempts)s, %(request_metadata)s::jsonb, %(reference_id)s,
    %(acted_at)s, %(acted_at)s, %(acted_at)s
)
RETURNING id::text
"""

_INSERT_INSTRUMENT = """
INSERT INTO retrywise.recovery_instruments (
    id, merchant_id, recovery_case_id, logical_order_id, provider_account_id,
    action_id, reference_id, amount_minor, currency, status, accept_partial,
    expires_at, created_at, updated_at
) VALUES (
    %(instrument_id)s, %(merchant_id)s, %(recovery_case_id)s,
    %(logical_order_id)s, %(provider_account_id)s, %(action_id)s,
    %(reference_id)s, %(amount_minor)s, %(currency)s, 'CREATING', FALSE,
    %(link_expires_at)s, %(acted_at)s, %(acted_at)s
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

_QUEUE_CASE = """
UPDATE retrywise.recovery_cases
SET state = 'ACTION_QUEUED',
    version = version + 1,
    attempt_count = attempt_count + 1,
    last_action_id = %(action_id)s,
    last_action_at = %(acted_at)s
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state = 'APPROVAL_REQUIRED'
  AND version = %(case_version)s
RETURNING version
"""

_REJECT_CASE = """
UPDATE retrywise.recovery_cases
SET state = 'SUPPRESSED_POLICY',
    version = version + 1,
    terminal_reason_code = %(reason_code)s,
    terminal_at = %(acted_at)s
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state = 'APPROVAL_REQUIRED'
  AND version = %(case_version)s
RETURNING version
"""

_INSERT_OUTBOX = """
INSERT INTO retrywise.outbox_jobs (
    id, merchant_id, aggregate_type, aggregate_id, command_type,
    command_schema_version, command_payload, idempotency_key, status,
    max_attempts, next_attempt_at, created_at, updated_at
) VALUES (
    %(outbox_job_id)s, %(merchant_id)s, 'ACTION', %(action_id)s,
    %(command_type)s, %(command_schema_version)s, %(command_payload)s::jsonb,
    %(idempotency_key)s, 'PENDING', %(outbox_max_attempts)s,
    %(acted_at)s, %(acted_at)s, %(acted_at)s
)
RETURNING id::text
"""


class ApprovalServiceError(RuntimeError):
    pass


class ApprovalNotFound(ApprovalServiceError):
    pass


class ApprovalConflict(ApprovalServiceError):
    pass


@dataclass(frozen=True, slots=True)
class ApprovalActionResult:
    approval_id: str
    verdict: str
    recovery_case_id: str
    case_version: int
    action_id: str | None = None
    outbox_job_id: str | None = None


@dataclass(frozen=True, slots=True)
class _Snapshot:
    approval_id: str
    decision_id: str
    decision_version: int
    requested_at: datetime
    expires_at: datetime
    proposal_value: object
    policy_version: str
    recovery_case_id: str
    logical_order_id: str
    provider_account_id: str
    currency: str
    amount_minor: int
    case_state: str
    case_version: int
    observation_deadline: datetime
    attempt_count: int
    contact_count: int
    incident_id: str | None
    merchant_status: str
    merchant_kill_switch: bool
    provider_account_identifier: str
    account_environment: str
    account_enabled: bool
    credential_binding_version: int
    canonical_truth: str
    payment_record_id: str
    provider_payment_id: str
    provider_order_id: str
    payment_method: str | None
    active_instruments: int
    database_now: datetime


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
            policy.connect(dsn, component="PostgresApprovalService"),
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
        raise ValueError
    return value


def _snapshot(row: Sequence[object] | None) -> _Snapshot:
    if row is None:
        raise ApprovalNotFound("approval_not_found")
    if len(row) != 31:
        raise ApprovalConflict("approval_snapshot_unsafe")
    try:
        candidates = row[5]
        if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes)):
            raise ValueError
        if len(candidates) != 1:
            raise ValueError
        return _Snapshot(
            approval_id=_ulid(row[0]),
            decision_id=_ulid(row[1]),
            decision_version=cast(int, row[2]),
            requested_at=cast(datetime, row[3]),
            expires_at=cast(datetime, row[4]),
            proposal_value=candidates[0],
            policy_version=cast(str, row[6]),
            recovery_case_id=_ulid(row[7]),
            logical_order_id=_ulid(row[8]),
            provider_account_id=_ulid(row[9]),
            currency=cast(str, row[10]),
            amount_minor=cast(int, row[11]),
            case_state=cast(str, row[12]),
            case_version=cast(int, row[13]),
            observation_deadline=cast(datetime, row[14]),
            attempt_count=cast(int, row[15]),
            contact_count=cast(int, row[16]),
            incident_id=cast(str | None, row[17]),
            merchant_status=cast(str, row[18]),
            merchant_kill_switch=cast(bool, row[19]),
            provider_account_identifier=cast(str, row[20]),
            account_environment=cast(str, row[21]),
            account_enabled=cast(bool, row[22]),
            credential_binding_version=cast(int, row[23]),
            canonical_truth=cast(str, row[24]),
            payment_record_id=_ulid(row[25]),
            provider_payment_id=cast(str, row[26]),
            provider_order_id=cast(str, row[27]),
            payment_method=cast(str | None, row[28]),
            active_instruments=cast(int, row[29]),
            database_now=cast(datetime, row[30]),
        )
    except (TypeError, ValueError, IndexError):
        raise ApprovalConflict("approval_snapshot_unsafe") from None


def _one(row: Sequence[object] | None, expected: object, operation: str) -> None:
    if row is None or len(row) != 1 or row[0] != expected:
        raise ApprovalConflict(operation)


def _same_binding(left: _Snapshot, right: _Snapshot) -> bool:
    return replace(left, database_now=right.database_now) == right


class PostgresApprovalService:
    def __init__(
        self,
        *,
        gate: DeterministicGate,
        provider_truth_reader: FreshProviderTruthReader,
        method_health_reader: FreshMethodHealthReader,
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
        self._gate = gate
        self._provider_truth_reader = provider_truth_reader
        self._method_health_reader = method_health_reader
        self._global_kill_switch = global_kill_switch
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
    ) -> ApprovalActionResult:
        merchant_id = _ulid(merchant_id)
        approval_id = _ulid(approval_id)
        if verdict not in {"APPROVED", "REJECTED"}:
            raise ValueError("verdict must be APPROVED or REJECTED")
        if not _REASON_RE.fullmatch(reason_code):
            raise ValueError("reason_code is invalid")
        if not operator_subject or len(operator_subject) > 200:
            raise ValueError("operator_subject is invalid")
        loaded = self._load(merchant_id=merchant_id, approval_id=approval_id, lock=False)
        if verdict == "REJECTED":
            return self._reject(loaded, operator_subject=operator_subject, reason_code=reason_code)
        return self._approve(loaded, operator_subject=operator_subject, reason_code=reason_code)

    def _load(self, *, merchant_id: str, approval_id: str, lock: bool) -> _Snapshot:
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(
                _LOCK_PENDING if lock else _LOAD_PENDING,
                {"merchant_id": merchant_id, "approval_id": approval_id},
            )
            return _snapshot(cursor.fetchone())

    def _approve(
        self,
        loaded: _Snapshot,
        *,
        operator_subject: str,
        reason_code: str,
    ) -> ApprovalActionResult:
        proposal = decode_action_proposal(loaded.proposal_value)
        truth = self._provider_truth_reader.fetch_fresh_payment_truth(
            ProviderTruthQuery(
                merchant_id=proposal.merchant_id,
                provider_account_id=loaded.provider_account_id,
                provider_account_identifier=loaded.provider_account_identifier,
                credential_binding_version=loaded.credential_binding_version,
                payment_record_id=loaded.payment_record_id,
                provider_payment_id=loaded.provider_payment_id,
                provider_order_id=loaded.provider_order_id,
            )
        )
        health = self._method_health_reader.fetch_fresh_method_health(
            MethodHealthQuery(
                merchant_id=proposal.merchant_id,
                provider_account_id=loaded.provider_account_id,
                payment_method=truth.payment_method,
                incident_id=loaded.incident_id,
            )
        )
        acted_at = max(loaded.database_now, truth.observed_at, health.observed_at)
        if acted_at >= loaded.expires_at or acted_at >= proposal.expires_at:
            return self._cancel(
                loaded,
                operator_subject=operator_subject,
                reason_code="approval_expired",
                verdict="EXPIRED",
                acted_at=acted_at,
            )
        approval = Approval(
            approval_id=loaded.approval_id,
            merchant_id=proposal.merchant_id,
            case_id=proposal.case_id,
            action_key=proposal.action_key,
            proposal_digest=proposal.proposal_digest,
            decision_version=proposal.decision_version,
            approved_by="operator:" + hashlib.sha256(operator_subject.encode()).hexdigest(),
            approved_at=acted_at,
            expires_at=loaded.expires_at,
        )
        decision = self._gate.evaluate_policy(
            proposal,
            GateContext(
                merchant_id=proposal.merchant_id,
                case_id=proposal.case_id,
                evaluated_at=acted_at,
                aggregate_version=loaded.case_version,
                expected_aggregate_version=loaded.case_version,
                recovery_state=RecoveryState.APPROVAL_REQUIRED,
                snapshot=ProviderSnapshot(
                    payment_state=truth.canonical_payment_state,
                    amount_due=Money(loaded.amount_minor, loaded.currency),
                    payment_method=truth.payment_method,
                    observed_at=truth.observed_at,
                    active_instrument_count=loaded.active_instruments,
                    incident_state=health.incident_state,
                    method_health_observed_at=health.observed_at,
                ),
                environment_effects_enabled=(
                    loaded.merchant_status == "ACTIVE"
                    and loaded.account_environment == "TEST"
                    and loaded.account_enabled
                ),
                observation_deadline=loaded.observation_deadline,
                global_kill_switch=self._global_kill_switch,
                merchant_kill_switch=loaded.merchant_kill_switch,
                contacts_in_window=loaded.contact_count,
                attempts_used=loaded.attempt_count,
                abstention_required=proposal.requires_approval,
                approval=approval,
            ),
        )
        if not decision.allowed:
            return self._cancel(
                loaded,
                operator_subject=operator_subject,
                reason_code="approved_proposal_no_longer_authorized",
                verdict="CANCELLED",
                acted_at=acted_at,
            )
        reference_id = make_recovery_reference_id(
            proposal.case_id,
            provider_account_id=loaded.provider_account_id,
        )
        link_expires_at = datetime.fromtimestamp(
            int((acted_at + timedelta(hours=24)).timestamp()), UTC
        )
        request = StandardPaymentLinkRequest(
            amount_minor=loaded.amount_minor,
            currency=loaded.currency,
            reference_id=reference_id,
            description=f"Retry payment for order {loaded.logical_order_id}",
            expire_by_epoch=int(link_expires_at.timestamp()),
            notes={
                # This provider-facing legacy key carries only our opaque
                # logical-order ULID, never the merchant's order reference.
                "merchant_order_id": loaded.logical_order_id,
                "recovery_case_id": proposal.case_id,
            },
        )
        command = CreatePaymentLinkCommand(
            proposal=proposal,
            prior_plan=decision,
            request=request,
            provider_account_id=loaded.provider_account_id,
        )
        intent = DurableActionIntent.record(command, recorded_at=acted_at)
        ids = tuple(_ulid(self._id_factory()) for _ in range(3))
        action_id, instrument_id, outbox_job_id = ids
        params: dict[str, object] = {
            "merchant_id": proposal.merchant_id,
            "approval_id": loaded.approval_id,
            "decision_id": loaded.decision_id,
            "decision_version": loaded.decision_version,
            "recovery_case_id": loaded.recovery_case_id,
            "logical_order_id": loaded.logical_order_id,
            "provider_account_id": loaded.provider_account_id,
            "case_version": loaded.case_version,
            "operator_subject": operator_subject,
            "reason_code": reason_code,
            "acted_at": acted_at,
            "action_id": action_id,
            "instrument_id": instrument_id,
            "outbox_job_id": outbox_job_id,
            "action_key": proposal.action_key,
            "action_max_attempts": 5,
            "outbox_max_attempts": 8,
            "reference_id": reference_id,
            "amount_minor": loaded.amount_minor,
            "currency": loaded.currency,
            "link_expires_at": link_expires_at,
            "request_metadata": json.dumps(
                {
                    "action_key": intent.action_key,
                    "executor_payload_sha256": intent.payload_digest,
                    "prior_plan_sha256": intent.prior_plan_digest,
                    "proposal_sha256": intent.proposal_digest,
                    "provider_account_id": intent.provider_account_id,
                    "provider_request_sha256": intent.request_digest,
                    "recorded_at": intent.recorded_at.isoformat().replace("+00:00", "Z"),
                    "reference_id": intent.reference_id,
                    "schema": "retrywise-durable-action-intent",
                    "schema_version": intent.schema_version,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            "command_type": CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
            "command_schema_version": CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
            "command_payload": json.dumps(
                encode_create_standard_payment_link_command(command),
                sort_keys=True,
                separators=(",", ":"),
            ),
            "idempotency_key": f"create-standard-payment-link:{proposal.action_key}",
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                _LOCK_PENDING,
                {"merchant_id": proposal.merchant_id, "approval_id": loaded.approval_id},
            )
            locked = _snapshot(cursor.fetchone())
            if not _same_binding(locked, loaded):
                raise ApprovalConflict("approval_state_changed")
            cursor.execute(_APPROVE, params)
            _one(cursor.fetchone(), "APPROVED", "approval_update_failed")
            cursor.execute(_INSERT_ACTION, params)
            _one(cursor.fetchone(), action_id, "approval_action_insert_failed")
            cursor.execute(_INSERT_INSTRUMENT, params)
            _one(cursor.fetchone(), instrument_id, "approval_instrument_insert_failed")
            cursor.execute(_QUEUE_ACTION, params)
            _one(cursor.fetchone(), "QUEUED", "approval_action_queue_failed")
            cursor.execute(_QUEUE_CASE, params)
            _one(cursor.fetchone(), loaded.case_version + 1, "approval_case_queue_failed")
            cursor.execute(_INSERT_OUTBOX, params)
            _one(cursor.fetchone(), outbox_job_id, "approval_outbox_insert_failed")
            self._audit(
                cursor,
                snapshot=loaded,
                operator_subject=operator_subject,
                verdict="APPROVED",
                reason_code=reason_code,
                acted_at=acted_at,
                action_id=action_id,
            )
        return ApprovalActionResult(
            approval_id=loaded.approval_id,
            verdict="APPROVED",
            recovery_case_id=loaded.recovery_case_id,
            case_version=loaded.case_version + 1,
            action_id=action_id,
            outbox_job_id=outbox_job_id,
        )

    def _cancel(
        self,
        loaded: _Snapshot,
        *,
        operator_subject: str,
        reason_code: str,
        verdict: str,
        acted_at: datetime,
    ) -> ApprovalActionResult:
        if verdict not in {"CANCELLED", "EXPIRED"}:
            raise ValueError("cancellation verdict is invalid")
        proposal = decode_action_proposal(loaded.proposal_value)
        params: dict[str, object] = {
            "merchant_id": proposal.merchant_id,
            "approval_id": loaded.approval_id,
            "recovery_case_id": loaded.recovery_case_id,
            "case_version": loaded.case_version,
            "operator_subject": operator_subject,
            "reason_code": reason_code,
            "acted_at": acted_at,
            "verdict": verdict,
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                _LOCK_PENDING,
                {"merchant_id": proposal.merchant_id, "approval_id": loaded.approval_id},
            )
            if not _same_binding(_snapshot(cursor.fetchone()), loaded):
                raise ApprovalConflict("approval_state_changed")
            cursor.execute(_CANCEL, params)
            _one(cursor.fetchone(), verdict, "approval_cancellation_failed")
            cursor.execute(_REJECT_CASE, params)
            _one(cursor.fetchone(), loaded.case_version + 1, "approval_case_cancel_failed")
            self._audit(
                cursor,
                snapshot=loaded,
                operator_subject=operator_subject,
                verdict=verdict,
                reason_code=reason_code,
                acted_at=acted_at,
                action_id=None,
            )
        return ApprovalActionResult(
            approval_id=loaded.approval_id,
            verdict=verdict,
            recovery_case_id=loaded.recovery_case_id,
            case_version=loaded.case_version + 1,
        )

    def _reject(
        self,
        loaded: _Snapshot,
        *,
        operator_subject: str,
        reason_code: str,
    ) -> ApprovalActionResult:
        acted_at = loaded.database_now
        params: dict[str, object] = {
            "merchant_id": _ulid(decode_action_proposal(loaded.proposal_value).merchant_id),
            "approval_id": loaded.approval_id,
            "recovery_case_id": loaded.recovery_case_id,
            "case_version": loaded.case_version,
            "operator_subject": operator_subject,
            "reason_code": reason_code,
            "acted_at": acted_at,
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                _LOCK_PENDING,
                {"merchant_id": params["merchant_id"], "approval_id": loaded.approval_id},
            )
            if not _same_binding(_snapshot(cursor.fetchone()), loaded):
                raise ApprovalConflict("approval_state_changed")
            cursor.execute(_REJECT, params)
            _one(cursor.fetchone(), "REJECTED", "approval_update_failed")
            cursor.execute(_REJECT_CASE, params)
            _one(cursor.fetchone(), loaded.case_version + 1, "approval_case_reject_failed")
            self._audit(
                cursor,
                snapshot=loaded,
                operator_subject=operator_subject,
                verdict="REJECTED",
                reason_code=reason_code,
                acted_at=acted_at,
                action_id=None,
            )
        return ApprovalActionResult(
            approval_id=loaded.approval_id,
            verdict="REJECTED",
            recovery_case_id=loaded.recovery_case_id,
            case_version=loaded.case_version + 1,
        )

    def _audit(
        self,
        cursor: _Cursor,
        *,
        snapshot: _Snapshot,
        operator_subject: str,
        verdict: str,
        reason_code: str,
        acted_at: datetime,
        action_id: str | None,
    ) -> None:
        if self._audit_appender is None:
            return
        facts: dict[str, object] = {
            "approval_id": snapshot.approval_id,
            "approval_verdict": verdict,
            "reason_code": reason_code.upper(),
        }
        if action_id is not None:
            facts["action_id"] = action_id
        self._audit_appender.append(
            cursor=cursor,
            audit_entry_id=_ulid(self._id_factory()),
            merchant_id=decode_action_proposal(snapshot.proposal_value).merchant_id,
            recovery_case_id=snapshot.recovery_case_id,
            entry_type="APPROVAL_ACTED",
            actor_type=AuditActorType.OPERATOR,
            actor_subject=(
                "operator:" + hashlib.sha256(operator_subject.encode("utf-8")).hexdigest()
            ),
            facts=facts,
            created_at=acted_at.astimezone(UTC),
        )


__all__ = [
    "ApprovalActionResult",
    "ApprovalConflict",
    "ApprovalNotFound",
    "ApprovalServiceError",
    "PostgresApprovalService",
]
