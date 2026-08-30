"""PostgreSQL composition for one safely convergent Test Mode create effect."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from typing import Protocol, cast

from ...packages.domain import (
    ActionProposal,
    Approval,
    DeterministicGate,
    GateContext,
    GateDecision,
    GateReason,
    Money,
    ProviderSnapshot,
    RecoveryState,
)
from .assessment_intent import (
    FreshMethodHealthReader,
    FreshProviderTruthReader,
    MethodHealthQuery,
    ProviderTruthQuery,
)
from .effect_command_codec import (
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
    EffectCommandCodecError,
    decode_create_standard_payment_link_command,
)
from .executor import (
    CreatePaymentLinkCommand,
    CreatePaymentLinkExecutor,
    DurableActionIntent,
    ExecutionDisposition,
    ExecutionResult,
    PaymentLinkProvider,
)
from .outbox import OutboxJob, OutboxState, RetryMode
from .outbox_worker import HandlerResult
from .postgres_audit import AuditActorType, TransactionalAuditAppender
from .postgres_connection import PostgresConnectionPolicy
from .postgres_outbox import ClaimedOutboxCommand


class CreateEffectPersistenceError(RuntimeError):
    """A sanitized state/fence failure around one provider effect."""


class CreateEffectAdapter(PaymentLinkProvider, Protocol):
    def close(self) -> None: ...


CreateEffectAdapterFactory = Callable[[str, str], CreateEffectAdapter]

_LOAD_INTENT = """
SELECT
    action.merchant_id::text,
    action.request_metadata
FROM retrywise.actions AS action
JOIN retrywise.recovery_cases AS recovery_case
  ON recovery_case.merchant_id = action.merchant_id
 AND recovery_case.id = action.recovery_case_id
WHERE action.action_key = %(action_key)s
  AND recovery_case.provider_account_id = %(provider_account_id)s
  AND action.action_type = 'CREATE_STANDARD_PAYMENT_LINK'
  AND action.source_label = 'RAZORPAY_TEST_MODE'
"""

_LOAD_CONTEXT = """
SELECT
    action.id::text,
    action.status::text,
    action.approval_id::text,
    recovery_case.state::text,
    recovery_case.version,
    recovery_case.observation_deadline_at,
    recovery_case.attempt_count,
    recovery_case.contact_count,
    recovery_case.incident_id::text,
    merchant.status::text,
    merchant.kill_switch_enabled,
    merchant.default_policy_version,
    account.provider_account_identifier,
    account.environment::text,
    account.enabled,
    account.credential_binding_version,
    logical_order.amount_due_minor,
    logical_order.currency::text,
    payment.id::text,
    payment.provider_payment_id,
    payment.provider_order_id,
    payment.amount_minor,
    payment.currency::text,
    payment.payment_method,
    (
        SELECT count(*)
        FROM retrywise.recovery_instruments AS other
        WHERE other.merchant_id = recovery_case.merchant_id
          AND other.logical_order_id = recovery_case.logical_order_id
          AND other.currency = recovery_case.currency
          AND other.action_id <> action.id
          AND other.status IN ('CREATING', 'UNCERTAIN', 'ISSUED', 'ACTIVE', 'CANCEL_PENDING')
    ),
    approval.id::text,
    approval.verdict::text,
    approval.approver_subject,
    approval.acted_at,
    approval.expires_at
FROM retrywise.actions AS action
JOIN retrywise.recovery_cases AS recovery_case
  ON recovery_case.merchant_id = action.merchant_id
 AND recovery_case.id = action.recovery_case_id
JOIN retrywise.merchants AS merchant
  ON merchant.id = recovery_case.merchant_id
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
LEFT JOIN retrywise.approvals AS approval
  ON approval.merchant_id = action.merchant_id
 AND approval.id = action.approval_id
WHERE action.merchant_id = %(merchant_id)s
  AND action.recovery_case_id = %(recovery_case_id)s
  AND action.action_key = %(action_key)s
  AND recovery_case.provider_account_id = %(provider_account_id)s
  AND action.action_type = 'CREATE_STANDARD_PAYMENT_LINK'
  AND action.source_label = 'RAZORPAY_TEST_MODE'
"""

_LOCK_FENCE = """
SELECT TRUE
FROM retrywise.outbox_jobs AS job
JOIN retrywise.actions AS action
  ON action.merchant_id = job.merchant_id
 AND action.id::text = job.aggregate_id
WHERE job.id = %(job_id)s
  AND job.merchant_id = %(merchant_id)s
  AND job.aggregate_type = 'ACTION'
  AND job.command_type = 'CREATE_STANDARD_PAYMENT_LINK'
  AND job.status = 'IN_PROGRESS'
  AND job.delivery_version = %(delivery_version)s
  AND job.lease_owner = %(worker_id)s
  AND job.lease_token = %(lease_token)s
  AND job.lease_expires_at > clock_timestamp()
  AND action.recovery_case_id = %(recovery_case_id)s
  AND action.action_key = %(action_key)s
FOR UPDATE OF job
"""

_LOCK_PATH = """
SELECT
    action.id::text,
    action.status::text,
    action.action_key,
    action.external_reference_id,
    action.request_metadata,
    recovery_case.state::text,
    recovery_case.version,
    instrument.id::text,
    instrument.status::text,
    instrument.reference_id,
    instrument.provider_payment_link_id,
    logical_order.canonical_truth::text,
    merchant.status::text,
    merchant.kill_switch_enabled,
    account.environment::text,
    account.enabled
FROM retrywise.actions AS action
JOIN retrywise.recovery_cases AS recovery_case
  ON recovery_case.merchant_id = action.merchant_id
 AND recovery_case.id = action.recovery_case_id
JOIN retrywise.recovery_instruments AS instrument
  ON instrument.merchant_id = action.merchant_id
 AND instrument.action_id = action.id
 AND instrument.recovery_case_id = action.recovery_case_id
JOIN retrywise.logical_orders AS logical_order
  ON logical_order.merchant_id = recovery_case.merchant_id
 AND logical_order.id = recovery_case.logical_order_id
 AND logical_order.provider_account_id = recovery_case.provider_account_id
JOIN retrywise.merchants AS merchant ON merchant.id = action.merchant_id
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = recovery_case.merchant_id
 AND account.id = recovery_case.provider_account_id
WHERE action.merchant_id = %(merchant_id)s
  AND action.recovery_case_id = %(recovery_case_id)s
  AND action.action_key = %(action_key)s
  AND recovery_case.provider_account_id = %(provider_account_id)s
FOR UPDATE OF action, recovery_case, instrument, logical_order
FOR SHARE OF merchant, account
"""

_START_CASE_EXECUTION = """
UPDATE retrywise.recovery_cases
SET state = 'EXECUTING', version = version + 1
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state = 'ACTION_QUEUED'
  AND version = %(case_version)s
RETURNING version
"""

_START_ACTION_EXECUTION = """
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
  AND recovery_case_id = %(recovery_case_id)s
  AND status = 'QUEUED'
RETURNING status::text
"""

_START_RECONCILIATION = """
UPDATE retrywise.actions
SET status = 'RECONCILING',
    lease_owner = %(worker_id)s,
    lease_expires_at = %(lease_expires_at)s,
    last_attempted_at = %(evaluated_at)s
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND recovery_case_id = %(recovery_case_id)s
  AND status IN ('UNCERTAIN', 'RECONCILING')
RETURNING status::text
"""

_LOCK_RESULT_PATH = _LOCK_PATH

_ISSUE_INSTRUMENT = """
UPDATE retrywise.recovery_instruments
SET status = 'ISSUED',
    provider_payment_link_id = COALESCE(provider_payment_link_id, %(payment_link_id)s),
    last_provider_status = 'created',
    reconciliation_status = 'CONFIRMED',
    last_reconciled_at = %(completed_at)s
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND recovery_case_id = %(recovery_case_id)s
  AND status IN ('CREATING', 'UNCERTAIN')
  AND (provider_payment_link_id IS NULL OR provider_payment_link_id = %(payment_link_id)s)
RETURNING status::text
"""

_ACTIVATE_INSTRUMENT = """
UPDATE retrywise.recovery_instruments
SET status = 'ACTIVE'
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'ISSUED'
RETURNING status::text
"""

_COMPLETE_ACTION = """
UPDATE retrywise.actions
SET status = %(action_status)s::retrywise.action_status,
    lease_owner = NULL,
    lease_expires_at = NULL,
    response_metadata = %(response_metadata)s::jsonb,
    provider_status = 'created',
    reconciliation_status = 'CONFIRMED',
    provider_resource_id = %(payment_link_id)s,
    completed_at = %(completed_at)s,
    last_error_code = NULL
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND recovery_case_id = %(recovery_case_id)s
  AND status = %(expected_action_status)s::retrywise.action_status
RETURNING status::text
"""

_ACTIVATE_CASE = """
UPDATE retrywise.recovery_cases
SET state = 'ACTIVE', version = version + 1
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state = %(expected_case_state)s::retrywise.recovery_case_state
  AND version = %(case_version)s
RETURNING version
"""

_MARK_UNCERTAIN_ACTION = """
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

_MARK_UNCERTAIN_INSTRUMENT = """
UPDATE retrywise.recovery_instruments
SET status = 'UNCERTAIN',
    reconciliation_status = 'PENDING',
    last_provider_status = 'unknown'
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'CREATING'
RETURNING status::text
"""

_MARK_UNCERTAIN_CASE = """
UPDATE retrywise.recovery_cases
SET state = 'ACTION_UNCERTAIN', version = version + 1
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state = 'EXECUTING'
  AND version = %(case_version)s
RETURNING version
"""

_MARK_ACTION_RETRYABLE = """
UPDATE retrywise.actions
SET status = 'FAILED_RETRYABLE',
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error_code = %(reason_code)s
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'EXECUTING'
RETURNING status::text
"""

_QUEUE_RETRYABLE_ACTION = """
UPDATE retrywise.actions
SET status = 'QUEUED'
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'FAILED_RETRYABLE'
RETURNING status::text
"""

_REQUEUE_ACTION_FROM_RECONCILING = """
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

_MARK_CASE_UNCERTAIN = """
UPDATE retrywise.recovery_cases
SET state = 'ACTION_UNCERTAIN', version = version + 1
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state = 'EXECUTING'
  AND version = %(case_version)s
RETURNING version
"""

_QUEUE_UNCERTAIN_CASE = """
UPDATE retrywise.recovery_cases
SET state = 'ACTION_QUEUED', version = version + 1
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state = 'ACTION_UNCERTAIN'
  AND version = %(case_version)s
RETURNING version
"""

_REQUEUE_CASE_FROM_UNCERTAIN = """
UPDATE retrywise.recovery_cases
SET state = 'ACTION_QUEUED', version = version + 1
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state = 'ACTION_UNCERTAIN'
  AND version = %(case_version)s
RETURNING version
"""

_RESET_UNCERTAIN_INSTRUMENT = """
UPDATE retrywise.recovery_instruments
SET status = 'CREATING', reconciliation_status = 'PENDING'
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'UNCERTAIN'
RETURNING status::text
"""

_FAIL_ACTION = """
UPDATE retrywise.actions
SET status = CASE
        WHEN status IN ('EXECUTING', 'RECONCILING') THEN 'FAILED_SAFE'
        ELSE 'DEAD_LETTER'
    END,
    lease_owner = NULL,
    lease_expires_at = NULL,
    completed_at = %(completed_at)s,
    last_error_code = %(reason_code)s,
    dead_lettered_at = CASE WHEN status = 'QUEUED' THEN %(completed_at)s ELSE NULL END,
    dead_letter_reason = CASE WHEN status = 'QUEUED' THEN %(reason_code)s ELSE NULL END
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status IN ('QUEUED', 'EXECUTING', 'RECONCILING')
RETURNING status::text
"""

_FAIL_INSTRUMENT = """
UPDATE retrywise.recovery_instruments
SET status = 'FAILED', reconciliation_status = 'CONFLICT', last_reconciled_at = %(completed_at)s
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND status IN ('CREATING', 'UNCERTAIN')
RETURNING status::text
"""

_FAIL_CASE = """
UPDATE retrywise.recovery_cases
SET state = 'FAILED_SAFE',
    version = version + 1,
    terminal_reason_code = %(reason_code)s,
    terminal_at = %(completed_at)s
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state IN ('ACTION_QUEUED', 'EXECUTING', 'ACTION_UNCERTAIN')
  AND version = %(case_version)s
RETURNING version
"""

_CANCEL_QUEUED_ACTION = """
UPDATE retrywise.actions
SET status = 'CANCELLED',
    effect_gate_snapshot = %(gate_snapshot)s::jsonb,
    effect_gate_verdict = 'BLOCKED',
    effect_gate_reason_codes = %(gate_reason_codes)s::text[],
    completed_at = %(completed_at)s,
    last_error_code = %(reason_code)s
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status = 'QUEUED'
RETURNING status::text
"""

_DEAD_LETTER_UNCERTAIN_ACTION = """
UPDATE retrywise.actions
SET status = 'DEAD_LETTER',
    lease_owner = NULL,
    lease_expires_at = NULL,
    completed_at = %(completed_at)s,
    dead_lettered_at = %(completed_at)s,
    dead_letter_reason = %(reason_code)s,
    last_error_code = %(reason_code)s
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND status IN ('UNCERTAIN', 'RECONCILING')
RETURNING status::text
"""

_SUPPRESS_INSTRUMENT = """
UPDATE retrywise.recovery_instruments
SET status = 'FAILED',
    reconciliation_status = %(reconciliation_status)s::retrywise.reconciliation_status,
    last_reconciled_at = %(completed_at)s,
    last_provider_status = %(provider_status)s
WHERE id = %(instrument_id)s
  AND merchant_id = %(merchant_id)s
  AND status IN ('CREATING', 'UNCERTAIN')
RETURNING status::text
"""

_SUPPRESS_CASE = """
UPDATE retrywise.recovery_cases
SET state = %(terminal_state)s::retrywise.recovery_case_state,
    version = version + 1,
    terminal_reason_code = %(reason_code)s,
    terminal_at = %(completed_at)s
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND state = %(expected_case_state)s::retrywise.recovery_case_state
  AND version = %(case_version)s
RETURNING version
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
            policy.connect(dsn, component="PostgresCreateEffectRepository"),
        )

    return connect


def _one(row: Sequence[object] | None, expected: object, operation: str) -> None:
    if row is None or len(row) != 1 or row[0] != expected:
        raise CreateEffectPersistenceError(operation)


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise CreateEffectPersistenceError("durable_intent_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CreateEffectPersistenceError("durable_intent_timestamp_invalid") from None
    if parsed.tzinfo is None:
        raise CreateEffectPersistenceError("durable_intent_timestamp_invalid")
    return parsed.astimezone(UTC)


def _job_from_claim(claimed: ClaimedOutboxCommand, command: CreatePaymentLinkCommand) -> OutboxJob:
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


def _result_audit_facts(*, action_id: str, result: ExecutionResult) -> dict[str, object]:
    """Map executor output into the audit chain's closed machine-fact profile."""

    return {
        "action_id": action_id,
        "disposition": result.disposition.value.upper(),
        "reason_sha256": hashlib.sha256(result.reason_code.encode("utf-8")).hexdigest(),
    }


class PostgresCreateEffectRepository:
    """Fresh gate context, pre-effect authorization, and durable result writer."""

    def __init__(
        self,
        *,
        provider_truth_reader: FreshProviderTruthReader,
        method_health_reader: FreshMethodHealthReader,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        policy_version: str = "policy-v1",
        global_kill_switch: bool = False,
        audit_appender: TransactionalAuditAppender | None = None,
        audit_id_factory: Callable[[], str] | None = None,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if dsn is not None:
            self._connector = _dsn_factory(dsn, require_tls=require_tls)
        else:
            if require_tls or not callable(connector):
                raise ValueError("custom connectors cannot attest TLS")
            self._connector = connector
        self._provider_truth_reader = provider_truth_reader
        self._method_health_reader = method_health_reader
        self._policy_version = policy_version
        self._global_kill_switch = global_kill_switch
        self._audit_appender = audit_appender
        self._audit_id_factory = audit_id_factory

    def load_durable_intent(
        self, *, action_key: str, provider_account_id: str
    ) -> DurableActionIntent | None:
        try:
            with self._connector() as connection, connection.cursor() as cursor:
                cursor.execute(
                    _LOAD_INTENT,
                    {"action_key": action_key, "provider_account_id": provider_account_id},
                )
                row = cursor.fetchone()
            if row is None:
                return None
            if len(row) != 2 or type(row[0]) is not str or not isinstance(row[1], Mapping):
                raise ValueError
            metadata = row[1]
            expected = {
                "action_key",
                "executor_payload_sha256",
                "prior_plan_sha256",
                "proposal_sha256",
                "provider_account_id",
                "provider_request_sha256",
                "recorded_at",
                "reference_id",
                "schema",
                "schema_version",
            }
            if set(metadata) != expected or metadata["schema"] != "retrywise-durable-action-intent":
                raise ValueError
            return DurableActionIntent(
                action_key=cast(str, metadata["action_key"]),
                merchant_id=row[0],
                provider_account_id=cast(str, metadata["provider_account_id"]),
                proposal_digest=cast(str, metadata["proposal_sha256"]),
                prior_plan_digest=cast(str, metadata["prior_plan_sha256"]),
                request_digest=cast(str, metadata["provider_request_sha256"]),
                payload_digest=cast(str, metadata["executor_payload_sha256"]),
                reference_id=cast(str, metadata["reference_id"]),
                recorded_at=_parse_utc(metadata["recorded_at"]),
                schema_version=cast(int, metadata["schema_version"]),
            )
        except CreateEffectPersistenceError:
            raise
        except Exception:
            raise CreateEffectPersistenceError("durable_intent_load_failed") from None

    def load_fresh_gate_context(
        self,
        *,
        proposal: ActionProposal,
        provider_account_id: str,
        evaluated_at: datetime,
    ) -> GateContext:
        params = {
            "merchant_id": proposal.merchant_id,
            "recovery_case_id": proposal.case_id,
            "action_key": proposal.action_key,
            "provider_account_id": provider_account_id,
        }
        try:
            with self._connector() as connection, connection.cursor() as cursor:
                cursor.execute(_LOAD_CONTEXT, params)
                row = cursor.fetchone()
            if row is None or len(row) != 30:
                raise ValueError
            (
                _action_id,
                _action_status,
                _action_approval_id,
                case_state,
                case_version,
                observation_deadline,
                attempt_count,
                contact_count,
                incident_id,
                merchant_status,
                merchant_kill_switch,
                merchant_policy_version,
                external_account_id,
                account_environment,
                account_enabled,
                credential_version,
                amount_due,
                currency,
                payment_record_id,
                provider_payment_id,
                provider_order_id,
                payment_amount,
                payment_currency,
                persisted_method,
                other_instruments,
                approval_id,
                approval_verdict,
                approver_subject,
                approval_acted_at,
                approval_expires_at,
            ) = row
            if merchant_policy_version != self._policy_version:
                raise ValueError
            provider_truth = self._provider_truth_reader.fetch_fresh_payment_truth(
                ProviderTruthQuery(
                    merchant_id=proposal.merchant_id,
                    provider_account_id=provider_account_id,
                    provider_account_identifier=cast(str, external_account_id),
                    credential_binding_version=cast(int, credential_version),
                    payment_record_id=cast(str, payment_record_id),
                    provider_payment_id=cast(str, provider_payment_id),
                    provider_order_id=cast(str, provider_order_id),
                )
            )
            if (
                provider_truth.amount_minor != payment_amount
                or provider_truth.currency != payment_currency
                or (
                    persisted_method is not None
                    and provider_truth.payment_method != persisted_method
                )
            ):
                raise ValueError
            health = self._method_health_reader.fetch_fresh_method_health(
                MethodHealthQuery(
                    merchant_id=proposal.merchant_id,
                    provider_account_id=provider_account_id,
                    payment_method=provider_truth.payment_method,
                    incident_id=cast(str | None, incident_id),
                )
            )
            approval: Approval | None = None
            if approval_id is not None:
                approval = Approval(
                    approval_id=cast(str, approval_id),
                    merchant_id=proposal.merchant_id,
                    case_id=proposal.case_id,
                    action_key=proposal.action_key,
                    proposal_digest=proposal.proposal_digest,
                    decision_version=proposal.decision_version,
                    approved_by=cast(str, approver_subject or "approval-pending"),
                    approved_at=cast(datetime, approval_acted_at or evaluated_at),
                    expires_at=cast(datetime, approval_expires_at),
                    granted=approval_verdict == "APPROVED",
                )
            return GateContext(
                merchant_id=proposal.merchant_id,
                case_id=proposal.case_id,
                evaluated_at=evaluated_at,
                aggregate_version=cast(int, case_version),
                expected_aggregate_version=cast(int, case_version),
                recovery_state=RecoveryState(cast(str, case_state).lower()),
                snapshot=ProviderSnapshot(
                    payment_state=provider_truth.canonical_payment_state,
                    amount_due=Money(cast(int, amount_due), cast(str, currency)),
                    payment_method=provider_truth.payment_method,
                    observed_at=provider_truth.observed_at,
                    active_instrument_count=cast(int, other_instruments),
                    incident_state=health.incident_state,
                    method_health_observed_at=health.observed_at,
                ),
                environment_effects_enabled=(
                    merchant_status == "ACTIVE"
                    and account_environment == "TEST"
                    and account_enabled is True
                ),
                observation_deadline=cast(datetime, observation_deadline),
                global_kill_switch=self._global_kill_switch,
                merchant_kill_switch=cast(bool, merchant_kill_switch),
                contacts_in_window=cast(int, contact_count),
                attempts_used=cast(int, attempt_count),
                abstention_required=proposal.requires_approval,
                approval=approval,
            )
        except Exception:
            raise CreateEffectPersistenceError("fresh_effect_context_failed") from None

    def record_effect_authorization(
        self,
        *,
        job: OutboxJob,
        command: CreatePaymentLinkCommand,
        decision: GateDecision,
        context: GateContext,
        worker_id: str,
        reconciliation_only: bool,
    ) -> None:
        if not decision.allowed:
            raise CreateEffectPersistenceError("effect_authorization_not_allowed")
        params: dict[str, object] = {
            "job_id": job.job_id,
            "merchant_id": command.proposal.merchant_id,
            "provider_account_id": command.provider_account_id,
            "recovery_case_id": command.proposal.case_id,
            "action_key": command.proposal.action_key,
            "delivery_version": job.version,
            "worker_id": worker_id,
            "lease_token": job.lease_token or "",
            "lease_expires_at": job.lease_expires_at,
            "evaluated_at": decision.evaluated_at,
            "gate_snapshot": json.dumps(
                decision.to_primitive(), sort_keys=True, separators=(",", ":")
            ),
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_LOCK_FENCE, params)
            _one(cursor.fetchone(), True, "effect_fence_lost")
            cursor.execute(_LOCK_PATH, params)
            row = cursor.fetchone()
            if row is None or len(row) != 16:
                raise CreateEffectPersistenceError("effect_path_missing")
            (
                action_id,
                action_status,
                action_key,
                reference_id,
                _metadata,
                case_state,
                case_version,
                instrument_id,
                instrument_status,
                instrument_reference,
                provider_link_id,
                order_truth,
                merchant_status,
                merchant_kill,
                account_environment,
                account_enabled,
            ) = row
            if (
                action_key != command.proposal.action_key
                or reference_id != command.request.reference_id
                or instrument_reference != command.request.reference_id
                or provider_link_id is not None
                or order_truth != "UNPAID"
                or merchant_status != "ACTIVE"
                or merchant_kill is not False
                or account_environment != "TEST"
                or account_enabled is not True
                or case_version != context.aggregate_version
                or instrument_status not in {"CREATING", "UNCERTAIN"}
            ):
                raise CreateEffectPersistenceError("effect_path_binding_changed")
            params.update(
                {
                    "action_id": action_id,
                    "instrument_id": instrument_id,
                    "case_version": case_version,
                }
            )
            if reconciliation_only:
                if case_state != "ACTION_UNCERTAIN" or action_status not in {
                    "UNCERTAIN",
                    "RECONCILING",
                }:
                    raise CreateEffectPersistenceError("reconciliation_path_invalid")
                cursor.execute(_START_RECONCILIATION, params)
                _one(cursor.fetchone(), "RECONCILING", "reconciliation_start_failed")
            else:
                if case_state == "ACTION_QUEUED" and action_status == "QUEUED":
                    cursor.execute(_START_CASE_EXECUTION, params)
                    case_version += 1
                    _one(cursor.fetchone(), case_version, "case_execution_start_failed")
                    params["case_version"] = case_version
                    cursor.execute(_START_ACTION_EXECUTION, params)
                    _one(cursor.fetchone(), "EXECUTING", "action_execution_start_failed")
                elif case_state != "EXECUTING" or action_status != "EXECUTING":
                    raise CreateEffectPersistenceError("effect_execution_path_invalid")
            self._append_audit(
                cursor,
                command=command,
                entry_type="EFFECT_AUTHORIZED",
                facts={
                    "action_id": cast(str, action_id),
                    "decision_digest": decision.decision_digest,
                    "reconciliation_only": reconciliation_only,
                },
                created_at=decision.evaluated_at,
            )

    def persist_result(
        self,
        *,
        job: OutboxJob,
        command: CreatePaymentLinkCommand,
        result: ExecutionResult,
    ) -> None:
        completed_at = result.effect_decision.evaluated_at
        params: dict[str, object] = {
            "job_id": job.job_id,
            "merchant_id": command.proposal.merchant_id,
            "provider_account_id": command.provider_account_id,
            "recovery_case_id": command.proposal.case_id,
            "action_key": command.proposal.action_key,
            "delivery_version": job.version,
            "worker_id": job.lease_owner or "",
            "lease_token": job.lease_token or "",
            "completed_at": completed_at,
            "reason_code": result.reason_code[:500],
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_LOCK_FENCE, params)
            _one(cursor.fetchone(), True, "result_fence_lost")
            cursor.execute(_LOCK_RESULT_PATH, params)
            row = cursor.fetchone()
            if row is None or len(row) != 16:
                raise CreateEffectPersistenceError("result_path_missing")
            (
                action_id,
                action_status,
                _,
                _,
                _,
                case_state,
                case_version,
                instrument_id,
                instrument_status,
                _,
                existing_link,
                *_,
            ) = row
            params.update(
                {
                    "action_id": action_id,
                    "instrument_id": instrument_id,
                    "case_version": case_version,
                }
            )
            if result.disposition in {ExecutionDisposition.CREATED, ExecutionDisposition.ADOPTED}:
                payment_link_id = result.payment_link_id
                if payment_link_id is None:
                    raise CreateEffectPersistenceError("provider_link_id_missing")
                if existing_link is not None and existing_link != payment_link_id:
                    raise CreateEffectPersistenceError("provider_link_id_conflict")
                params.update(
                    {
                        "payment_link_id": payment_link_id,
                        "response_metadata": json.dumps(
                            {
                                "reason_code": result.reason_code,
                                "reference_id": result.reference_id,
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        "action_status": (
                            "SUCCEEDED" if action_status == "EXECUTING" else "RECONCILED"
                        ),
                        "expected_action_status": action_status,
                        "expected_case_state": case_state,
                    }
                )
                if instrument_status in {"CREATING", "UNCERTAIN"}:
                    cursor.execute(_ISSUE_INSTRUMENT, params)
                    _one(cursor.fetchone(), "ISSUED", "instrument_issue_failed")
                    cursor.execute(_ACTIVATE_INSTRUMENT, params)
                    _one(cursor.fetchone(), "ACTIVE", "instrument_activation_failed")
                cursor.execute(_COMPLETE_ACTION, params)
                _one(cursor.fetchone(), params["action_status"], "action_completion_failed")
                cursor.execute(_ACTIVATE_CASE, params)
                _one(
                    cursor.fetchone(),
                    cast(int, case_version) + 1,
                    "case_activation_failed",
                )
            elif result.disposition is ExecutionDisposition.REQUERY_REQUIRED:
                cursor.execute(_MARK_UNCERTAIN_ACTION, params)
                _one(cursor.fetchone(), "UNCERTAIN", "action_uncertain_failed")
                cursor.execute(_MARK_UNCERTAIN_INSTRUMENT, params)
                _one(cursor.fetchone(), "UNCERTAIN", "instrument_uncertain_failed")
                cursor.execute(_MARK_UNCERTAIN_CASE, params)
                _one(
                    cursor.fetchone(),
                    cast(int, case_version) + 1,
                    "case_uncertain_failed",
                )
            elif result.disposition is ExecutionDisposition.REQUEUED:
                if action_status == "EXECUTING":
                    cursor.execute(_MARK_ACTION_RETRYABLE, params)
                    _one(cursor.fetchone(), "FAILED_RETRYABLE", "action_retryable_failed")
                    cursor.execute(_QUEUE_RETRYABLE_ACTION, params)
                    _one(cursor.fetchone(), "QUEUED", "action_requeue_failed")
                    cursor.execute(_MARK_CASE_UNCERTAIN, params)
                    _one(
                        cursor.fetchone(),
                        cast(int, case_version) + 1,
                        "case_uncertain_failed",
                    )
                    params["case_version"] = cast(int, case_version) + 1
                    cursor.execute(_QUEUE_UNCERTAIN_CASE, params)
                    _one(
                        cursor.fetchone(),
                        cast(int, case_version) + 2,
                        "case_requeue_failed",
                    )
                elif action_status == "RECONCILING":
                    cursor.execute(_REQUEUE_ACTION_FROM_RECONCILING, params)
                    _one(cursor.fetchone(), "QUEUED", "action_requeue_failed")
                    cursor.execute(_REQUEUE_CASE_FROM_UNCERTAIN, params)
                    _one(
                        cursor.fetchone(),
                        cast(int, case_version) + 1,
                        "case_requeue_failed",
                    )
                    cursor.execute(_RESET_UNCERTAIN_INSTRUMENT, params)
                    _one(cursor.fetchone(), "CREATING", "instrument_requeue_failed")
                else:
                    raise CreateEffectPersistenceError("requeue_path_invalid")
            elif result.disposition in {
                ExecutionDisposition.ESCALATED,
                ExecutionDisposition.DEAD_LETTER,
            }:
                cursor.execute(_FAIL_ACTION, params)
                if cursor.fetchone() is None:
                    raise CreateEffectPersistenceError("action_failure_persistence_failed")
                if instrument_status in {"CREATING", "UNCERTAIN"}:
                    cursor.execute(_FAIL_INSTRUMENT, params)
                    _one(cursor.fetchone(), "FAILED", "instrument_failure_persistence_failed")
                cursor.execute(_FAIL_CASE, params)
                if cursor.fetchone() is None:
                    raise CreateEffectPersistenceError("case_failure_persistence_failed")
            elif result.disposition is ExecutionDisposition.SUPPRESSED:
                reason_values = [reason.value for reason in result.effect_decision.reasons]
                payment_truth_blocks = (
                    GateReason.PAYMENT_TRUTH_NOT_UNPAID in result.effect_decision.reasons
                )
                params.update(
                    {
                        "gate_snapshot": json.dumps(
                            result.effect_decision.to_primitive(),
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        "gate_reason_codes": reason_values,
                        "terminal_state": (
                            "SUPPRESSED_PAID" if payment_truth_blocks else "SUPPRESSED_POLICY"
                        ),
                        "expected_case_state": case_state,
                        "reconciliation_status": (
                            "CONFIRMED" if payment_truth_blocks else "CONFLICT"
                        ),
                        "provider_status": (
                            "payment_truth_not_unpaid"
                            if payment_truth_blocks
                            else "effect_gate_blocked"
                        ),
                    }
                )
                if action_status == "QUEUED":
                    cursor.execute(_CANCEL_QUEUED_ACTION, params)
                    _one(cursor.fetchone(), "CANCELLED", "action_suppression_failed")
                elif action_status in {"UNCERTAIN", "RECONCILING"}:
                    cursor.execute(_DEAD_LETTER_UNCERTAIN_ACTION, params)
                    _one(cursor.fetchone(), "DEAD_LETTER", "action_suppression_failed")
                    if not payment_truth_blocks:
                        params["terminal_state"] = "ESCALATED"
                else:
                    raise CreateEffectPersistenceError("suppression_path_invalid")
                if instrument_status in {"CREATING", "UNCERTAIN"}:
                    cursor.execute(_SUPPRESS_INSTRUMENT, params)
                    _one(cursor.fetchone(), "FAILED", "instrument_suppression_failed")
                cursor.execute(_SUPPRESS_CASE, params)
                _one(
                    cursor.fetchone(),
                    cast(int, case_version) + 1,
                    "case_suppression_failed",
                )
            else:
                raise CreateEffectPersistenceError("unsupported_execution_result")
            self._append_audit(
                cursor,
                command=command,
                entry_type="EFFECT_RESULT_COMMITTED",
                facts=_result_audit_facts(
                    action_id=cast(str, action_id),
                    result=result,
                ),
                created_at=completed_at,
            )

    def _append_audit(
        self,
        cursor: _Cursor,
        *,
        command: CreatePaymentLinkCommand,
        entry_type: str,
        facts: Mapping[str, object],
        created_at: datetime,
    ) -> None:
        if self._audit_appender is None or self._audit_id_factory is None:
            return
        self._audit_appender.append(
            cursor=cursor,
            audit_entry_id=self._audit_id_factory(),
            merchant_id=command.proposal.merchant_id,
            recovery_case_id=command.proposal.case_id,
            entry_type=entry_type,
            actor_type=AuditActorType.WORKER,
            actor_subject=("worker:" + hashlib.sha256(b"retrywise-effect-worker").hexdigest()),
            facts=facts,
            created_at=created_at,
        )


class CreateStandardPaymentLinkHandler:
    """Decode, execute, persist, and settle one Test Mode Payment Link intent."""

    def __init__(
        self,
        *,
        gate: DeterministicGate,
        repository: PostgresCreateEffectRepository,
        adapter_factory: CreateEffectAdapterFactory,
        clock: Callable[[], datetime],
    ) -> None:
        self._gate = gate
        self._repository = repository
        self._adapter_factory = adapter_factory
        self._clock = clock

    def __call__(self, claimed: ClaimedOutboxCommand) -> HandlerResult:
        try:
            command = decode_create_standard_payment_link_command(claimed.command_payload)
        except (EffectCommandCodecError, TypeError, ValueError):
            return HandlerResult.dead_letter("invalid_create_payment_link_command")
        if (
            claimed.command_type != CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE
            or claimed.command_schema_version != CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION
            or claimed.aggregate_type != "ACTION"
            or claimed.merchant_id != command.proposal.merchant_id
            or claimed.idempotency_key
            != f"create-standard-payment-link:{command.proposal.action_key}"
        ):
            return HandlerResult.dead_letter("invalid_create_payment_link_command")
        provider: CreateEffectAdapter | None = None
        try:
            provider = self._adapter_factory(
                command.proposal.merchant_id,
                command.provider_account_id,
            )
            executor = CreatePaymentLinkExecutor(
                gate=self._gate,
                intents=self._repository,
                contexts=self._repository,
                provider=provider,
                clock=self._clock,
                authorization_recorder=self._repository,
            )
            job = _job_from_claim(claimed, command)
            result = executor.execute(job=job, command=command, worker_id=claimed.worker_id)
            self._repository.persist_result(job=job, command=command, result=result)
        except CreateEffectPersistenceError:
            return HandlerResult.retry_safely(
                "create_effect_persistence_unavailable",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        except Exception:
            return HandlerResult.retry_safely(
                "create_effect_execution_unavailable",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        finally:
            if provider is not None:
                with suppress(Exception):
                    provider.close()
        if result.disposition in {
            ExecutionDisposition.CREATED,
            ExecutionDisposition.ADOPTED,
            ExecutionDisposition.SUPPRESSED,
        }:
            return HandlerResult.succeeded(
                result.payment_link_id or f"suppressed:{result.effect_decision.decision_digest}"
            )
        if result.disposition in {
            ExecutionDisposition.REQUEUED,
            ExecutionDisposition.REQUERY_REQUIRED,
        }:
            return HandlerResult.retry_safely(
                result.reason_code,
                retry_mode=result.job.retry_mode,
            )
        return HandlerResult.dead_letter(result.reason_code)


__all__ = [
    "CreateEffectAdapter",
    "CreateEffectAdapterFactory",
    "CreateEffectPersistenceError",
    "CreateStandardPaymentLinkHandler",
    "PostgresCreateEffectRepository",
]
