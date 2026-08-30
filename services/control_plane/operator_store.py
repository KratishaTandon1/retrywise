"""Sanitized tenant-scoped operational reads for the Test Mode console."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Protocol, cast

from .postgres_audit import PostgresAuditRepository
from .postgres_connection import PostgresConnectionPolicy

_OVERVIEW = """
SELECT
    clock_timestamp(),
    count(*) FILTER (WHERE recovery_case.state IN (
        'OBSERVING', 'ASSESSING', 'WAITING', 'APPROVAL_REQUIRED',
        'ACTION_QUEUED', 'EXECUTING', 'ACTION_UNCERTAIN', 'ACTIVE'
    )),
    count(*) FILTER (WHERE recovery_case.state = 'SUPPRESSED_PAID'),
    count(*) FILTER (WHERE recovery_case.state = 'RECOVERED'),
    COALESCE((
        SELECT sum(instrument.collected_minor)
        FROM retrywise.recovery_instruments AS instrument
        WHERE instrument.merchant_id = %(merchant_id)s
          AND instrument.status = 'PAID'
    ), 0),
    (
        SELECT count(*)
        FROM retrywise.outbox_jobs AS job
        WHERE job.merchant_id = %(merchant_id)s
          AND job.command_type = 'CREATE_STANDARD_PAYMENT_LINK'
          AND job.status = 'SUCCEEDED'
    ),
    (
        SELECT count(*)
        FROM retrywise.actions AS action
        JOIN retrywise.recovery_cases AS effect_case
          ON effect_case.merchant_id = action.merchant_id
         AND effect_case.id = action.recovery_case_id
        JOIN retrywise.logical_orders AS logical_order
          ON logical_order.merchant_id = effect_case.merchant_id
         AND logical_order.id = effect_case.logical_order_id
        WHERE action.merchant_id = %(merchant_id)s
          AND action.action_type = 'CREATE_STANDARD_PAYMENT_LINK'
          AND action.status IN (
              'EXECUTING', 'SUCCEEDED', 'FAILED_RETRYABLE',
              'UNCERTAIN', 'RECONCILING', 'RECONCILED'
          )
          AND (
              action.effect_gate_verdict IS DISTINCT FROM 'ALLOWED'
              OR logical_order.canonical_truth <> 'UNPAID'
                 AND action.status IN ('EXECUTING', 'FAILED_RETRYABLE')
          )
    ) + (
        SELECT count(*)
        FROM (
            SELECT instrument.logical_order_id, instrument.currency
            FROM retrywise.recovery_instruments AS instrument
            WHERE instrument.merchant_id = %(merchant_id)s
              AND instrument.status IN (
                  'CREATING', 'UNCERTAIN', 'ISSUED', 'ACTIVE', 'CANCEL_PENDING'
              )
            GROUP BY instrument.logical_order_id, instrument.currency
            HAVING count(*) > 1
        ) AS duplicate_active_paths
    )
FROM retrywise.recovery_cases AS recovery_case
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = recovery_case.merchant_id
 AND account.id = recovery_case.provider_account_id
WHERE recovery_case.merchant_id = %(merchant_id)s
  AND account.provider = 'RAZORPAY'
  AND account.environment = 'TEST'
"""

_LIST_CASES = """
SELECT
    recovery_case.id::text,
    logical_order.merchant_order_reference,
    recovery_case.amount_due_snapshot_minor,
    recovery_case.currency::text,
    recovery_case.state::text,
    recovery_case.version,
    payment.payment_method,
    recovery_case.terminal_reason_code,
    recovery_case.created_at,
    recovery_case.updated_at,
    recovery_case.last_decision_id::text,
    recovery_case.last_action_id::text
FROM retrywise.recovery_cases AS recovery_case
JOIN retrywise.logical_orders AS logical_order
  ON logical_order.merchant_id = recovery_case.merchant_id
 AND logical_order.id = recovery_case.logical_order_id
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = recovery_case.merchant_id
 AND account.id = recovery_case.provider_account_id
LEFT JOIN LATERAL (
    SELECT candidate.payment_method
    FROM retrywise.provider_payments AS candidate
    WHERE candidate.merchant_id = recovery_case.merchant_id
      AND candidate.provider_account_id = recovery_case.provider_account_id
      AND candidate.logical_order_id = recovery_case.logical_order_id
    ORDER BY candidate.provider_snapshot_at DESC, candidate.id
    LIMIT 1
) AS payment ON TRUE
WHERE recovery_case.merchant_id = %(merchant_id)s
  AND account.provider = 'RAZORPAY'
  AND account.environment = 'TEST'
ORDER BY
    CASE recovery_case.state
        WHEN 'APPROVAL_REQUIRED' THEN 0
        WHEN 'ACTION_UNCERTAIN' THEN 1
        WHEN 'EXECUTING' THEN 2
        WHEN 'ACTION_QUEUED' THEN 3
        WHEN 'WAITING' THEN 4
        ELSE 5
    END,
    recovery_case.updated_at DESC,
    recovery_case.id
LIMIT %(limit)s
"""

_CASE = """
SELECT
    recovery_case.id::text,
    recovery_case.logical_order_id::text,
    recovery_case.provider_account_id::text,
    logical_order.merchant_order_reference,
    logical_order.original_provider_order_id,
    recovery_case.amount_due_snapshot_minor,
    recovery_case.currency::text,
    recovery_case.state::text,
    recovery_case.version,
    recovery_case.attempt_count,
    recovery_case.contact_count,
    recovery_case.observation_deadline_at,
    recovery_case.evaluation_deadline_at,
    recovery_case.terminal_reason_code,
    recovery_case.terminal_at,
    logical_order.canonical_truth::text,
    logical_order.captured_total_minor,
    logical_order.refunded_total_minor,
    logical_order.truth_version,
    logical_order.provider_snapshot_at,
    account.provider_account_identifier,
    account.environment::text,
    account.enabled,
    merchant.kill_switch_enabled
FROM retrywise.recovery_cases AS recovery_case
JOIN retrywise.logical_orders AS logical_order
  ON logical_order.merchant_id = recovery_case.merchant_id
 AND logical_order.id = recovery_case.logical_order_id
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = recovery_case.merchant_id
 AND account.id = recovery_case.provider_account_id
JOIN retrywise.merchants AS merchant ON merchant.id = recovery_case.merchant_id
WHERE recovery_case.merchant_id = %(merchant_id)s
  AND recovery_case.id = %(recovery_case_id)s
  AND account.provider = 'RAZORPAY'
  AND account.environment = 'TEST'
"""

_CASE_ACTIONS = """
SELECT
    action.id::text,
    action.action_type::text,
    action.status::text,
    action.attempt_number,
    action.max_attempts,
    action.effect_gate_verdict::text,
    action.effect_gate_reason_codes,
    action.external_reference_id,
    action.provider_resource_id,
    action.provider_status,
    action.reconciliation_status::text,
    action.last_error_code,
    action.scheduled_at,
    action.first_attempted_at,
    action.completed_at
FROM retrywise.actions AS action
WHERE action.merchant_id = %(merchant_id)s
  AND action.recovery_case_id = %(recovery_case_id)s
ORDER BY action.created_at, action.id
"""

_CASE_INSTRUMENTS = """
SELECT
    instrument.id::text,
    instrument.status::text,
    instrument.reference_id,
    instrument.provider_payment_link_id,
    instrument.provider_order_id,
    instrument.provider_payment_id,
    instrument.amount_minor,
    instrument.currency::text,
    instrument.collected_minor,
    instrument.refunded_minor,
    instrument.last_provider_status,
    instrument.reconciliation_status::text,
    instrument.expires_at,
    instrument.last_reconciled_at
FROM retrywise.recovery_instruments AS instrument
WHERE instrument.merchant_id = %(merchant_id)s
  AND instrument.recovery_case_id = %(recovery_case_id)s
ORDER BY instrument.created_at, instrument.id
"""

_CASE_DECISIONS = """
SELECT
    decision.id::text,
    decision.aggregate_version,
    decision.model_name,
    decision.model_version,
    decision.class_probabilities,
    decision.requested_diagnosis_mode,
    decision.executed_diagnosis_engine,
    decision.diagnosis_latency_ms,
    decision.diagnosis_fallback_reason_code,
    decision.shadow_diagnosis,
    decision.abstained,
    decision.out_of_distribution,
    decision.policy_version,
    decision.selected_action::text,
    decision.planning_gate_verdict::text,
    decision.planning_gate_reason_codes,
    decision.expected_value_minor,
    decision.source_label::text,
    decision.created_at
FROM retrywise.decisions AS decision
WHERE decision.merchant_id = %(merchant_id)s
  AND decision.recovery_case_id = %(recovery_case_id)s
ORDER BY decision.aggregate_version, decision.id
"""

_INCIDENTS = """
SELECT
    incident.id::text,
    incident.provider_account_id::text,
    incident.payment_method,
    incident.state::text,
    incident.severity::text,
    incident.confidence::text,
    incident.detector_version,
    incident.threshold_version,
    incident.first_seen_at,
    incident.last_seen_at,
    incident.expires_at,
    incident.cooling_deadline_at
FROM retrywise.incidents AS incident
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = incident.merchant_id
 AND account.id = incident.provider_account_id
WHERE incident.merchant_id = %(merchant_id)s
  AND account.environment = 'TEST'
ORDER BY incident.last_seen_at DESC, incident.id
LIMIT %(limit)s
"""

_APPROVALS = """
SELECT
    approval.id::text,
    approval.recovery_case_id::text,
    approval.decision_id::text,
    approval.aggregate_version,
    approval.verdict::text,
    approval.requested_at,
    approval.expires_at,
    approval.approver_subject,
    approval.reason_code,
    approval.acted_at,
    recovery_case.amount_due_snapshot_minor,
    recovery_case.currency::text,
    recovery_case.state::text
FROM retrywise.approvals AS approval
JOIN retrywise.recovery_cases AS recovery_case
  ON recovery_case.merchant_id = approval.merchant_id
 AND recovery_case.id = approval.recovery_case_id
WHERE approval.merchant_id = %(merchant_id)s
ORDER BY
    CASE approval.verdict WHEN 'PENDING' THEN 0 ELSE 1 END,
    approval.requested_at DESC,
    approval.id
LIMIT %(limit)s
"""


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def fetchall(self) -> Sequence[Sequence[object]]: ...

    def __enter__(self) -> _Cursor: ...

    def __exit__(self, *args: object) -> bool | None: ...


class _Connection(Protocol):
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
            policy.connect(dsn, component="PostgresOperatorStore"),
        )

    return connect


def _iso(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimeError("operator query timestamp is invalid")
    return value.isoformat().replace("+00:00", "Z")


def _rows(rows: Sequence[Sequence[object]], fields: tuple[str, ...]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for row in rows:
        if len(row) != len(fields):
            raise RuntimeError("operator query returned an unexpected row")
        item: dict[str, object] = {}
        for field, value in zip(fields, row, strict=True):
            item[field] = _iso(value) if isinstance(value, datetime) else value
        result.append(item)
    return result


class PostgresOperatorStore:
    def __init__(self, *, dsn: str, require_tls: bool = False) -> None:
        self._connector = _dsn_factory(dsn, require_tls=require_tls)
        self._audit = PostgresAuditRepository(dsn=dsn, require_tls=require_tls)

    def overview(self, *, merchant_id: str) -> dict[str, object]:
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(_OVERVIEW, {"merchant_id": merchant_id})
            row = cursor.fetchone()
        if row is None or len(row) != 7:
            raise RuntimeError("test overview returned an unexpected row")
        return {
            "environment": "RAZORPAY_TEST_MODE",
            "labels": {
                "value_label": "Actual Razorpay Test Mode evidence",
                "real_money": False,
                "observed_real_merchant_revenue_claimed": False,
            },
            "observed_at": _iso(row[0]),
            "open_cases": row[1],
            "safely_suppressed": row[2],
            "recovered_cases": row[3],
            "test_mode_recovered_minor": row[4],
            "provider_create_runs": row[5],
            "hard_safety_violations": row[6],
        }

    def list_cases(self, *, merchant_id: str, limit: int = 100) -> list[dict[str, object]]:
        if not 1 <= limit <= 200:
            raise ValueError("case limit is invalid")
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(_LIST_CASES, {"merchant_id": merchant_id, "limit": limit})
            rows = cursor.fetchall()
        return _rows(
            rows,
            (
                "id",
                "merchant_order_reference",
                "amount_minor",
                "currency",
                "state",
                "version",
                "payment_method",
                "terminal_reason_code",
                "created_at",
                "updated_at",
                "last_decision_id",
                "last_action_id",
            ),
        )

    def case_detail(self, *, merchant_id: str, recovery_case_id: str) -> dict[str, object] | None:
        params = {"merchant_id": merchant_id, "recovery_case_id": recovery_case_id}
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(_CASE, params)
            case = cursor.fetchone()
            if case is None:
                return None
            cursor.execute(_CASE_DECISIONS, params)
            decisions = cursor.fetchall()
            cursor.execute(_CASE_ACTIONS, params)
            actions = cursor.fetchall()
            cursor.execute(_CASE_INSTRUMENTS, params)
            instruments = cursor.fetchall()
        case_values = _rows(
            (case,),
            (
                "id",
                "logical_order_id",
                "provider_account_id",
                "merchant_order_reference",
                "original_provider_order_id",
                "amount_minor",
                "currency",
                "state",
                "version",
                "attempt_count",
                "contact_count",
                "observation_deadline_at",
                "evaluation_deadline_at",
                "terminal_reason_code",
                "terminal_at",
                "canonical_truth",
                "captured_total_minor",
                "refunded_total_minor",
                "truth_version",
                "provider_snapshot_at",
                "provider_account_identifier",
                "provider_environment",
                "provider_enabled",
                "merchant_kill_switch_enabled",
            ),
        )[0]
        case_values["decisions"] = _rows(
            decisions,
            (
                "id",
                "aggregate_version",
                "model_name",
                "model_version",
                "class_probabilities",
                "requested_diagnosis_mode",
                "executed_diagnosis_engine",
                "diagnosis_latency_ms",
                "diagnosis_fallback_reason_code",
                "shadow_diagnosis",
                "abstained",
                "out_of_distribution",
                "policy_version",
                "selected_action",
                "planning_gate_verdict",
                "planning_gate_reason_codes",
                "expected_value_minor",
                "source_label",
                "created_at",
            ),
        )
        case_values["actions"] = _rows(
            actions,
            (
                "id",
                "action_type",
                "status",
                "attempt_number",
                "max_attempts",
                "effect_gate_verdict",
                "effect_gate_reason_codes",
                "external_reference_id",
                "provider_resource_id",
                "provider_status",
                "reconciliation_status",
                "last_error_code",
                "scheduled_at",
                "first_attempted_at",
                "completed_at",
            ),
        )
        case_values["instruments"] = _rows(
            instruments,
            (
                "id",
                "status",
                "reference_id",
                "provider_payment_link_id",
                "provider_order_id",
                "provider_payment_id",
                "amount_minor",
                "currency",
                "collected_minor",
                "refunded_minor",
                "last_provider_status",
                "reconciliation_status",
                "expires_at",
                "last_reconciled_at",
            ),
        )
        return case_values

    def list_incidents(self, *, merchant_id: str, limit: int = 100) -> list[dict[str, object]]:
        if not 1 <= limit <= 200:
            raise ValueError("incident limit is invalid")
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(_INCIDENTS, {"merchant_id": merchant_id, "limit": limit})
            rows = cursor.fetchall()
        return _rows(
            rows,
            (
                "id",
                "provider_account_id",
                "payment_method",
                "state",
                "severity",
                "confidence",
                "detector_version",
                "threshold_version",
                "first_seen_at",
                "last_seen_at",
                "expires_at",
                "cooling_deadline_at",
            ),
        )

    def list_approvals(self, *, merchant_id: str, limit: int = 100) -> list[dict[str, object]]:
        if not 1 <= limit <= 200:
            raise ValueError("approval limit is invalid")
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(_APPROVALS, {"merchant_id": merchant_id, "limit": limit})
            rows = cursor.fetchall()
        return _rows(
            rows,
            (
                "id",
                "recovery_case_id",
                "decision_id",
                "aggregate_version",
                "verdict",
                "requested_at",
                "expires_at",
                "approver_subject",
                "reason_code",
                "acted_at",
                "amount_minor",
                "currency",
                "case_state",
            ),
        )

    def verify_audit(self, *, merchant_id: str, recovery_case_id: str) -> dict[str, object]:
        result = self._audit.verify_chain(
            merchant_id=merchant_id,
            recovery_case_id=recovery_case_id,
        )
        return {
            "profile": "POSTGRES_AUDIT_CHAIN_V1",
            "valid": result.valid,
            "reason": result.reason.value,
            "checked_entries": result.checked_entries,
            "error_sequence": result.error_sequence,
            "head_hash": result.head_hash,
            "entries": [
                {
                    "id": entry.audit_entry_id,
                    "sequence_number": entry.sequence_number,
                    "entry_type": entry.entry_type,
                    "actor_type": entry.actor_type.value,
                    "facts": dict(entry.facts),
                    "entry_hash": entry.entry_hash,
                    "previous_entry_hash": entry.previous_entry_hash,
                    "created_at": _iso(entry.created_at),
                }
                for entry in result.entries
            ],
        }


__all__ = ["PostgresOperatorStore"]
