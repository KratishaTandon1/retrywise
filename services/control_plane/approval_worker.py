"""Worker-side materialization of operator-approved recovery effects."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, cast

from .approval_command import (
    ApprovalCommandCodecError,
    MaterializeApprovedActionCommand,
    decode_materialize_approved_action_command,
)
from .approval_service import ApprovalConflict, ApprovalNotFound, PostgresApprovalService
from .outbox import RetryMode
from .outbox_worker import HandlerResult
from .postgres_connection import PostgresConnectionPolicy
from .postgres_outbox import ClaimedOutboxCommand

_COMPLETION = """
SELECT
    approval.verdict::text,
    action.id::text,
    effect_job.id::text
FROM retrywise.approvals AS approval
LEFT JOIN retrywise.actions AS action
  ON action.merchant_id = approval.merchant_id
 AND action.approval_id = approval.id
LEFT JOIN retrywise.outbox_jobs AS effect_job
  ON effect_job.merchant_id = action.merchant_id
 AND effect_job.aggregate_type = 'ACTION'
 AND effect_job.aggregate_id = action.id::text
 AND effect_job.command_type = 'CREATE_STANDARD_PAYMENT_LINK'
WHERE approval.merchant_id = %(merchant_id)s
  AND approval.id = %(approval_id)s
"""


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

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
            policy.connect(dsn, component="PostgresApprovalCompletionProbe"),
        )

    return connect


class PostgresApprovalCompletionProbe:
    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        self._connector = (
            _dsn_factory(dsn, require_tls=require_tls)
            if dsn is not None
            else cast(ConnectionFactory, connector)
        )

    def result(self, command: MaterializeApprovedActionCommand) -> str | None:
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(
                _COMPLETION,
                {
                    "merchant_id": command.merchant_id,
                    "approval_id": command.approval_id,
                },
            )
            row = cursor.fetchone()
        if row is None:
            return None
        if len(row) != 3 or not isinstance(row[0], str):
            raise RuntimeError("approval_completion_snapshot_unsafe")
        verdict = row[0]
        if verdict == "APPROVED":
            if not isinstance(row[1], str) or not isinstance(row[2], str):
                raise RuntimeError("approved_action_materialization_incomplete")
            return f"approved:{row[1]}:{row[2]}"
        if verdict in {"REJECTED", "EXPIRED", "CANCELLED"}:
            return verdict.casefold()
        return None


class MaterializeApprovedActionHandler:
    def __init__(
        self,
        *,
        service: PostgresApprovalService,
        completion_probe: PostgresApprovalCompletionProbe,
    ) -> None:
        self._service = service
        self._completion_probe = completion_probe

    def __call__(self, claimed: ClaimedOutboxCommand) -> HandlerResult:
        try:
            command = decode_materialize_approved_action_command(
                claimed.command_payload,
                command_type=claimed.command_type,
                command_schema_version=claimed.command_schema_version,
            )
        except (ApprovalCommandCodecError, TypeError, ValueError):
            return HandlerResult.dead_letter("invalid_approval_materialization_command")
        if (
            claimed.aggregate_type != "APPROVAL"
            or claimed.aggregate_id != command.approval_id
            or claimed.merchant_id != command.merchant_id
            or claimed.idempotency_key != f"materialize-approved-action:{command.approval_id}"
        ):
            return HandlerResult.dead_letter("invalid_approval_materialization_command")
        try:
            completed = self._completion_probe.result(command)
            if completed is not None:
                return HandlerResult.succeeded(completed)
            result = self._service.act(
                merchant_id=command.merchant_id,
                approval_id=command.approval_id,
                operator_subject=command.operator_subject,
                verdict="APPROVED",
                reason_code=command.reason_code,
            )
        except ApprovalNotFound:
            try:
                completed = self._completion_probe.result(command)
            except Exception:
                completed = None
            if completed is not None:
                return HandlerResult.succeeded(completed)
            return HandlerResult.dead_letter("approval_no_longer_exists")
        except ApprovalConflict as exc:
            reason = str(exc)
            if reason == "approval_state_changed":
                try:
                    completed = self._completion_probe.result(command)
                except Exception:
                    completed = None
                if completed is not None:
                    return HandlerResult.succeeded(completed)
            return HandlerResult.dead_letter(f"approval_conflict:{reason}"[:500])
        except Exception:
            return HandlerResult.retry_safely(
                "approval_fresh_truth_unavailable",
                retry_mode=RetryMode.RECONCILE_ONLY,
            )
        reference = result.action_id or result.verdict.casefold()
        return HandlerResult.succeeded(
            f"approval:{result.approval_id}:{result.verdict.casefold()}:{reference}"
        )


__all__ = [
    "MaterializeApprovedActionHandler",
    "PostgresApprovalCompletionProbe",
]
