"""Durable worker liveness evidence used by API readiness."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol, cast

from .outbox_worker import PollResult
from .postgres_connection import PostgresConnectionPolicy

_UPSERT_HEARTBEAT = """
INSERT INTO retrywise.worker_heartbeats (
    worker_id,
    role,
    code_revision,
    started_at,
    heartbeat_at,
    last_poll_selected,
    last_poll_succeeded,
    last_poll_retried,
    last_poll_dead_lettered,
    last_error_code
) VALUES (
    %(worker_id)s,
    'OUTBOX',
    %(code_revision)s,
    clock_timestamp(),
    clock_timestamp(),
    %(selected)s,
    %(succeeded)s,
    %(retried)s,
    %(dead_lettered)s,
    %(last_error_code)s
)
ON CONFLICT (worker_id) DO UPDATE
SET code_revision = EXCLUDED.code_revision,
    heartbeat_at = clock_timestamp(),
    last_poll_selected = EXCLUDED.last_poll_selected,
    last_poll_succeeded = EXCLUDED.last_poll_succeeded,
    last_poll_retried = EXCLUDED.last_poll_retried,
    last_poll_dead_lettered = EXCLUDED.last_poll_dead_lettered,
    last_error_code = EXCLUDED.last_error_code
RETURNING worker_id
"""

_CHECK_FRESH_WORKER = """
SELECT EXISTS (
    SELECT 1
    FROM retrywise.worker_heartbeats
    WHERE role = 'OUTBOX'
      AND code_revision = %(code_revision)s
      AND heartbeat_at >= clock_timestamp() - %(maximum_age)s
)
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
            policy.connect(dsn, component="PostgresWorkerHeartbeatRepository"),
        )

    return connect


@dataclass(frozen=True, slots=True)
class WorkerHeartbeat:
    worker_id: str
    code_revision: str

    def __post_init__(self) -> None:
        for field, maximum in (("worker_id", 128), ("code_revision", 128)):
            value = getattr(self, field)
            if (
                not isinstance(value, str)
                or not value
                or value != value.strip()
                or len(value) > maximum
            ):
                raise ValueError(f"{field} is invalid")


class PostgresWorkerHeartbeatRepository:
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

    def beat(
        self,
        heartbeat: WorkerHeartbeat,
        *,
        result: PollResult | None = None,
        last_error_code: str | None = None,
    ) -> None:
        if not isinstance(heartbeat, WorkerHeartbeat):
            raise TypeError("heartbeat must be WorkerHeartbeat")
        selected = succeeded = retried = dead_lettered = 0
        if result is not None:
            if not isinstance(result, PollResult):
                raise TypeError("result must be PollResult")
            selected = result.selected
            succeeded = result.succeeded
            retried = result.retried
            dead_lettered = result.dead_lettered
        if last_error_code is not None and (
            not last_error_code
            or last_error_code != last_error_code.strip()
            or len(last_error_code) > 200
        ):
            raise ValueError("last_error_code is invalid")
        params: dict[str, object] = {
            "worker_id": heartbeat.worker_id,
            "code_revision": heartbeat.code_revision,
            "selected": selected,
            "succeeded": succeeded,
            "retried": retried,
            "dead_lettered": dead_lettered,
            "last_error_code": last_error_code,
        }
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_UPSERT_HEARTBEAT, params)
            if cursor.fetchone() != (heartbeat.worker_id,):
                raise RuntimeError("worker heartbeat write was not confirmed")

    def is_fresh(
        self,
        *,
        code_revision: str,
        maximum_age: timedelta = timedelta(seconds=45),
    ) -> bool:
        if not code_revision or len(code_revision) > 128:
            raise ValueError("code_revision is invalid")
        if not isinstance(maximum_age, timedelta) or not timedelta(0) < maximum_age <= timedelta(
            minutes=5
        ):
            raise ValueError("maximum_age is invalid")
        with self._connector() as connection, connection.cursor() as cursor:
            cursor.execute(
                _CHECK_FRESH_WORKER,
                {"code_revision": code_revision, "maximum_age": maximum_age},
            )
            row = cursor.fetchone()
        if row is None or len(row) != 1 or type(row[0]) is not bool:
            raise RuntimeError("worker readiness query returned an unexpected row")
        return row[0]


__all__ = ["PostgresWorkerHeartbeatRepository", "WorkerHeartbeat"]
