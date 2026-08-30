from __future__ import annotations

import hashlib
import json
import re
import unittest
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from retrywise.packages.razorpay import (
    InboxConflictError,
    InboxRecord,
    InboxWriteResult,
    normalize_verified_webhook,
)
from retrywise.services.control_plane.postgres_inbox import PostgresWebhookInbox

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")


def _raw_body(*, payment_id: str = "pay_test_1") -> bytes:
    return json.dumps(
        {
            "account_id": "acc_test_1",
            "created_at": 1_788_000_000,
            "event": "payment.failed",
            "payload": {
                "payment": {
                    "entity": {
                        "amount": 129_900,
                        "currency": "INR",
                        "id": payment_id,
                        "order_id": "order_test_1",
                        "status": "failed",
                    }
                }
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _record(*, payment_id: str = "pay_test_1") -> InboxRecord:
    raw_body = _raw_body(payment_id=payment_id)
    event = normalize_verified_webhook(raw_body, event_id="evt_test_1")
    return InboxRecord(event=event, received_at_epoch=1_788_000_001)


RowFactory = Callable[[Mapping[str, object]], Sequence[object] | None]


@dataclass(frozen=True)
class _Step:
    marker: str
    row_factory: RowFactory = lambda _params: None
    error: BaseException | None = None


class _FakeCursor:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection
        self._row: Sequence[object] | None = None

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: Mapping[str, object]) -> None:
        if not self._connection.steps:
            raise AssertionError(f"unexpected query: {query}")
        step = self._connection.steps.pop(0)
        if step.marker not in query:
            raise AssertionError(f"expected query containing {step.marker!r}, got {query!r}")
        copied_params = dict(params)
        self._connection.executions.append((query, copied_params))
        if step.error is not None:
            raise step.error
        self._row = step.row_factory(copied_params)

    def fetchone(self) -> Sequence[object] | None:
        return self._row


class _FakeTransaction:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def __enter__(self) -> object:
        self._connection.transactions_started += 1
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: object | None,
    ) -> None:
        if exc_type is None:
            self._connection.transactions_committed += 1
        else:
            self._connection.transactions_rolled_back += 1
        return None


class _FakeConnection:
    def __init__(self, steps: list[_Step]) -> None:
        self.steps = list(steps)
        self.executions: list[tuple[str, dict[str, object]]] = []
        self.transactions_started = 0
        self.transactions_committed = 0
        self.transactions_rolled_back = 0
        self.closed = 0

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed += 1
        return None

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)


class _FakeConnector:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection
        self.calls = 0

    def __call__(self) -> _FakeConnection:
        self.calls += 1
        return self.connection


def _inserted_id(params: Mapping[str, object]) -> Sequence[object]:
    return (params["provider_event_record_id"],)


class PostgresWebhookInboxTests(unittest.TestCase):
    def _adapter(self, connection: _FakeConnection) -> tuple[PostgresWebhookInbox, _FakeConnector]:
        connector = _FakeConnector(connection)
        adapter = PostgresWebhookInbox(
            merchant_id=MERCHANT_ID,
            provider_account_id=PROVIDER_ACCOUNT_ID,
            provider_account_identifier="acc_test_1",
            connector=connector,
        )
        return adapter, connector

    def test_new_event_commits_evidence_inbox_and_outbox_atomically(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FOR SHARE", lambda _params: (True,)),
                _Step("INSERT INTO retrywise.provider_events", _inserted_id),
                _Step("INSERT INTO retrywise.inbox_events"),
                _Step("INSERT INTO retrywise.outbox_jobs"),
            ]
        )
        adapter, connector = self._adapter(connection)

        result = adapter.store_once(_record())

        self.assertIs(result, InboxWriteResult.STORED)
        self.assertEqual(connector.calls, 1)
        self.assertEqual(connection.transactions_started, 1)
        self.assertEqual(connection.transactions_committed, 1)
        self.assertEqual(connection.transactions_rolled_back, 0)
        self.assertEqual(connection.closed, 1)
        self.assertEqual(connection.steps, [])

        binding_params = connection.executions[0][1]
        provider_params = connection.executions[1][1]
        inbox_params = connection.executions[2][1]
        outbox_params = connection.executions[3][1]
        self.assertEqual(binding_params["provider_account_identifier"], "acc_test_1")
        generated_ids = [
            provider_params["provider_event_record_id"],
            inbox_params["inbox_event_id"],
            outbox_params["outbox_job_id"],
        ]
        self.assertTrue(all(isinstance(value, str) for value in generated_ids))
        self.assertTrue(all(ULID_RE.fullmatch(str(value)) for value in generated_ids))
        self.assertEqual(generated_ids, sorted(generated_ids))
        self.assertEqual(len(set(generated_ids)), 3)

        self.assertEqual(provider_params["merchant_id"], MERCHANT_ID)
        self.assertEqual(provider_params["provider_account_id"], PROVIDER_ACCOUNT_ID)
        self.assertEqual(provider_params["body_sha256"], hashlib.sha256(_raw_body()).digest())
        self.assertEqual(
            provider_params["provider_occurred_at"],
            datetime.fromtimestamp(1_788_000_000, UTC),
        )
        self.assertEqual(
            provider_params["received_at"],
            datetime.fromtimestamp(1_788_000_001, UTC),
        )
        canonical = json.loads(str(provider_params["canonical_event"]))
        self.assertEqual(canonical["event_id"], "evt_test_1")
        self.assertEqual(canonical["resource"]["id"], "pay_test_1")

        self.assertEqual(
            inbox_params["provider_event_record_id"],
            provider_params["provider_event_record_id"],
        )
        command = json.loads(str(outbox_params["command_payload"]))
        self.assertEqual(command["inbox_event_id"], inbox_params["inbox_event_id"])
        self.assertEqual(
            command["provider_event_record_id"],
            provider_params["provider_event_record_id"],
        )
        self.assertEqual(command["schema_version"], 1)
        self.assertEqual(
            outbox_params["idempotency_key"],
            f"normalized-provider-event:{provider_params['provider_event_record_id']}",
        )

    def test_exact_duplicate_returns_duplicate_without_second_work_item(self) -> None:
        digest = hashlib.sha256(_raw_body()).digest()
        connection = _FakeConnection(
            [
                _Step("FOR SHARE", lambda _params: (True,)),
                _Step("INSERT INTO retrywise.provider_events"),
                _Step(
                    "SELECT body_sha256",
                    lambda _params: (memoryview(digest),),
                ),
            ]
        )
        adapter, _connector = self._adapter(connection)

        result = adapter.store_once(_record())

        self.assertIs(result, InboxWriteResult.DUPLICATE)
        self.assertEqual(len(connection.executions), 3)
        self.assertEqual(connection.transactions_committed, 1)
        self.assertEqual(connection.transactions_rolled_back, 0)
        self.assertEqual(connection.steps, [])

    def test_reused_provider_event_id_with_other_body_rolls_back_as_conflict(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FOR SHARE", lambda _params: (True,)),
                _Step("INSERT INTO retrywise.provider_events"),
                _Step("SELECT body_sha256", lambda _params: (b"\x00" * 32,)),
            ]
        )
        adapter, _connector = self._adapter(connection)

        with self.assertRaisesRegex(InboxConflictError, "different content"):
            adapter.store_once(_record())

        self.assertEqual(connection.transactions_committed, 0)
        self.assertEqual(connection.transactions_rolled_back, 1)
        self.assertEqual(connection.closed, 1)

    def test_missing_row_after_unique_conflict_is_an_integrity_failure(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FOR SHARE", lambda _params: (True,)),
                _Step("INSERT INTO retrywise.provider_events"),
                _Step("SELECT body_sha256"),
            ]
        )
        adapter, _connector = self._adapter(connection)

        with self.assertRaisesRegex(RuntimeError, "duplicate lookup"):
            adapter.store_once(_record())

        self.assertEqual(connection.transactions_rolled_back, 1)

    def test_outbox_insert_failure_rolls_back_the_entire_unit(self) -> None:
        connection = _FakeConnection(
            [
                _Step("FOR SHARE", lambda _params: (True,)),
                _Step("INSERT INTO retrywise.provider_events", _inserted_id),
                _Step("INSERT INTO retrywise.inbox_events"),
                _Step(
                    "INSERT INTO retrywise.outbox_jobs",
                    error=RuntimeError("simulated database failure"),
                ),
            ]
        )
        adapter, _connector = self._adapter(connection)

        with self.assertRaisesRegex(RuntimeError, "simulated database failure"):
            adapter.store_once(_record())

        self.assertEqual(connection.transactions_committed, 0)
        self.assertEqual(connection.transactions_rolled_back, 1)
        self.assertEqual(connection.closed, 1)

    def test_readiness_checks_schema_and_bound_enabled_account(self) -> None:
        for database_value in (True, False):
            with self.subTest(database_value=database_value):
                connection = _FakeConnection(
                    [
                        _Step(
                            "to_regclass('retrywise.provider_events')",
                            lambda _params, value=database_value: (value,),
                        )
                    ]
                )
                adapter, connector = self._adapter(connection)

                self.assertIs(adapter.check_ready(), database_value)
                self.assertTrue(adapter.durable)
                self.assertEqual(connector.calls, 1)
                self.assertEqual(connection.transactions_committed, 1)
                params = connection.executions[0][1]
                self.assertEqual(params["merchant_id"], MERCHANT_ID)
                self.assertEqual(params["provider_account_id"], PROVIDER_ACCOUNT_ID)
                self.assertEqual(params["provider_account_identifier"], "acc_test_1")

    def test_store_rechecks_database_account_binding_inside_transaction(self) -> None:
        connection = _FakeConnection([_Step("FOR SHARE")])
        adapter, _connector = self._adapter(connection)

        with self.assertRaisesRegex(RuntimeError, "binding is unavailable"):
            adapter.store_once(_record())

        self.assertEqual(connection.transactions_committed, 0)
        self.assertEqual(connection.transactions_rolled_back, 1)
        self.assertEqual(len(connection.executions), 1)

    def test_record_account_mismatch_fails_before_database_use(self) -> None:
        connection = _FakeConnection([])
        adapter, connector = self._adapter(connection)
        record = _record()
        mismatched = InboxRecord(
            event=replace(record.event, provider_account_id="acc_other"),
            received_at_epoch=record.received_at_epoch,
        )

        with self.assertRaisesRegex(ValueError, "does not match adapter binding"):
            adapter.store_once(mismatched)

        self.assertEqual(connector.calls, 0)

    def test_constructor_requires_database_shaped_internal_ids_and_one_connector(self) -> None:
        connection = _FakeConnection([])
        with self.assertRaisesRegex(ValueError, "merchant_id"):
            PostgresWebhookInbox(
                merchant_id="merchant-1",
                provider_account_id=PROVIDER_ACCOUNT_ID,
                provider_account_identifier="acc_test_1",
                connector=_FakeConnector(connection),
            )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            PostgresWebhookInbox(
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
                provider_account_identifier="acc_test_1",
            )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            PostgresWebhookInbox(
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
                provider_account_identifier="acc_test_1",
                dsn="postgresql://localhost/retrywise",
                connector=_FakeConnector(connection),
            )
        with self.assertRaisesRegex(ValueError, "policy is verifiable"):
            PostgresWebhookInbox(
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
                provider_account_identifier="acc_test_1",
                connector=_FakeConnector(connection),
                require_tls=True,
            )

    def test_malformed_digest_is_rejected_before_opening_a_connection(self) -> None:
        connection = _FakeConnection([])
        adapter, connector = self._adapter(connection)
        record = _record()
        malformed = InboxRecord(
            event=replace(record.event, raw_body_sha256="AA " * 32),
            received_at_epoch=record.received_at_epoch,
        )

        with self.assertRaisesRegex(ValueError, "lowercase hexadecimal SHA-256"):
            adapter.store_once(malformed)

        self.assertEqual(connector.calls, 0)


if __name__ == "__main__":
    unittest.main()
