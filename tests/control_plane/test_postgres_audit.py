from __future__ import annotations

import json
import unittest
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from unittest.mock import patch

from retrywise.packages.domain.ledger import DecisionLedger
from retrywise.services.control_plane.postgres_audit import (
    POSTGRES_AUDIT_VERIFICATION_PROFILE,
    AuditActorType,
    AuditInputError,
    AuditRepositoryError,
    AuditRepositoryErrorCode,
    AuditVerificationReason,
    PostgresAuditAppender,
    PostgresAuditRepository,
    TransactionalAuditAppender,
    audit_entry_hash_v1,
)
from retrywise.services.control_plane.postgres_connection import PostgresConnectionPolicy

NOW = datetime(2026, 8, 29, 12, 0, 0, 123456, tzinfo=UTC)
MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER_MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
ENTRY_ID_1 = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
ENTRY_ID_2 = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
FACTS_1 = {
    "amount_minor": 1200,
    "gate": {"approved": False},
    "reason_code": "LATE_CAPTURE_WINDOW_OPEN",
}
FACTS_2 = {
    "action_id": "01ARZ3NDEKTSV4RRFFQ69G5FB0",
    "reason_code": "FRESH_PROVIDER_TRUTH_CONFIRMED",
}


RowFactory = Callable[[Mapping[str, object]], list[Sequence[object]]]


@dataclass(frozen=True)
class _Step:
    marker: str
    rows: RowFactory = lambda _params: []
    error: Exception | None = None


class _FakeCursor:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection
        self._rows: list[Sequence[object]] = []

    def __enter__(self) -> _FakeCursor:
        self._connection.cursor_open = True
        return self

    def __exit__(self, *_args: object) -> None:
        self._connection.cursor_open = False
        return None

    def execute(self, query: str, params: Mapping[str, object]) -> None:
        if not self._connection.in_transaction:
            raise AssertionError("audit query must execute inside a transaction")
        if not self._connection.steps:
            raise AssertionError(f"unexpected query: {query}")
        step = self._connection.steps.pop(0)
        if step.marker not in query:
            raise AssertionError(f"expected query containing {step.marker!r}, got {query!r}")
        copied_params = dict(params)
        self._connection.executions.append((query, copied_params))
        if step.error is not None:
            raise step.error
        self._rows = step.rows(copied_params)

    def fetchone(self) -> Sequence[object] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> Sequence[Sequence[object]]:
        return list(self._rows)


class _FakeTransaction:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def __enter__(self) -> object:
        self._connection.in_transaction = True
        self._connection.transactions_started += 1
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: object | None,
    ) -> None:
        self._connection.in_transaction = False
        if exc_type is None:
            self._connection.transactions_committed += 1
        else:
            self._connection.transactions_rolled_back += 1
        return None


class _FakeConnection:
    def __init__(self, steps: Sequence[_Step]) -> None:
        self.steps = list(steps)
        self.executions: list[tuple[str, dict[str, object]]] = []
        self.in_transaction = False
        self.cursor_open = False
        self.transactions_started = 0
        self.transactions_committed = 0
        self.transactions_rolled_back = 0
        self.connection_contexts_entered = 0
        self.connection_contexts_exited = 0

    def __enter__(self) -> _FakeConnection:
        self.connection_contexts_entered += 1
        return self

    def __exit__(self, *_args: object) -> None:
        self.connection_contexts_exited += 1
        return None

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)


class _FakeConnector:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection
        self.calls = 0

    def __call__(self) -> _FakeConnection:
        self.calls += 1
        return self.connection


def _step(marker: str, *rows: Sequence[object]) -> _Step:
    return _Step(marker, lambda _params: list(rows))


def _repository(*steps: _Step) -> tuple[PostgresAuditRepository, _FakeConnection]:
    connection = _FakeConnection(steps)
    return PostgresAuditRepository(connector=_FakeConnector(connection)), connection


def _audit_row(
    *,
    sequence_number: int,
    audit_entry_id: str,
    facts: Mapping[str, object],
    previous_entry_hash: str | None,
    created_at: datetime,
    merchant_id: str = MERCHANT_ID,
    recovery_case_id: str = CASE_ID,
    entry_type: str = "GATE_EVALUATED",
    actor_type: str = "SYSTEM",
    actor_subject: str | None = None,
) -> tuple[object, ...]:
    entry_hash = audit_entry_hash_v1(
        audit_entry_id=audit_entry_id,
        merchant_id=merchant_id,
        recovery_case_id=recovery_case_id,
        sequence_number=sequence_number,
        entry_type=entry_type,
        actor_type=actor_type,
        actor_subject=actor_subject,
        facts=facts,
        previous_entry_hash=previous_entry_hash,
        created_at=created_at,
    )
    return (
        audit_entry_id,
        merchant_id,
        recovery_case_id,
        sequence_number,
        entry_type,
        actor_type,
        actor_subject,
        {"audit_hash_schema_version": 1, "facts": dict(facts)},
        bytes.fromhex(previous_entry_hash) if previous_entry_hash else None,
        bytes.fromhex(entry_hash),
        created_at,
    )


class AuditHashContractTests(unittest.TestCase):
    def test_v1_hash_has_a_stable_vector_and_is_not_domain_fixture_evidence(self) -> None:
        digest = audit_entry_hash_v1(
            audit_entry_id=ENTRY_ID_1,
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
            sequence_number=1,
            entry_type="GATE_EVALUATED",
            actor_type=AuditActorType.SYSTEM,
            actor_subject=None,
            facts=FACTS_1,
            previous_entry_hash=None,
            created_at=NOW,
        )

        self.assertEqual(
            "4e58a6bcc0ed609187c01b48e6a278ce80b33c2f117fd41db1dceb2718773f21",
            digest,
        )
        domain_entry = DecisionLedger(CASE_ID).append(
            entry_type="GATE_EVALUATED",
            payload=FACTS_1,
            recorded_at=NOW,
        )
        self.assertNotEqual(domain_entry.entry_hash, digest)
        self.assertEqual("POSTGRES_AUDIT_CHAIN_V1", POSTGRES_AUDIT_VERIFICATION_PROFILE)

    def test_hash_binds_tenant_case_actor_and_previous_head(self) -> None:
        base = dict(
            audit_entry_id=ENTRY_ID_1,
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
            sequence_number=1,
            entry_type="GATE_EVALUATED",
            actor_type=AuditActorType.SYSTEM,
            actor_subject=None,
            facts=FACTS_1,
            previous_entry_hash=None,
            created_at=NOW,
        )
        digest = audit_entry_hash_v1(**base)  # type: ignore[arg-type]
        changed = {**base, "merchant_id": OTHER_MERCHANT_ID}
        self.assertNotEqual(digest, audit_entry_hash_v1(**changed))  # type: ignore[arg-type]
        changed = {**base, "recovery_case_id": ENTRY_ID_2}
        self.assertNotEqual(digest, audit_entry_hash_v1(**changed))  # type: ignore[arg-type]

    def test_non_pii_contract_rejects_free_text_and_sensitive_shapes(self) -> None:
        base = dict(
            audit_entry_id=ENTRY_ID_1,
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
            sequence_number=1,
            entry_type="GATE_EVALUATED",
            actor_type=AuditActorType.SYSTEM,
            actor_subject=None,
            previous_entry_hash=None,
            created_at=NOW,
        )
        bad_facts = (
            {"reason_code": "this is free text"},
            {"outcome": "Alice"},
            {"email": "person.example"},
            {"remote_ip": "192.168.1.8"},
            {"phone_hash": "9876543210"},
            {"score": 0.9},
            {"secret_ref": "vault://audit/key"},
            {"error_code": "some error"},
        )
        for facts in bad_facts:
            with (
                self.subTest(facts=facts),
                self.assertRaisesRegex(AuditInputError, "^AUDIT_INVALID_ARGUMENT$"),
            ):
                audit_entry_hash_v1(facts=facts, **base)  # type: ignore[arg-type]
        with self.assertRaises(AuditInputError):
            audit_entry_hash_v1(
                facts=FACTS_1,
                **{**base, "actor_subject": "system:Alice Smith"},  # type: ignore[arg-type]
            )


class PostgresAuditAppendTests(unittest.TestCase):
    def test_transaction_scoped_appender_uses_only_the_caller_owned_cursor(self) -> None:
        connection = _FakeConnection(
            [
                _step("pg_advisory_xact_lock", (None,)),
                _step("FROM retrywise.recovery_cases", (True,)),
                _step("FROM retrywise.audit_entries"),
                _Step(
                    "INSERT INTO retrywise.audit_entries",
                    lambda params: [
                        (
                            params["audit_entry_id"],
                            params["sequence_number"],
                            params["entry_hash"],
                            params["created_at"],
                        )
                    ],
                ),
            ]
        )
        appender: TransactionalAuditAppender = PostgresAuditAppender()

        with connection.transaction(), connection.cursor() as cursor:
            entry = appender.append(
                cursor=cursor,
                audit_entry_id=ENTRY_ID_1,
                merchant_id=MERCHANT_ID,
                recovery_case_id=CASE_ID,
                entry_type="GATE_EVALUATED",
                actor_type=AuditActorType.SYSTEM,
                actor_subject=None,
                facts=FACTS_1,
                created_at=NOW,
            )
            self.assertEqual(1, connection.transactions_started)
            self.assertEqual(0, connection.transactions_committed)
            self.assertEqual(0, connection.connection_contexts_entered)

        self.assertEqual(1, entry.sequence_number)
        self.assertEqual(1, connection.transactions_started)
        self.assertEqual(1, connection.transactions_committed)
        self.assertEqual(0, connection.connection_contexts_entered)
        self.assertEqual(0, connection.connection_contexts_exited)
        self.assertFalse(connection.steps)

    def test_repository_append_owns_exactly_one_connection_and_transaction(self) -> None:
        connection = _FakeConnection(
            [
                _step("pg_advisory_xact_lock", (None,)),
                _step("FROM retrywise.recovery_cases", (True,)),
                _step("FROM retrywise.audit_entries"),
                _Step(
                    "INSERT INTO retrywise.audit_entries",
                    lambda params: [
                        (
                            params["audit_entry_id"],
                            params["sequence_number"],
                            params["entry_hash"],
                            params["created_at"],
                        )
                    ],
                ),
            ]
        )
        connector = _FakeConnector(connection)
        repository = PostgresAuditRepository(connector=connector)

        repository.append(
            audit_entry_id=ENTRY_ID_1,
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
            entry_type="GATE_EVALUATED",
            actor_type=AuditActorType.SYSTEM,
            actor_subject=None,
            facts=FACTS_1,
            created_at=NOW,
        )

        self.assertEqual(1, connector.calls)
        self.assertEqual(1, connection.connection_contexts_entered)
        self.assertEqual(1, connection.connection_contexts_exited)
        self.assertEqual(1, connection.transactions_started)
        self.assertEqual(1, connection.transactions_committed)
        self.assertEqual(0, connection.transactions_rolled_back)

    def test_transaction_scoped_appender_rejects_a_mismatched_returning_row(self) -> None:
        connection = _FakeConnection(
            [
                _step("pg_advisory_xact_lock", (None,)),
                _step("FROM retrywise.recovery_cases", (True,)),
                _step("FROM retrywise.audit_entries"),
                _step(
                    "INSERT INTO retrywise.audit_entries",
                    (ENTRY_ID_1, 1, bytes.fromhex("0" * 64), NOW),
                ),
            ]
        )
        appender = PostgresAuditAppender()

        with (
            self.assertRaises(AuditRepositoryError) as caught,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            appender.append(
                cursor=cursor,
                audit_entry_id=ENTRY_ID_1,
                merchant_id=MERCHANT_ID,
                recovery_case_id=CASE_ID,
                entry_type="GATE_EVALUATED",
                actor_type=AuditActorType.SYSTEM,
                actor_subject=None,
                facts=FACTS_1,
                created_at=NOW,
            )

        self.assertIs(AuditRepositoryErrorCode.STORAGE_FAILURE, caught.exception.code)
        self.assertEqual(1, connection.transactions_started)
        self.assertEqual(0, connection.transactions_committed)
        self.assertEqual(1, connection.transactions_rolled_back)

    def test_first_append_locks_exact_case_and_commits_versioned_payload(self) -> None:
        repository, connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases", (True,)),
            _step("FROM retrywise.audit_entries"),
            _Step(
                "INSERT INTO retrywise.audit_entries",
                lambda params: [
                    (
                        params["audit_entry_id"],
                        params["sequence_number"],
                        params["entry_hash"],
                        params["created_at"],
                    )
                ],
            ),
        )

        entry = repository.append(
            audit_entry_id=ENTRY_ID_1,
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
            entry_type="GATE_EVALUATED",
            actor_type=AuditActorType.SYSTEM,
            actor_subject=None,
            facts=FACTS_1,
            created_at=NOW,
        )

        self.assertEqual(1, entry.sequence_number)
        self.assertIsNone(entry.previous_entry_hash)
        with self.assertRaises(TypeError):
            entry.facts["amount_minor"] = 999  # type: ignore[index]
        self.assertEqual(1, connection.transactions_committed)
        self.assertFalse(connection.steps)
        case_params = connection.executions[1][1]
        self.assertEqual(MERCHANT_ID, case_params["merchant_id"])
        self.assertEqual(CASE_ID, case_params["recovery_case_id"])
        inserted = connection.executions[3][1]
        self.assertIsNone(inserted["previous_entry_hash"])
        self.assertEqual(bytes.fromhex(entry.entry_hash), inserted["entry_hash"])
        self.assertEqual(
            {"audit_hash_schema_version": 1, "facts": FACTS_1},
            json.loads(str(inserted["payload_json"])),
        )

    def test_continuation_uses_locked_head_and_rejects_time_regression(self) -> None:
        first_hash = audit_entry_hash_v1(
            audit_entry_id=ENTRY_ID_1,
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
            sequence_number=1,
            entry_type="GATE_EVALUATED",
            actor_type=AuditActorType.SYSTEM,
            actor_subject=None,
            facts=FACTS_1,
            previous_entry_hash=None,
            created_at=NOW,
        )
        repository, connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases", (True,)),
            _step("FROM retrywise.audit_entries", (1, bytes.fromhex(first_hash), NOW)),
            _Step(
                "INSERT INTO retrywise.audit_entries",
                lambda params: [
                    (
                        params["audit_entry_id"],
                        params["sequence_number"],
                        params["entry_hash"],
                        params["created_at"],
                    )
                ],
            ),
        )
        entry = repository.append(
            audit_entry_id=ENTRY_ID_2,
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
            entry_type="ACTION_AUTHORIZED",
            actor_type=AuditActorType.WORKER,
            actor_subject=f"worker:{ENTRY_ID_1}",
            facts=FACTS_2,
            created_at=NOW + timedelta(seconds=1),
        )
        self.assertEqual(2, entry.sequence_number)
        self.assertEqual(first_hash, entry.previous_entry_hash)
        self.assertEqual(
            bytes.fromhex(first_hash), connection.executions[3][1]["previous_entry_hash"]
        )

        regressing, regressing_connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases", (True,)),
            _step("FROM retrywise.audit_entries", (1, bytes.fromhex(first_hash), NOW)),
        )
        with self.assertRaises(AuditRepositoryError) as caught:
            regressing.append(
                audit_entry_id=ENTRY_ID_2,
                merchant_id=MERCHANT_ID,
                recovery_case_id=CASE_ID,
                entry_type="ACTION_AUTHORIZED",
                actor_type="SYSTEM",
                actor_subject=None,
                facts=FACTS_2,
                created_at=NOW - timedelta(microseconds=1),
            )
        self.assertIs(AuditRepositoryErrorCode.TIMESTAMP_REGRESSION, caught.exception.code)
        self.assertEqual(1, regressing_connection.transactions_rolled_back)

    def test_missing_case_and_database_failure_are_stable_and_non_sensitive(self) -> None:
        missing, missing_connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases"),
        )
        with self.assertRaises(AuditRepositoryError) as caught:
            missing.append(
                audit_entry_id=ENTRY_ID_1,
                merchant_id=MERCHANT_ID,
                recovery_case_id=CASE_ID,
                entry_type="GATE_EVALUATED",
                actor_type="SYSTEM",
                actor_subject=None,
                facts=FACTS_1,
                created_at=NOW,
            )
        self.assertEqual("AUDIT_CASE_NOT_FOUND", str(caught.exception))
        self.assertEqual(1, missing_connection.transactions_rolled_back)

        broken, _connection = _repository(
            _Step("pg_advisory_xact_lock", error=RuntimeError("password=do-not-leak"))
        )
        with self.assertRaises(AuditRepositoryError) as caught:
            broken.append(
                audit_entry_id=ENTRY_ID_1,
                merchant_id=MERCHANT_ID,
                recovery_case_id=CASE_ID,
                entry_type="GATE_EVALUATED",
                actor_type="SYSTEM",
                actor_subject=None,
                facts=FACTS_1,
                created_at=NOW,
            )
        self.assertEqual("AUDIT_STORAGE_FAILURE", str(caught.exception))
        self.assertNotIn("password", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)


class PostgresAuditVerificationTests(unittest.TestCase):
    def _two_rows(self) -> tuple[tuple[object, ...], tuple[object, ...], str]:
        first = _audit_row(
            sequence_number=1,
            audit_entry_id=ENTRY_ID_1,
            facts=FACTS_1,
            previous_entry_hash=None,
            created_at=NOW,
        )
        first_hash = cast(bytes, first[9]).hex()
        second = _audit_row(
            sequence_number=2,
            audit_entry_id=ENTRY_ID_2,
            facts=FACTS_2,
            previous_entry_hash=first_hash,
            created_at=NOW + timedelta(seconds=1),
            entry_type="ACTION_AUTHORIZED",
            actor_type="WORKER",
            actor_subject=f"worker:{ENTRY_ID_1}",
        )
        return first, second, first_hash

    def test_reads_keyset_pages_under_lock_and_returns_only_complete_verified_chain(self) -> None:
        first, second, _first_hash = self._two_rows()
        repository, connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases", (True,)),
            _step("sequence_number >", first),
            _step("sequence_number >", second),
            _step("sequence_number >"),
        )

        result = repository.verify_chain(
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
            page_size=1,
        )

        self.assertTrue(result.valid)
        self.assertIs(AuditVerificationReason.OK, result.reason)
        self.assertEqual(2, result.checked_entries)
        self.assertEqual(2, len(result.entries))
        self.assertEqual(result.entries[-1].entry_hash, result.head_hash)
        self.assertEqual(POSTGRES_AUDIT_VERIFICATION_PROFILE, result.profile)
        page_params = [
            params for query, params in connection.executions if "sequence_number >" in query
        ]
        self.assertEqual([0, 1, 2], [params["after_sequence"] for params in page_params])
        self.assertEqual([1, 1, 1], [params["fetch_limit"] for params in page_params])
        self.assertEqual(1, connection.transactions_committed)

    def test_corruption_returns_no_partially_trusted_entries(self) -> None:
        first, second, _first_hash = self._two_rows()
        corrupted = list(second)
        corrupted[9] = b"x" * 32
        repository, _connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases", (True,)),
            _step("sequence_number >", first, tuple(corrupted)),
        )

        result = repository.verify_chain(
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
        )

        self.assertFalse(result.valid)
        self.assertIs(AuditVerificationReason.ENTRY_HASH_MISMATCH, result.reason)
        self.assertEqual(1, result.checked_entries)
        self.assertEqual(2, result.error_sequence)
        self.assertEqual((), result.entries)
        self.assertIsNone(result.head_hash)

    def test_unknown_hash_schema_and_cross_tenant_row_fail_closed(self) -> None:
        first, _second, _first_hash = self._two_rows()
        unknown_schema = list(first)
        unknown_schema[7] = {"audit_hash_schema_version": 2, "facts": FACTS_1}
        repository, _connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases", (True,)),
            _step("sequence_number >", tuple(unknown_schema)),
        )
        result = repository.verify_chain(
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
        )
        self.assertIs(AuditVerificationReason.HASH_SCHEMA_UNSUPPORTED, result.reason)

        wrong_tenant = list(first)
        wrong_tenant[1] = OTHER_MERCHANT_ID
        repository, _connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases", (True,)),
            _step("sequence_number >", tuple(wrong_tenant)),
        )
        result = repository.verify_chain(
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
        )
        self.assertIs(AuditVerificationReason.TENANT_MISMATCH, result.reason)

    def test_limit_is_a_fail_closed_result_and_case_absence_is_not_an_empty_chain(self) -> None:
        first, second, _first_hash = self._two_rows()
        repository, _connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases", (True,)),
            _step("sequence_number >", first),
            _step("sequence_number >", second),
        )
        result = repository.verify_chain(
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
            page_size=1,
            max_entries=1,
        )
        self.assertIs(AuditVerificationReason.LIMIT_EXCEEDED, result.reason)
        self.assertEqual(1, result.checked_entries)
        self.assertEqual((), result.entries)

        missing, _connection = _repository(
            _step("pg_advisory_xact_lock", (None,)),
            _step("FROM retrywise.recovery_cases"),
        )
        result = missing.verify_chain(
            merchant_id=MERCHANT_ID,
            recovery_case_id=CASE_ID,
        )
        self.assertIs(AuditVerificationReason.CASE_NOT_FOUND, result.reason)
        self.assertFalse(result.valid)

    def test_dsn_connector_uses_shared_enforceable_tls_policy(self) -> None:
        dsn = "postgresql://audit@db.example/retrywise?sslmode=verify-full"
        connection = _FakeConnection(
            [
                _step("pg_advisory_xact_lock", (None,)),
                _step("FROM retrywise.recovery_cases"),
            ]
        )
        with patch.object(
            PostgresConnectionPolicy,
            "connect",
            autospec=True,
            return_value=connection,
        ) as connect:
            repository = PostgresAuditRepository(dsn=dsn, require_tls=True)
            result = repository.verify_chain(
                merchant_id=MERCHANT_ID,
                recovery_case_id=CASE_ID,
            )

        self.assertIs(AuditVerificationReason.CASE_NOT_FOUND, result.reason)
        policy = connect.call_args.args[0]
        self.assertIsInstance(policy, PostgresConnectionPolicy)
        self.assertTrue(policy.require_tls)
        self.assertEqual("PostgresAuditRepository", connect.call_args.kwargs["component"])


class PostgresAuditMigrationContractTests(unittest.TestCase):
    def test_initial_schema_has_exact_binding_lock_chain_and_immutability_guards(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        migration = (project_root / "infrastructure/postgres/migrations/001_initial.sql").read_text(
            encoding="utf-8"
        )

        self.assertIn("CREATE TABLE retrywise.audit_entries", migration)
        self.assertIn("FOREIGN KEY (merchant_id, recovery_case_id)", migration)
        self.assertIn("CREATE FUNCTION retrywise.enforce_audit_chain()", migration)
        self.assertIn("pg_advisory_xact_lock", migration)
        self.assertIn("audit previous hash does not match chain head", migration)
        self.assertIn("audit_entries_90_forbid_mutation", migration)
        self.assertIn("UNIQUE (merchant_id, recovery_case_id, sequence_number)", migration)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
