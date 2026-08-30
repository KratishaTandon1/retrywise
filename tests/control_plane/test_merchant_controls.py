from __future__ import annotations

import hashlib
import unittest
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from retrywise.services.control_plane.merchant_controls import (
    MerchantControlConflict,
    MerchantControlNotFound,
    MerchantControlState,
    PostgresMerchantControlService,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
EVENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
SUBJECT = "operator-ayu"
IDEMPOTENCY_KEY = "merchant-control-request-0001"


class _Step:
    def __init__(self, marker: str, row: Sequence[object] | None) -> None:
        self.marker = marker
        self.row = row


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.row: Sequence[object] | None = None

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: Mapping[str, object]) -> None:
        if not self.connection.steps:
            raise AssertionError(f"unexpected query: {query}")
        step = self.connection.steps.pop(0)
        if step.marker not in query:
            raise AssertionError(f"expected {step.marker!r}, got {query!r}")
        self.connection.executions.append((query, dict(params)))
        self.row = step.row

    def fetchone(self) -> Sequence[object] | None:
        return self.row


class _Context:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __enter__(self) -> object:
        return self

    def __exit__(self, exc_type: object, *_args: object) -> None:
        if exc_type is None:
            self.connection.commits += 1
        else:
            self.connection.rollbacks += 1
        return None


class _Connection:
    def __init__(self, steps: list[_Step]) -> None:
        self.steps = list(steps)
        self.executions: list[tuple[str, dict[str, object]]] = []
        self.commits = 0
        self.rollbacks = 0

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _Cursor:
        return _Cursor(self)

    def transaction(self) -> _Context:
        return _Context(self)


class _Connector:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __call__(self) -> _Connection:
        return self.connection


def service(connection: _Connection) -> PostgresMerchantControlService:
    return PostgresMerchantControlService(
        connector=_Connector(connection),  # type: ignore[arg-type]
        id_factory=lambda: EVENT_ID,
    )


class MerchantControlTests(unittest.TestCase):
    def test_state_without_event_is_valid_but_partial_or_malformed_event_is_not(self) -> None:
        state = MerchantControlState(
            merchant_id=MERCHANT_ID,
            kill_switch_enabled=False,
            policy_version="policy-v1",
        )
        self.assertIsNone(state.to_primitive()["last_event"])

        invalid_values = (
            {"event_id": EVENT_ID},
            {
                "event_id": EVENT_ID,
                "sequence_number": 0,
                "reason_code": "emergency_stop",
                "changed_at": NOW,
            },
            {
                "event_id": EVENT_ID,
                "sequence_number": 1,
                "reason_code": "INVALID",
                "changed_at": NOW,
            },
            {
                "event_id": EVENT_ID,
                "sequence_number": 1,
                "reason_code": "emergency_stop",
                "changed_at": NOW.replace(tzinfo=None),
            },
        )
        for values in invalid_values:
            with self.subTest(values=values), self.assertRaises(ValueError):
                MerchantControlState(
                    merchant_id=MERCHANT_ID,
                    kill_switch_enabled=False,
                    policy_version="policy-v1",
                    **values,
                )
        with self.assertRaises(TypeError):
            MerchantControlState(
                merchant_id=MERCHANT_ID,
                kill_switch_enabled=1,  # type: ignore[arg-type]
                policy_version="policy-v1",
            )
        with self.assertRaises(TypeError):
            MerchantControlState(
                merchant_id=MERCHANT_ID,
                kill_switch_enabled=False,
                policy_version="policy-v1",
                idempotent_replay=1,  # type: ignore[arg-type]
            )

    def test_reads_effective_merchant_control_state(self) -> None:
        connection = _Connection(
            [
                _Step(
                    "LEFT JOIN LATERAL",
                    (MERCHANT_ID, True, "policy-v1", EVENT_ID, 4, "emergency_stop", NOW),
                )
            ]
        )

        state = service(connection).get(merchant_id=MERCHANT_ID)

        self.assertTrue(state.kill_switch_enabled)
        self.assertFalse(state.to_primitive()["collection_effects_enabled"])
        self.assertEqual(4, state.sequence_number)

    def test_switch_change_is_atomic_append_only_and_secret_free(self) -> None:
        connection = _Connection(
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, False, "policy-v1")),
                _Step("FROM retrywise.merchant_control_events", None),
                _Step("UPDATE retrywise.merchants", (True,)),
                _Step(
                    "INSERT INTO retrywise.merchant_control_events",
                    (EVENT_ID, 1, "emergency_stop", NOW),
                ),
            ]
        )

        state = service(connection).set_kill_switch(
            merchant_id=MERCHANT_ID,
            enabled=True,
            reason_code="emergency_stop",
            operator_subject=SUBJECT,
            idempotency_key=IDEMPOTENCY_KEY,
        )

        self.assertTrue(state.kill_switch_enabled)
        self.assertFalse(state.idempotent_replay)
        self.assertEqual(1, connection.commits)
        self.assertEqual([], connection.steps)
        params = connection.executions[-1][1]
        self.assertEqual(hashlib.sha256(SUBJECT.encode()).digest(), params["actor_subject_sha256"])
        self.assertEqual(
            hashlib.sha256(IDEMPOTENCY_KEY.encode()).digest(),
            params["idempotency_key_sha256"],
        )
        insert_query = connection.executions[-1][0]
        self.assertEqual(
            2,
            insert_query.count("%(merchant_id)s::retrywise.ulid"),
        )
        rendered = str(params)
        self.assertNotIn(SUBJECT, rendered)
        self.assertNotIn(IDEMPOTENCY_KEY, rendered)

    def test_idempotent_replay_does_not_overwrite_a_later_state(self) -> None:
        connection = _Connection(
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, False, "policy-v1")),
                _Step(
                    "FROM retrywise.merchant_control_events",
                    (
                        EVENT_ID,
                        1,
                        True,
                        "emergency_stop",
                        hashlib.sha256(SUBJECT.encode()).digest(),
                        NOW,
                    ),
                ),
            ]
        )

        state = service(connection).set_kill_switch(
            merchant_id=MERCHANT_ID,
            enabled=True,
            reason_code="emergency_stop",
            operator_subject=SUBJECT,
            idempotency_key=IDEMPOTENCY_KEY,
        )

        self.assertFalse(state.kill_switch_enabled)
        self.assertTrue(state.idempotent_replay)
        self.assertFalse(
            any("UPDATE retrywise.merchants" in query for query, _ in connection.executions)
        )

    def test_reused_key_with_different_request_is_a_conflict(self) -> None:
        connection = _Connection(
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, True, "policy-v1")),
                _Step(
                    "FROM retrywise.merchant_control_events",
                    (
                        EVENT_ID,
                        1,
                        True,
                        "emergency_stop",
                        hashlib.sha256(SUBJECT.encode()).digest(),
                        NOW,
                    ),
                ),
            ]
        )

        with self.assertRaises(MerchantControlConflict):
            service(connection).set_kill_switch(
                merchant_id=MERCHANT_ID,
                enabled=True,
                reason_code="operator_safety_hold",
                operator_subject=SUBJECT,
                idempotency_key=IDEMPOTENCY_KEY,
            )
        self.assertEqual(1, connection.rollbacks)

    def test_resume_requires_an_explicit_resume_reason(self) -> None:
        connection = _Connection([])
        with self.assertRaises(ValueError):
            service(connection).set_kill_switch(
                merchant_id=MERCHANT_ID,
                enabled=False,
                reason_code="emergency_stop",
                operator_subject=SUBJECT,
                idempotency_key=IDEMPOTENCY_KEY,
            )
        self.assertEqual([], connection.executions)

    def test_database_and_input_corruption_fail_closed(self) -> None:
        with self.assertRaises(MerchantControlNotFound):
            service(_Connection([_Step("LEFT JOIN LATERAL", None)])).get(merchant_id=MERCHANT_ID)
        with self.assertRaises(RuntimeError):
            service(
                _Connection(
                    [
                        _Step(
                            "LEFT JOIN LATERAL",
                            (MERCHANT_ID, "true", "policy-v1", None, None, None, None),
                        )
                    ]
                )
            ).get(merchant_id=MERCHANT_ID)

        for values, error in (
            ({"enabled": "true"}, TypeError),
            ({"operator_subject": ""}, ValueError),
            ({"idempotency_key": "short"}, ValueError),
        ):
            arguments: dict[str, object] = {
                "merchant_id": MERCHANT_ID,
                "enabled": True,
                "reason_code": "emergency_stop",
                "operator_subject": SUBJECT,
                "idempotency_key": IDEMPOTENCY_KEY,
                **values,
            }
            with self.subTest(arguments=arguments), self.assertRaises(error):
                service(_Connection([])).set_kill_switch(**arguments)  # type: ignore[arg-type]

        with self.assertRaises(MerchantControlNotFound):
            service(_Connection([_Step("FROM retrywise.merchants", None)])).set_kill_switch(
                merchant_id=MERCHANT_ID,
                enabled=True,
                reason_code="emergency_stop",
                operator_subject=SUBJECT,
                idempotency_key=IDEMPOTENCY_KEY,
            )

        malformed_previous = _Connection(
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, True, "policy-v1")),
                _Step("FROM retrywise.merchant_control_events", (EVENT_ID,)),
            ]
        )
        with self.assertRaises(RuntimeError):
            service(malformed_previous).set_kill_switch(
                merchant_id=MERCHANT_ID,
                enabled=True,
                reason_code="emergency_stop",
                operator_subject=SUBJECT,
                idempotency_key=IDEMPOTENCY_KEY,
            )

        bad_hash = _Connection(
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, True, "policy-v1")),
                _Step(
                    "FROM retrywise.merchant_control_events",
                    (EVENT_ID, 1, True, "emergency_stop", b"short", NOW),
                ),
            ]
        )
        with self.assertRaises(RuntimeError):
            service(bad_hash).set_kill_switch(
                merchant_id=MERCHANT_ID,
                enabled=True,
                reason_code="emergency_stop",
                operator_subject=SUBJECT,
                idempotency_key=IDEMPOTENCY_KEY,
            )

        for steps in (
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, False, "policy-v1")),
                _Step("FROM retrywise.merchant_control_events", None),
                _Step("UPDATE retrywise.merchants", None),
            ],
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, False, "policy-v1")),
                _Step("FROM retrywise.merchant_control_events", None),
                _Step("UPDATE retrywise.merchants", (True,)),
                _Step("INSERT INTO retrywise.merchant_control_events", None),
            ],
        ):
            with self.subTest(step_count=len(steps)), self.assertRaises(RuntimeError):
                service(_Connection(steps)).set_kill_switch(
                    merchant_id=MERCHANT_ID,
                    enabled=True,
                    reason_code="emergency_stop",
                    operator_subject=SUBJECT,
                    idempotency_key=IDEMPOTENCY_KEY,
                )

        with self.assertRaises(ValueError):
            PostgresMerchantControlService()
        with self.assertRaises(TypeError):
            PostgresMerchantControlService(
                connector=lambda: _Connection([]),
                id_factory=None,  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
