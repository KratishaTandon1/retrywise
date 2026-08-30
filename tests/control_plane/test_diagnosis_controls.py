from __future__ import annotations

import hashlib
import unittest
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from retrywise.packages.diagnosis import DiagnosisMode
from retrywise.services.control_plane.diagnosis_controls import (
    DiagnosisControlConflict,
    DiagnosisControlNotFound,
    DiagnosisControlState,
    PostgresDiagnosisControlService,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
EVENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
SUBJECT = "operator-ayu"
KEY = "diagnosis-control-request-0001"


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
        step = self.connection.steps.pop(0)
        if step.marker not in query:
            raise AssertionError(f"expected {step.marker!r}")
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


def service(connection: _Connection) -> PostgresDiagnosisControlService:
    return PostgresDiagnosisControlService(
        connector=lambda: connection,  # type: ignore[arg-type]
        gemini_configured=True,
        id_factory=lambda: EVENT_ID,
    )


class DiagnosisControlTests(unittest.TestCase):
    def test_state_exposes_only_safe_configuration(self) -> None:
        state = DiagnosisControlState(
            merchant_id=MERCHANT_ID,
            mode=DiagnosisMode.HYBRID_GEMINI,
            gemini_configured=True,
            event_id=EVENT_ID,
            sequence_number=2,
            reason_code="operator_selected_hybrid_gemini",
            changed_at=NOW,
        )

        primitive = state.to_primitive()

        self.assertEqual("HYBRID_GEMINI", primitive["mode"])
        self.assertEqual("DETERMINISTIC", primitive["policy_authority"])
        self.assertNotIn("api_key", repr(primitive))

    def test_change_commits_mode_and_append_only_digest_evidence(self) -> None:
        connection = _Connection(
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, "LOCAL_ML")),
                _Step("FROM retrywise.diagnosis_mode_events", None),
                _Step("UPDATE retrywise.merchants", ("HYBRID_GEMINI",)),
                _Step(
                    "INSERT INTO retrywise.diagnosis_mode_events",
                    (EVENT_ID, 1, "operator_selected_hybrid_gemini", NOW),
                ),
            ]
        )

        state = service(connection).set_mode(
            merchant_id=MERCHANT_ID,
            mode=DiagnosisMode.HYBRID_GEMINI,
            operator_subject=SUBJECT,
            idempotency_key=KEY,
        )

        self.assertIs(state.mode, DiagnosisMode.HYBRID_GEMINI)
        self.assertEqual(1, connection.commits)
        params = connection.executions[-1][1]
        self.assertEqual(hashlib.sha256(SUBJECT.encode()).digest(), params["actor_subject_sha256"])
        self.assertEqual(hashlib.sha256(KEY.encode()).digest(), params["idempotency_key_sha256"])
        self.assertNotIn(SUBJECT, repr(params))
        self.assertNotIn(KEY, repr(params))

    def test_idempotent_replay_and_conflict_are_distinct(self) -> None:
        previous = (
            EVENT_ID,
            1,
            "HYBRID_GEMINI",
            "operator_selected_hybrid_gemini",
            memoryview(hashlib.sha256(SUBJECT.encode()).digest()),
            NOW,
        )
        replay_connection = _Connection(
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, "SHADOW")),
                _Step("FROM retrywise.diagnosis_mode_events", previous),
            ]
        )
        replay = service(replay_connection).set_mode(
            merchant_id=MERCHANT_ID,
            mode=DiagnosisMode.HYBRID_GEMINI,
            operator_subject=SUBJECT,
            idempotency_key=KEY,
        )
        self.assertTrue(replay.idempotent_replay)
        self.assertIs(replay.mode, DiagnosisMode.SHADOW)

        conflict_connection = _Connection(
            [
                _Step("FROM retrywise.merchants", (MERCHANT_ID, "SHADOW")),
                _Step("FROM retrywise.diagnosis_mode_events", previous),
            ]
        )
        with self.assertRaises(DiagnosisControlConflict):
            service(conflict_connection).set_mode(
                merchant_id=MERCHANT_ID,
                mode=DiagnosisMode.LOCAL_ML,
                operator_subject=SUBJECT,
                idempotency_key=KEY,
            )
        self.assertEqual(1, conflict_connection.rollbacks)

    def test_invalid_state_and_constructor_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            DiagnosisControlState(
                merchant_id=MERCHANT_ID,
                mode=DiagnosisMode.LOCAL_ML,
                gemini_configured=False,
                event_id=EVENT_ID,
            )
        with self.assertRaises(ValueError):
            DiagnosisControlState(
                merchant_id=MERCHANT_ID,
                mode=DiagnosisMode.LOCAL_ML,
                gemini_configured=False,
                event_id=EVENT_ID,
                sequence_number=1,
                reason_code="invalid_reason",
                changed_at=NOW,
            )
        with self.assertRaises(ValueError):
            PostgresDiagnosisControlService()
        with self.assertRaises(TypeError):
            PostgresDiagnosisControlService(
                connector=lambda: _Connection([]),
                gemini_configured=1,  # type: ignore[arg-type]
            )
        with self.assertRaises(TypeError):
            PostgresDiagnosisControlService(
                connector=lambda: _Connection([]),
                id_factory=None,  # type: ignore[arg-type]
            )
        with self.assertRaises(ValueError):
            PostgresDiagnosisControlService(
                dsn="postgresql://localhost/retrywise",
                connector=lambda: _Connection([]),
            )

    def test_state_without_event_and_state_validation(self) -> None:
        state = DiagnosisControlState(
            merchant_id=MERCHANT_ID,
            mode=DiagnosisMode.LOCAL_ML,
            gemini_configured=False,
        )
        self.assertIsNone(state.to_primitive()["last_event"])

        invalid_states = (
            {"merchant_id": "invalid"},
            {"mode": "LOCAL_ML"},
            {"gemini_configured": 1},
            {
                "event_id": EVENT_ID,
                "sequence_number": 0,
                "reason_code": "operator_selected_local_ml",
                "changed_at": NOW,
            },
            {
                "event_id": EVENT_ID,
                "sequence_number": 1,
                "reason_code": "operator_selected_local_ml",
                "changed_at": NOW.replace(tzinfo=None),
            },
            {"idempotent_replay": 1},
        )
        base = {
            "merchant_id": MERCHANT_ID,
            "mode": DiagnosisMode.LOCAL_ML,
            "gemini_configured": False,
        }
        for change in invalid_states:
            with self.subTest(change=change), self.assertRaises((TypeError, ValueError)):
                DiagnosisControlState(**{**base, **change})  # type: ignore[arg-type]

    def test_get_mode_and_missing_or_malformed_rows(self) -> None:
        good_row = (MERCHANT_ID, "SHADOW", EVENT_ID, 1, "operator_selected_shadow", NOW)
        connection = _Connection([_Step("FROM retrywise.merchants", good_row)])
        self.assertIs(service(connection).get(merchant_id=MERCHANT_ID).mode, DiagnosisMode.SHADOW)

        connection = _Connection([_Step("FROM retrywise.merchants", good_row)])
        self.assertIs(
            service(connection).diagnosis_mode(merchant_id=MERCHANT_ID), DiagnosisMode.SHADOW
        )

        for row in (None, (MERCHANT_ID,), (MERCHANT_ID, "UNKNOWN", None, None, None, None)):
            with self.subTest(row=row):
                connection = _Connection([_Step("FROM retrywise.merchants", row)])
                with self.assertRaises((DiagnosisControlNotFound, RuntimeError)):
                    service(connection).get(merchant_id=MERCHANT_ID)

    def test_set_mode_persistence_failures_are_closed(self) -> None:
        with self.assertRaises(TypeError):
            service(_Connection([])).set_mode(
                merchant_id=MERCHANT_ID,
                mode="LOCAL_ML",  # type: ignore[arg-type]
                operator_subject=SUBJECT,
                idempotency_key=KEY,
            )
        for operator_subject, idempotency_key in ((" bad", KEY), (SUBJECT, "short")):
            with (
                self.subTest(operator_subject=operator_subject, idempotency_key=idempotency_key),
                self.assertRaises(ValueError),
            ):
                service(_Connection([])).set_mode(
                    merchant_id=MERCHANT_ID,
                    mode=DiagnosisMode.LOCAL_ML,
                    operator_subject=operator_subject,
                    idempotency_key=idempotency_key,
                )

        scenarios = (
            (
                [_Step("FROM retrywise.merchants", None)],
                DiagnosisControlNotFound,
            ),
            (
                [
                    _Step("FROM retrywise.merchants", (MERCHANT_ID, "LOCAL_ML")),
                    _Step("FROM retrywise.diagnosis_mode_events", (EVENT_ID,)),
                ],
                RuntimeError,
            ),
            (
                [
                    _Step("FROM retrywise.merchants", (MERCHANT_ID, "LOCAL_ML")),
                    _Step(
                        "FROM retrywise.diagnosis_mode_events",
                        (
                            EVENT_ID,
                            1,
                            "LOCAL_ML",
                            "operator_selected_local_ml",
                            b"short",
                            NOW,
                        ),
                    ),
                ],
                RuntimeError,
            ),
            (
                [
                    _Step("FROM retrywise.merchants", (MERCHANT_ID, "LOCAL_ML")),
                    _Step("FROM retrywise.diagnosis_mode_events", None),
                    _Step("UPDATE retrywise.merchants", None),
                ],
                RuntimeError,
            ),
            (
                [
                    _Step("FROM retrywise.merchants", (MERCHANT_ID, "LOCAL_ML")),
                    _Step("FROM retrywise.diagnosis_mode_events", None),
                    _Step("UPDATE retrywise.merchants", ("LOCAL_ML",)),
                    _Step("INSERT INTO retrywise.diagnosis_mode_events", None),
                ],
                RuntimeError,
            ),
        )
        for steps, error in scenarios:
            with self.subTest(error=error.__name__), self.assertRaises(error):
                service(_Connection(steps)).set_mode(
                    merchant_id=MERCHANT_ID,
                    mode=DiagnosisMode.LOCAL_ML,
                    operator_subject=SUBJECT,
                    idempotency_key=KEY,
                )


if __name__ == "__main__":
    unittest.main()
