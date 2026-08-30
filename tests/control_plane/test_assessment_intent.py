from __future__ import annotations

import json
import unittest
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from retrywise.packages.diagnosis import (
    PINNED_BUNDLED_VERSION,
    DiagnosisResult,
    DiagnosisRouter,
)
from retrywise.packages.domain import (
    ActionType,
    DeterministicGate,
    GatePolicy,
    GateReason,
    IncidentState,
    Money,
    Probability,
)
from retrywise.services.control_plane import assessment_intent as assessment_module
from retrywise.services.control_plane.assessment_intent import (
    AssessmentDisposition,
    AssessmentMethodHealthError,
    AssessmentNotEligibleError,
    AssessmentPersistenceError,
    AssessmentProviderTruthError,
    AssessmentSource,
    AssessmentStateChangedError,
    AssessmentToIntentService,
    AssessRecoveryCaseCommand,
    AuthorizedAssessmentPlan,
    BlockedAssessmentPlan,
    FreshMethodHealthTruth,
    FreshProviderPaymentTruth,
    PostgresAssessmentIntentRepository,
    ProviderPaymentStatus,
    StandardPaymentLinkAssessmentPlanner,
)
from retrywise.services.control_plane.effect_command_codec import (
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
    decode_create_standard_payment_link_command,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
LOGICAL_ORDER_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
PAYMENT_RECORD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
CASE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
DECISION_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
ACTION_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
INSTRUMENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
OUTBOX_JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB3"
INCIDENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB4"
APPROVAL_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB5"
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
AMOUNT = 129_900


def command(**updates: object) -> AssessRecoveryCaseCommand:
    values: dict[str, object] = {
        "merchant_id": MERCHANT_ID,
        "provider_account_id": PROVIDER_ACCOUNT_ID,
        "logical_order_id": LOGICAL_ORDER_ID,
        "payment_record_id": PAYMENT_RECORD_ID,
        "recovery_case_id": CASE_ID,
        "expected_case_version": 0,
    }
    values.update(updates)
    return AssessRecoveryCaseCommand(**values)  # type: ignore[arg-type]


def candidate_row(**updates: object) -> tuple[object, ...]:
    values: dict[str, object] = {
        "database_now": NOW,
        "case_id": CASE_ID,
        "merchant_id": MERCHANT_ID,
        "logical_order_id": LOGICAL_ORDER_ID,
        "provider_account_id": PROVIDER_ACCOUNT_ID,
        "currency": "INR",
        "amount_minor": AMOUNT,
        "case_state": "OBSERVING",
        "case_version": 0,
        "observation_contract_version": 1,
        "observation_started_at": NOW - timedelta(minutes=4),
        "observation_deadline_at": NOW - timedelta(minutes=1),
        "attempt_count": 0,
        "contact_count": 0,
        "incident_id": None,
        "merchant_status": "ACTIVE",
        "merchant_kill_switch": False,
        "policy_version": "policy-v1",
        "provider": "RAZORPAY",
        "provider_account_identifier": "acc_retrywise_test_1",
        "environment": "TEST",
        "account_enabled": True,
        "credential_binding_version": 7,
        "original_provider_order_id": "order_test_1",
        "order_amount_minor": AMOUNT,
        "order_currency": "INR",
        "captured_total_minor": 0,
        "refunded_total_minor": 0,
        "canonical_truth": "UNPAID",
        "truth_version": 3,
        "order_snapshot_at": NOW - timedelta(seconds=3),
        "mapping_status": "MAPPED",
        "payment_record_id": PAYMENT_RECORD_ID,
        "provider_payment_id": "pay_test_1",
        "provider_order_id": "order_test_1",
        "payment_status": "FAILED",
        "payment_amount_minor": AMOUNT,
        "payment_currency": "INR",
        "captured_minor": 0,
        "refunded_minor": 0,
        "payment_method": "upi",
        "error_source": "customer",
        "error_step": "payment_authentication",
        "error_reason": "incorrect_pin",
        "provider_created_at": NOW - timedelta(minutes=5),
        "payment_snapshot_at": NOW - timedelta(seconds=3),
        "active_instrument_count": 0,
    }
    values.update(updates)
    return (
        values["database_now"],
        values["case_id"],
        values["merchant_id"],
        values["logical_order_id"],
        values["provider_account_id"],
        values["currency"],
        values["amount_minor"],
        values["case_state"],
        values["case_version"],
        values["observation_contract_version"],
        values["observation_started_at"],
        values["observation_deadline_at"],
        values["attempt_count"],
        values["contact_count"],
        values["incident_id"],
        values["merchant_status"],
        values["merchant_kill_switch"],
        values["policy_version"],
        values["provider"],
        values["provider_account_identifier"],
        values["environment"],
        values["account_enabled"],
        values["credential_binding_version"],
        values["original_provider_order_id"],
        values["order_amount_minor"],
        values["order_currency"],
        values["captured_total_minor"],
        values["refunded_total_minor"],
        values["canonical_truth"],
        values["truth_version"],
        values["order_snapshot_at"],
        values["mapping_status"],
        values["payment_record_id"],
        values["provider_payment_id"],
        values["provider_order_id"],
        values["payment_status"],
        values["payment_amount_minor"],
        values["payment_currency"],
        values["captured_minor"],
        values["refunded_minor"],
        values["payment_method"],
        values["error_source"],
        values["error_step"],
        values["error_reason"],
        values["provider_created_at"],
        values["payment_snapshot_at"],
        values["active_instrument_count"],
    )


def provider_truth(**updates: object) -> FreshProviderPaymentTruth:
    values: dict[str, object] = {
        "merchant_id": MERCHANT_ID,
        "provider_account_id": PROVIDER_ACCOUNT_ID,
        "credential_binding_version": 7,
        "provider_payment_id": "pay_test_1",
        "provider_order_id": "order_test_1",
        "status": ProviderPaymentStatus.FAILED,
        "amount_minor": AMOUNT,
        "currency": "INR",
        "captured_minor": 0,
        "refunded_minor": 0,
        "payment_method": "upi",
        "error_source": "customer",
        "error_step": "payment_authentication",
        "error_reason": "incorrect_pin",
        "observed_at": NOW - timedelta(seconds=1),
    }
    values.update(updates)
    return FreshProviderPaymentTruth(**values)  # type: ignore[arg-type]


def method_health(**updates: object) -> FreshMethodHealthTruth:
    values: dict[str, object] = {
        "merchant_id": MERCHANT_ID,
        "provider_account_id": PROVIDER_ACCOUNT_ID,
        "payment_method": "upi",
        "incident_state": IncidentState.NORMAL,
        "observed_at": NOW - timedelta(seconds=1),
        "detector_version": "detector-v1",
        "threshold_version": "threshold-v1",
        "incident_id": None,
    }
    values.update(updates)
    return FreshMethodHealthTruth(**values)  # type: ignore[arg-type]


def gate_policy(*, threshold: int = 500_000) -> GatePolicy:
    return GatePolicy(
        version="policy-v1",
        allowed_actions=frozenset({ActionType.CREATE_STANDARD_PAYMENT_LINK}),
        provider_snapshot_max_age=timedelta(seconds=30),
        incident_health_max_age=timedelta(seconds=60),
        max_attempts=3,
        max_contacts_in_window=2,
        approval_threshold=Money(threshold, "INR"),
        min_confidence=Probability("0.75"),
    )


def planner(
    *,
    threshold: int = 500_000,
    global_kill_switch: bool = False,
    diagnosis_router: DiagnosisRouter | None = None,
) -> StandardPaymentLinkAssessmentPlanner:
    generated = iter((DECISION_ID, ACTION_ID, INSTRUMENT_ID, OUTBOX_JOB_ID))
    return StandardPaymentLinkAssessmentPlanner(
        gate=DeterministicGate(gate_policy(threshold=threshold)),
        id_factory=lambda: next(generated),
        global_kill_switch=global_kill_switch,
        diagnosis_router=diagnosis_router,
    )


RowFactory = Callable[[Mapping[str, object]], Sequence[object] | None]


@dataclass(frozen=True)
class _Step:
    marker: str
    row_factory: RowFactory = lambda _params: None


class _FakeCursor:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection
        self._row: Sequence[object] | None = None

    def __enter__(self) -> _FakeCursor:
        self._connection.cursor_open = True
        return self

    def __exit__(self, *_args: object) -> None:
        self._connection.cursor_open = False
        return None

    def execute(self, query: str, params: Mapping[str, object]) -> None:
        if not self._connection.in_transaction:
            raise AssertionError("assessment SQL must run inside a transaction")
        if not self._connection.steps:
            raise AssertionError(f"unexpected query: {query}")
        step = self._connection.steps.pop(0)
        if step.marker not in query:
            raise AssertionError(f"expected query containing {step.marker!r}, got {query!r}")
        copied = dict(params)
        self._connection.executions.append((query, copied))
        self._row = step.row_factory(copied)

    def fetchone(self) -> Sequence[object] | None:
        return self._row


class _FakeTransaction:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def __enter__(self) -> object:
        if self._connection.in_transaction:
            raise AssertionError("nested fake transaction")
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
    def __init__(self, steps: list[_Step]) -> None:
        self.steps = list(steps)
        self.executions: list[tuple[str, dict[str, object]]] = []
        self.in_transaction = False
        self.cursor_open = False
        self.transactions_started = 0
        self.transactions_committed = 0
        self.transactions_rolled_back = 0

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *_args: object) -> None:
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


class _TruthReader:
    def __init__(
        self,
        connection: _FakeConnection,
        *,
        truth: FreshProviderPaymentTruth | None = None,
        error: Exception | None = None,
    ) -> None:
        self.connection = connection
        self.truth = truth
        self.error = error
        self.queries: list[object] = []
        self.transaction_seen = False

    def fetch_fresh_payment_truth(self, query: object) -> FreshProviderPaymentTruth:
        self.queries.append(query)
        self.transaction_seen = self.connection.in_transaction or self.connection.cursor_open
        if self.error is not None:
            raise self.error
        if self.truth is None:
            raise AssertionError("test truth reader has no truth")
        return self.truth


class _HealthReader:
    def __init__(
        self,
        connection: _FakeConnection,
        *,
        health: FreshMethodHealthTruth | None = None,
        error: Exception | None = None,
    ) -> None:
        self.connection = connection
        self.health = health
        self.error = error
        self.queries: list[object] = []
        self.transaction_seen = False

    def fetch_fresh_method_health(self, query: object) -> FreshMethodHealthTruth:
        self.queries.append(query)
        self.transaction_seen = self.connection.in_transaction or self.connection.cursor_open
        if self.error is not None:
            raise self.error
        if self.health is None:
            raise AssertionError("test method-health reader has no truth")
        return self.health


class _AssertingDiagnosisRouter(DiagnosisRouter):
    def __init__(self, connection: _FakeConnection) -> None:
        super().__init__()
        self.connection = connection
        self.transaction_seen = False

    def infer(self, *, merchant_id: str, raw_features: Mapping[str, object]) -> DiagnosisResult:
        self.transaction_seen = self.connection.in_transaction or self.connection.cursor_open
        return super().infer(merchant_id=merchant_id, raw_features=raw_features)


def happy_steps(*, locked_row: Sequence[object] | None = None) -> list[_Step]:
    return [
        _Step("FROM retrywise.recovery_cases AS recovery_case", lambda _p: candidate_row()),
        _Step(
            "FOR UPDATE OF recovery_case",
            lambda _p: locked_row or candidate_row(database_now=NOW + timedelta(seconds=1)),
        ),
        _Step("SET state = 'ASSESSING'", lambda _p: (1,)),
        _Step("INSERT INTO retrywise.decisions", lambda p: (p["decision_id"],)),
        _Step("INSERT INTO retrywise.actions", lambda p: (p["action_id"],)),
        _Step("INSERT INTO retrywise.recovery_instruments", lambda p: (p["instrument_id"],)),
        _Step("SET status = 'QUEUED'", lambda _p: ("QUEUED",)),
        _Step("SET state = 'ACTION_QUEUED'", lambda _p: (2,)),
        _Step("INSERT INTO retrywise.outbox_jobs", lambda p: (p["outbox_job_id"],)),
    ]


class AssessmentContractTests(unittest.TestCase):
    def test_audit_policy_version_is_recorded_as_a_non_pii_digest(self) -> None:
        digest = assessment_module._audit_policy_version_sha256("policy-v1")

        self.assertEqual(64, len(digest))
        self.assertEqual(
            "72993b6cb83904d39a8c73bd0651aa6251288ede5dbc2c7bcbdc54cc5bbf5d77",
            digest,
        )

    def test_command_requires_exact_ulids_optimistic_version_and_test_source(self) -> None:
        with self.assertRaises(ValueError):
            command(expected_case_version=True)
        with self.assertRaises(ValueError):
            command(payment_record_id="pay_external")
        with self.assertRaises(ValueError):
            command(source="REPLAY")

        built = command()
        self.assertEqual(0, built.expected_case_version)
        self.assertIs(AssessmentSource.RAZORPAY_TEST_MODE, built.source)

    def test_fresh_truth_is_closed_redacted_and_derives_money_state(self) -> None:
        truth = provider_truth()
        self.assertEqual("unpaid", truth.canonical_payment_state.value)
        self.assertNotIn("contact", repr(truth).lower())

        authorized = provider_truth(
            status=ProviderPaymentStatus.AUTHORIZED,
            error_source=None,
            error_step=None,
            error_reason=None,
        )
        captured = provider_truth(
            status=ProviderPaymentStatus.CAPTURED,
            captured_minor=AMOUNT,
            error_source=None,
            error_step=None,
            error_reason=None,
        )
        self.assertEqual("authorized", authorized.canonical_payment_state.value)
        self.assertEqual("paid", captured.canonical_payment_state.value)

        with self.assertRaises(ValueError):
            provider_truth(error_reason="customer@example.com")
        with self.assertRaises(ValueError):
            provider_truth(status=ProviderPaymentStatus.FAILED, captured_minor=1)
        with self.assertRaises(ValueError):
            provider_truth(source="REPLAY")
        with self.assertRaises(ValueError):
            provider_truth(
                status=ProviderPaymentStatus.AUTHORIZED,
                error_source="customer",
                error_step="payment_authentication",
                error_reason="incorrect_pin",
            )

    def test_planner_uses_pinned_model_closed_proposal_and_machine_only_request(self) -> None:
        snapshot = assessment_module._snapshot_from_row(candidate_row(), command=command())
        outcome = planner().plan(snapshot, provider_truth(), method_health())

        self.assertIsInstance(outcome, AuthorizedAssessmentPlan)
        assert isinstance(outcome, AuthorizedAssessmentPlan)
        self.assertEqual(PINNED_BUNDLED_VERSION, outcome.diagnosis.artifact_version)
        self.assertEqual(
            "authentication",
            outcome.diagnosis.feature_snapshot.value_for("error_step"),
        )
        self.assertTrue(outcome.planning_decision.allowed)
        self.assertIs(ActionType.CREATE_STANDARD_PAYMENT_LINK, outcome.proposal.action_type)
        self.assertEqual(LOGICAL_ORDER_ID, outcome.command.request.notes["merchant_order_id"])
        self.assertEqual(CASE_ID, outcome.command.request.notes["recovery_case_id"])
        serialized = json.dumps(outcome.command.request.to_payload())
        self.assertNotIn("customer", serialized.lower())
        self.assertNotIn("contact", serialized.lower())
        self.assertNotIn(
            "merchant_order_reference",
            assessment_module._ASSESSMENT_COLUMNS,
        )

    def test_gate_blocks_kill_switch_active_instrument_and_stale_truth(self) -> None:
        cases = (
            (
                planner(global_kill_switch=True),
                candidate_row(),
                provider_truth(),
                method_health(),
                GateReason.GLOBAL_KILL_SWITCH_ACTIVE,
            ),
            (
                planner(),
                candidate_row(active_instrument_count=1),
                provider_truth(),
                method_health(),
                GateReason.ACTIVE_INSTRUMENT_EXISTS,
            ),
            (
                planner(),
                candidate_row(),
                provider_truth(observed_at=NOW - timedelta(minutes=5)),
                method_health(),
                GateReason.PROVIDER_SNAPSHOT_STALE,
            ),
            (
                planner(),
                candidate_row(),
                provider_truth(),
                method_health(observed_at=NOW - timedelta(minutes=5)),
                GateReason.INCIDENT_HEALTH_STALE,
            ),
        )
        for planner_value, row, truth, health, expected_reason in cases:
            with self.subTest(reason=expected_reason):
                snapshot = assessment_module._snapshot_from_row(row, command=command())
                outcome = planner_value.plan(snapshot, truth, health)
                self.assertIsInstance(outcome, BlockedAssessmentPlan)
                assert isinstance(outcome, BlockedAssessmentPlan)
                self.assertIn(expected_reason.value, outcome.reason_codes)

    def test_high_value_requires_approval_and_never_authorizes_an_intent(self) -> None:
        snapshot = assessment_module._snapshot_from_row(
            candidate_row(amount_minor=AMOUNT, order_amount_minor=AMOUNT),
            command=command(),
        )
        outcome = planner(threshold=AMOUNT).plan(
            snapshot,
            provider_truth(),
            method_health(),
        )

        self.assertIsInstance(outcome, BlockedAssessmentPlan)
        assert isinstance(outcome, BlockedAssessmentPlan)
        self.assertIs(AssessmentDisposition.APPROVAL_REQUIRED, outcome.disposition)
        self.assertIn(GateReason.HIGH_VALUE_REQUIRES_APPROVAL.value, outcome.reason_codes)
        self.assertIn(GateReason.APPROVAL_REQUIRED.value, outcome.reason_codes)

    def test_non_failed_or_misbound_fresh_truth_cannot_authorize(self) -> None:
        snapshot = assessment_module._snapshot_from_row(candidate_row(), command=command())
        created = planner().plan(
            snapshot,
            provider_truth(
                status=ProviderPaymentStatus.CREATED,
                error_source=None,
                error_step=None,
                error_reason=None,
            ),
            method_health(),
        )
        self.assertIsInstance(created, BlockedAssessmentPlan)
        assert isinstance(created, BlockedAssessmentPlan)
        self.assertEqual(("PROVIDER_PAYMENT_NOT_FAILED",), created.reason_codes)

        with self.assertRaisesRegex(
            AssessmentProviderTruthError,
            "fresh_provider_truth_binding_mismatch",
        ):
            planner().plan(
                snapshot,
                provider_truth(credential_binding_version=8),
                method_health(),
            )

        with self.assertRaisesRegex(
            AssessmentMethodHealthError,
            "fresh_method_health_binding_mismatch",
        ):
            planner().plan(
                snapshot,
                provider_truth(),
                method_health(provider_account_id=DECISION_ID),
            )


class PostgresAssessmentIntentTests(unittest.TestCase):
    def test_service_fetches_truth_outside_transactions_and_commits_one_atomic_intent(self) -> None:
        connection = _FakeConnection(happy_steps())
        repository = PostgresAssessmentIntentRepository(
            connector=_FakeConnector(connection),
        )
        reader = _TruthReader(connection, truth=provider_truth())
        health_reader = _HealthReader(connection, health=method_health())
        diagnosis_router = _AssertingDiagnosisRouter(connection)
        service = AssessmentToIntentService(
            repository=repository,
            provider_truth_reader=reader,
            method_health_reader=health_reader,
            planner=planner(diagnosis_router=diagnosis_router),
        )

        result = service.assess(command())

        self.assertIs(AssessmentDisposition.INTENT_QUEUED, result.disposition)
        self.assertEqual(2, result.final_case_version)
        self.assertEqual(DECISION_ID, result.decision_id)
        self.assertEqual(ACTION_ID, result.action_id)
        self.assertEqual(INSTRUMENT_ID, result.instrument_id)
        self.assertEqual(OUTBOX_JOB_ID, result.outbox_job_id)
        self.assertFalse(reader.transaction_seen)
        self.assertFalse(health_reader.transaction_seen)
        self.assertFalse(diagnosis_router.transaction_seen)
        self.assertEqual(1, len(reader.queries))
        self.assertEqual(1, len(health_reader.queries))
        health_query = health_reader.queries[0]
        self.assertEqual(MERCHANT_ID, health_query.merchant_id)
        self.assertEqual(PROVIDER_ACCOUNT_ID, health_query.provider_account_id)
        self.assertEqual("upi", health_query.payment_method)
        self.assertIsNone(health_query.incident_id)
        self.assertEqual(2, connection.transactions_started)
        self.assertEqual(2, connection.transactions_committed)
        self.assertEqual(0, connection.transactions_rolled_back)
        self.assertFalse(connection.steps)

        self.assertIn("CROSS JOIN statement", connection.executions[0][0])
        lock_query = connection.executions[1][0]
        self.assertIn("CROSS JOIN statement", lock_query)
        self.assertIn("FOR UPDATE OF recovery_case", lock_query)
        self.assertIn("FOR SHARE OF merchant, account, logical_order, payment", lock_query)
        start_params = connection.executions[2][1]
        self.assertEqual(0, start_params["expected_case_version"])
        self.assertEqual(MERCHANT_ID, start_params["merchant_id"])
        self.assertEqual(PROVIDER_ACCOUNT_ID, start_params["provider_account_id"])
        self.assertEqual(PAYMENT_RECORD_ID, start_params["payment_record_id"])

    def test_durable_decision_intent_and_outbox_are_closed_and_cross_bound(self) -> None:
        connection = _FakeConnection(happy_steps())
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(connector=_FakeConnector(connection)),
            provider_truth_reader=_TruthReader(connection, truth=provider_truth()),
            method_health_reader=_HealthReader(connection, health=method_health()),
            planner=planner(),
        )
        result = service.assess(command())

        decision_params = next(
            params
            for query, params in connection.executions
            if "INSERT INTO retrywise.decisions" in query
        )
        self.assertEqual(PINNED_BUNDLED_VERSION, decision_params["model_version"])
        self.assertEqual(1, decision_params["feature_schema_version"])
        self.assertEqual(32, len(decision_params["feature_snapshot_sha256"]))
        feature_snapshot = json.loads(decision_params["feature_snapshot"])
        self.assertEqual(
            {
                "attempt_bucket",
                "error_reason",
                "error_source",
                "error_step",
                "failure_age_bucket",
                "incident_state",
                "payment_method",
            },
            set(feature_snapshot["values"]),
        )
        expected_value_inputs = json.loads(decision_params["expected_value_inputs"])
        self.assertEqual("detector-v1", expected_value_inputs["detector_version"])
        self.assertEqual("threshold-v1", expected_value_inputs["threshold_version"])

        action_params = next(
            params
            for query, params in connection.executions
            if "INSERT INTO retrywise.actions" in query
        )
        metadata = json.loads(action_params["request_metadata"])
        self.assertEqual(result.action_key, metadata["action_key"])
        self.assertEqual(PROVIDER_ACCOUNT_ID, metadata["provider_account_id"])

        outbox_params = next(
            params
            for query, params in connection.executions
            if "INSERT INTO retrywise.outbox_jobs" in query
        )
        self.assertEqual(
            CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
            outbox_params["command_type"],
        )
        self.assertEqual(
            CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
            outbox_params["command_schema_version"],
        )
        decoded = decode_create_standard_payment_link_command(
            outbox_params["command_payload"],
            command_type=outbox_params["command_type"],
            command_schema_version=outbox_params["command_schema_version"],
        )
        self.assertEqual(result.action_key, decoded.proposal.action_key)
        self.assertEqual(result.reference_id, decoded.request.reference_id)
        serialized = outbox_params["command_payload"]
        self.assertNotIn("customer", serialized.lower())
        self.assertNotIn("contact", serialized.lower())

    def test_state_drift_after_provider_read_rolls_back_without_any_write(self) -> None:
        drifted = candidate_row(
            database_now=NOW + timedelta(seconds=1),
            truth_version=4,
        )
        connection = _FakeConnection(
            [
                _Step(
                    "FROM retrywise.recovery_cases AS recovery_case",
                    lambda _p: candidate_row(),
                ),
                _Step("FOR UPDATE OF recovery_case", lambda _p: drifted),
            ]
        )
        reader = _TruthReader(connection, truth=provider_truth())
        health_reader = _HealthReader(connection, health=method_health())
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(connector=_FakeConnector(connection)),
            provider_truth_reader=reader,
            method_health_reader=health_reader,
            planner=planner(),
        )

        with self.assertRaisesRegex(
            AssessmentStateChangedError,
            "assessment_state_changed_during_provider_read",
        ):
            service.assess(command())

        self.assertFalse(reader.transaction_seen)
        self.assertFalse(health_reader.transaction_seen)
        self.assertEqual(2, len(connection.executions))
        self.assertEqual(1, connection.transactions_committed)
        self.assertEqual(1, connection.transactions_rolled_back)

    def test_blocked_gate_commits_terminal_decision_without_effect_intent(self) -> None:
        connection = _FakeConnection(
            [
                _Step(
                    "FROM retrywise.recovery_cases AS recovery_case",
                    lambda _p: candidate_row(active_instrument_count=1),
                ),
                _Step(
                    "FOR UPDATE OF recovery_case",
                    lambda _p: candidate_row(
                        database_now=NOW + timedelta(seconds=1),
                        active_instrument_count=1,
                    ),
                ),
                _Step("SET state = 'ASSESSING'", lambda _p: (1,)),
                _Step("INSERT INTO retrywise.decisions", lambda p: (p["decision_id"],)),
                _Step("SET state = %(case_state)s", lambda _p: (2,)),
            ]
        )
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(
                connector=_FakeConnector(connection),
                id_factory=lambda: DECISION_ID,
            ),
            provider_truth_reader=_TruthReader(connection, truth=provider_truth()),
            method_health_reader=_HealthReader(connection, health=method_health()),
            planner=planner(),
        )

        result = service.assess(command())

        self.assertIs(AssessmentDisposition.BLOCKED, result.disposition)
        self.assertIn(GateReason.ACTIVE_INSTRUMENT_EXISTS.value, result.reason_codes)
        self.assertIsNone(result.action_id)
        self.assertEqual(5, len(connection.executions))
        self.assertEqual(2, connection.transactions_committed)

    def test_high_value_gate_commits_pending_approval_without_effect(self) -> None:
        generated = iter((DECISION_ID, APPROVAL_ID))
        connection = _FakeConnection(
            [
                _Step("FROM retrywise.recovery_cases AS recovery_case", lambda _p: candidate_row()),
                _Step("FOR UPDATE OF recovery_case", lambda _p: candidate_row()),
                _Step("SET state = 'ASSESSING'", lambda _p: (1,)),
                _Step("INSERT INTO retrywise.decisions", lambda p: (p["decision_id"],)),
                _Step("INSERT INTO retrywise.approvals", lambda p: (p["approval_id"],)),
                _Step("SET state = %(case_state)s", lambda _p: (2,)),
            ]
        )
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(
                connector=_FakeConnector(connection),
                id_factory=lambda: next(generated),
            ),
            provider_truth_reader=_TruthReader(connection, truth=provider_truth()),
            method_health_reader=_HealthReader(connection, health=method_health()),
            planner=planner(threshold=100_000),
        )

        result = service.assess(command())

        self.assertIs(AssessmentDisposition.APPROVAL_REQUIRED, result.disposition)
        self.assertEqual(APPROVAL_ID, result.approval_id)
        self.assertIsNone(result.action_id)
        finish_params = connection.executions[-1][1]
        self.assertEqual("APPROVAL_REQUIRED", finish_params["case_state"])
        self.assertIsNone(finish_params["terminal_at"])

    def test_unhealthy_method_commits_wait_and_reassessment_deadline(self) -> None:
        connection = _FakeConnection(
            [
                _Step(
                    "FROM retrywise.recovery_cases AS recovery_case",
                    lambda _p: candidate_row(incident_id=INCIDENT_ID),
                ),
                _Step(
                    "FOR UPDATE OF recovery_case",
                    lambda _p: candidate_row(incident_id=INCIDENT_ID),
                ),
                _Step("SET state = 'ASSESSING'", lambda _p: (1,)),
                _Step("INSERT INTO retrywise.decisions", lambda p: (p["decision_id"],)),
                _Step("SET state = %(case_state)s", lambda _p: (2,)),
            ]
        )
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(
                connector=_FakeConnector(connection),
                id_factory=lambda: DECISION_ID,
            ),
            provider_truth_reader=_TruthReader(connection, truth=provider_truth()),
            method_health_reader=_HealthReader(
                connection,
                health=method_health(
                    incident_state=IncidentState.CONFIRMED,
                    incident_id=INCIDENT_ID,
                ),
            ),
            planner=planner(),
        )

        result = service.assess(command())

        self.assertIs(AssessmentDisposition.WAITING, result.disposition)
        finish_params = connection.executions[-1][1]
        self.assertEqual("WAITING", finish_params["case_state"])
        self.assertEqual(NOW + timedelta(minutes=5), finish_params["evaluation_deadline_at"])
        self.assertIsNone(finish_params["terminal_at"])

    def test_provider_failure_is_sanitized_and_no_locking_transaction_starts(self) -> None:
        connection = _FakeConnection(
            [
                _Step(
                    "FROM retrywise.recovery_cases AS recovery_case",
                    lambda _p: candidate_row(),
                )
            ]
        )
        reader = _TruthReader(
            connection,
            error=RuntimeError("credential=secret contact=9999999999"),
        )
        health_reader = _HealthReader(connection, health=method_health())
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(connector=_FakeConnector(connection)),
            provider_truth_reader=reader,
            method_health_reader=health_reader,
            planner=planner(),
        )

        with self.assertRaisesRegex(
            AssessmentProviderTruthError,
            "fresh_provider_truth_unavailable",
        ) as raised:
            service.assess(command())

        self.assertNotIn("secret", str(raised.exception))
        self.assertFalse(reader.transaction_seen)
        self.assertFalse(health_reader.queries)
        self.assertEqual(1, connection.transactions_started)
        self.assertEqual(1, connection.transactions_committed)

    def test_method_health_failure_is_sanitized_and_no_locking_transaction_starts(self) -> None:
        connection = _FakeConnection(
            [
                _Step(
                    "FROM retrywise.recovery_cases AS recovery_case",
                    lambda _p: candidate_row(),
                )
            ]
        )
        truth_reader = _TruthReader(connection, truth=provider_truth())
        health_reader = _HealthReader(
            connection,
            error=RuntimeError("detector_token=secret contact=9999999999"),
        )
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(connector=_FakeConnector(connection)),
            provider_truth_reader=truth_reader,
            method_health_reader=health_reader,
            planner=planner(),
        )

        with self.assertRaisesRegex(
            AssessmentMethodHealthError,
            "fresh_method_health_unavailable",
        ) as raised:
            service.assess(command())

        self.assertNotIn("secret", str(raised.exception))
        self.assertFalse(truth_reader.transaction_seen)
        self.assertFalse(health_reader.transaction_seen)
        self.assertEqual(1, connection.transactions_started)
        self.assertEqual(1, connection.transactions_committed)

    def test_case_incident_change_after_external_reads_fails_locked_revalidation(self) -> None:
        connection = _FakeConnection(
            [
                _Step(
                    "FROM retrywise.recovery_cases AS recovery_case",
                    lambda _p: candidate_row(incident_id=INCIDENT_ID),
                ),
                _Step(
                    "FOR UPDATE OF recovery_case",
                    lambda _p: candidate_row(
                        database_now=NOW + timedelta(seconds=1),
                        incident_id=None,
                    ),
                ),
            ]
        )
        health_reader = _HealthReader(
            connection,
            health=method_health(incident_id=INCIDENT_ID),
        )
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(connector=_FakeConnector(connection)),
            provider_truth_reader=_TruthReader(connection, truth=provider_truth()),
            method_health_reader=health_reader,
            planner=planner(),
        )

        with self.assertRaisesRegex(
            AssessmentStateChangedError,
            "assessment_state_changed_during_provider_read",
        ):
            service.assess(command())

        self.assertEqual(INCIDENT_ID, health_reader.queries[0].incident_id)
        self.assertEqual(1, connection.transactions_rolled_back)

    def test_database_driver_details_are_sanitized_at_commit_boundary(self) -> None:
        def leak_secret(_params: Mapping[str, object]) -> Sequence[object] | None:
            raise RuntimeError("postgres_detail=credential-secret contact=9999999999")

        steps = happy_steps()
        steps[3] = _Step("INSERT INTO retrywise.decisions", leak_secret)
        connection = _FakeConnection(steps)
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(connector=_FakeConnector(connection)),
            provider_truth_reader=_TruthReader(connection, truth=provider_truth()),
            method_health_reader=_HealthReader(connection, health=method_health()),
            planner=planner(),
        )

        with self.assertRaisesRegex(
            AssessmentPersistenceError,
            "assessment_commit_failed",
        ) as raised:
            service.assess(command())

        self.assertNotIn("secret", str(raised.exception))
        self.assertEqual(4, len(connection.executions))
        self.assertEqual(1, connection.transactions_rolled_back)

    def test_compare_and_swap_failure_rolls_back_the_whole_write_set(self) -> None:
        steps = happy_steps()
        steps[2] = _Step("SET state = 'ASSESSING'", lambda _p: None)
        connection = _FakeConnection(steps)
        service = AssessmentToIntentService(
            repository=PostgresAssessmentIntentRepository(connector=_FakeConnector(connection)),
            provider_truth_reader=_TruthReader(connection, truth=provider_truth()),
            method_health_reader=_HealthReader(connection, health=method_health()),
            planner=planner(),
        )

        with self.assertRaisesRegex(
            assessment_module.AssessmentPersistenceError,
            "start_assessment_compare_and_swap_failed",
        ):
            service.assess(command())

        self.assertEqual(3, len(connection.executions))
        self.assertEqual(1, connection.transactions_committed)
        self.assertEqual(1, connection.transactions_rolled_back)

    def test_legacy_observation_or_credential_binding_is_rejected_before_provider_io(self) -> None:
        unsafe_rows = (
            candidate_row(observation_contract_version=0),
            candidate_row(credential_binding_version=0),
            candidate_row(environment="LIVE"),
            candidate_row(database_now=NOW - timedelta(minutes=2)),
        )
        for row in unsafe_rows:
            with self.subTest(row=row):
                connection = _FakeConnection(
                    [
                        _Step(
                            "FROM retrywise.recovery_cases AS recovery_case",
                            lambda _p, value=row: value,
                        )
                    ]
                )
                reader = _TruthReader(connection, truth=provider_truth())
                service = AssessmentToIntentService(
                    repository=PostgresAssessmentIntentRepository(
                        connector=_FakeConnector(connection)
                    ),
                    provider_truth_reader=reader,
                    method_health_reader=_HealthReader(
                        connection,
                        health=method_health(),
                    ),
                    planner=planner(),
                )
                with self.assertRaises(AssessmentNotEligibleError):
                    service.assess(command())
                self.assertFalse(reader.queries)


if __name__ == "__main__":
    unittest.main()
