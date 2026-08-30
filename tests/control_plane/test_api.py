from __future__ import annotations

import json
import logging
import os
import unittest
from asyncio import run
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
except ImportError:  # Dependency-free CI intentionally skips transport tests.
    TestClient = None

if os.environ.get("RETRYWISE_REQUIRE_API_TESTS") == "1" and TestClient is None:
    raise RuntimeError("FastAPI API extras are required for transport verification")

from retrywise.packages.diagnosis import DiagnosisMode
from retrywise.packages.razorpay import calculate_webhook_signature
from retrywise.services.control_plane.api import _read_bounded_body, create_app
from retrywise.services.control_plane.approval_request import (
    ApprovalRequestConflict,
    ApprovalRequestNotFound,
    ApprovalRequestResult,
)
from retrywise.services.control_plane.diagnosis_controls import (
    DiagnosisControlConflict,
    DiagnosisControlNotFound,
    DiagnosisControlState,
)
from retrywise.services.control_plane.merchant_controls import (
    MerchantControlConflict,
    MerchantControlNotFound,
    MerchantControlState,
)
from retrywise.services.control_plane.observability import Observability, StructuredJsonFormatter
from retrywise.services.control_plane.runtime import ControlPlaneRuntime
from retrywise.services.control_plane.webhook_ingress import IngressError, PayloadTooLarge

TOKEN = "endpoint_token_1234567890abcdef"
SECRET = b"test-webhook-secret-32-bytes-long"
OPERATOR_TOKEN = "operator-token-with-more-than-32-bytes!!"
APPROVAL_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
CONTROL_MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
CONTROL_EVENT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"


class _ApprovalRequests:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def act(self, **values: str) -> ApprovalRequestResult:
        self.calls.append(dict(values))
        return ApprovalRequestResult(
            approval_id=values["approval_id"],
            verdict="APPROVAL_QUEUED",
            recovery_case_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            case_version=4,
            outbox_job_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
            command_status="PENDING",
        )


class _MerchantControls:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    @staticmethod
    def _state(enabled: bool) -> MerchantControlState:
        return MerchantControlState(
            merchant_id=CONTROL_MERCHANT_ID,
            kill_switch_enabled=enabled,
            policy_version="policy-v1",
            event_id=CONTROL_EVENT_ID,
            sequence_number=2,
            reason_code="emergency_stop" if enabled else "resume_after_verification",
            changed_at=datetime(2026, 8, 29, 12, 0, tzinfo=UTC),
        )

    def get(self, **_values: object) -> MerchantControlState:
        return self._state(True)

    def set_kill_switch(self, **values: object) -> MerchantControlState:
        if type(values.get("enabled")) is not bool:
            raise TypeError("enabled")
        self.calls.append(dict(values))
        return self._state(values["enabled"])  # type: ignore[arg-type]


class _DiagnosisControls:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    @staticmethod
    def _state(mode: DiagnosisMode) -> DiagnosisControlState:
        reasons = {
            DiagnosisMode.LOCAL_ML: "operator_selected_local_ml",
            DiagnosisMode.HYBRID_GEMINI: "operator_selected_hybrid_gemini",
            DiagnosisMode.SHADOW: "operator_selected_shadow",
        }
        return DiagnosisControlState(
            merchant_id=CONTROL_MERCHANT_ID,
            mode=mode,
            gemini_configured=True,
            event_id=CONTROL_EVENT_ID,
            sequence_number=3,
            reason_code=reasons[mode],
            changed_at=datetime(2026, 8, 29, 12, 0, tzinfo=UTC),
        )

    def get(self, **_values: object) -> DiagnosisControlState:
        return self._state(DiagnosisMode.LOCAL_ML)

    def set_mode(self, **values: object) -> DiagnosisControlState:
        self.calls.append(dict(values))
        return self._state(values["mode"])  # type: ignore[arg-type]


class _UnavailableDurableIngress:
    durable = True

    def check_ready(self) -> bool:
        return False


class _OperatorStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def _result(self, value: object) -> object:
        if self.fail:
            raise RuntimeError("database unavailable")
        return value

    def overview(self, **_values: object) -> object:
        return self._result({"environment": "RAZORPAY_TEST_MODE", "open_cases": 1})

    def list_cases(self, **_values: object) -> object:
        return self._result([{"id": APPROVAL_ID}])

    def case_detail(self, **values: object) -> object:
        recovery_case_id = values["recovery_case_id"]
        return self._result(
            None if recovery_case_id == CONTROL_EVENT_ID else {"id": recovery_case_id}
        )

    def list_incidents(self, **_values: object) -> object:
        return self._result([{"state": "NORMAL"}])

    def list_approvals(self, **_values: object) -> object:
        return self._result([{"id": APPROVAL_ID}])

    def verify_audit(self, **_values: object) -> object:
        return self._result({"valid": True})


class _Raises:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def act(self, **_values: object) -> object:
        raise self.error

    def get(self, **_values: object) -> object:
        raise self.error

    def set_kill_switch(self, **_values: object) -> object:
        raise self.error

    def set_mode(self, **_values: object) -> object:
        raise self.error


class _StreamRequest:
    def __init__(self, headers: dict[str, str], chunks: tuple[bytes, ...] = ()) -> None:
        self.headers = headers
        self.chunks = chunks

    async def stream(self) -> object:
        for chunk in self.chunks:
            yield chunk


class _IngressRaises:
    durable = True

    def accept(self, **_values: object) -> object:
        raise IngressError("invalid request")

    def check_ready(self) -> bool:
        return True


@unittest.skipIf(TestClient is None, "FastAPI api extra is not installed")
class ControlPlaneApiTests(unittest.TestCase):
    def setUp(self) -> None:
        runtime = ControlPlaneRuntime.from_mapping(
            {
                "RETRYWISE_CODE_REVISION": "api-test-revision",
                "RETRYWISE_WEBHOOK_ENDPOINT_TOKEN": TOKEN,
                "RETRYWISE_MERCHANT_ID": "merchant-1",
                "RETRYWISE_PROVIDER_ACCOUNT_ID": "provider-account-1",
                "RAZORPAY_ACCOUNT_ID": "acc_test_1",
                "RAZORPAY_WEBHOOK_SECRET_CURRENT": SECRET.decode("utf-8"),
                "RETRYWISE_OPERATOR_TOKEN": OPERATOR_TOKEN,
            }
        )
        self.runtime = runtime
        self.log_output = StringIO()
        logger = logging.Logger(f"retrywise.test.api.{id(self)}", level=logging.INFO)
        handler = logging.StreamHandler(self.log_output)
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)
        self.observability = Observability(logger=logger)
        self.client = TestClient(create_app(runtime, observability=self.observability))
        self.auth = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}

    def test_health_is_public_but_operator_data_is_authenticated(self) -> None:
        self.assertEqual(self.client.get("/health/live").status_code, 200)
        readiness = self.client.get("/health/ready")
        self.assertEqual(readiness.status_code, 200)
        self.assertFalse(readiness.json()["durable_ingress"])
        self.assertTrue(readiness.json()["webhook_ingress_ready"])
        response = self.client.get("/api/v1/overview", params={"environment": "REPLAY"})
        self.assertEqual(response.status_code, 401)
        authorized = self.client.get(
            "/api/v1/overview",
            params={"environment": "REPLAY"},
            headers=self.auth,
        )
        self.assertEqual(authorized.status_code, 200)

    def test_readiness_fails_when_durable_ingress_cannot_commit(self) -> None:
        runtime = replace(
            self.runtime,
            webhook_ingress=_UnavailableDurableIngress(),
            webhook_configured=True,
        )
        client = TestClient(create_app(runtime))

        response = client.get("/health/ready")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["status"], "not_ready")
        self.assertTrue(response.json()["durable_ingress"])
        self.assertFalse(response.json()["webhook_ingress_ready"])

    def test_overview_keeps_replay_and_test_mode_values_separate(self) -> None:
        replay = self.client.get(
            "/api/v1/overview",
            params={"environment": "REPLAY"},
            headers=self.auth,
        ).json()
        test_mode = self.client.get(
            "/api/v1/overview",
            params={"environment": "RAZORPAY_TEST_MODE"},
            headers=self.auth,
        ).json()
        self.assertIn("offline_simulated_incremental_value_minor", replay)
        self.assertFalse(replay["labels"]["real_money"])
        self.assertNotIn("offline_simulated_incremental_value_minor", test_mode)
        self.assertIsNone(test_mode["test_mode_recovered_minor"])
        self.assertIsNone(test_mode["open_cases"])
        self.assertIsNone(test_mode["hard_safety_violations"])
        self.assertIn("not executed", test_mode["labels"]["value_label"])

    def test_real_operator_read_routes_are_tenant_scoped_and_fail_closed(self) -> None:
        runtime = replace(self.runtime, operator_store=_OperatorStore())
        client = TestClient(create_app(runtime))
        overview = client.get(
            "/api/v1/overview",
            params={"environment": "RAZORPAY_TEST_MODE"},
            headers=self.auth,
        )
        cases = client.get("/api/v1/recovery-cases", headers=self.auth)
        detail = client.get(f"/api/v1/recovery-cases/{APPROVAL_ID}", headers=self.auth)
        missing = client.get(f"/api/v1/recovery-cases/{CONTROL_EVENT_ID}", headers=self.auth)
        incidents = client.get("/api/v1/incidents", headers=self.auth)
        approvals = client.get("/api/v1/approvals", headers=self.auth)
        audit = client.get(
            f"/api/v1/recovery-cases/{APPROVAL_ID}/audit",
            headers=self.auth,
        )

        self.assertEqual(200, overview.status_code)
        self.assertEqual(200, cases.status_code)
        self.assertEqual(APPROVAL_ID, detail.json()["id"])
        self.assertEqual(404, missing.status_code)
        self.assertEqual(200, incidents.status_code)
        self.assertEqual(200, approvals.status_code)
        self.assertTrue(audit.json()["valid"])

        invalid = client.get("/api/v1/recovery-cases/not-a-ulid", headers=self.auth)
        self.assertEqual(400, invalid.status_code)

        unavailable = TestClient(
            create_app(replace(self.runtime, operator_store=_OperatorStore(fail=True)))
        )
        for path in (
            "/api/v1/overview?environment=RAZORPAY_TEST_MODE",
            "/api/v1/recovery-cases",
            f"/api/v1/recovery-cases/{APPROVAL_ID}",
            "/api/v1/incidents",
            "/api/v1/approvals",
            f"/api/v1/recovery-cases/{APPROVAL_ID}/audit",
        ):
            with self.subTest(path=path):
                self.assertEqual(503, unavailable.get(path, headers=self.auth).status_code)

        unconfigured = self.client.get("/api/v1/recovery-cases", headers=self.auth)
        self.assertEqual(503, unconfigured.status_code)

    def test_replay_submission_is_strict_and_idempotent(self) -> None:
        payload = {"seed": 7, "case_count": 24, "bootstrap_samples": 10}
        missing_key = self.client.post("/api/v1/impact/runs", json=payload, headers=self.auth)
        self.assertEqual(missing_key.status_code, 400)
        self.assertEqual(missing_key.json()["detail"]["code"], "INVALID_IDEMPOTENCY_KEY")

        headers = {
            **self.auth,
            "Idempotency-Key": "replay-api-request-0001",
        }
        first = self.client.post("/api/v1/impact/runs", json=payload, headers=headers)
        duplicate = self.client.post("/api/v1/impact/runs", json=payload, headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), duplicate.json())

        conflict = self.client.post(
            "/api/v1/impact/runs",
            json={**payload, "case_count": 25},
            headers=headers,
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["detail"]["code"], "IDEMPOTENCY_KEY_REUSED")

        unknown = self.client.post(
            "/api/v1/impact/runs",
            json={**payload, "revenue": "real"},
            headers={**self.auth, "Idempotency-Key": "replay-api-request-0002"},
        )
        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(unknown.json()["detail"]["code"], "INVALID_REPLAY_REQUEST")
        relabel = self.client.post(
            "/api/v1/impact/runs",
            json={**payload, "model_version": "invented-model-label"},
            headers={**self.auth, "Idempotency-Key": "replay-api-request-0003"},
        )
        self.assertEqual(relabel.status_code, 400)
        counters = self.observability.counters.snapshot()
        self.assertEqual(counters["replay_submission_total"], 2)
        self.assertNotIn(OPERATOR_TOKEN, self.log_output.getvalue())

    def test_approval_decision_requires_auth_and_idempotency_then_queues_worker(self) -> None:
        approvals = _ApprovalRequests()
        runtime = replace(self.runtime, approval_requests=approvals)
        client = TestClient(create_app(runtime))
        route = f"/api/v1/approvals/{APPROVAL_ID}/decision"
        body = {"verdict": "APPROVED", "reason_code": "operator_verified"}

        self.assertEqual(client.post(route, json=body).status_code, 401)
        missing_key = client.post(route, json=body, headers=self.auth)
        self.assertEqual(missing_key.status_code, 400)
        response = client.post(
            route,
            json=body,
            headers={**self.auth, "Idempotency-Key": "approval-request-0001"},
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["verdict"], "APPROVAL_QUEUED")
        self.assertEqual(1, len(approvals.calls))
        self.assertEqual("local-operator", approvals.calls[0]["operator_subject"])

    def test_approval_api_maps_expiry_conflict_not_found_and_service_failure(self) -> None:
        route = f"/api/v1/approvals/{APPROVAL_ID}/decision"
        headers = {**self.auth, "Idempotency-Key": "approval-request-0009"}
        body = {"verdict": "APPROVED", "reason_code": "operator_verified"}
        scenarios = (
            (ApprovalRequestNotFound("missing"), 404),
            (ApprovalRequestConflict("approval_state_changed"), 409),
            (ValueError("invalid"), 400),
            (RuntimeError("database"), 503),
        )
        for error, expected in scenarios:
            with self.subTest(error=type(error).__name__):
                client = TestClient(
                    create_app(replace(self.runtime, approval_requests=_Raises(error)))
                )
                self.assertEqual(
                    expected, client.post(route, json=body, headers=headers).status_code
                )

        expired = _ApprovalRequests()
        expired.act = lambda **values: ApprovalRequestResult(
            approval_id=values["approval_id"],
            verdict="EXPIRED",
            recovery_case_id=CONTROL_MERCHANT_ID,
            case_version=5,
            outbox_job_id=None,
            command_status="NOT_QUEUED",
        )
        response = TestClient(create_app(replace(self.runtime, approval_requests=expired))).post(
            route, json=body, headers=headers
        )
        self.assertEqual(409, response.status_code)
        self.assertEqual("APPROVAL_EXPIRED", response.json()["code"])

        invalid_id = TestClient(
            create_app(replace(self.runtime, approval_requests=_ApprovalRequests()))
        ).post(
            "/api/v1/approvals/not-a-ulid/decision",
            json=body,
            headers=headers,
        )
        self.assertEqual(400, invalid_id.status_code)

        malformed = TestClient(
            create_app(replace(self.runtime, approval_requests=_ApprovalRequests()))
        ).post(route, json={"verdict": "APPROVED"}, headers=headers)
        self.assertEqual(400, malformed.status_code)

        invalid_json = TestClient(
            create_app(replace(self.runtime, approval_requests=_ApprovalRequests()))
        ).post(route, content=b"{", headers={**headers, "Content-Type": "application/json"})
        self.assertEqual(400, invalid_json.status_code)
        self.assertEqual(503, self.client.post(route, json=body, headers=headers).status_code)

    def test_kill_switch_is_authenticated_idempotent_and_globally_fail_closed(self) -> None:
        controls = _MerchantControls()
        runtime = replace(self.runtime, merchant_controls=controls)
        client = TestClient(create_app(runtime))
        route = "/api/v1/controls/kill-switch"

        self.assertEqual(client.get(route).status_code, 401)
        current = client.get(route, headers=self.auth)
        self.assertEqual(200, current.status_code)
        self.assertTrue(current.json()["kill_switch_enabled"])
        self.assertTrue(current.json()["global_kill_switch_enabled"])
        self.assertFalse(current.json()["collection_effects_enabled"])

        missing_key = client.post(
            route,
            json={"enabled": False, "reason_code": "resume_after_verification"},
            headers=self.auth,
        )
        self.assertEqual(400, missing_key.status_code)
        changed = client.post(
            route,
            json={"enabled": False, "reason_code": "resume_after_verification"},
            headers={**self.auth, "Idempotency-Key": "merchant-control-0001"},
        )
        self.assertEqual(200, changed.status_code)
        self.assertFalse(changed.json()["kill_switch_enabled"])
        self.assertFalse(changed.json()["collection_effects_enabled"])
        self.assertEqual("local-operator", controls.calls[0]["operator_subject"])

        invalid = client.post(
            route,
            json={"enabled": "false", "reason_code": "resume_after_verification"},
            headers={**self.auth, "Idempotency-Key": "merchant-control-0002"},
        )
        self.assertEqual(400, invalid.status_code)

    def test_kill_switch_api_maps_missing_conflict_and_storage_errors(self) -> None:
        headers = {**self.auth, "Idempotency-Key": "merchant-control-0009"}
        body = {"enabled": True, "reason_code": "emergency_stop"}
        for error, expected in (
            (MerchantControlNotFound("missing"), 404),
            (MerchantControlConflict("conflict"), 409),
            (RuntimeError("database"), 503),
        ):
            with self.subTest(error=type(error).__name__):
                client = TestClient(
                    create_app(replace(self.runtime, merchant_controls=_Raises(error)))
                )
                self.assertEqual(
                    expected,
                    client.get("/api/v1/controls/kill-switch", headers=self.auth).status_code
                    if expected in {404, 503}
                    else client.post(
                        "/api/v1/controls/kill-switch", json=body, headers=headers
                    ).status_code,
                )

        unconfigured = self.client.get("/api/v1/controls/kill-switch", headers=self.auth)
        self.assertEqual(503, unconfigured.status_code)
        malformed = TestClient(
            create_app(replace(self.runtime, merchant_controls=_MerchantControls()))
        ).post(
            "/api/v1/controls/kill-switch",
            json={"enabled": True},
            headers=headers,
        )
        self.assertEqual(400, malformed.status_code)

        client = TestClient(
            create_app(replace(self.runtime, merchant_controls=_MerchantControls()))
        )
        invalid_json = client.post(
            "/api/v1/controls/kill-switch",
            content=b"{",
            headers={**headers, "Content-Type": "application/json"},
        )
        self.assertEqual(400, invalid_json.status_code)
        self.assertEqual(
            503,
            self.client.post(
                "/api/v1/controls/kill-switch",
                json=body,
                headers=headers,
            ).status_code,
        )
        for error, expected in (
            (MerchantControlNotFound("missing"), 404),
            (RuntimeError("database"), 503),
        ):
            with self.subTest(post_error=type(error).__name__):
                failing = TestClient(
                    create_app(replace(self.runtime, merchant_controls=_Raises(error)))
                )
                self.assertEqual(
                    expected,
                    failing.post(
                        "/api/v1/controls/kill-switch", json=body, headers=headers
                    ).status_code,
                )

    def test_diagnosis_engine_control_is_authenticated_and_idempotent(self) -> None:
        controls = _DiagnosisControls()
        client = TestClient(create_app(replace(self.runtime, diagnosis_controls=controls)))
        route = "/api/v1/controls/diagnosis-engine"

        self.assertEqual(401, client.get(route).status_code)
        current = client.get(route, headers=self.auth)
        self.assertEqual(200, current.status_code)
        self.assertEqual("LOCAL_ML", current.json()["mode"])
        self.assertTrue(current.json()["gemini_configured"])
        changed = client.post(
            route,
            json={"mode": "HYBRID_GEMINI"},
            headers={**self.auth, "Idempotency-Key": "diagnosis-control-0001"},
        )
        self.assertEqual(200, changed.status_code)
        self.assertEqual("HYBRID_GEMINI", changed.json()["mode"])
        self.assertEqual(DiagnosisMode.HYBRID_GEMINI, controls.calls[0]["mode"])
        self.assertEqual("local-operator", controls.calls[0]["operator_subject"])

        for body in ({"mode": "unknown"}, {"mode": "LOCAL_ML", "extra": True}):
            with self.subTest(body=body):
                response = client.post(
                    route,
                    json=body,
                    headers={**self.auth, "Idempotency-Key": "diagnosis-control-0002"},
                )
                self.assertEqual(400, response.status_code)

    def test_diagnosis_engine_control_maps_storage_failures(self) -> None:
        route = "/api/v1/controls/diagnosis-engine"
        headers = {**self.auth, "Idempotency-Key": "diagnosis-control-0009"}
        for error, expected in (
            (DiagnosisControlNotFound("missing"), 404),
            (DiagnosisControlConflict("conflict"), 409),
            (RuntimeError("database"), 503),
        ):
            with self.subTest(error=type(error).__name__):
                client = TestClient(
                    create_app(replace(self.runtime, diagnosis_controls=_Raises(error)))
                )
                response = (
                    client.post(route, json={"mode": "LOCAL_ML"}, headers=headers)
                    if expected == 409
                    else client.get(route, headers=self.auth)
                )
                self.assertEqual(expected, response.status_code)

    def test_verified_webhook_is_accepted_and_deduplicated(self) -> None:
        raw = json.dumps(
            {
                "account_id": "acc_test_1",
                "event": "payment.failed",
                "created_at": 1_788_000_000,
                "payload": {"payment": {"entity": {"id": "pay_test_1"}}},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Razorpay-Signature": calculate_webhook_signature(raw, SECRET),
            "x-razorpay-event-id": "event-api-1",
        }
        first = self.client.post(f"/api/v1/webhooks/razorpay/{TOKEN}", content=raw, headers=headers)
        second = self.client.post(
            f"/api/v1/webhooks/razorpay/{TOKEN}", content=raw, headers=headers
        )
        self.assertEqual(first.status_code, 204)
        self.assertEqual(first.headers["x-retrywise-ingress-status"], "ACCEPTED")
        self.assertEqual(second.status_code, 204)
        self.assertEqual(second.headers["x-retrywise-ingress-status"], "DUPLICATE")
        counters = self.observability.counters.snapshot()
        self.assertEqual(counters["webhook_accepted_total"], 1)
        self.assertEqual(counters["webhook_duplicate_total"], 1)
        logs = self.log_output.getvalue()
        self.assertNotIn(TOKEN, logs)
        self.assertNotIn("pay_test_1", logs)
        self.assertIn("/api/v1/webhooks/razorpay/{endpoint_token}", logs)

    def test_invalid_signature_and_account_binding_fail_closed(self) -> None:
        raw = json.dumps(
            {
                "account_id": "acc_other",
                "event": "payment.failed",
                "created_at": 1_788_000_000,
                "payload": {"payment": {"entity": {"id": "pay_test_2"}}},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        invalid = self.client.post(
            f"/api/v1/webhooks/razorpay/{TOKEN}",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-Razorpay-Signature": "0" * 64,
                "x-razorpay-event-id": "event-api-2",
            },
        )
        self.assertEqual(invalid.status_code, 401)
        self.assertEqual(
            self.observability.counters.snapshot()["webhook_verification_failure_total"],
            1,
        )
        mismatch = self.client.post(
            f"/api/v1/webhooks/razorpay/{TOKEN}",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-Razorpay-Signature": calculate_webhook_signature(raw, SECRET),
                "x-razorpay-event-id": "event-api-2",
            },
        )
        self.assertEqual(mismatch.status_code, 400)
        self.assertEqual(mismatch.json()["detail"]["code"], "PROVIDER_ACCOUNT_MISMATCH")

    def test_webhook_transport_maps_endpoint_media_decode_and_request_errors(self) -> None:
        valid = json.dumps(
            {
                "account_id": "acc_test_1",
                "event": "payment.failed",
                "created_at": 1_788_000_000,
                "payload": {"payment": {"entity": {"id": "pay_error_paths"}}},
            },
            separators=(",", ":"),
        ).encode()

        def headers(body: bytes, *, media_type: str = "application/json") -> dict[str, str]:
            return {
                "Content-Type": media_type,
                "X-Razorpay-Signature": calculate_webhook_signature(body, SECRET),
                "x-razorpay-event-id": "event-error-paths-1",
            }

        missing = self.client.post(
            "/api/v1/webhooks/razorpay/wrong_endpoint_token_1234567890",
            content=valid,
            headers=headers(valid),
        )
        unsupported = self.client.post(
            f"/api/v1/webhooks/razorpay/{TOKEN}",
            content=valid,
            headers=headers(valid, media_type="text/plain"),
        )
        invalid_json = b"not-json"
        malformed = self.client.post(
            f"/api/v1/webhooks/razorpay/{TOKEN}",
            content=invalid_json,
            headers=headers(invalid_json),
        )
        no_event_id_headers = headers(valid)
        no_event_id_headers.pop("x-razorpay-event-id")
        incomplete = self.client.post(
            f"/api/v1/webhooks/razorpay/{TOKEN}",
            content=valid,
            headers=no_event_id_headers,
        )

        self.assertEqual(404, missing.status_code)
        self.assertEqual(415, unsupported.status_code)
        self.assertEqual(400, malformed.status_code)
        self.assertEqual(400, incomplete.status_code)

    def test_bounded_body_rejects_invalid_length_and_stream_overflow(self) -> None:
        with self.assertRaises(IngressError):
            run(
                _read_bounded_body(
                    _StreamRequest({"content-length": "not-an-integer"}),
                    max_body_bytes=8,
                )
            )
        with self.assertRaises(IngressError):
            run(
                _read_bounded_body(
                    _StreamRequest({"content-length": "-1"}),
                    max_body_bytes=8,
                )
            )
        with self.assertRaises(PayloadTooLarge):
            run(
                _read_bounded_body(
                    _StreamRequest({}, (b"1234", b"56789")),
                    max_body_bytes=8,
                )
            )
        self.assertEqual(
            b"12345678",
            run(
                _read_bounded_body(
                    _StreamRequest({}, (b"1234", b"5678")),
                    max_body_bytes=8,
                )
            ),
        )

    def test_remaining_transport_validation_and_middleware_failure_are_safe(self) -> None:
        replay_headers = {**self.auth, "Idempotency-Key": "replay-api-request-0099"}
        invalid_json = self.client.post(
            "/api/v1/impact/runs",
            content=b"{",
            headers={**replay_headers, "Content-Type": "application/json"},
        )
        non_object = self.client.post(
            "/api/v1/impact/runs",
            json=[],
            headers=replay_headers,
        )
        invalid_bounds = self.client.post(
            "/api/v1/impact/runs",
            json={"case_count": 0},
            headers=replay_headers,
        )
        invalid_audit = self.client.get(
            "/api/v1/recovery-cases/not-a-ulid/audit",
            headers=self.auth,
        )
        self.assertEqual(400, invalid_json.status_code)
        self.assertEqual(400, non_object.status_code)
        self.assertEqual(400, invalid_bounds.status_code)
        self.assertEqual(400, invalid_audit.status_code)

        raw = b"{}"
        ingress_runtime = replace(self.runtime, webhook_ingress=_IngressRaises())
        generic = TestClient(create_app(ingress_runtime)).post(
            f"/api/v1/webhooks/razorpay/{TOKEN}",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-Razorpay-Signature": calculate_webhook_signature(raw, SECRET),
                "x-razorpay-event-id": "event-generic-ingress-1",
            },
        )
        self.assertEqual(400, generic.status_code)
        self.assertEqual("INVALID_WEBHOOK_REQUEST", generic.json()["detail"]["code"])

        client = TestClient(create_app(self.runtime), raise_server_exceptions=False)
        with patch.object(ControlPlaneRuntime, "readiness", side_effect=RuntimeError("private")):
            failed = client.get("/health/ready")
        self.assertEqual(500, failed.status_code)

    def test_correlation_id_is_propagated_and_invalid_input_is_not_reflected(self) -> None:
        supplied = self.client.get(
            "/health/live",
            headers={"X-Request-ID": "caller-request-0001"},
        )
        self.assertEqual(supplied.headers["x-request-id"], "caller-request-0001")

        unsafe = "bad request id Authorization=Bearer-secret"
        generated = self.client.get("/health/live", headers={"X-Request-ID": unsafe})
        self.assertRegex(generated.headers["x-request-id"], r"^req_[0-9a-f]{32}$")
        self.assertNotIn(unsafe, self.log_output.getvalue())

    def test_oversized_content_length_is_rejected_before_body_verification(self) -> None:
        response = self.client.post(
            f"/api/v1/webhooks/razorpay/{TOKEN}",
            content=b"{}",
            headers={
                "Content-Length": str(self.runtime.settings.webhook_max_body_bytes + 1),
                "Content-Type": "application/json",
                "X-Razorpay-Signature": "0" * 64,
                "x-razorpay-event-id": "event-too-large-1",
            },
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["detail"]["code"], "WEBHOOK_BODY_TOO_LARGE")
        self.assertEqual(
            self.observability.counters.snapshot()["webhook_verification_failure_total"],
            0,
        )

    def test_same_event_id_with_different_verified_bytes_counts_conflict(self) -> None:
        def send(payment_id: str) -> object:
            raw = json.dumps(
                {
                    "account_id": "acc_test_1",
                    "event": "payment.failed",
                    "created_at": 1_788_000_000,
                    "payload": {"payment": {"entity": {"id": payment_id}}},
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            return self.client.post(
                f"/api/v1/webhooks/razorpay/{TOKEN}",
                content=raw,
                headers={
                    "Content-Type": "application/json",
                    "X-Razorpay-Signature": calculate_webhook_signature(raw, SECRET),
                    "x-razorpay-event-id": "event-conflict-1",
                },
            )

        self.assertEqual(send("pay_conflict_1").status_code, 204)
        self.assertEqual(send("pay_conflict_2").status_code, 409)
        counters = self.observability.counters.snapshot()
        self.assertEqual(counters["webhook_accepted_total"], 1)
        self.assertEqual(counters["webhook_conflict_total"], 1)


if __name__ == "__main__":
    unittest.main()
