from __future__ import annotations

import json
import unittest
import urllib.error
from collections.abc import Mapping
from decimal import Decimal
from unittest.mock import patch

from retrywise.packages.diagnosis import (
    AbstentionReason,
    DiagnosisEngine,
    DiagnosisMode,
    DiagnosisRouter,
    FailureClass,
    GeminiDiagnosisClient,
    GeminiDiagnosisError,
    SensitiveFeatureError,
    ShadowDiagnosis,
    StaticDiagnosisModeReader,
    normalize_features,
)
from retrywise.packages.diagnosis.gemini import UrlLibGeminiTransport
from retrywise.packages.diagnosis.provenance import DiagnosisProvenance
from retrywise.packages.domain.values import Probability


def features() -> dict[str, object]:
    return {
        "payment_method": "upi",
        "error_source": "customer",
        "error_step": "authentication",
        "error_reason": "incorrect_pin",
        "incident_state": "normal",
        "attempt_bucket": "first",
        "failure_age_bucket": "recent",
    }


def model_response(*, predicted: str = "customer_correctable") -> dict[str, object]:
    points = {
        "provider_incident": 300,
        "customer_correctable": 7600,
        "credential_permanent": 600,
        "funds_temporary": 700,
        "merchant_integration": 400,
        "unknown": 400,
    }
    return {
        "status": "completed",
        "steps": [
            {
                "type": "model_output",
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "predicted_class": predicted,
                                "probabilities_basis_points": points,
                            }
                        ),
                    }
                ],
            }
        ],
    }


class _Transport:
    def __init__(self, response: Mapping[str, object] | None = None) -> None:
        self.response = response or model_response()
        self.calls: list[dict[str, object]] = []
        self.error: GeminiDiagnosisError | None = None

    def post(
        self,
        *,
        api_key: str,
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append(
            {
                "api_key": api_key,
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.error is not None:
            raise self.error
        return self.response


def client(transport: _Transport) -> GeminiDiagnosisClient:
    return GeminiDiagnosisClient(
        api_key="test-key-1234567890",
        transport=transport,
    )


class _HttpResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> _HttpResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self.body


class GeminiDiagnosisRouterTests(unittest.TestCase):
    def test_hybrid_uses_structured_gemini_result_without_sensitive_fields(self) -> None:
        transport = _Transport()
        router = DiagnosisRouter(
            mode_reader=StaticDiagnosisModeReader(DiagnosisMode.HYBRID_GEMINI),
            gemini=client(transport),
        )

        result = router.infer(merchant_id="merchant", raw_features=features())

        self.assertIs(result.predicted_class, FailureClass.CUSTOMER_CORRECTABLE)
        self.assertEqual("0.76", result.confidence.to_primitive())
        self.assertIs(result.provenance.executed_engine, DiagnosisEngine.GEMINI)
        self.assertFalse(result.provenance.used_fallback)
        payload = transport.calls[0]["payload"]
        rendered = json.dumps(payload)
        self.assertNotIn("customer_id", rendered)
        self.assertNotIn("payment_id", rendered)
        self.assertEqual("application/json", payload["response_format"]["mime_type"])

    def test_invalid_external_semantics_fall_back_and_force_approval(self) -> None:
        response = model_response(predicted="provider_incident")
        transport = _Transport(response)
        router = DiagnosisRouter(
            mode_reader=StaticDiagnosisModeReader(DiagnosisMode.HYBRID_GEMINI),
            gemini=client(transport),
        )

        result = router.infer(merchant_id="merchant", raw_features=features())

        self.assertIs(result.provenance.executed_engine, DiagnosisEngine.LOCAL_ML)
        self.assertEqual("GEMINI_PREDICTION_MISMATCH", result.provenance.fallback_reason_code)
        self.assertTrue(result.abstained)
        self.assertIn(
            AbstentionReason.EXTERNAL_ENGINE_FALLBACK,
            result.abstention_reasons,
        )

    def test_shadow_never_replaces_local_authority(self) -> None:
        router = DiagnosisRouter(
            mode_reader=StaticDiagnosisModeReader(DiagnosisMode.SHADOW),
            gemini=client(_Transport()),
        )

        result = router.infer(merchant_id="merchant", raw_features=features())

        self.assertIs(result.provenance.executed_engine, DiagnosisEngine.LOCAL_ML)
        self.assertIsNotNone(result.provenance.shadow)
        self.assertIsInstance(result.provenance.shadow.agreed, bool)  # type: ignore[union-attr]

    def test_missing_key_is_audited_local_fallback(self) -> None:
        router = DiagnosisRouter(mode_reader=StaticDiagnosisModeReader(DiagnosisMode.HYBRID_GEMINI))

        result = router.infer(merchant_id="merchant", raw_features=features())

        self.assertTrue(result.provenance.used_fallback)
        self.assertEqual("GEMINI_NOT_CONFIGURED", result.provenance.fallback_reason_code)
        self.assertTrue(result.abstained)

    def test_sensitive_feature_is_rejected_before_external_transport(self) -> None:
        transport = _Transport()
        router = DiagnosisRouter(
            mode_reader=StaticDiagnosisModeReader(DiagnosisMode.HYBRID_GEMINI),
            gemini=client(transport),
        )

        with self.assertRaises(SensitiveFeatureError):
            router.infer(
                merchant_id="merchant",
                raw_features={**features(), "phone": "+919999999999"},
            )
        self.assertEqual([], transport.calls)

    def test_circuit_opens_after_three_external_failures(self) -> None:
        transport = _Transport()
        transport.error = GeminiDiagnosisError("GEMINI_UNAVAILABLE")
        router = DiagnosisRouter(
            mode_reader=StaticDiagnosisModeReader(DiagnosisMode.HYBRID_GEMINI),
            gemini=client(transport),
        )

        reasons = [
            router.infer(
                merchant_id="merchant", raw_features=features()
            ).provenance.fallback_reason_code
            for _ in range(4)
        ]

        self.assertEqual(3, len(transport.calls))
        self.assertEqual("GEMINI_CIRCUIT_OPEN", reasons[-1])

    def test_structured_output_is_semantically_validated(self) -> None:
        invalid_probabilities = model_response()
        invalid_probabilities["steps"][0]["content"][0]["text"] = json.dumps(  # type: ignore[index]
            {
                "predicted_class": "customer_correctable",
                "probabilities_basis_points": {
                    "provider_incident": 300,
                    "customer_correctable": 7599,
                    "credential_permanent": 600,
                    "funds_temporary": 700,
                    "merchant_integration": 400,
                    "unknown": 400,
                },
            }
        )
        invalid_cases = (
            ({"status": "pending", "steps": []}, "GEMINI_INCOMPLETE_RESPONSE"),
            ({"status": "completed", "steps": "invalid"}, "GEMINI_INVALID_RESPONSE"),
            (
                {
                    "steps": [
                        {
                            "type": "model_output",
                            "content": [{"type": "text", "text": "not-json"}],
                        }
                    ]
                },
                "GEMINI_INVALID_STRUCTURED_OUTPUT",
            ),
            (
                {
                    "steps": [
                        {
                            "type": "model_output",
                            "content": [{"type": "text", "text": "[]"}],
                        }
                    ]
                },
                "GEMINI_INVALID_STRUCTURED_OUTPUT",
            ),
            (
                {"steps": [{"type": "model_output", "content": "invalid"}]},
                "GEMINI_INVALID_RESPONSE",
            ),
            (
                {
                    "steps": [
                        {
                            "type": "model_output",
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(
                                        {
                                            "predicted_class": "customer_correctable",
                                            "probabilities_basis_points": [],
                                        }
                                    ),
                                }
                            ],
                        }
                    ]
                },
                "GEMINI_SCHEMA_MISMATCH",
            ),
            (invalid_probabilities, "GEMINI_PROBABILITY_MISMATCH"),
        )
        vector = normalize_features(features())
        for response, reason_code in invalid_cases:
            with (
                self.subTest(reason_code=reason_code),
                self.assertRaisesRegex(GeminiDiagnosisError, reason_code),
            ):
                client(_Transport(response)).infer_vector(vector)

    def test_low_confidence_ood_result_abstains_for_both_reasons(self) -> None:
        response = model_response(predicted="provider_incident")
        response["steps"][0]["content"][0]["text"] = json.dumps(  # type: ignore[index]
            {
                "predicted_class": "provider_incident",
                "probabilities_basis_points": {
                    "provider_incident": 2000,
                    "customer_correctable": 1800,
                    "credential_permanent": 1600,
                    "funds_temporary": 1600,
                    "merchant_integration": 1500,
                    "unknown": 1500,
                },
            }
        )

        result = client(_Transport(response)).infer_vector(normalize_features({}))

        self.assertTrue(result.out_of_distribution)
        self.assertEqual(
            (AbstentionReason.OUT_OF_DISTRIBUTION, AbstentionReason.LOW_CONFIDENCE),
            result.abstention_reasons,
        )

    def test_client_configuration_and_repr_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            GeminiDiagnosisClient(api_key="short")
        with self.assertRaises(ValueError):
            GeminiDiagnosisClient(api_key="test-key-1234567890", model="")
        with self.assertRaises(ValueError):
            GeminiDiagnosisClient(api_key="test-key-1234567890", timeout_seconds=0.1)
        with self.assertRaises(TypeError):
            GeminiDiagnosisClient(api_key="test-key-1234567890", transport=object())  # type: ignore[arg-type]
        configured = GeminiDiagnosisClient(api_key="test-key-1234567890")
        self.assertNotIn("test-key", repr(configured))
        with self.assertRaises(TypeError):
            configured.infer_vector({})  # type: ignore[arg-type]

    def test_fixed_origin_transport_bounds_and_sanitizes_failures(self) -> None:
        transport = UrlLibGeminiTransport()
        valid_body = json.dumps({"status": "completed"}).encode()
        with patch("urllib.request.urlopen", return_value=_HttpResponse(valid_body)) as opened:
            decoded = transport.post(
                api_key="private-test-key",
                payload={"model": "gemini-2.5-flash"},
                timeout_seconds=1,
            )
        request = opened.call_args.args[0]
        self.assertEqual("completed", decoded["status"])
        self.assertNotIn("private-test-key", request.full_url)
        self.assertEqual("private-test-key", request.get_header("X-goog-api-key"))

        failures: tuple[tuple[object, str], ...] = (
            (_HttpResponse(b"x" * 65_537), "GEMINI_RESPONSE_TOO_LARGE"),
            (
                urllib.error.HTTPError("https://fixed.invalid", 429, "", None, None),
                "GEMINI_RATE_LIMITED",
            ),
            (
                urllib.error.HTTPError("https://fixed.invalid", 503, "", None, None),
                "GEMINI_UNAVAILABLE",
            ),
            (
                urllib.error.HTTPError("https://fixed.invalid", 400, "", None, None),
                "GEMINI_REQUEST_REJECTED",
            ),
            (TimeoutError(), "GEMINI_TIMEOUT"),
            (OSError(), "GEMINI_UNAVAILABLE"),
            (_HttpResponse(b"\xff"), "GEMINI_INVALID_RESPONSE"),
            (_HttpResponse(b"[]"), "GEMINI_INVALID_RESPONSE"),
        )
        for outcome, reason_code in failures:
            with self.subTest(reason_code=reason_code):
                patched = (
                    patch("urllib.request.urlopen", return_value=outcome)
                    if isinstance(outcome, _HttpResponse)
                    else patch("urllib.request.urlopen", side_effect=outcome)
                )
                with patched, self.assertRaisesRegex(GeminiDiagnosisError, reason_code):
                    transport.post(api_key="private-test-key", payload={}, timeout_seconds=1)

    def test_provenance_invariants_and_serialization(self) -> None:
        shadow = ShadowDiagnosis(
            model_name="google_gemini",
            model_version="gemini-2.5-flash",
            predicted_class="customer_correctable",
            confidence=Probability(Decimal("0.76")),
            agreed=True,
        )
        provenance = DiagnosisProvenance(
            requested_mode=DiagnosisMode.SHADOW,
            shadow=shadow,
        )
        self.assertEqual("google_gemini", provenance.to_primitive()["shadow"]["model_name"])  # type: ignore[index]
        self.assertFalse(provenance.used_fallback)

        invalid_shadow_values = (
            {"model_name": "bad name"},
            {"model_version": "bad name"},
            {"confidence": "0.76"},
            {"agreed": 1},
        )
        base = {
            "model_name": "google_gemini",
            "model_version": "gemini-2.5-flash",
            "predicted_class": "customer_correctable",
            "confidence": Probability(Decimal("0.76")),
            "agreed": True,
        }
        for change in invalid_shadow_values:
            with self.subTest(change=change), self.assertRaises((TypeError, ValueError)):
                ShadowDiagnosis(**{**base, **change})  # type: ignore[arg-type]

        invalid_provenance = (
            {"requested_mode": "LOCAL_ML"},
            {"executed_engine": "LOCAL_ML"},
            {"model_name": "bad name"},
            {"latency_ms": -1},
            {"fallback_reason_code": "lowercase"},
            {"shadow": "invalid"},
            {"executed_engine": DiagnosisEngine.GEMINI},
            {
                "requested_mode": DiagnosisMode.HYBRID_GEMINI,
                "shadow": shadow,
            },
            {"requested_mode": DiagnosisMode.SHADOW},
            {
                "requested_mode": DiagnosisMode.SHADOW,
                "executed_engine": DiagnosisEngine.GEMINI,
                "shadow": shadow,
            },
        )
        for change in invalid_provenance:
            with self.subTest(change=change), self.assertRaises((TypeError, ValueError)):
                DiagnosisProvenance(**change)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
