from __future__ import annotations

import unittest

from retrywise.services.control_plane.replay import (
    ReplayIdempotencyConflict,
    ReplayRunRequest,
    ReplayService,
)


class ReplayServiceTests(unittest.TestCase):
    def test_overview_is_honest_safe_and_reproducible(self) -> None:
        service = ReplayService()
        request = ReplayRunRequest(
            seed=42,
            case_count=2_000,
            bootstrap_samples=400,
            code_revision="test-revision",
        )
        first = service.overview(request)
        second = service.overview(request)
        self.assertEqual(first, second)
        self.assertEqual(first["environment"], "REPLAY")
        self.assertFalse(first["labels"]["real_money"])
        self.assertFalse(first["labels"]["observed_real_merchant_revenue_claimed"])
        self.assertEqual(first["hard_safety_violations"], 0)
        self.assertEqual(first["audit_completeness_pct"], 100.0)
        self.assertGreater(first["offline_simulated_incremental_value_minor"], 0)
        self.assertGreater(first["net_lift_vs_b3_minor"], 0)
        self.assertTrue(first["paired_interval_vs_b3_minor"]["supports_improvement"])
        self.assertEqual(first["manifest"]["case_count"], 2_000)
        self.assertTrue(first["manifest"]["model_version"].startswith("sha256:"))
        self.assertEqual(
            first["diagnosis_model"]["artifact_version"],
            first["manifest"]["model_version"],
        )
        self.assertFalse(first["diagnosis_model"]["merchant_performance_claimed"])
        self.assertEqual(first["diagnosis_model"]["metrics"]["sample_count"], 18)
        self.assertGreater(first["model_abstentions"], 0)

    def test_run_bounds_prevent_uncontrolled_work(self) -> None:
        with self.assertRaises(ValueError):
            ReplayRunRequest(case_count=0)
        with self.assertRaises(ValueError):
            ReplayRunRequest(case_count=5_001)
        with self.assertRaises(ValueError):
            ReplayRunRequest(bootstrap_samples=2_001)
        with self.assertRaises(TypeError):
            ReplayRunRequest(model_version="invented-label")

    def test_submission_is_idempotent_and_merchant_scoped(self) -> None:
        service = ReplayService()
        request = ReplayRunRequest(case_count=24, bootstrap_samples=10)
        first = service.submit(
            merchant_id="merchant-1",
            idempotency_key="replay-request-key-0001",
            request=request,
        )
        duplicate = service.submit(
            merchant_id="merchant-1",
            idempotency_key="replay-request-key-0001",
            request=request,
        )
        other_merchant = service.submit(
            merchant_id="merchant-2",
            idempotency_key="replay-request-key-0001",
            request=request,
        )
        self.assertEqual(first, duplicate)
        self.assertEqual(first, other_merchant)

        with self.assertRaises(ReplayIdempotencyConflict):
            service.submit(
                merchant_id="merchant-1",
                idempotency_key="replay-request-key-0001",
                request=ReplayRunRequest(case_count=25, bootstrap_samples=10),
            )


if __name__ == "__main__":
    unittest.main()
