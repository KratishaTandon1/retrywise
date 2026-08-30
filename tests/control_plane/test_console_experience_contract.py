from __future__ import annotations

import struct
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONSOLE_ROOT = PROJECT_ROOT / "apps" / "console"


class ConsoleExperienceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.component = (CONSOLE_ROOT / "app" / "retrywise-dashboard.jsx").read_text(
            encoding="utf-8"
        )
        self.styles = (CONSOLE_ROOT / "app" / "globals.css").read_text(encoding="utf-8")
        self.layout = (CONSOLE_ROOT / "app" / "layout.tsx").read_text(encoding="utf-8")

    def test_real_test_mode_story_is_the_default_and_never_uses_replay_fallback(self) -> None:
        self.assertIn("const [mode, setMode] = useState('test')", self.component)
        self.assertIn("Persisted provider evidence", self.component)
        self.assertIn("Razorpay Test Mode · no real money", self.component)
        self.assertIn("Recovered revenue without retrying the original payment.", self.component)

    def test_runtime_case_and_evidence_routes_back_every_proof_surface(self) -> None:
        for route in (
            "/api/retrywise/overview",
            "/api/retrywise/cases",
            "/api/retrywise/approvals",
            "/api/retrywise/controls/kill-switch",
            "/api/retrywise/controls/diagnosis-engine",
            "/api/retrywise/impact",
        ):
            self.assertIn(route, self.component)
        self.assertIn("/audit`,", self.component)
        self.assertIn("caseDetail", self.component)
        self.assertIn("provider_payment_link_id", self.component)
        self.assertIn("provider_payment_id", self.component)
        self.assertIn("Gemini + fallback", self.component)
        self.assertIn("Shadow comparison", self.component)
        self.assertIn("Local ML fallback", self.component)

    def test_product_explains_trigger_detection_authority_and_reconciliation(self) -> None:
        for required_stage in (
            "Razorpay payment.failed",
            "Verify, deduplicate, re-read",
            "Classify failure and uncertainty",
            "Deterministic policy owns the effect",
            "Create one bounded payment path",
            "Close only on provider money truth",
        ):
            self.assertIn(required_stage, self.component)
        self.assertIn("How a failed payment becomes a governed recovery.", self.component)

    def test_live_trace_polls_follows_newest_and_explains_the_external_trigger(self) -> None:
        for required_behavior in (
            "const LIVE_REFRESH_MS = 5000",
            "window.setInterval(refreshEvidence, LIVE_REFRESH_MS)",
            "document.addEventListener('visibilitychange', refreshWhenVisible)",
            "following newest case",
            "Start a fresh Test recovery",
            "failure@razorpay",
            "The original failed payment is never retried.",
            'aria-live="polite"',
        ):
            self.assertIn(required_behavior, self.component)
        for visual_behavior in (
            ".live-trace-bar",
            ".flow-grid li.active",
            ".event-stream",
            ".test-trigger-guide",
            ".diagnosis-control-panel",
            "@keyframes progressFlow",
        ):
            self.assertIn(visual_behavior, self.styles)

    def test_client_source_contains_no_credentials_or_recorded_provider_ids(self) -> None:
        for forbidden in (
            "rzp_test_",
            "rzp_live_",
            "RAZORPAY_KEY_SECRET",
            "pay_TV",
            "order_TV",
            "plink_TV",
            "01M17H",
        ):
            self.assertNotIn(forbidden, self.component)

    def test_social_card_and_metadata_are_release_ready(self) -> None:
        card = (CONSOLE_ROOT / "public" / "og.png").read_bytes()
        self.assertEqual(b"\x89PNG\r\n\x1a\n", card[:8])
        width, height = struct.unpack(">II", card[16:24])
        self.assertEqual((1200, 630), (width, height))
        self.assertIn("RETRYWISE_SITE_URL", self.layout)
        self.assertIn("openGraph", self.layout)
        self.assertIn("summary_large_image", self.layout)
        self.assertIn("/og.png", self.layout)

    def test_visual_system_has_responsive_and_reduced_motion_contracts(self) -> None:
        self.assertIn("@media (max-width: 860px)", self.styles)
        self.assertIn("@media (max-width: 560px)", self.styles)
        self.assertIn("@media (prefers-reduced-motion: reduce)", self.styles)
        self.assertIn(".operational-flow", self.styles)
        self.assertIn(".flow-grid", self.styles)
        self.assertIn(".recovery-rail", self.styles)


if __name__ == "__main__":
    unittest.main()
