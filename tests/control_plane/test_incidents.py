from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from retrywise.packages.domain import IncidentState, Probability
from retrywise.services.control_plane.incidents import (
    IncidentDetector,
    IncidentDetectorConfig,
    IncidentProjection,
    MethodHealthWindow,
)

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def window(
    *,
    at: datetime = NOW,
    successes: int,
    failures: int,
    provider: bool = False,
) -> MethodHealthWindow:
    return MethodHealthWindow(
        scope_id="scope-upi-hdfc",
        merchant_id="merchant-1",
        payment_method="upi",
        window_started_at=at - timedelta(minutes=5),
        observed_at=at,
        successes=successes,
        failures=failures,
        baseline_success_rate=Probability("0.92"),
        provider_downtime_active=provider,
    )


def projection(state: IncidentState = IncidentState.NORMAL) -> IncidentProjection:
    return IncidentProjection(
        scope_id="scope-upi-hdfc",
        merchant_id="merchant-1",
        payment_method="upi",
        state=state,
    )


class IncidentDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = IncidentDetector(
            IncidentDetectorConfig(version="incident-detector-v1", minimum_volume=20)
        )

    def test_minimum_volume_prevents_small_sample_alerts(self) -> None:
        result = self.detector.evaluate(projection(), window(successes=1, failures=9))
        self.assertIs(result.projection.state, IncidentState.NORMAL)
        self.assertFalse(result.minimum_volume_met)
        self.assertFalse(result.changed)

    def test_degradation_progresses_through_suspected_then_confirmed(self) -> None:
        suspected = self.detector.evaluate(projection(), window(successes=30, failures=30))
        self.assertIs(suspected.projection.state, IncidentState.SUSPECTED)
        confirmed = self.detector.evaluate(
            suspected.projection,
            window(at=NOW + timedelta(seconds=30), successes=30, failures=30),
        )
        self.assertIs(confirmed.projection.state, IncidentState.CONFIRMED)
        self.assertEqual(confirmed.projection.version, 2)

    def test_provider_signal_confirms_after_suspected_transition(self) -> None:
        suspected = self.detector.evaluate(
            projection(), window(successes=18, failures=2, provider=True)
        )
        self.assertIs(suspected.projection.state, IncidentState.SUSPECTED)
        confirmed = self.detector.evaluate(
            suspected.projection,
            window(
                at=NOW + timedelta(seconds=10),
                successes=18,
                failures=2,
                provider=True,
            ),
        )
        self.assertIs(confirmed.projection.state, IncidentState.CONFIRMED)
        self.assertTrue(confirmed.provider_corroborated)

    def test_confirmed_incident_uses_cooling_hysteresis(self) -> None:
        initial = IncidentProjection(
            scope_id="scope-upi-hdfc",
            merchant_id="merchant-1",
            payment_method="upi",
            state=IncidentState.CONFIRMED,
            version=2,
            state_since=NOW - timedelta(minutes=2),
            last_evidence_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=9),
        )
        cooling = self.detector.evaluate(initial, window(successes=91, failures=9))
        self.assertIs(cooling.projection.state, IncidentState.COOLING)
        self.assertIsNotNone(cooling.projection.cooling_until)
        still_cooling = self.detector.evaluate(
            cooling.projection,
            window(at=NOW + timedelta(minutes=2), successes=91, failures=9),
        )
        self.assertIs(still_cooling.projection.state, IncidentState.COOLING)
        normal = self.detector.evaluate(
            still_cooling.projection,
            window(at=NOW + timedelta(minutes=4), successes=91, failures=9),
        )
        self.assertIs(normal.projection.state, IncidentState.NORMAL)

    def test_cooling_returns_to_confirmed_when_degradation_resumes(self) -> None:
        cooling = IncidentProjection(
            scope_id="scope-upi-hdfc",
            merchant_id="merchant-1",
            payment_method="upi",
            state=IncidentState.COOLING,
            version=3,
            state_since=NOW - timedelta(minutes=1),
            last_evidence_at=NOW - timedelta(minutes=1),
            cooling_until=NOW + timedelta(minutes=2),
        )
        result = self.detector.evaluate(cooling, window(successes=30, failures=30))
        self.assertIs(result.projection.state, IncidentState.CONFIRMED)
        self.assertEqual(result.reason_code, "DEGRADATION_RESUMED")

    def test_evidence_from_the_past_is_rejected(self) -> None:
        current = IncidentProjection(
            scope_id="scope-upi-hdfc",
            merchant_id="merchant-1",
            payment_method="upi",
            last_evidence_at=NOW,
        )
        with self.assertRaises(ValueError):
            self.detector.evaluate(
                current,
                window(at=NOW - timedelta(seconds=1), successes=20, failures=0),
            )


if __name__ == "__main__":
    unittest.main()
