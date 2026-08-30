from __future__ import annotations

import unittest
from datetime import UTC, datetime

from retrywise.services.control_plane.auth import DenyAllAuthorizer
from retrywise.services.control_plane.postgres_inbox import PostgresWebhookInbox
from retrywise.services.control_plane.runtime import ControlPlaneRuntime
from retrywise.services.control_plane.settings import ConfigurationError


class RuntimeCompositionTests(unittest.TestCase):
    def test_empty_environment_composes_fail_closed_runtime(self) -> None:
        runtime = ControlPlaneRuntime.from_mapping({})
        self.assertTrue(runtime.settings.global_kill_switch)
        self.assertIsInstance(runtime.operator_authorizer, DenyAllAuthorizer)
        ready, report = runtime.readiness()
        self.assertTrue(ready)
        self.assertFalse(report["webhook_configured"])
        self.assertFalse(report["durable_ingress"])

    def test_operator_tenant_configuration_does_not_activate_webhook(self) -> None:
        runtime = ControlPlaneRuntime.from_mapping(
            {
                "RETRYWISE_OPERATOR_TOKEN": "operator-token-with-more-than-32-bytes!!",
                "RETRYWISE_MERCHANT_ID": "merchant-1",
            }
        )

        self.assertFalse(runtime.webhook_configured)

    def test_partial_webhook_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "incomplete"):
            ControlPlaneRuntime.from_mapping(
                {"RETRYWISE_WEBHOOK_ENDPOINT_TOKEN": "token_1234567890abcdefghijkl"}
            )

    def test_short_operator_token_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ControlPlaneRuntime.from_mapping(
                {
                    "RETRYWISE_OPERATOR_TOKEN": "short",
                    "RETRYWISE_MERCHANT_ID": "merchant-1",
                }
            )

    def test_deployed_webhook_requires_postgres_and_selects_durable_adapter(self) -> None:
        base = {
            "RETRYWISE_ENVIRONMENT": "sandbox",
            "RETRYWISE_PUBLIC_BASE_URL": "https://api.retrywise.example",
            "RETRYWISE_CORS_ALLOWED_ORIGINS": "https://console.retrywise.example",
            "RETRYWISE_CODE_REVISION": "sha256:deployment-123",
            "DATABASE_REQUIRE_TLS": "true",
            "RETRYWISE_WEBHOOK_ENDPOINT_TOKEN": "endpoint_token_1234567890abcdef",
            "RETRYWISE_MERCHANT_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "RETRYWISE_PROVIDER_ACCOUNT_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "RAZORPAY_ACCOUNT_ID": "acc_test_1",
            "RAZORPAY_WEBHOOK_SECRET_CURRENT": "test-webhook-secret-32-bytes-long",
        }
        with self.assertRaisesRegex(ConfigurationError, "DATABASE_URL"):
            ControlPlaneRuntime.from_mapping(base)

        runtime = ControlPlaneRuntime.from_mapping(
            {**base, "DATABASE_URL": "postgresql://retrywise@database/retrywise"}
        )

        self.assertTrue(runtime.webhook_configured)
        self.assertTrue(runtime.webhook_ingress.durable)
        self.assertIsInstance(runtime.webhook_ingress._inbox, PostgresWebhookInbox)

    def test_tls_required_runtime_rejects_conflicting_dsn_without_echoing_secret(self) -> None:
        password = "database-password-must-not-leak"
        mapping = {
            "RETRYWISE_ENVIRONMENT": "sandbox",
            "RETRYWISE_PUBLIC_BASE_URL": "https://api.retrywise.example",
            "RETRYWISE_CORS_ALLOWED_ORIGINS": "https://console.retrywise.example",
            "RETRYWISE_CODE_REVISION": "sha256:deployment-123",
            "DATABASE_REQUIRE_TLS": "true",
            "DATABASE_URL": (
                f"postgresql://retrywise:{password}@database/retrywise?sslmode=disable"
            ),
        }

        with self.assertRaises(ConfigurationError) as raised:
            ControlPlaneRuntime.from_mapping(mapping)

        self.assertIn("sslmode=verify-full", str(raised.exception))
        self.assertNotIn(password, str(raised.exception))

    def test_previous_webhook_secret_requires_future_canonical_utc_expiry(self) -> None:
        base = {
            "RETRYWISE_WEBHOOK_ENDPOINT_TOKEN": "endpoint_token_1234567890abcdef",
            "RETRYWISE_MERCHANT_ID": "merchant-1",
            "RETRYWISE_PROVIDER_ACCOUNT_ID": "provider-account-1",
            "RAZORPAY_ACCOUNT_ID": "acc_test_1",
            "RAZORPAY_WEBHOOK_SECRET_CURRENT": "current-secret",
        }
        now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)

        for partial in (
            {"RAZORPAY_WEBHOOK_SECRET_PREVIOUS": "previous-secret"},
            {"RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT": "2026-08-30T12:00:00Z"},
        ):
            with (
                self.subTest(partial=tuple(partial)),
                self.assertRaisesRegex(ConfigurationError, "configured together"),
            ):
                ControlPlaneRuntime.from_mapping({**base, **partial}, clock=lambda: now)

        with self.assertRaisesRegex(ConfigurationError, "YYYY-MM-DD"):
            ControlPlaneRuntime.from_mapping(
                {
                    **base,
                    "RAZORPAY_WEBHOOK_SECRET_PREVIOUS": "previous-secret",
                    "RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT": ("2026-08-30T12:00:00+00:00"),
                },
                clock=lambda: now,
            )

        with self.assertRaisesRegex(ConfigurationError, "must be in the future"):
            ControlPlaneRuntime.from_mapping(
                {
                    **base,
                    "RAZORPAY_WEBHOOK_SECRET_PREVIOUS": "previous-secret",
                    "RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT": "2026-08-29T12:00:00Z",
                },
                clock=lambda: now,
            )

        with self.assertRaisesRegex(ConfigurationError, "must be different"):
            ControlPlaneRuntime.from_mapping(
                {
                    **base,
                    "RAZORPAY_WEBHOOK_SECRET_PREVIOUS": "current-secret",
                    "RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT": ("2026-08-30T12:00:00Z"),
                },
                clock=lambda: now,
            )

        runtime = ControlPlaneRuntime.from_mapping(
            {
                **base,
                "RAZORPAY_WEBHOOK_SECRET_PREVIOUS": "previous-secret",
                "RAZORPAY_WEBHOOK_SECRET_PREVIOUS_EXPIRES_AT": "2026-08-30T12:00:00Z",
            },
            clock=lambda: now,
        )
        self.assertTrue(runtime.webhook_configured)
        self.assertNotIn("previous-secret", repr(runtime))

    def test_deployed_test_mode_requires_webhook_endpoint(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "webhook endpoint"):
            ControlPlaneRuntime.from_mapping(
                {
                    "RETRYWISE_ENVIRONMENT": "sandbox",
                    "RETRYWISE_DATA_SOURCE": "RAZORPAY_TEST_MODE",
                    "RETRYWISE_PUBLIC_BASE_URL": "https://api.retrywise.example",
                    "RETRYWISE_CORS_ALLOWED_ORIGINS": "https://console.retrywise.example",
                    "RETRYWISE_CODE_REVISION": "sha256:deployment-123",
                    "DATABASE_REQUIRE_TLS": "true",
                }
            )

    def test_effects_configuration_is_not_ready_without_composed_worker(self) -> None:
        runtime = ControlPlaneRuntime.from_mapping(
            {
                "RETRYWISE_DATA_SOURCE": "RAZORPAY_TEST_MODE",
                "RETRYWISE_EFFECTS_MODE": "razorpay_test",
            }
        )

        ready, report = runtime.readiness()

        self.assertFalse(ready)
        self.assertTrue(report["effect_path_required"])
        self.assertFalse(report["effect_path_ready"])
        self.assertFalse(report["worker_composed"])


if __name__ == "__main__":
    unittest.main()
