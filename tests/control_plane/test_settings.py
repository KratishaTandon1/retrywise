from __future__ import annotations

import unittest
from dataclasses import replace

from retrywise.services.control_plane.settings import (
    ConfigurationError,
    ControlPlaneSettings,
    DataSource,
    DeploymentProfile,
    EffectsMode,
)


class ControlPlaneSettingsTests(unittest.TestCase):
    def test_defaults_are_replay_and_fail_closed(self) -> None:
        settings = ControlPlaneSettings.from_mapping({})
        self.assertIs(settings.data_source, DataSource.REPLAY)
        self.assertIs(settings.environment, DeploymentProfile.DEVELOPMENT)
        self.assertIs(settings.effects_mode, EffectsMode.DISABLED)
        self.assertTrue(settings.global_kill_switch)
        self.assertFalse(settings.database_require_tls)
        self.assertFalse(settings.embedded_worker_enabled)

    def test_render_revision_is_automatic_and_overrides_manual_revision(self) -> None:
        settings = ControlPlaneSettings.from_mapping(
            {
                "RENDER_GIT_COMMIT": "render-sha-current",
                "RETRYWISE_CODE_REVISION": "stale-manual-sha",
            }
        )
        self.assertEqual("render-sha-current", settings.code_revision)

    def test_embedded_worker_flag_is_strict(self) -> None:
        settings = ControlPlaneSettings.from_mapping({"RETRYWISE_EMBEDDED_WORKER": "true"})
        self.assertTrue(settings.embedded_worker_enabled)
        with self.assertRaises(ConfigurationError):
            ControlPlaneSettings.from_mapping({"RETRYWISE_EMBEDDED_WORKER": "True"})

    def test_effects_cannot_be_enabled_in_replay(self) -> None:
        with self.assertRaises(ConfigurationError):
            ControlPlaneSettings.from_mapping(
                {
                    "RETRYWISE_DATA_SOURCE": "REPLAY",
                    "RETRYWISE_EFFECTS_MODE": "razorpay_test",
                }
            )

    def test_test_effects_require_test_data_source_but_not_raw_credentials(self) -> None:
        settings = ControlPlaneSettings.from_mapping(
            {
                "RETRYWISE_DATA_SOURCE": "RAZORPAY_TEST_MODE",
                "RETRYWISE_EFFECTS_MODE": "razorpay_test",
            }
        )
        self.assertIs(settings.effects_mode, EffectsMode.RAZORPAY_TEST)

    def test_raw_api_credentials_are_always_rejected(self) -> None:
        for raw in (
            {"RAZORPAY_KEY_ID": "rzp_test_example"},
            {"RAZORPAY_KEY_SECRET": "test-secret-example"},
            {
                "RAZORPAY_KEY_ID": "rzp_test_example",
                "RAZORPAY_KEY_SECRET": "test-secret-example",
            },
            {
                "RAZORPAY_KEY_ID": "rzp_live_forbidden",
                "RAZORPAY_KEY_SECRET": "live-secret-forbidden",
            },
            {"GEMINI_API_KEY": "gemini-secret-forbidden"},
        ):
            with (
                self.subTest(raw=tuple(raw)),
                self.assertRaises(ConfigurationError),
            ):
                ControlPlaneSettings.from_mapping(raw)

    def test_boolean_parser_is_strict(self) -> None:
        with self.assertRaises(ConfigurationError):
            ControlPlaneSettings.from_mapping({"RETRYWISE_GLOBAL_KILL_SWITCH": "True"})
        with self.assertRaises(ConfigurationError):
            ControlPlaneSettings.from_mapping({"DATABASE_REQUIRE_TLS": "1"})

    def test_public_summary_names_only_the_non_secret_credential_authority(self) -> None:
        settings = ControlPlaneSettings.from_mapping({})
        summary = settings.public_summary()
        self.assertEqual(
            "versioned_managed_secret_binding",
            summary["razorpay_effect_credential_source"],
        )
        self.assertNotIn("credential", repr(settings))
        self.assertFalse(summary["database_tls_required"])

    def test_environment_and_http_origins_are_closed(self) -> None:
        with self.assertRaises(ConfigurationError):
            ControlPlaneSettings.from_mapping({"RETRYWISE_ENVIRONMENT": "staging-ish"})
        with self.assertRaises(ConfigurationError):
            ControlPlaneSettings.from_mapping(
                {"RETRYWISE_CORS_ALLOWED_ORIGINS": "https://console.example/path"}
            )

    def test_deployed_profiles_require_https_and_immutable_revision(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "HTTPS"):
            ControlPlaneSettings.from_mapping(
                {
                    "RETRYWISE_ENVIRONMENT": "sandbox",
                    "RETRYWISE_CODE_REVISION": "abc123",
                }
            )
        settings = ControlPlaneSettings.from_mapping(
            {
                "RETRYWISE_ENVIRONMENT": "sandbox",
                "RETRYWISE_PUBLIC_BASE_URL": "https://api.retrywise.example",
                "RETRYWISE_CORS_ALLOWED_ORIGINS": "https://console.retrywise.example",
                "RETRYWISE_CODE_REVISION": "git-sha-abc123",
                "DATABASE_REQUIRE_TLS": "true",
            }
        )
        self.assertIs(settings.environment, DeploymentProfile.SANDBOX)

    def test_deployed_profiles_require_database_tls_policy(self) -> None:
        deployed = {
            "RETRYWISE_ENVIRONMENT": "production",
            "RETRYWISE_PUBLIC_BASE_URL": "https://api.retrywise.example",
            "RETRYWISE_CORS_ALLOWED_ORIGINS": "https://console.retrywise.example",
            "RETRYWISE_CODE_REVISION": "git-sha-abc123",
        }

        with self.assertRaisesRegex(ConfigurationError, "DATABASE_REQUIRE_TLS=true"):
            ControlPlaneSettings.from_mapping(deployed)

        settings = ControlPlaneSettings.from_mapping({**deployed, "DATABASE_REQUIRE_TLS": "true"})
        self.assertTrue(settings.database_require_tls)

    def test_closed_types_are_revalidated_at_the_dataclass_boundary(self) -> None:
        valid = ControlPlaneSettings.from_mapping({})
        invalid_values = {
            "environment": "development",
            "data_source": "REPLAY",
            "effects_mode": "disabled",
            "global_kill_switch": 1,
            "database_require_tls": 1,
            "embedded_worker_enabled": 1,
        }
        for field, value in invalid_values.items():
            with self.subTest(field=field), self.assertRaises(ConfigurationError):
                replace(valid, **{field: value})

    def test_origins_bounds_and_revision_are_strict(self) -> None:
        valid = ControlPlaneSettings.from_mapping({})
        invalid_replacements = (
            {"public_base_url": "not-a-url"},
            {"public_base_url": "https://user:secret@example.test"},
            {"public_base_url": "https://example.test/#fragment"},
            {"cors_allowed_origins": ()},
            {"webhook_max_body_bytes": 1_023},
            {"webhook_max_body_bytes": 1_048_577},
            {"code_revision": ""},
            {"code_revision": " revision "},
            {"code_revision": "r" * 129},
        )
        for replacement in invalid_replacements:
            with (
                self.subTest(replacement=tuple(replacement)),
                self.assertRaises(ConfigurationError),
            ):
                replace(valid, **replacement)

        with self.assertRaisesRegex(ConfigurationError, "immutable code revision"):
            replace(
                valid,
                environment=DeploymentProfile.SANDBOX,
                public_base_url="https://api.example.test",
                cors_allowed_origins=("https://console.example.test",),
                database_require_tls=True,
            )

    def test_mapping_enums_and_integer_bounds_fail_closed(self) -> None:
        for field, value in (
            ("RETRYWISE_DATA_SOURCE", "provider-ish"),
            ("RETRYWISE_EFFECTS_MODE", "enabled"),
            ("RETRYWISE_WEBHOOK_MAX_BODY_BYTES", "many"),
            ("RETRYWISE_WEBHOOK_MAX_BODY_BYTES", "100"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ConfigurationError):
                ControlPlaneSettings.from_mapping({field: value})


if __name__ == "__main__":
    unittest.main()
