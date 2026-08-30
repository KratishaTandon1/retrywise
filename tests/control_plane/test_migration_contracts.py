from __future__ import annotations

import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_DIR = PROJECT_ROOT / "infrastructure" / "postgres" / "migrations"


class MigrationContractTests(unittest.TestCase):
    def test_numbered_migrations_are_wired_in_order_everywhere(self) -> None:
        migration_names = [path.name for path in sorted(MIGRATION_DIR.glob("*.sql"))]
        self.assertEqual(
            [
                "001_initial.sql",
                "002_fenced_outbox_delivery.sql",
                "003_enforce_effect_source_boundary.sql",
                "004_enforce_observation_deadline.sql",
                "005_bind_provider_event_account.sql",
                "006_version_credential_binding.sql",
                "007_index_provider_event_body_reuse.sql",
                "008_allow_late_link_money_truth.sql",
                "009_worker_heartbeats.sql",
                "010_merchant_control_events.sql",
                "011_diagnosis_engine_routing.sql",
            ],
            migration_names,
        )

        migration_runner = (
            PROJECT_ROOT / "infrastructure" / "postgres" / "apply-local-migration.sh"
        ).read_text(encoding="utf-8")
        compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        continuous_integration = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        for document in (migration_runner, compose, continuous_integration):
            positions = [document.index(name) for name in migration_names]
            self.assertEqual(sorted(positions), positions)

        self.assertIn("seed_pre_hardening_upgrade.sql", continuous_integration)
        self.assertIn("verify_post_hardening_upgrade.sql", continuous_integration)
        for column in ("observation_started_at", "observation_contract_version"):
            self.assertIn(column, migration_runner)
            self.assertIn(column, continuous_integration)
        for column in ("credential_key_id_sha256", "credential_binding_version"):
            self.assertIn(column, migration_runner)
            self.assertIn(column, continuous_integration)

    def test_fenced_outbox_completion_and_database_clock_are_explicit(self) -> None:
        migration = (MIGRATION_DIR / "002_fenced_outbox_delivery.sql").read_text(encoding="utf-8")
        self.assertIn("delivery_version > 0", migration)
        self.assertIn("completion_reference IS NOT NULL", migration)
        self.assertIn("outbox delivery_version must increase by exactly one", migration)

        repository = (PROJECT_ROOT / "services" / "control_plane" / "postgres_outbox.py").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(repository.count("SELECT clock_timestamp() AS now"), 4)
        self.assertNotIn("%(now)s", repository)

    def test_provider_effect_and_observation_boundaries_are_database_enforced(self) -> None:
        effect_boundary = (MIGRATION_DIR / "003_enforce_effect_source_boundary.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("NEW.source_label <> 'RAZORPAY_TEST_MODE'", effect_boundary)
        self.assertIn("provider effects are forbidden", effect_boundary)

        observation = (MIGRATION_DIR / "004_enforce_observation_deadline.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "observation_started_at + interval '2 minutes'",
            observation,
        )
        self.assertIn("database_now + interval '2 minutes'", observation)
        self.assertIn("NEW.observation_contract_version := 1", observation)
        self.assertIn("legacy recovery case lacks trusted observation evidence", observation)
        self.assertIn("observation timing is immutable", observation)
        self.assertIn("clock_timestamp() < OLD.observation_deadline_at", observation)

        account_binding = (MIGRATION_DIR / "005_bind_provider_event_account.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("account.provider = 'RAZORPAY'", account_binding)
        self.assertIn("account.environment = 'TEST'", account_binding)
        self.assertIn("NEW.canonical_event ->> 'provider_account_id'", account_binding)
        self.assertIn("legacy provider evidence has an unsafe account binding", account_binding)

        credential_binding = (MIGRATION_DIR / "006_version_credential_binding.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("credential_key_id_sha256 retrywise.sha256_digest", credential_binding)
        self.assertIn("credential_binding_version bigint NOT NULL DEFAULT 0", credential_binding)
        self.assertIn(
            "credential binding version must increase by exactly one when material changes",
            credential_binding,
        )
        self.assertIn(
            "credential binding version cannot change without material rotation",
            credential_binding,
        )
        self.assertIn("provider account identity and environment are immutable", credential_binding)
        self.assertIn("provider_accounts_credential_key_uidx", credential_binding)
        self.assertIn("BEFORE INSERT OR UPDATE", credential_binding)

        upgrade_verification = (
            PROJECT_ROOT
            / "infrastructure"
            / "postgres"
            / "tests"
            / "verify_post_hardening_upgrade.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("migration invented credential enrollment evidence", upgrade_verification)
        self.assertIn("event_upgrade_fixture_v0_ingress", upgrade_verification)
        self.assertIn("credential generation skipped a version", upgrade_verification)
        self.assertIn("valid credential rotation was not persisted exactly", upgrade_verification)

        body_reuse_index = (MIGRATION_DIR / "007_index_provider_event_body_reuse.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("CREATE INDEX CONCURRENTLY", body_reuse_index)
        self.assertIn("merchant_id,", body_reuse_index)
        self.assertIn("provider_account_id,", body_reuse_index)
        self.assertIn("body_sha256,", body_reuse_index)
        self.assertIn("INCLUDE (provider_event_id)", body_reuse_index)
        self.assertNotIn("BEGIN;", body_reuse_index)

        late_link_money = (MIGRATION_DIR / "008_allow_late_link_money_truth.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("OLD.status IN ('CANCELLED', 'EXPIRED')", late_link_money)
        self.assertIn("NEW.status IN ('PAID', 'PARTIALLY_PAID')", late_link_money)
        self.assertIn("NEW.collected_minor < OLD.collected_minor", late_link_money)
        self.assertIn("provider ids on a recovery instrument are write-once", late_link_money)
        self.assertIn("LOCK TABLE retrywise.recovery_instruments", late_link_money)

        worker_heartbeats = (MIGRATION_DIR / "009_worker_heartbeats.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("CREATE TABLE retrywise.worker_heartbeats", worker_heartbeats)
        self.assertIn("worker_heartbeats_freshness_idx", worker_heartbeats)
        self.assertIn("REVOKE ALL", worker_heartbeats)

        merchant_controls = (MIGRATION_DIR / "010_merchant_control_events.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("CREATE TABLE retrywise.merchant_control_events", merchant_controls)
        self.assertIn("idempotency_key_sha256", merchant_controls)
        self.assertIn("merchant control events are append-only", merchant_controls)
        self.assertIn("BEFORE UPDATE OR DELETE", merchant_controls)

        diagnosis_routing = (MIGRATION_DIR / "011_diagnosis_engine_routing.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("ADD COLUMN diagnosis_mode", diagnosis_routing)
        self.assertIn("CREATE TABLE retrywise.diagnosis_mode_events", diagnosis_routing)
        self.assertIn("requested_diagnosis_mode", diagnosis_routing)
        self.assertIn("executed_diagnosis_engine", diagnosis_routing)
        self.assertIn("decisions_diagnosis_provenance_complete", diagnosis_routing)
        self.assertNotIn(
            "requested_diagnosis_mode text NOT NULL DEFAULT 'LOCAL_ML'",
            diagnosis_routing,
        )
        self.assertIn("diagnosis mode events are append-only", diagnosis_routing)

        self.assertIn("migration_quarantined_non_test_effect", effect_boundary)
        self.assertIn("BEFORE INSERT OR UPDATE", effect_boundary)


if __name__ == "__main__":
    unittest.main()
