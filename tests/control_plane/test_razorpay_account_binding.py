from __future__ import annotations

import hashlib
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import replace
from unittest.mock import patch

from retrywise.services.control_plane import razorpay_account_binding as binding_module
from retrywise.services.control_plane.razorpay_account_binding import (
    PostgresRazorpayAccountBindingRepository,
    RazorpayAccountNotFoundError,
    RazorpayAccountUnsafeError,
    RazorpayAdapterCompositionError,
    RazorpayCredentialMaterial,
    RazorpayCredentialMismatchError,
    RazorpayCredentialResolutionError,
    RazorpayTestAccountBinding,
    compose_razorpay_test_mode_adapter,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER_MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
OTHER_PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
EXTERNAL_ACCOUNT_ID = "acc_retrywise_test_1"
SECRET_REF = "secret://retrywise/razorpay/test/account-1/version-7"
KEY_ID = "rzp_test_retrywiseKey123"
KEY_SECRET = "test-key-secret-value-that-never-leaks"
KEY_ID_SHA256 = hashlib.sha256(KEY_ID.encode("ascii")).digest()
CREDENTIAL_BINDING_VERSION = 7


def account_row(**overrides: object) -> tuple[object, ...]:
    values: dict[str, object] = {
        "merchant_id": MERCHANT_ID,
        "provider_account_id": PROVIDER_ACCOUNT_ID,
        "provider": "RAZORPAY",
        "external_id": EXTERNAL_ACCOUNT_ID,
        "environment": "TEST",
        "enabled": True,
        "secret_ref": SECRET_REF,
        "key_id_sha256": KEY_ID_SHA256,
        "binding_version": CREDENTIAL_BINDING_VERSION,
    }
    values.update(overrides)
    return (
        values["merchant_id"],
        values["provider_account_id"],
        values["provider"],
        values["external_id"],
        values["environment"],
        values["enabled"],
        values["secret_ref"],
        values["key_id_sha256"],
        values["binding_version"],
    )


def credential_material(**overrides: object) -> RazorpayCredentialMaterial:
    values: dict[str, object] = {
        "merchant_id": MERCHANT_ID,
        "provider_account_id": PROVIDER_ACCOUNT_ID,
        "provider_account_identifier": EXTERNAL_ACCOUNT_ID,
        "environment": "TEST",
        "enabled": True,
        "credential_secret_ref": SECRET_REF,
        "credential_binding_version": CREDENTIAL_BINDING_VERSION,
        "key_id": KEY_ID,
        "key_secret": KEY_SECRET,
    }
    values.update(overrides)
    return RazorpayCredentialMaterial(  # type: ignore[arg-type]
        merchant_id=values["merchant_id"],
        provider_account_id=values["provider_account_id"],
        provider_account_identifier=values["provider_account_identifier"],
        environment=values["environment"],
        enabled=values["enabled"],
        credential_secret_ref=values["credential_secret_ref"],
        credential_binding_version=values["credential_binding_version"],
        key_id=values["key_id"],
        key_secret=values["key_secret"],
    )


class _FakeCursor:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def __enter__(self) -> _FakeCursor:
        self._connection.cursor_open = True
        return self

    def __exit__(self, *_args: object) -> None:
        self._connection.cursor_open = False
        return None

    def execute(self, query: str, params: Mapping[str, object]) -> None:
        if not self._connection.in_transaction:
            raise AssertionError("account query must execute inside a transaction")
        self._connection.executions.append((query, dict(params)))

    def fetchone(self) -> Sequence[object] | None:
        index = len(self._connection.executions) - 1
        if index >= len(self._connection.rows):
            raise AssertionError("test connection has no row for this query")
        return self._connection.rows[index]


class _FakeTransaction:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def __enter__(self) -> object:
        self._connection.in_transaction = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: object | None,
    ) -> None:
        self._connection.in_transaction = False
        if exc_type is None:
            self._connection.commits += 1
        else:
            self._connection.rollbacks += 1
        return None


class _FakeConnection:
    def __init__(self, rows: Sequence[Sequence[object] | None]) -> None:
        self.rows = tuple(rows)
        self.executions: list[tuple[str, dict[str, object]]] = []
        self.in_transaction = False
        self.cursor_open = False
        self.commits = 0
        self.rollbacks = 0
        self.closed = 0

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed += 1
        return None

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)


class _FakeConnector:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection
        self.calls = 0

    def __call__(self) -> _FakeConnection:
        self.calls += 1
        return self.connection


class _Resolver:
    def __init__(
        self,
        material: RazorpayCredentialMaterial | None,
        *,
        connection: _FakeConnection,
        error: Exception | None = None,
    ) -> None:
        self.material = material
        self.connection = connection
        self.error = error
        self.refs: list[str] = []
        self.transaction_seen = False

    def resolve(self, *, credential_secret_ref: str) -> RazorpayCredentialMaterial:
        self.refs.append(credential_secret_ref)
        self.transaction_seen = self.connection.in_transaction or self.connection.cursor_open
        if self.error is not None:
            raise self.error
        if self.material is None:
            raise AssertionError("test resolver has no material")
        return self.material


def repository_for(
    row: Sequence[object] | None,
    *later_rows: Sequence[object] | None,
) -> tuple[PostgresRazorpayAccountBindingRepository, _FakeConnection, _FakeConnector]:
    connection = _FakeConnection((row, *later_rows))
    connector = _FakeConnector(connection)
    repository = PostgresRazorpayAccountBindingRepository(connector=connector)
    return repository, connection, connector


class PostgresRazorpayAccountBindingRepositoryTests(unittest.TestCase):
    def test_binding_is_tenant_scoped_share_locked_and_immutable(self) -> None:
        repository, connection, connector = repository_for(account_row())

        with repository.locked_test_account(
            merchant_id=MERCHANT_ID,
            provider_account_id=PROVIDER_ACCOUNT_ID,
        ) as binding:
            self.assertTrue(connection.in_transaction)
            self.assertTrue(connection.cursor_open)
            self.assertEqual(MERCHANT_ID, binding.merchant_id)
            self.assertEqual(PROVIDER_ACCOUNT_ID, binding.provider_account_id)
            self.assertEqual(EXTERNAL_ACCOUNT_ID, binding.provider_account_identifier)
            self.assertEqual("TEST", binding.environment)
            self.assertTrue(binding.enabled)
            self.assertEqual(KEY_ID_SHA256, binding.credential_key_id_sha256)
            self.assertEqual(
                CREDENTIAL_BINDING_VERSION,
                binding.credential_binding_version,
            )
            with self.assertRaises((AttributeError, TypeError)):
                binding.enabled = False  # type: ignore[misc]

        self.assertEqual(1, connector.calls)
        self.assertEqual(1, connection.commits)
        self.assertEqual(0, connection.rollbacks)
        self.assertEqual(1, connection.closed)
        query, params = connection.executions[0]
        self.assertIn("account.merchant_id = %(merchant_id)s", query)
        self.assertIn("account.id = %(provider_account_id)s", query)
        self.assertIn("FOR SHARE OF account", query)
        self.assertEqual(
            {"merchant_id": MERCHANT_ID, "provider_account_id": PROVIDER_ACCOUNT_ID},
            params,
        )
        self.assertNotIn(SECRET_REF, repr(binding))
        self.assertNotIn(KEY_ID_SHA256.hex(), repr(binding))
        self.assertNotIn(SECRET_REF, repr(repository))

    def test_snapshot_read_ends_before_return_and_does_not_lock(self) -> None:
        repository, connection, connector = repository_for(account_row())

        binding = repository.load_test_account(
            merchant_id=MERCHANT_ID,
            provider_account_id=PROVIDER_ACCOUNT_ID,
        )

        self.assertEqual(CREDENTIAL_BINDING_VERSION, binding.credential_binding_version)
        self.assertFalse(connection.in_transaction)
        self.assertFalse(connection.cursor_open)
        self.assertEqual(1, connector.calls)
        self.assertEqual(1, connection.commits)
        self.assertEqual(1, connection.closed)
        self.assertNotIn("FOR SHARE", connection.executions[0][0])

    def test_missing_and_unsafe_rows_fail_closed_without_metadata_leakage(self) -> None:
        unsafe_rows: tuple[tuple[str, Sequence[object] | None, type[Exception]], ...] = (
            ("missing", None, RazorpayAccountNotFoundError),
            ("wrong provider", account_row(provider="OTHER"), RazorpayAccountUnsafeError),
            ("live", account_row(environment="LIVE"), RazorpayAccountUnsafeError),
            ("disabled", account_row(enabled=False), RazorpayAccountUnsafeError),
            (
                "tenant result mismatch",
                account_row(merchant_id=OTHER_MERCHANT_ID),
                RazorpayAccountUnsafeError,
            ),
            (
                "secret ref malformed",
                account_row(secret_ref="bad\x00ref"),
                RazorpayAccountUnsafeError,
            ),
            (
                "legacy version zero",
                account_row(key_id_sha256=None, binding_version=0),
                RazorpayAccountUnsafeError,
            ),
            (
                "digest malformed",
                account_row(key_id_sha256=b"short"),
                RazorpayAccountUnsafeError,
            ),
            (
                "version malformed",
                account_row(binding_version=-1),
                RazorpayAccountUnsafeError,
            ),
            ("wrong shape", account_row()[:-1], RazorpayAccountUnsafeError),
        )
        for label, row, expected_error in unsafe_rows:
            repository, connection, _connector = repository_for(row)
            with (
                self.subTest(label=label),
                self.assertRaises(expected_error) as raised,
                repository.locked_test_account(
                    merchant_id=MERCHANT_ID,
                    provider_account_id=PROVIDER_ACCOUNT_ID,
                ),
            ):
                self.fail("unsafe binding was yielded")
            self.assertNotIn(SECRET_REF, str(raised.exception))
            self.assertNotIn(KEY_SECRET, str(raised.exception))
            self.assertEqual(0, connection.commits)
            self.assertEqual(1, connection.rollbacks)

    def test_invalid_requested_identity_is_rejected_before_database_use(self) -> None:
        repository, _connection, connector = repository_for(account_row())

        for merchant_id, provider_account_id in (
            ("merchant-1", PROVIDER_ACCOUNT_ID),
            (MERCHANT_ID, "provider-account-1"),
            (OTHER_MERCHANT_ID.lower(), PROVIDER_ACCOUNT_ID),
        ):
            with (
                self.subTest(
                    merchant_id=merchant_id,
                    provider_account_id=provider_account_id,
                ),
                self.assertRaises(ValueError),
                repository.locked_test_account(
                    merchant_id=merchant_id,
                    provider_account_id=provider_account_id,
                ),
            ):
                self.fail("invalid identity was yielded")

        self.assertEqual(0, connector.calls)

    def test_constructor_requires_one_verifiable_connection_boundary(self) -> None:
        connection = _FakeConnection((account_row(),))
        connector = _FakeConnector(connection)

        with self.assertRaises(ValueError):
            PostgresRazorpayAccountBindingRepository()
        with self.assertRaises(ValueError):
            PostgresRazorpayAccountBindingRepository(
                dsn="postgresql://database/retrywise",
                connector=connector,
            )
        with self.assertRaises(ValueError):
            PostgresRazorpayAccountBindingRepository(
                connector=connector,
                require_tls=True,
            )


class RazorpayCredentialMaterialTests(unittest.TestCase):
    def test_material_is_strict_immutable_and_redacts_all_secret_values(self) -> None:
        material = credential_material()

        rendered = repr(material)
        self.assertNotIn(SECRET_REF, rendered)
        self.assertNotIn(KEY_ID, rendered)
        self.assertNotIn(KEY_SECRET, rendered)
        with self.assertRaises((AttributeError, TypeError)):
            material.key_secret = "changed-secret"  # type: ignore[misc]

    def test_non_test_disabled_live_and_malformed_material_is_rejected(self) -> None:
        invalid_overrides: tuple[dict[str, object], ...] = (
            {"environment": "LIVE"},
            {"enabled": False},
            {"key_id": "rzp_live_forbidden"},
            {"key_id": "not_a_razorpay_key"},
            {"key_secret": "short"},
            {"credential_secret_ref": "secret://bad ref"},
            {"credential_secret_ref": "secret://bad\x00ref"},
            {"credential_binding_version": 0},
            {"credential_binding_version": -1},
        )
        for overrides in invalid_overrides:
            with self.subTest(overrides=tuple(overrides)):
                with self.assertRaises(ValueError) as raised:
                    credential_material(**overrides)
                self.assertNotIn(str(next(iter(overrides.values()))), str(raised.exception))
                self.assertNotIn(KEY_SECRET, str(raised.exception))


class RazorpayAdapterCompositionTests(unittest.TestCase):
    def test_secret_resolution_is_outside_transactions_then_generation_is_locked(self) -> None:
        repository, connection, _connector = repository_for(account_row(), account_row())
        material = credential_material()
        resolver = _Resolver(material, connection=connection)
        constructed: list[tuple[RazorpayTestAccountBinding, RazorpayCredentialMaterial]] = []
        sentinel_adapter = object()

        def construct(
            *,
            binding: RazorpayTestAccountBinding,
            material: RazorpayCredentialMaterial,
        ) -> object:
            self.assertTrue(connection.in_transaction)
            self.assertTrue(connection.cursor_open)
            self.assertEqual(SECRET_REF, material.credential_secret_ref)
            constructed.append((binding, material))
            return sentinel_adapter

        with patch.object(binding_module, "_construct_test_adapter", side_effect=construct):
            result = compose_razorpay_test_mode_adapter(
                account_bindings=repository,
                secret_resolver=resolver,
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
            )

        self.assertIs(sentinel_adapter, result)
        self.assertEqual([SECRET_REF], resolver.refs)
        self.assertFalse(resolver.transaction_seen)
        self.assertEqual(1, len(constructed))
        self.assertIs(material, constructed[0][1])
        self.assertNotIn("FOR SHARE", connection.executions[0][0])
        self.assertIn("FOR SHARE OF account", connection.executions[1][0])
        self.assertEqual(2, connection.commits)
        self.assertEqual(0, connection.rollbacks)

    def test_default_helper_constructs_the_real_adapter_without_a_provider_call(self) -> None:
        try:
            from retrywise.services.control_plane.razorpay_test_adapter import (
                RazorpayTestModePaymentLinkAdapter,
            )
        except ImportError:
            self.skipTest("the optional api extra with httpx is not installed")

        repository, connection, _connector = repository_for(account_row(), account_row())
        resolver = _Resolver(credential_material(), connection=connection)

        adapter = compose_razorpay_test_mode_adapter(
            account_bindings=repository,
            secret_resolver=resolver,
            merchant_id=MERCHANT_ID,
            provider_account_id=PROVIDER_ACCOUNT_ID,
        )
        try:
            self.assertIsInstance(adapter, RazorpayTestModePaymentLinkAdapter)
            self.assertFalse(resolver.transaction_seen)
            self.assertNotIn(KEY_ID, repr(adapter))
            self.assertNotIn(KEY_SECRET, repr(adapter))
            self.assertIn("internal_account_pinned=True", repr(adapter))
            self.assertNotIn("account_bound", repr(adapter))
            self.assertEqual(2, connection.commits)
        finally:
            adapter.close()

    def test_every_metadata_mismatch_and_secret_ref_drift_blocks_construction(self) -> None:
        base = credential_material()
        mismatches = (
            replace(base, merchant_id=OTHER_MERCHANT_ID),
            replace(base, provider_account_id=OTHER_PROVIDER_ACCOUNT_ID),
            replace(base, provider_account_identifier="acc_retrywise_test_2"),
            replace(base, credential_secret_ref="secret://retrywise/razorpay/test/drifted"),
            replace(base, credential_binding_version=CREDENTIAL_BINDING_VERSION + 1),
        )
        for material in mismatches:
            with self.subTest(material=repr(material)):
                repository, connection, _connector = repository_for(
                    account_row(),
                    account_row(),
                )
                resolver = _Resolver(material, connection=connection)
                with (
                    patch.object(binding_module, "_construct_test_adapter") as construct,
                    self.assertRaises(RazorpayCredentialMismatchError) as raised,
                ):
                    compose_razorpay_test_mode_adapter(
                        account_bindings=repository,
                        secret_resolver=resolver,
                        merchant_id=MERCHANT_ID,
                        provider_account_id=PROVIDER_ACCOUNT_ID,
                    )
                construct.assert_not_called()
                self.assertEqual("razorpay_credential_binding_mismatch", str(raised.exception))
                self.assertEqual(1, connection.commits)
                self.assertEqual(1, connection.rollbacks)

    def test_wrong_account_key_id_fingerprint_blocks_construction(self) -> None:
        repository, connection, _connector = repository_for(account_row(), account_row())
        resolver = _Resolver(
            credential_material(key_id="rzp_test_otherAccountKey456"),
            connection=connection,
        )

        with (
            patch.object(binding_module, "_construct_test_adapter") as construct,
            self.assertRaises(RazorpayCredentialMismatchError) as raised,
        ):
            compose_razorpay_test_mode_adapter(
                account_bindings=repository,
                secret_resolver=resolver,
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
            )

        construct.assert_not_called()
        self.assertEqual("razorpay_credential_binding_mismatch", str(raised.exception))
        self.assertEqual(1, connection.commits)
        self.assertEqual(1, connection.rollbacks)

    def test_rotation_during_resolution_is_fenced_by_binding_generation(self) -> None:
        rotated_key_id = "rzp_test_rotatedKey456"
        rotated_ref = "secret://retrywise/razorpay/test/account-1/version-8"
        repository, connection, _connector = repository_for(
            account_row(),
            account_row(
                secret_ref=rotated_ref,
                key_id_sha256=hashlib.sha256(rotated_key_id.encode("ascii")).digest(),
                binding_version=CREDENTIAL_BINDING_VERSION + 1,
            ),
        )
        resolver = _Resolver(credential_material(), connection=connection)

        with (
            patch.object(binding_module, "_construct_test_adapter") as construct,
            self.assertRaises(RazorpayCredentialMismatchError) as raised,
        ):
            compose_razorpay_test_mode_adapter(
                account_bindings=repository,
                secret_resolver=resolver,
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
            )

        construct.assert_not_called()
        self.assertFalse(resolver.transaction_seen)
        self.assertEqual(
            "razorpay_account_binding_changed_during_resolution",
            str(raised.exception),
        )
        self.assertEqual(1, connection.commits)
        self.assertEqual(1, connection.rollbacks)

    def test_legacy_version_zero_account_cannot_resolve_outbound_credentials(self) -> None:
        repository, connection, _connector = repository_for(
            account_row(key_id_sha256=None, binding_version=0)
        )
        resolver = _Resolver(credential_material(), connection=connection)

        with self.assertRaises(RazorpayAccountUnsafeError):
            compose_razorpay_test_mode_adapter(
                account_bindings=repository,
                secret_resolver=resolver,
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
            )

        self.assertEqual([], resolver.refs)
        self.assertEqual(0, connection.commits)
        self.assertEqual(1, connection.rollbacks)

    def test_resolver_and_constructor_failures_are_sanitized_and_roll_back_lock(self) -> None:
        for stage in ("resolver", "constructor"):
            with self.subTest(stage=stage):
                repository, connection, _connector = repository_for(
                    account_row(),
                    account_row(),
                )
                resolver = _Resolver(
                    credential_material(),
                    connection=connection,
                    error=(
                        RuntimeError(f"secret provider leaked {KEY_SECRET}")
                        if stage == "resolver"
                        else None
                    ),
                )
                constructor_error = (
                    RuntimeError(f"adapter leaked {KEY_SECRET}") if stage == "constructor" else None
                )
                expected = (
                    RazorpayCredentialResolutionError
                    if stage == "resolver"
                    else RazorpayAdapterCompositionError
                )
                with (
                    patch.object(
                        binding_module,
                        "_construct_test_adapter",
                        side_effect=constructor_error,
                    ) as construct,
                    self.assertRaises(expected) as raised,
                ):
                    compose_razorpay_test_mode_adapter(
                        account_bindings=repository,
                        secret_resolver=resolver,
                        merchant_id=MERCHANT_ID,
                        provider_account_id=PROVIDER_ACCOUNT_ID,
                    )
                self.assertNotIn(KEY_SECRET, str(raised.exception))
                if stage == "resolver":
                    construct.assert_not_called()
                    self.assertFalse(resolver.transaction_seen)
                    self.assertEqual(1, connection.commits)
                    self.assertEqual(0, connection.rollbacks)
                    self.assertEqual(1, len(connection.executions))
                else:
                    self.assertEqual(1, connection.commits)
                    self.assertEqual(1, connection.rollbacks)

    def test_non_postgres_repository_is_rejected_before_secret_resolution(self) -> None:
        class UnsafeRepository:
            pass

        connection = _FakeConnection((account_row(),))
        resolver = _Resolver(credential_material(), connection=connection)
        with self.assertRaises(RazorpayAccountUnsafeError):
            compose_razorpay_test_mode_adapter(
                account_bindings=UnsafeRepository(),  # type: ignore[arg-type]
                secret_resolver=resolver,
                merchant_id=MERCHANT_ID,
                provider_account_id=PROVIDER_ACCOUNT_ID,
            )
        self.assertEqual([], resolver.refs)


if __name__ == "__main__":
    unittest.main()
