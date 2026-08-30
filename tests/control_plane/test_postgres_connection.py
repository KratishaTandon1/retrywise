from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import patch

from retrywise.services.control_plane.postgres_connection import (
    PostgresConnectionConfigurationError,
    PostgresConnectionPolicy,
)


class PostgresConnectionPolicyTests(unittest.TestCase):
    def test_local_policy_keeps_socket_and_non_tls_development_flexible(self) -> None:
        policy = PostgresConnectionPolicy(require_tls=False)

        policy.validate_dsn("dbname=retrywise host=/var/run/postgresql sslmode=disable")

    def test_tls_policy_requires_unambiguous_tcp_postgresql_uri(self) -> None:
        policy = PostgresConnectionPolicy(require_tls=True)
        policy.validate_dsn("postgresql://retrywise@database/retrywise")
        policy.validate_dsn("postgresql://retrywise@database:5432/retrywise?sslmode=verify-full")

        invalid = (
            "dbname=retrywise host=database",
            "postgresql:///retrywise?host=/var/run/postgresql",
            "postgresql://database/retrywise?host=other",
            "postgresql://database/retrywise?hostaddr=127.0.0.1",
            "postgresql://%2Fvar%2Frun%2Fpostgresql/retrywise",
            "postgresql://database/retrywise?sslmode=require",
            "postgresql://database/retrywise?sslmode=verify-full&sslmode=verify-full",
            "postgresql://database/retrywise?gssencmode=prefer",
        )
        for dsn in invalid:
            with self.subTest(dsn=dsn), self.assertRaises(PostgresConnectionConfigurationError):
                policy.validate_dsn(dsn)

    def test_tls_policy_does_not_echo_dsn_credentials_on_failure(self) -> None:
        password = "private-database-password"
        dsn = f"postgresql://user:{password}@database/retrywise?sslmode=disable"

        with self.assertRaises(PostgresConnectionConfigurationError) as raised:
            PostgresConnectionPolicy(require_tls=True).validate_dsn(dsn)

        self.assertNotIn(password, str(raised.exception))
        self.assertNotIn(password, repr(PostgresConnectionPolicy(require_tls=True)))

    def test_psycopg_connector_forces_verify_full_when_tls_is_required(self) -> None:
        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        connection = object()

        def connect(*args: object, **kwargs: object) -> object:
            calls.append((args, kwargs))
            return connection

        fake_psycopg = types.SimpleNamespace(connect=connect)
        dsn = "postgresql://retrywise:private@database/retrywise"
        with patch.dict(sys.modules, {"psycopg": fake_psycopg}):
            result = PostgresConnectionPolicy(require_tls=True).connect(
                dsn,
                component="test component",
            )

        self.assertIs(result, connection)
        self.assertEqual(
            calls,
            [((dsn,), {"sslmode": "verify-full", "gssencmode": "disable"})],
        )

    def test_local_psycopg_connector_does_not_invent_tls_configuration(self) -> None:
        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

        def connect(*args: object, **kwargs: object) -> object:
            calls.append((args, kwargs))
            return object()

        fake_psycopg = types.SimpleNamespace(connect=connect)
        dsn = "dbname=retrywise host=/var/run/postgresql"
        with patch.dict(sys.modules, {"psycopg": fake_psycopg}):
            PostgresConnectionPolicy(require_tls=False).connect(
                dsn,
                component="test component",
            )

        self.assertEqual(calls, [((dsn,), {})])

    def test_policy_rejects_invalid_type_dirty_dsn_and_malformed_uri(self) -> None:
        with self.assertRaises(TypeError):
            PostgresConnectionPolicy(require_tls=1)  # type: ignore[arg-type]

        policy = PostgresConnectionPolicy(require_tls=True)
        invalid = (
            "",
            " postgresql://database/retrywise",
            "postgresql://database/retrywise\n",
            "x" * 2_049,
            "postgresql://database:not-a-port/retrywise",
            "mysql://database/retrywise",
            "postgresql://database/retrywise#fragment",
            "postgresql://one,two/retrywise",
            "postgresql://database/retrywise?broken-query",
        )
        for dsn in invalid:
            with (
                self.subTest(dsn=dsn[:60]),
                self.assertRaises(PostgresConnectionConfigurationError),
            ):
                policy.validate_dsn(dsn)


if __name__ == "__main__":
    unittest.main()
