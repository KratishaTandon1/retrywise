"""Fail-closed PostgreSQL transport policy shared by durable adapters.

The policy never stores or renders a DSN.  Deployed composition can therefore
prove that the built-in psycopg connector requests certificate and hostname
verification without putting database credentials into settings diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit


class PostgresConnectionConfigurationError(ValueError):
    """A PostgreSQL connection setting cannot satisfy the transport boundary."""


def _clean_dsn(dsn: str) -> str:
    if (
        not isinstance(dsn, str)
        or not dsn
        or dsn != dsn.strip()
        or len(dsn) > 2_048
        or any(ord(character) < 32 or ord(character) == 127 for character in dsn)
    ):
        raise PostgresConnectionConfigurationError(
            "DATABASE_URL must be clean, non-empty text no longer than 2048 characters"
        )
    return dsn


@dataclass(frozen=True, slots=True)
class PostgresConnectionPolicy:
    """Describe and enforce the PostgreSQL transport used by one process role."""

    require_tls: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.require_tls, bool):
            raise TypeError("require_tls must be boolean")

    def validate_dsn(self, dsn: str) -> None:
        """Validate target shape without retaining or echoing the credential-bearing DSN."""

        dsn = _clean_dsn(dsn)
        if not self.require_tls:
            return

        try:
            parsed = urlsplit(dsn)
            hostname = parsed.hostname
            _port = parsed.port  # Force validation of malformed/non-numeric ports.
            query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError as exc:
            raise PostgresConnectionConfigurationError(
                "TLS-required DATABASE_URL must be a valid PostgreSQL URI"
            ) from exc

        if parsed.scheme.lower() not in {"postgres", "postgresql"}:
            raise PostgresConnectionConfigurationError(
                "TLS-required DATABASE_URL must use a PostgreSQL URI"
            )
        if not hostname or parsed.fragment or "," in hostname or "%" in hostname:
            raise PostgresConnectionConfigurationError(
                "TLS-required DATABASE_URL must identify one TCP database host"
            )

        target_overrides = {"host", "hostaddr", "service", "servicefile"}
        if any(name.lower() in target_overrides for name, _value in query):
            raise PostgresConnectionConfigurationError(
                "TLS-required DATABASE_URL cannot override its database host"
            )

        sslmodes = [value for name, value in query if name.lower() == "sslmode"]
        if len(sslmodes) > 1 or any(value != "verify-full" for value in sslmodes):
            raise PostgresConnectionConfigurationError(
                "TLS-required DATABASE_URL cannot weaken sslmode=verify-full"
            )
        gss_modes = [value for name, value in query if name.lower() == "gssencmode"]
        if len(gss_modes) > 1 or any(value != "disable" for value in gss_modes):
            raise PostgresConnectionConfigurationError(
                "TLS-required DATABASE_URL cannot select a non-TLS GSS transport"
            )

    def connect(self, dsn: str, *, component: str) -> object:
        """Open a psycopg connection under this policy.

        Keyword connection parameters override conninfo parameters in psycopg.
        For the deployed policy, this makes ``verify-full`` an executable
        connection requirement even when the URI omits an ``sslmode`` query.
        """

        self.validate_dsn(dsn)
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - optional production dependency
            raise RuntimeError(
                f"{component} requires the 'api' extra with psycopg installed"
            ) from exc

        if self.require_tls:
            return psycopg.connect(
                dsn,
                sslmode="verify-full",
                gssencmode="disable",
            )
        return psycopg.connect(dsn)


__all__ = [
    "PostgresConnectionConfigurationError",
    "PostgresConnectionPolicy",
]
