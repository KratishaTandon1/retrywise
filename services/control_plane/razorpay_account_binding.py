"""Version-fenced Razorpay Test credential metadata attestation boundary.

The provider adapter accepts credentials because it is intentionally transport
focused. This module proves that one resolved Test credential agrees with an
enrolled, versioned database attestation before an adapter can be constructed.
It does not cryptographically discover which Razorpay account owns the key.

The first database snapshot is released before secret resolution. The repository
then reacquires a short ``FOR SHARE`` lock and proves that the row and monotonic
credential generation did not change before constructing the Test-only adapter.
No database transaction is held across secret-manager I/O.

This is a composition foundation, not an effect worker.  Importing this module,
loading a binding, and constructing the adapter perform no Razorpay request and
do not change control-plane readiness.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

from .postgres_connection import PostgresConnectionPolicy

if TYPE_CHECKING:
    from .razorpay_test_adapter import RazorpayTestModePaymentLinkAdapter


_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_PROVIDER_ACCOUNT_IDENTIFIER_RE = re.compile(r"^acc_[A-Za-z0-9_-]{1,124}$")
_TEST_KEY_ID_RE = re.compile(r"^rzp_test_[A-Za-z0-9_-]{1,119}$")
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")

_TEST_ACCOUNT_COLUMNS = """
SELECT
    account.merchant_id::text,
    account.id::text,
    account.provider::text,
    account.provider_account_identifier,
    account.environment::text,
    account.enabled,
    account.credential_secret_ref,
    account.credential_key_id_sha256,
    account.credential_binding_version
FROM retrywise.provider_accounts AS account
WHERE account.merchant_id = %(merchant_id)s
  AND account.id = %(provider_account_id)s
"""

_LOAD_TEST_ACCOUNT = _TEST_ACCOUNT_COLUMNS

_LOCK_TEST_ACCOUNT = (
    _TEST_ACCOUNT_COLUMNS
    + """
FOR SHARE OF account
"""
)


class RazorpayAccountBindingError(RuntimeError):
    """A sanitized, fail-closed account/credential binding failure."""

    def __init__(self, reason_code: str) -> None:
        if not isinstance(reason_code, str) or not _REASON_CODE_RE.fullmatch(reason_code):
            raise ValueError("reason_code must be a stable lowercase identifier")
        self.reason_code = reason_code
        super().__init__(reason_code)


class RazorpayAccountNotFoundError(RazorpayAccountBindingError):
    """No account exists for the exact tenant and internal account identity."""


class RazorpayAccountUnsafeError(RazorpayAccountBindingError):
    """The durable row is malformed, disabled, non-Razorpay, or non-Test."""


class RazorpayCredentialResolutionError(RazorpayAccountBindingError):
    """Credential material could not be obtained without weakening the boundary."""


class RazorpayCredentialMismatchError(RazorpayAccountBindingError):
    """Resolved secret metadata does not identify the exact locked account row."""


class RazorpayAdapterCompositionError(RazorpayAccountBindingError):
    """The already-bound adapter could not be constructed safely."""


def _require_ulid(value: object, *, field_name: str) -> str:
    if type(value) is not str or not _ULID_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be an uppercase Crockford ULID")
    return value


def _require_provider_account_identifier(value: object) -> str:
    if type(value) is not str or not _PROVIDER_ACCOUNT_IDENTIFIER_RE.fullmatch(value):
        raise ValueError("provider_account_identifier must be a canonical Razorpay account id")
    return value


def _require_secret_ref(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 500
        or not value.isascii()
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise ValueError("credential_secret_ref must be clean opaque ASCII metadata")
    return value


def _require_test_key_id(value: object) -> str:
    if type(value) is not str or not _TEST_KEY_ID_RE.fullmatch(value):
        raise ValueError("Razorpay credential key id must be an rzp_test_ key")
    return value


def _require_sha256_digest(value: object) -> bytes:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("credential_key_id_sha256 must be a binary SHA-256 digest")
    return value


def _require_binding_version(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("credential_binding_version must be a positive integer")
    return value


def _require_key_secret(value: object) -> str:
    if (
        type(value) is not str
        or not 8 <= len(value) <= 256
        or value != value.strip()
        or not value.isascii()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("Razorpay credential key secret is malformed")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RazorpayTestAccountBinding:
    """Immutable projection of one effect-enabled Razorpay TEST attestation."""

    merchant_id: str
    provider_account_id: str
    provider_account_identifier: str
    environment: str
    enabled: bool
    credential_secret_ref: str = field(repr=False)
    credential_key_id_sha256: bytes = field(repr=False)
    credential_binding_version: int

    def __post_init__(self) -> None:
        _require_ulid(self.merchant_id, field_name="merchant_id")
        _require_ulid(self.provider_account_id, field_name="provider_account_id")
        _require_provider_account_identifier(self.provider_account_identifier)
        if type(self.environment) is not str or self.environment != "TEST":
            raise ValueError("Razorpay effect account must be TEST")
        if type(self.enabled) is not bool or not self.enabled:
            raise ValueError("Razorpay effect account must be enabled")
        _require_secret_ref(self.credential_secret_ref)
        _require_sha256_digest(self.credential_key_id_sha256)
        _require_binding_version(self.credential_binding_version)

    def __repr__(self) -> str:
        return (
            "RazorpayTestAccountBinding("
            f"merchant_id={self.merchant_id!r}, "
            f"provider_account_id={self.provider_account_id!r}, "
            f"provider_account_identifier={self.provider_account_identifier!r}, "
            "environment='TEST', enabled=True, credential_secret_ref=<redacted>, "
            "credential_key_id_sha256=<redacted>, "
            f"credential_binding_version={self.credential_binding_version!r})"
        )


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class RazorpayCredentialMaterial:
    """Secret-manager result carrying credentials plus attested account metadata.

    Metadata is deliberately duplicated from PostgreSQL.  The composition
    helper treats the material as unusable unless every duplicated field equals
    the locked authority row and the key-id digest matches the enrolled digest.
    This is an operational attestation, not provider-issued proof of key
    ownership. ``key_id``, ``key_secret``, and the secret reference are excluded
    from representations.
    """

    merchant_id: str
    provider_account_id: str
    provider_account_identifier: str
    environment: str
    enabled: bool
    credential_secret_ref: str = field(repr=False)
    credential_binding_version: int
    key_id: str = field(repr=False)
    key_secret: str = field(repr=False)

    def __post_init__(self) -> None:
        _require_ulid(self.merchant_id, field_name="merchant_id")
        _require_ulid(self.provider_account_id, field_name="provider_account_id")
        _require_provider_account_identifier(self.provider_account_identifier)
        if type(self.environment) is not str or self.environment != "TEST":
            raise ValueError("resolved Razorpay credential environment must be TEST")
        if type(self.enabled) is not bool or not self.enabled:
            raise ValueError("resolved Razorpay credential metadata must be enabled")
        _require_secret_ref(self.credential_secret_ref)
        _require_binding_version(self.credential_binding_version)
        _require_test_key_id(self.key_id)
        _require_key_secret(self.key_secret)

    def __repr__(self) -> str:
        return (
            "RazorpayCredentialMaterial("
            f"merchant_id={self.merchant_id!r}, "
            f"provider_account_id={self.provider_account_id!r}, "
            f"provider_account_identifier={self.provider_account_identifier!r}, "
            "environment='TEST', enabled=True, credential_secret_ref=<redacted>, "
            f"credential_binding_version={self.credential_binding_version!r}, "
            "key_id=<redacted>, key_secret=<redacted>)"
        )


class RazorpayCredentialSecretResolver(Protocol):
    """Resolve one managed-secret reference to explicitly bound material."""

    def resolve(self, *, credential_secret_ref: str) -> RazorpayCredentialMaterial: ...


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def __enter__(self) -> _Cursor: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class _Transaction(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...

    def transaction(self) -> _Transaction: ...


class _ConnectionContext(Protocol):
    def __enter__(self) -> _Connection: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


ConnectionFactory = Callable[[], _ConnectionContext]


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresRazorpayAccountBindingRepository"),
        )

    return connect


def _binding_from_row(row: Sequence[object]) -> RazorpayTestAccountBinding:
    if len(row) != 9:
        raise ValueError("provider account query returned an unexpected row shape")
    (
        merchant_id,
        provider_account_id,
        provider,
        external_id,
        environment,
        enabled,
        secret_ref,
        key_id_sha256,
        binding_version,
    ) = row
    if provider != "RAZORPAY":
        raise ValueError("provider account is not Razorpay")
    return RazorpayTestAccountBinding(
        merchant_id=_require_ulid(merchant_id, field_name="merchant_id"),
        provider_account_id=_require_ulid(
            provider_account_id,
            field_name="provider_account_id",
        ),
        provider_account_identifier=_require_provider_account_identifier(external_id),
        environment=environment if type(environment) is str else "",
        enabled=enabled if type(enabled) is bool else False,
        credential_secret_ref=_require_secret_ref(secret_ref),
        credential_key_id_sha256=_require_sha256_digest(key_id_sha256),
        credential_binding_version=_require_binding_version(binding_version),
    )


def _requested_identity(*, merchant_id: str, provider_account_id: str) -> dict[str, str]:
    return {
        "merchant_id": _require_ulid(merchant_id, field_name="merchant_id"),
        "provider_account_id": _require_ulid(
            provider_account_id,
            field_name="provider_account_id",
        ),
    }


def _safe_binding(
    row: Sequence[object] | None,
    *,
    expected: Mapping[str, str],
) -> RazorpayTestAccountBinding:
    if row is None:
        raise RazorpayAccountNotFoundError("razorpay_account_binding_not_found")
    try:
        binding = _binding_from_row(row)
    except (TypeError, ValueError):
        raise RazorpayAccountUnsafeError("razorpay_account_binding_unsafe") from None
    if not (
        hmac.compare_digest(binding.merchant_id, expected["merchant_id"])
        and hmac.compare_digest(
            binding.provider_account_id,
            expected["provider_account_id"],
        )
    ):
        raise RazorpayAccountUnsafeError("razorpay_account_binding_unsafe")
    return binding


class PostgresRazorpayAccountBindingRepository:
    """Read and briefly lock one exact versioned tenant/account attestation."""

    durable = True

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if not isinstance(require_tls, bool):
            raise TypeError("require_tls must be boolean")
        if dsn is not None:
            self._connector = _dsn_factory(dsn, require_tls=require_tls)
        else:
            if require_tls:
                raise ValueError(
                    "require_tls needs the built-in DSN connector so its policy is verifiable"
                )
            if not callable(connector):
                raise TypeError("connector must be callable")
            self._connector = connector

    def __repr__(self) -> str:
        return "PostgresRazorpayAccountBindingRepository(durable=True)"

    def load_test_account(
        self,
        *,
        merchant_id: str,
        provider_account_id: str,
    ) -> RazorpayTestAccountBinding:
        """Return an enrolled snapshot from a transaction that ends before resolution."""

        identity = _requested_identity(
            merchant_id=merchant_id,
            provider_account_id=provider_account_id,
        )
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_LOAD_TEST_ACCOUNT, identity)
            row = cursor.fetchone()
            return _safe_binding(row, expected=identity)

    @contextmanager
    def locked_test_account(
        self,
        *,
        merchant_id: str,
        provider_account_id: str,
    ) -> Iterator[RazorpayTestAccountBinding]:
        """Yield one binding while PostgreSQL prevents concurrent row drift."""

        identity = _requested_identity(
            merchant_id=merchant_id,
            provider_account_id=provider_account_id,
        )
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                _LOCK_TEST_ACCOUNT,
                identity,
            )
            row = cursor.fetchone()
            yield _safe_binding(row, expected=identity)


def _material_matches_binding(
    binding: RazorpayTestAccountBinding,
    material: RazorpayCredentialMaterial,
) -> bool:
    string_pairs = (
        (binding.merchant_id, material.merchant_id),
        (binding.provider_account_id, material.provider_account_id),
        (binding.provider_account_identifier, material.provider_account_identifier),
        (binding.environment, material.environment),
        (binding.credential_secret_ref, material.credential_secret_ref),
    )
    return (
        all(hmac.compare_digest(expected, actual) for expected, actual in string_pairs)
        and material.enabled is binding.enabled
        and material.credential_binding_version == binding.credential_binding_version
        and hmac.compare_digest(
            hashlib.sha256(material.key_id.encode("ascii")).digest(),
            binding.credential_key_id_sha256,
        )
    )


def _binding_snapshot_is_current(
    initial: RazorpayTestAccountBinding,
    current: RazorpayTestAccountBinding,
) -> bool:
    string_pairs = (
        (initial.merchant_id, current.merchant_id),
        (initial.provider_account_id, current.provider_account_id),
        (initial.provider_account_identifier, current.provider_account_identifier),
        (initial.environment, current.environment),
        (initial.credential_secret_ref, current.credential_secret_ref),
    )
    return (
        all(hmac.compare_digest(expected, actual) for expected, actual in string_pairs)
        and current.enabled is initial.enabled
        and current.credential_binding_version == initial.credential_binding_version
        and hmac.compare_digest(
            current.credential_key_id_sha256,
            initial.credential_key_id_sha256,
        )
    )


def compose_razorpay_test_mode_adapter(
    *,
    account_bindings: PostgresRazorpayAccountBindingRepository,
    secret_resolver: RazorpayCredentialSecretResolver,
    merchant_id: str,
    provider_account_id: str,
) -> RazorpayTestModePaymentLinkAdapter:
    """Construct a no-request Test adapter after versioned metadata attestation.

    Secret resolution occurs after the initial read transaction has closed. A
    second, short locked read must match the initial generation before adapter
    construction. Exceptions from secret providers and the adapter constructor
    are deliberately normalized so neither secret values nor provider-library
    diagnostics escape. The returned adapter is a configuration snapshot, not
    provider-issued proof that the key belongs to the attested external account.
    A future effect handler must compose it at its bounded execution boundary
    rather than treating startup construction as permanent authorization.
    """

    if type(account_bindings) is not PostgresRazorpayAccountBindingRepository:
        raise RazorpayAccountUnsafeError("razorpay_account_repository_unsafe")

    initial = account_bindings.load_test_account(
        merchant_id=merchant_id,
        provider_account_id=provider_account_id,
    )
    try:
        material = secret_resolver.resolve(
            credential_secret_ref=initial.credential_secret_ref,
        )
    except Exception:
        raise RazorpayCredentialResolutionError("razorpay_credential_resolution_failed") from None

    with account_bindings.locked_test_account(
        merchant_id=merchant_id,
        provider_account_id=provider_account_id,
    ) as current:
        if type(current) is not RazorpayTestAccountBinding:
            raise RazorpayAccountUnsafeError("razorpay_account_binding_unsafe")
        if not _binding_snapshot_is_current(initial, current):
            raise RazorpayCredentialMismatchError(
                "razorpay_account_binding_changed_during_resolution"
            )
        if type(material) is not RazorpayCredentialMaterial or not _material_matches_binding(
            current,
            material,
        ):
            raise RazorpayCredentialMismatchError("razorpay_credential_binding_mismatch")

        try:
            adapter = _construct_test_adapter(binding=current, material=material)
        except RazorpayAdapterCompositionError:
            raise
        except Exception:
            raise RazorpayAdapterCompositionError(
                "razorpay_test_adapter_composition_failed"
            ) from None
        return adapter


def _construct_test_adapter(
    *,
    binding: RazorpayTestAccountBinding,
    material: RazorpayCredentialMaterial,
) -> RazorpayTestModePaymentLinkAdapter:
    """Instantiate the narrow adapter without issuing a provider request."""

    try:
        from .razorpay_test_adapter import RazorpayTestModePaymentLinkAdapter
    except Exception:
        raise RazorpayAdapterCompositionError("razorpay_test_adapter_unavailable") from None
    return RazorpayTestModePaymentLinkAdapter(
        key_id=material.key_id,
        key_secret=material.key_secret,
        provider_account_id=binding.provider_account_id,
    )


__all__ = [
    "PostgresRazorpayAccountBindingRepository",
    "RazorpayAccountBindingError",
    "RazorpayAccountNotFoundError",
    "RazorpayAccountUnsafeError",
    "RazorpayAdapterCompositionError",
    "RazorpayCredentialMaterial",
    "RazorpayCredentialMismatchError",
    "RazorpayCredentialResolutionError",
    "RazorpayCredentialSecretResolver",
    "RazorpayTestAccountBinding",
    "compose_razorpay_test_mode_adapter",
]
