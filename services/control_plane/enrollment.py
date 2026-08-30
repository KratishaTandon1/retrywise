"""One-time local Razorpay Test enrollment without command-line secrets."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import secrets
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import httpx

from .postgres_connection import PostgresConnectionPolicy
from .razorpay_test_adapter import (
    RazorpayAdapterError,
    RazorpayTestModePaymentLinkAdapter,
)

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_ACCOUNT_RE = re.compile(r"^acc_[A-Za-z0-9_-]{1,124}$")
_KEY_ID_RE = re.compile(r"^rzp_test_[A-Za-z0-9_-]{1,119}$")

_INSERT = """
WITH merchant_insert AS (
    INSERT INTO retrywise.merchants (
        id, display_name, status, timezone, kill_switch_enabled,
        default_policy_version
    ) VALUES (
        %(merchant_id)s, %(display_name)s, 'ACTIVE', %(timezone)s, TRUE,
        'policy-v1'
    )
    RETURNING id
)
INSERT INTO retrywise.provider_accounts (
    id, merchant_id, provider, provider_account_identifier, environment,
    credential_secret_ref, webhook_secret_current_ref, enabled,
    credential_key_id_sha256, credential_binding_version
) VALUES (
    %(provider_account_id)s, %(merchant_id)s, 'RAZORPAY',
    %(provider_account_identifier)s, 'TEST', 'file:account.json',
    'file:webhook.json', TRUE, %(credential_key_id_sha256)s, 1
)
RETURNING id::text
"""


class EnrollmentError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EnrollmentResult:
    merchant_id: str
    provider_account_id: str
    runtime_env_path: Path
    credential_path: Path
    webhook_path: Path


def verify_razorpay_test_credentials(
    *,
    key_id: str,
    key_secret: str,
    provider_account_id: str,
    transport: httpx.BaseTransport | None = None,
) -> None:
    """Prove the supplied Test key can complete a read-only Razorpay API call."""

    reference_id = f"rw-attest-{secrets.token_hex(8)}"
    try:
        with RazorpayTestModePaymentLinkAdapter(
            key_id=key_id,
            key_secret=key_secret,
            provider_account_id=provider_account_id,
            transport=transport,
        ) as adapter:
            matches = adapter.list_payment_links_by_reference(
                reference_id=reference_id,
                provider_account_id=provider_account_id,
            )
    except (RazorpayAdapterError, httpx.HTTPError, ValueError) as exc:
        reason = getattr(exc, "reason_code", type(exc).__name__)
        raise EnrollmentError(f"razorpay_test_attestation_failed:{reason}") from None
    if matches:
        raise EnrollmentError("razorpay_test_attestation_failed:reference_collision")


def _new_ulid() -> str:
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = ((time.time_ns() // 1_000_000) << 80) | secrets.randbits(80)
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = alphabet[value & 31]
        value >>= 5
    return "".join(characters)


def _clean(value: str, *, field: str, maximum: int) -> str:
    if (
        not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EnrollmentError(f"{field} is invalid")
    return value


def _secret(value: str, *, field: str, minimum: int = 16, maximum: int = 512) -> str:
    value = _clean(value, field=field, maximum=maximum)
    if len(value) < minimum or not value.isascii():
        raise EnrollmentError(f"{field} is invalid")
    return value


def _write_private(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(content)
        written = 0
        while written < len(content):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise EnrollmentError("private file write was incomplete")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def enroll(
    *,
    dsn: str,
    secret_root: Path,
    display_name: str,
    timezone: str,
    provider_account_identifier: str,
    key_id: str,
    key_secret: str,
    webhook_secret: str,
    require_tls: bool,
) -> EnrollmentResult:
    """Write protected files and enroll their non-secret binding metadata."""

    display_name = _clean(display_name, field="display_name", maximum=200)
    timezone = _clean(timezone, field="timezone", maximum=100)
    if _ACCOUNT_RE.fullmatch(provider_account_identifier) is None:
        raise EnrollmentError("provider_account_identifier must start with acc_")
    if _KEY_ID_RE.fullmatch(key_id) is None:
        raise EnrollmentError("key_id must be a Razorpay Test key")
    key_secret = _secret(key_secret, field="key_secret", minimum=8, maximum=256)
    webhook_secret = _secret(webhook_secret, field="webhook_secret")
    if not secret_root.is_absolute():
        raise EnrollmentError("secret_root must be absolute")
    if secret_root.exists():
        raise EnrollmentError("secret_root already exists; refusing to overwrite")
    if not secret_root.parent.is_dir():
        raise EnrollmentError("secret_root parent does not exist")

    merchant_id = _new_ulid()
    provider_account_id = _new_ulid()
    endpoint_token = secrets.token_urlsafe(32)
    operator_token = secrets.token_urlsafe(48)
    credential_directory = secret_root / "razorpay"
    webhook_directory = secret_root / "webhook"
    credential_path = credential_directory / "account.json"
    webhook_path = webhook_directory / "webhook.json"
    runtime_env_path = secret_root / "retrywise-test.env"

    secret_root.mkdir(mode=0o700)
    credential_directory.mkdir(mode=0o700)
    webhook_directory.mkdir(mode=0o700)
    try:
        credential = {
            "credential_binding_version": 1,
            "enabled": True,
            "environment": "TEST",
            "key_id": key_id,
            "key_secret": key_secret,
            "merchant_id": merchant_id,
            "provider_account_id": provider_account_id,
            "provider_account_identifier": provider_account_identifier,
        }
        _write_private(
            credential_path,
            json.dumps(credential, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        _write_private(
            webhook_path,
            json.dumps({"current": webhook_secret}, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            ),
        )
        runtime_lines = (
            "RETRYWISE_ENVIRONMENT=development",
            "RETRYWISE_DATA_SOURCE=RAZORPAY_TEST_MODE",
            "RETRYWISE_EFFECTS_MODE=disabled",
            "RETRYWISE_GLOBAL_KILL_SWITCH=true",
            "RETRYWISE_CODE_REVISION=local-test-enrollment",
            f"RETRYWISE_MERCHANT_ID={merchant_id}",
            f"RETRYWISE_PROVIDER_ACCOUNT_ID={provider_account_id}",
            f"RAZORPAY_ACCOUNT_ID={provider_account_identifier}",
            f"RETRYWISE_WEBHOOK_ENDPOINT_TOKEN={endpoint_token}",
            "RAZORPAY_WEBHOOK_SECRET_FILE=/run/secrets/webhook/webhook.json",
            f"RETRYWISE_SECRET_ROOT_HOST={credential_directory}",
            f"RETRYWISE_WEBHOOK_SECRET_ROOT_HOST={webhook_directory}",
            f"RETRYWISE_OPERATOR_TOKEN={operator_token}",
            "RETRYWISE_OPERATOR_SUBJECT=local-enrollment-operator",
        )
        _write_private(runtime_env_path, ("\n".join(runtime_lines) + "\n").encode("utf-8"))

        policy = PostgresConnectionPolicy(require_tls=require_tls)
        policy.validate_dsn(dsn)
        connection_context = cast(Any, policy.connect(dsn, component="RazorpayTestEnrollment"))
        with (
            connection_context as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                _INSERT,
                {
                    "merchant_id": merchant_id,
                    "provider_account_id": provider_account_id,
                    "display_name": display_name,
                    "timezone": timezone,
                    "provider_account_identifier": provider_account_identifier,
                    "credential_key_id_sha256": hashlib.sha256(key_id.encode("ascii")).digest(),
                },
            )
            row = cursor.fetchone()
            if row is None or len(row) != 1 or row[0] != provider_account_id:
                raise EnrollmentError("database enrollment did not confirm the account")
    except Exception as exc:
        # These paths were created by this invocation and have never been shared.
        for path in (runtime_env_path, webhook_path, credential_path):
            with suppress(OSError):
                path.unlink(missing_ok=True)
        for directory in (webhook_directory, credential_directory, secret_root):
            with suppress(OSError):
                directory.rmdir()
        if isinstance(exc, EnrollmentError):
            raise
        raise EnrollmentError(f"enrollment_failed:{type(exc).__name__}") from None

    return EnrollmentResult(
        merchant_id=merchant_id,
        provider_account_id=provider_account_id,
        runtime_env_path=runtime_env_path,
        credential_path=credential_path,
        webhook_path=webhook_path,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enroll one Razorpay Test account using protected local prompts."
    )
    parser.add_argument("--secret-root", required=True, type=Path)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--timezone", default="Asia/Kolkata")
    parser.add_argument("--account-id", required=True, help="Razorpay acc_ account identifier")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--database-require-tls", action="store_true")
    arguments = parser.parse_args(argv)
    if not arguments.database_url:
        parser.error("--database-url or DATABASE_URL is required")
    key_id = getpass.getpass("Razorpay Test key id (hidden): ")
    key_secret = getpass.getpass("Razorpay Test key secret (hidden): ")
    webhook_secret = getpass.getpass("Webhook signing secret (hidden): ")
    try:
        verify_razorpay_test_credentials(
            key_id=key_id,
            key_secret=key_secret,
            provider_account_id="pending-enrollment",
        )
        result = enroll(
            dsn=arguments.database_url,
            secret_root=arguments.secret_root,
            display_name=arguments.display_name,
            timezone=arguments.timezone,
            provider_account_identifier=arguments.account_id,
            key_id=key_id,
            key_secret=key_secret,
            webhook_secret=webhook_secret,
            require_tls=arguments.database_require_tls,
        )
    except EnrollmentError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"merchant_id={result.merchant_id}")
    print(f"provider_account_id={result.provider_account_id}")
    print(f"protected_runtime_env={result.runtime_env_path}")
    print("Read-only Razorpay Test API credential attestation passed.")
    print("Secrets were written with mode 0600 and were not printed.")
    print("Effects and the global kill switch remain disabled/armed until the smoke proof.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EnrollmentError",
    "EnrollmentResult",
    "enroll",
    "main",
    "verify_razorpay_test_credentials",
]
