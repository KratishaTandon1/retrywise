from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import httpx

from retrywise.services.control_plane.enrollment import (
    EnrollmentError,
    EnrollmentResult,
    enroll,
    main,
    verify_razorpay_test_credentials,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ACCOUNT_ROW_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
KEY_ID = "rzp_test_not_a_real_key"
KEY_SECRET = "not-a-real-key-secret"
WEBHOOK_SECRET = "not-a-real-webhook-signing-secret"


class _Cursor:
    def __init__(self, row: Sequence[object] | None) -> None:
        self.row = row
        self.params: dict[str, object] | None = None

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, _query: str, params: Mapping[str, object]) -> None:
        self.params = dict(params)

    def fetchone(self) -> Sequence[object] | None:
        return self.row


class _Context:
    def __enter__(self) -> object:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _Connection:
    def __init__(self, cursor: _Cursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def transaction(self) -> _Context:
        return _Context()

    def cursor(self) -> _Cursor:
        return self._cursor


def invoke(secret_root: Path, cursor: _Cursor) -> object:
    with (
        patch(
            "retrywise.services.control_plane.enrollment._new_ulid",
            side_effect=(MERCHANT_ID, ACCOUNT_ROW_ID),
        ),
        patch(
            "retrywise.services.control_plane.enrollment.PostgresConnectionPolicy.connect",
            return_value=_Connection(cursor),
        ),
    ):
        return enroll(
            dsn="postgresql://retrywise:password@database.example/retrywise",
            secret_root=secret_root,
            display_name="Winning Test Merchant",
            timezone="Asia/Kolkata",
            provider_account_identifier="acc_test_merchant_1",
            key_id=KEY_ID,
            key_secret=KEY_SECRET,
            webhook_secret=WEBHOOK_SECRET,
            require_tls=True,
        )


class EnrollmentTests(unittest.TestCase):
    def test_read_only_provider_attestation_accepts_test_credentials_only(self) -> None:
        observed: list[httpx.Request] = []

        def success(request: httpx.Request) -> httpx.Response:
            observed.append(request)
            return httpx.Response(200, json={"payment_links": []})

        verify_razorpay_test_credentials(
            key_id=KEY_ID,
            key_secret=KEY_SECRET,
            provider_account_id=ACCOUNT_ROW_ID,
            transport=httpx.MockTransport(success),
        )
        self.assertEqual(1, len(observed))
        self.assertEqual("GET", observed[0].method)
        self.assertEqual("api.razorpay.com", observed[0].url.host)
        self.assertNotIn(KEY_SECRET, str(observed[0].url))

        def unauthorized(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": {"code": "BAD_REQUEST_ERROR"}})

        with self.assertRaisesRegex(
            EnrollmentError,
            "razorpay_test_attestation_failed:provider_read_http_401",
        ):
            verify_razorpay_test_credentials(
                key_id=KEY_ID,
                key_secret=KEY_SECRET,
                provider_account_id=ACCOUNT_ROW_ID,
                transport=httpx.MockTransport(unauthorized),
            )

    def test_input_boundaries_reject_non_test_or_unsafe_secret_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            base: dict[str, object] = {
                "dsn": "postgresql://retrywise@database/retrywise",
                "secret_root": Path(parent) / "secrets",
                "display_name": "Test Merchant",
                "timezone": "Asia/Kolkata",
                "provider_account_identifier": "acc_test_merchant_1",
                "key_id": KEY_ID,
                "key_secret": KEY_SECRET,
                "webhook_secret": WEBHOOK_SECRET,
                "require_tls": False,
            }
            invalid = (
                {"display_name": ""},
                {"provider_account_identifier": "live_account"},
                {"key_id": "rzp_live_forbidden"},
                {"key_secret": "short"},
                {"webhook_secret": "non-ascii-秘密-secret-value"},
                {"secret_root": Path("relative-secret-root")},
                {"secret_root": Path(parent) / "missing" / "secrets"},
            )
            for changes in invalid:
                with self.subTest(changes=changes), self.assertRaises(EnrollmentError):
                    enroll(**{**base, **changes})  # type: ignore[arg-type]

    def test_writes_owner_only_files_and_only_non_secret_database_binding(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            cursor = _Cursor((ACCOUNT_ROW_ID,))
            secret_root = Path(parent) / "retrywise-secrets"

            result = invoke(secret_root, cursor)

            for path in (
                secret_root,
                secret_root / "razorpay",
                secret_root / "webhook",
            ):
                self.assertTrue(path.is_dir())
                if os.name != "nt":
                    self.assertEqual(0o700, stat.S_IMODE(path.stat().st_mode))
            for path in (result.credential_path, result.webhook_path, result.runtime_env_path):
                self.assertTrue(path.is_file())
                if os.name != "nt":
                    self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

            credential = json.loads(result.credential_path.read_text(encoding="utf-8"))
            self.assertEqual(KEY_SECRET, credential["key_secret"])
            runtime_env = result.runtime_env_path.read_text(encoding="utf-8")
            self.assertNotIn(KEY_ID, runtime_env)
            self.assertNotIn(KEY_SECRET, runtime_env)
            self.assertNotIn(WEBHOOK_SECRET, runtime_env)
            self.assertIn("RETRYWISE_EFFECTS_MODE=disabled", runtime_env)
            self.assertIn("RETRYWISE_GLOBAL_KILL_SWITCH=true", runtime_env)

            self.assertIsNotNone(cursor.params)
            assert cursor.params is not None
            self.assertEqual(
                hashlib.sha256(KEY_ID.encode("ascii")).digest(),
                cursor.params["credential_key_id_sha256"],
            )
            persisted = str(cursor.params)
            self.assertNotIn(KEY_ID, persisted)
            self.assertNotIn(KEY_SECRET, persisted)
            self.assertNotIn(WEBHOOK_SECRET, persisted)

    def test_existing_secret_root_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            secret_root = Path(parent) / "existing"
            secret_root.mkdir()
            marker = secret_root / "keep.txt"
            marker.write_text("owned by user", encoding="utf-8")

            with self.assertRaises(EnrollmentError):
                invoke(secret_root, _Cursor((ACCOUNT_ROW_ID,)))

            self.assertEqual("owned by user", marker.read_text(encoding="utf-8"))

    def test_unconfirmed_database_insert_rolls_back_new_secret_tree(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            secret_root = Path(parent) / "retrywise-secrets"

            with self.assertRaises(EnrollmentError):
                invoke(secret_root, _Cursor(None))

            self.assertFalse(secret_root.exists())

    def test_cli_prompts_without_echoing_secrets_and_reports_only_safe_paths(self) -> None:
        result = EnrollmentResult(
            merchant_id=MERCHANT_ID,
            provider_account_id=ACCOUNT_ROW_ID,
            runtime_env_path=Path("/protected/retrywise-test.env"),
            credential_path=Path("/protected/razorpay/account.json"),
            webhook_path=Path("/protected/webhook/webhook.json"),
        )
        arguments = [
            "--secret-root",
            "/protected",
            "--display-name",
            "Test Merchant",
            "--account-id",
            "acc_test_merchant_1",
            "--database-url",
            "postgresql://retrywise@database/retrywise",
        ]
        output = StringIO()
        errors = StringIO()
        with (
            patch(
                "retrywise.services.control_plane.enrollment.getpass.getpass",
                side_effect=(KEY_ID, KEY_SECRET, WEBHOOK_SECRET),
            ) as prompt,
            patch("retrywise.services.control_plane.enrollment.enroll", return_value=result),
            patch("retrywise.services.control_plane.enrollment.verify_razorpay_test_credentials"),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            status = main(arguments)

        self.assertEqual(0, status)
        self.assertEqual(3, prompt.call_count)
        rendered = output.getvalue()
        self.assertIn(MERCHANT_ID, rendered)
        self.assertNotIn(KEY_ID, rendered)
        self.assertNotIn(KEY_SECRET, rendered)
        self.assertNotIn(WEBHOOK_SECRET, rendered)
        self.assertEqual("", errors.getvalue())

        failure_output = StringIO()
        failure_error = StringIO()
        with (
            patch(
                "retrywise.services.control_plane.enrollment.getpass.getpass",
                side_effect=(KEY_ID, KEY_SECRET, WEBHOOK_SECRET),
            ),
            patch(
                "retrywise.services.control_plane.enrollment.enroll",
                side_effect=EnrollmentError("safe_enrollment_error"),
            ),
            patch("retrywise.services.control_plane.enrollment.verify_razorpay_test_credentials"),
            redirect_stdout(failure_output),
            redirect_stderr(failure_error),
        ):
            self.assertEqual(2, main(arguments))
        self.assertIn("safe_enrollment_error", failure_error.getvalue())
        self.assertEqual("", failure_output.getvalue())

        missing_database_error = StringIO()
        with (
            patch.dict("retrywise.services.control_plane.enrollment.os.environ", {}, clear=True),
            redirect_stderr(missing_database_error),
            self.assertRaises(SystemExit),
        ):
            main(
                [
                    "--secret-root",
                    "/protected",
                    "--display-name",
                    "Test Merchant",
                    "--account-id",
                    "acc_test_merchant_1",
                ]
            )
        self.assertIn("--database-url", missing_database_error.getvalue())


if __name__ == "__main__":
    unittest.main()
