from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from retrywise.services.control_plane.razorpay_account_binding import (
    RazorpayCredentialResolutionError,
)
from retrywise.services.control_plane.test_mode_secrets import (
    FileRazorpayCredentialSecretResolver,
)

MERCHANT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
PROVIDER_ACCOUNT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"


def _payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "merchant_id": MERCHANT_ID,
        "provider_account_id": PROVIDER_ACCOUNT_ID,
        "provider_account_identifier": "acc_test_1",
        "environment": "TEST",
        "enabled": True,
        "credential_binding_version": 1,
        "key_id": "rzp_test_examplekey",
        "key_secret": "example-secret-not-real",
    }
    payload.update(updates)
    return payload


class FileRazorpayCredentialSecretResolverTests(unittest.TestCase):
    def test_resolves_exact_owner_only_test_material_without_repr_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            path.write_text(json.dumps(_payload()), encoding="utf-8")
            path.chmod(0o600)

            resolver = FileRazorpayCredentialSecretResolver(secret_root=directory)
            material = resolver.resolve(credential_secret_ref="file:account.json")

            self.assertEqual(MERCHANT_ID, material.merchant_id)
            self.assertEqual(PROVIDER_ACCOUNT_ID, material.provider_account_id)
            self.assertEqual("rzp_test_examplekey", material.key_id)
            self.assertNotIn("example-secret-not-real", repr(material))
            self.assertNotIn(directory, repr(resolver))

    def test_rejects_live_keys_unknown_fields_and_permissive_files(self) -> None:
        variants = (
            _payload(key_id="rzp_live_forbidden"),
            {**_payload(), "extra": "forbidden"},
        )
        for index, payload in enumerate(variants):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "account.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                path.chmod(0o600)
                resolver = FileRazorpayCredentialSecretResolver(secret_root=directory)
                with self.assertRaisesRegex(
                    RazorpayCredentialResolutionError,
                    "^razorpay_credential_resolution_failed$",
                ):
                    resolver.resolve(credential_secret_ref="file:account.json")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            path.write_text(json.dumps(_payload()), encoding="utf-8")
            path.chmod(0o640)
            resolver = FileRazorpayCredentialSecretResolver(secret_root=directory)
            with self.assertRaises(RazorpayCredentialResolutionError):
                resolver.resolve(credential_secret_ref="file:account.json")

    def test_rejects_traversal_symlinks_nonexistent_and_oversized_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            resolver = FileRazorpayCredentialSecretResolver(secret_root=directory)
            for reference in ("file:../account.json", "file:/account.json", "env:key"):
                with (
                    self.subTest(reference=reference),
                    self.assertRaises(RazorpayCredentialResolutionError),
                ):
                    resolver.resolve(credential_secret_ref=reference)

            with self.assertRaises(RazorpayCredentialResolutionError):
                resolver.resolve(credential_secret_ref="file:missing.json")

            target = Path(directory) / "target.json"
            target.write_text(json.dumps(_payload()), encoding="utf-8")
            target.chmod(0o600)
            link = Path(directory) / "link.json"
            os.symlink(target, link)
            with self.assertRaises(RazorpayCredentialResolutionError):
                resolver.resolve(credential_secret_ref="file:link.json")

            oversized = Path(directory) / "oversized.json"
            oversized.write_bytes(b"{" + b" " * (8 * 1024) + b"}")
            oversized.chmod(0o600)
            with self.assertRaises(RazorpayCredentialResolutionError):
                resolver.resolve(credential_secret_ref="file:oversized.json")

    def test_requires_absolute_existing_real_root(self) -> None:
        with self.assertRaises(ValueError):
            FileRazorpayCredentialSecretResolver(secret_root="relative")
        with self.assertRaises(ValueError):
            FileRazorpayCredentialSecretResolver(secret_root="/definitely/missing/retrywise")


if __name__ == "__main__":
    unittest.main()
