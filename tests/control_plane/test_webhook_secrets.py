from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from retrywise.services.control_plane.runtime import ControlPlaneRuntime
from retrywise.services.control_plane.settings import ConfigurationError
from retrywise.services.control_plane.webhook_secrets import (
    WebhookSecretFileError,
    load_webhook_secret_file,
)


class WebhookSecretFileTests(unittest.TestCase):
    def test_owner_only_exact_file_loads_without_repr_leakage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "webhook.json"
            current = "webhook-current-secret-32-bytes-long"
            path.write_text(json.dumps({"current": current}), encoding="utf-8")
            path.chmod(0o600)

            snapshot = load_webhook_secret_file(str(path))

            self.assertEqual(current, snapshot.current)
            self.assertNotIn(current, repr(snapshot))

    def test_symlink_permissive_mode_and_unknown_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "webhook.json"
            path.write_text(json.dumps({"current": "x" * 32}), encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaises(WebhookSecretFileError):
                load_webhook_secret_file(str(path))
            path.chmod(0o600)
            link = root / "link.json"
            os.symlink(path, link)
            with self.assertRaises(WebhookSecretFileError):
                load_webhook_secret_file(str(link))
            path.write_text(json.dumps({"current": "x" * 32, "extra": True}), encoding="utf-8")
            with self.assertRaises(WebhookSecretFileError):
                load_webhook_secret_file(str(path))

    def test_runtime_rejects_mixed_secret_authorities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "webhook.json"
            path.write_text(json.dumps({"current": "x" * 32}), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(ConfigurationError, "exactly one"):
                ControlPlaneRuntime.from_mapping(
                    {
                        "RAZORPAY_WEBHOOK_SECRET_FILE": str(path),
                        "RAZORPAY_WEBHOOK_SECRET_PREVIOUS": "y" * 32,
                    }
                )


if __name__ == "__main__":
    unittest.main()
