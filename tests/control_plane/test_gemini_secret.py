from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from retrywise.services.control_plane.gemini_secret import (
    GeminiSecretFileError,
    load_gemini_api_key_file,
)


class GeminiSecretFileTests(unittest.TestCase):
    def test_owner_only_exact_json_file_loads_without_repr_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gemini.json"
            path.write_text(json.dumps({"api_key": "test-gemini-key-123456"}), encoding="utf-8")
            path.chmod(0o600)

            value = load_gemini_api_key_file(str(path))

            self.assertEqual("test-gemini-key-123456", value)

    def test_relative_loose_symlink_and_extra_field_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "valid.json"
            valid.write_text(json.dumps({"api_key": "test-gemini-key-123456"}), encoding="utf-8")
            valid.chmod(0o600)
            loose = root / "loose.json"
            loose.write_text(valid.read_text(encoding="utf-8"), encoding="utf-8")
            loose.chmod(0o644)
            extra = root / "extra.json"
            extra.write_text(
                json.dumps({"api_key": "test-gemini-key-123456", "model": "ignored"}),
                encoding="utf-8",
            )
            extra.chmod(0o600)
            link = root / "link.json"
            os.symlink(valid, link)

            for path in ("relative.json", str(loose), str(extra), str(link)):
                with self.subTest(path=Path(path).name), self.assertRaises(GeminiSecretFileError):
                    load_gemini_api_key_file(path)

    def test_malformed_and_unbounded_secret_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents: tuple[tuple[str, bytes], ...] = (
                ("empty.json", b""),
                ("oversized.json", b"x" * 2049),
                ("invalid-utf8.json", b"\xff"),
                ("invalid-json.json", b"{"),
                ("array.json", b"[]"),
                ("short-key.json", json.dumps({"api_key": "short"}).encode()),
                (
                    "whitespace-key.json",
                    json.dumps({"api_key": " test-gemini-key-123456"}).encode(),
                ),
            )
            paths: list[Path] = []
            for name, content in contents:
                path = root / name
                path.write_bytes(content)
                path.chmod(0o600)
                paths.append(path)
            paths.append(root)

            for path in paths:
                with self.subTest(path=path.name), self.assertRaises(GeminiSecretFileError):
                    load_gemini_api_key_file(str(path))


if __name__ == "__main__":
    unittest.main()
