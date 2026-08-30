from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from retrywise.packages.simulator.cli import main


class CliTests(unittest.TestCase):
    def test_cli_writes_machine_readable_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "evaluation.json"

            status = main(
                [
                    "--seed",
                    "11",
                    "--cases",
                    "40",
                    "--bootstrap-samples",
                    "20",
                    "--code-revision",
                    "cli-test",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(status, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["manifest"]["seed"], 11)
            self.assertEqual(payload["manifest"]["case_count"], 40)
            self.assertEqual(payload["labels"]["execution_context"], "offline_replay")
            self.assertFalse(payload["labels"]["real_money"])
            self.assertEqual(
                set(payload["results"]),
                {"B0", "B1", "B2", "B3", "RetryWise", "oracle"},
            )


if __name__ == "__main__":
    unittest.main()
