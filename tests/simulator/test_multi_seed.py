from __future__ import annotations

import unittest
from argparse import ArgumentTypeError
from pathlib import Path
from tempfile import TemporaryDirectory

from retrywise.packages.diagnosis import PINNED_BUNDLED_VERSION
from retrywise.packages.simulator.multi_seed import _parse_seeds, main, summarize_multi_seed


class MultiSeedSummaryTests(unittest.TestCase):
    def test_summary_is_honest_model_bound_and_deterministic(self) -> None:
        arguments = {
            "seeds": (3, 5),
            "case_count": 40,
            "bootstrap_samples": 10,
            "code_revision": "multi-seed-test",
        }

        first = summarize_multi_seed(**arguments)
        second = summarize_multi_seed(**arguments)

        self.assertEqual(first, second)
        self.assertEqual(first["manifest"]["total_cases"], 80)
        self.assertEqual(first["manifest"]["model_version"], PINNED_BUNDLED_VERSION)
        self.assertFalse(first["labels"]["real_money"])
        self.assertFalse(first["labels"]["observed_real_merchant_revenue_claimed"])
        self.assertEqual(first["aggregate"]["run_count"], 2)
        self.assertEqual(len(first["runs"]), 2)

    def test_seeds_must_be_non_empty_unique_integers(self) -> None:
        for seeds in ((), (1, 1), (1, "2")):
            with self.subTest(seeds=seeds), self.assertRaises(ValueError):
                summarize_multi_seed(
                    seeds=seeds,
                    case_count=10,
                    bootstrap_samples=5,
                    code_revision="test",
                )

    def test_default_revision_is_bound_to_evaluation_sources(self) -> None:
        summary = summarize_multi_seed(
            seeds=(7,),
            case_count=10,
            bootstrap_samples=5,
        )

        revision = summary["manifest"]["code_revision"]
        self.assertIsInstance(revision, str)
        self.assertTrue(str(revision).startswith("source-sha256:"))

    def test_cli_writes_honestly_labelled_nested_summary(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "multi.json"
            result = main(
                (
                    "--seeds",
                    "3, 5",
                    "--cases",
                    "10",
                    "--bootstrap-samples",
                    "5",
                    "--code-revision",
                    "cli-test-revision",
                    "--output",
                    str(output),
                )
            )

            self.assertEqual(0, result)
            rendered = output.read_text(encoding="utf-8")
            self.assertIn('"total_cases": 20', rendered)
            self.assertIn('"real_money": false', rendered)
            self.assertTrue(rendered.endswith("\n"))

    def test_seed_parser_trims_values_and_rejects_empty_or_invalid_input(self) -> None:
        self.assertEqual((3, 5), _parse_seeds(" 3, ,5 "))
        for value in ("", " , ", "3,not-an-integer"):
            with self.subTest(value=value), self.assertRaises(ArgumentTypeError):
                _parse_seeds(value)


if __name__ == "__main__":
    unittest.main()
