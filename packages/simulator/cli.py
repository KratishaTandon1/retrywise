"""Command-line entry point for deterministic offline evaluation."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .evaluator import evaluate
from .models import POLICY_VERSION_DEFAULT


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="retrywise-simulator",
        description="Run the deterministic RetryWise offline replay evaluator.",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cases", type=int, default=200, dest="case_count")
    parser.add_argument("--bootstrap-samples", type=int, default=400)
    parser.add_argument("--policy-version", default=POLICY_VERSION_DEFAULT)
    parser.add_argument("--code-revision", default=None)
    parser.add_argument("--include-case-outcomes", action="store_true")
    parser.add_argument("--output", "-o", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = evaluate(
        seed=args.seed,
        case_count=args.case_count,
        policy_version=args.policy_version,
        code_revision=args.code_revision,
        bootstrap_samples=args.bootstrap_samples,
    )
    payload = report.to_dict(include_case_outcomes=args.include_case_outcomes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote offline synthetic replay report for {args.case_count} cases to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
