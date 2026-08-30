"""Deterministic multi-seed evaluation summary for published evidence."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .evaluator import evaluate, evaluation_source_revision
from .models import MODEL_VERSION_DEFAULT, POLICY_VERSION_DEFAULT


def summarize_multi_seed(
    *,
    seeds: tuple[int, ...],
    case_count: int,
    bootstrap_samples: int,
    code_revision: str | None = None,
) -> dict[str, object]:
    if not seeds or len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be non-empty and unique")
    if any(type(seed) is not int for seed in seeds):
        raise ValueError("every seed must be an integer")

    resolved_code_revision = code_revision or evaluation_source_revision()
    runs: list[dict[str, object]] = []
    lifts: list[int] = []
    total_value = total_lift = total_recoveries = total_violations = 0
    supported_runs = 0
    for seed in seeds:
        report = evaluate(
            seed=seed,
            case_count=case_count,
            bootstrap_samples=bootstrap_samples,
            code_revision=resolved_code_revision,
        )
        retrywise = next(item for item in report.results if item.policy_key == "RetryWise")
        b3 = next(item for item in report.results if item.policy_key == "B3")
        comparison = next(
            item
            for item in report.comparisons
            if item.candidate == "RetryWise" and item.reference == "B3"
        )
        metrics = retrywise.metrics
        lift = (
            metrics.net_simulated_incremental_value_minor
            - b3.metrics.net_simulated_incremental_value_minor
        )
        total_value += metrics.net_simulated_incremental_value_minor
        total_lift += lift
        lifts.append(lift)
        total_recoveries += metrics.incremental_recovered_orders
        total_violations += metrics.hard_safety_violations
        supported_runs += int(comparison.supports_improvement)
        runs.append(
            {
                "seed": seed,
                "dataset_hash": report.manifest.dataset_hash,
                "retrywise_net_simulated_incremental_value_minor": (
                    metrics.net_simulated_incremental_value_minor
                ),
                "net_lift_vs_b3_minor": lift,
                "incremental_recovered_orders": metrics.incremental_recovered_orders,
                "hard_safety_violations": metrics.hard_safety_violations,
                "paired_interval_vs_b3_minor": {
                    "low": comparison.confidence_interval.low_minor,
                    "high": comparison.confidence_interval.high_minor,
                    "supports_improvement": comparison.supports_improvement,
                },
            }
        )

    return {
        "schema_version": "retrywise.multi_seed.v1",
        "labels": {
            "dataset": "Synthetic counterfactual scenarios",
            "value": "Offline simulated recovered value",
            "real_money": False,
            "observed_real_merchant_revenue_claimed": False,
        },
        "manifest": {
            "seeds": list(seeds),
            "case_count_per_seed": case_count,
            "total_cases": case_count * len(seeds),
            "bootstrap_samples_per_seed": bootstrap_samples,
            "policy_version": POLICY_VERSION_DEFAULT,
            "model_version": MODEL_VERSION_DEFAULT,
            "code_revision": resolved_code_revision,
        },
        "aggregate": {
            "retrywise_net_simulated_incremental_value_minor": total_value,
            "net_lift_vs_b3_minor": total_lift,
            "incremental_recovered_orders": total_recoveries,
            "hard_safety_violations": total_violations,
            "runs_supporting_improvement": supported_runs,
            "run_count": len(seeds),
            "all_point_estimates_positive": all(lift > 0 for lift in lifts),
        },
        "runs": runs,
    }


def _parse_seeds(value: str) -> tuple[int, ...]:
    try:
        seeds = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("seeds must be comma-separated integers") from exc
    if not seeds:
        raise argparse.ArgumentTypeError("at least one seed is required")
    return seeds


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="retrywise-evaluate-multiseed",
        description="Publish a deterministic multi-seed RetryWise evidence summary.",
    )
    parser.add_argument("--seeds", type=_parse_seeds, required=True)
    parser.add_argument("--cases", type=int, default=2_000, dest="case_count")
    parser.add_argument("--bootstrap-samples", type=int, default=400)
    parser.add_argument("--code-revision")
    parser.add_argument("--output", "-o", type=Path, required=True)
    args = parser.parse_args(argv)
    payload = summarize_multi_seed(
        seeds=args.seeds,
        case_count=args.case_count,
        bootstrap_samples=args.bootstrap_samples,
        code_revision=args.code_revision,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"Wrote {len(args.seeds)}-seed offline synthetic summary "
        f"for {args.case_count * len(args.seeds)} cases to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
