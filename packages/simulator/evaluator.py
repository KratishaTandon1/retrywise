"""Paired evaluation, clustered confidence intervals, and report manifests."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from pathlib import Path

from .engine import run_policy
from .generator import generate_dataset, keyed_u64
from .models import (
    MODEL_VERSION_DEFAULT,
    POLICY_VERSION_DEFAULT,
    SCHEMA_VERSION,
    SIMULATOR_VERSION,
    ConfidenceInterval,
    EvaluationReport,
    HonestLabels,
    PairedComparison,
    PolicyResult,
    RunManifest,
)
from .policies import policy_catalog


def evaluate(
    *,
    seed: int = 42,
    case_count: int = 200,
    policy_version: str = POLICY_VERSION_DEFAULT,
    model_version: str = MODEL_VERSION_DEFAULT,
    code_revision: str | None = None,
    bootstrap_samples: int = 400,
) -> EvaluationReport:
    if bootstrap_samples <= 0:
        raise ValueError("bootstrap_samples must be positive")
    dataset = generate_dataset(
        seed=seed,
        case_count=case_count,
        policy_version=policy_version,
    )
    results = tuple(
        run_policy(dataset, policy) for policy in policy_catalog(model_version=model_version)
    )
    by_key = {result.policy_key: result for result in results}
    comparisons = tuple(
        _paired_comparison(
            seed,
            by_key[candidate],
            by_key[reference],
            bootstrap_samples,
        )
        for candidate, reference in (
            ("B1", "B0"),
            ("B2", "B0"),
            ("B3", "B0"),
            ("RetryWise", "B0"),
            ("RetryWise", "B2"),
            ("RetryWise", "B3"),
            ("oracle", "RetryWise"),
        )
    )
    deployable = tuple(result for result in results if result.deployable)
    ranking = tuple(
        result.policy_key
        for result in sorted(
            deployable,
            key=lambda item: (
                item.metrics.hard_safety_violations,
                -item.metrics.audit_completeness_pct,
                -item.metrics.net_simulated_incremental_value_minor,
            ),
        )
    )
    manifest = RunManifest(
        seed=seed,
        case_count=case_count,
        dataset_hash=dataset.dataset_hash,
        policy_version=policy_version,
        model_version=model_version,
        code_revision=_resolve_code_revision(code_revision),
        simulator_version=SIMULATOR_VERSION,
        bootstrap_samples=bootstrap_samples,
        cost_assumptions=dataset.costs,
        scenario_family_counts=tuple(
            sorted(Counter(item.family for item in dataset.scenarios).items())
        ),
        delivery_mutation_counts=tuple(
            sorted(
                Counter(
                    mutation for item in dataset.scenarios for mutation in item.delivery_mutations
                ).items()
            )
        ),
        adversarial_flag_counts=tuple(
            sorted(
                Counter(
                    flag for item in dataset.scenarios for flag in item.adversarial_flags
                ).items()
            )
        ),
    )
    return EvaluationReport(
        schema_version=SCHEMA_VERSION,
        labels=HonestLabels(),
        manifest=manifest,
        results=results,
        comparisons=comparisons,
        deployable_ranking=ranking,
    )


def _resolve_code_revision(explicit: str | None) -> str:
    if explicit:
        return explicit
    return evaluation_source_revision()


def evaluation_source_revision() -> str:
    """Bind evidence to every Python source that can influence evaluation."""

    digest = hashlib.sha256()
    package_root = Path(__file__).resolve().parents[1]
    for module_name in ("diagnosis", "domain", "simulator"):
        module_root = package_root / module_name
        for source in sorted(module_root.rglob("*.py")):
            relative_path = source.relative_to(package_root).as_posix()
            digest.update(relative_path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(source.read_bytes())
            digest.update(b"\0")
    return f"source-sha256:{digest.hexdigest()}"


def _paired_comparison(
    seed: int,
    candidate: PolicyResult,
    reference: PolicyResult,
    bootstrap_samples: int,
) -> PairedComparison:
    candidate_by_case = {outcome.scenario_id: outcome for outcome in candidate.case_outcomes}
    reference_by_case = {outcome.scenario_id: outcome for outcome in reference.case_outcomes}
    if candidate_by_case.keys() != reference_by_case.keys():
        raise ValueError("paired policies must evaluate identical scenario IDs")

    deltas: dict[str, tuple[str, int]] = {}
    wins = losses = ties = 0
    for scenario_id in sorted(candidate_by_case):
        candidate_outcome = candidate_by_case[scenario_id]
        reference_outcome = reference_by_case[scenario_id]
        delta = (
            candidate_outcome.net_incremental_value_minor
            - reference_outcome.net_incremental_value_minor
        )
        deltas[scenario_id] = (candidate_outcome.merchant_id, delta)
        if delta > 0:
            wins += 1
        elif delta < 0:
            losses += 1
        else:
            ties += 1

    interval = _clustered_bootstrap_interval(
        seed,
        candidate.policy_key,
        reference.policy_key,
        deltas,
        bootstrap_samples,
    )
    delta_safety = (
        candidate.metrics.hard_safety_violations - reference.metrics.hard_safety_violations
    )
    supports_improvement = delta_safety <= 0 and interval.low_minor > 0
    if delta_safety > 0:
        conclusion = "worse_safety_no_improvement_claim"
    elif interval.low_minor > 0:
        conclusion = "paired_interval_supports_improvement"
    elif interval.high_minor < 0:
        conclusion = "paired_interval_supports_regression"
    else:
        conclusion = "paired_interval_inconclusive"
    return PairedComparison(
        candidate=candidate.policy_key,
        reference=reference.policy_key,
        paired_on="scenario_id_and_precomputed_potential_outcomes",
        delta_net_value_minor=(
            candidate.metrics.net_simulated_incremental_value_minor
            - reference.metrics.net_simulated_incremental_value_minor
        ),
        delta_incremental_recovered_orders=(
            candidate.metrics.incremental_recovered_orders
            - reference.metrics.incremental_recovered_orders
        ),
        delta_hard_safety_violations=delta_safety,
        wins=wins,
        losses=losses,
        ties=ties,
        confidence_interval=interval,
        supports_improvement=supports_improvement,
        conclusion=conclusion,
    )


def _clustered_bootstrap_interval(
    seed: int,
    candidate_key: str,
    reference_key: str,
    deltas: dict[str, tuple[str, int]],
    bootstrap_samples: int,
) -> ConfidenceInterval:
    by_merchant: dict[str, int] = defaultdict(int)
    for merchant_id, delta in deltas.values():
        by_merchant[merchant_id] += delta
    merchants = sorted(by_merchant)
    samples: list[int]
    if not merchants:
        samples = [0]
    else:
        samples = []
        for replicate in range(bootstrap_samples):
            total = 0
            for position in range(len(merchants)):
                selected = keyed_u64(
                    seed,
                    "bootstrap",
                    candidate_key,
                    reference_key,
                    replicate,
                    position,
                ) % len(merchants)
                total += by_merchant[merchants[selected]]
            samples.append(total)
    samples.sort()
    low_index = int(0.025 * (len(samples) - 1))
    high_index = int(0.975 * (len(samples) - 1))
    return ConfidenceInterval(
        low_minor=samples[low_index],
        high_minor=samples[high_index],
        confidence=0.95,
        bootstrap_samples=bootstrap_samples,
        cluster_unit="merchant_id",
    )
