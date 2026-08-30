"""Application service for honest, reproducible offline evaluation."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from functools import lru_cache
from threading import Lock
from typing import Any

from ...packages.diagnosis import (
    BUNDLED_ARTIFACT,
    HELD_OUT_CORPUS,
    PINNED_BUNDLED_VERSION,
    DiagnosisModel,
    evaluate_holdout,
)
from ...packages.simulator import EvaluationReport, evaluate


class ReplayIdempotencyConflict(ValueError):
    """An idempotency key was reused for a different replay manifest."""


@dataclass(frozen=True, slots=True)
class ReplayRunRequest:
    seed: int = 42
    case_count: int = 2_000
    bootstrap_samples: int = 400
    policy_version: str = "recovery-policy-v1"
    model_version: str = field(default=PINNED_BUNDLED_VERSION, init=False)
    code_revision: str = "local-development"

    def __post_init__(self) -> None:
        if type(self.seed) is not int:
            raise ValueError("seed must be an integer")
        if type(self.case_count) is not int or not 1 <= self.case_count <= 5_000:
            raise ValueError("case_count must be between 1 and 5,000")
        if type(self.bootstrap_samples) is not int or not 1 <= self.bootstrap_samples <= 2_000:
            raise ValueError("bootstrap_samples must be between 1 and 2,000")
        for name in ("policy_version", "code_revision"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError(f"{name} must be a non-empty string")

    def to_primitive(self) -> dict[str, object]:
        return {
            "bootstrap_samples": self.bootstrap_samples,
            "case_count": self.case_count,
            "code_revision": self.code_revision,
            "model_version": self.model_version,
            "policy_version": self.policy_version,
            "seed": self.seed,
        }

    @property
    def request_digest(self) -> str:
        payload = json.dumps(
            self.to_primitive(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


class ReplayService:
    """Runs/caches deterministic reports and exposes presentation-safe views."""

    def __init__(self) -> None:
        self._submission_lock = Lock()
        self._submissions: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}

    def run(self, request: ReplayRunRequest) -> EvaluationReport:
        if not isinstance(request, ReplayRunRequest):
            raise TypeError("request must be ReplayRunRequest")
        return _cached_evaluate(
            request.seed,
            request.case_count,
            request.bootstrap_samples,
            request.policy_version,
            request.model_version,
            request.code_revision,
        )

    def overview(self, request: ReplayRunRequest) -> dict[str, Any]:
        report = self.run(request)
        retrywise = next(item for item in report.results if item.policy_key == "RetryWise")
        b3 = next(item for item in report.results if item.policy_key == "B3")
        metrics = retrywise.metrics
        comparison = next(
            item
            for item in report.comparisons
            if item.candidate == "RetryWise" and item.reference == "B3"
        )
        model_abstentions = sum(
            1
            for outcome in retrywise.case_outcomes
            if any("model_abstained" in entry.reason_code for entry in outcome.audit_entries)
        )
        return {
            "environment": "REPLAY",
            "labels": report.to_dict()["labels"],
            "as_of": "deterministic-run",
            "offline_simulated_incremental_value_minor": (
                metrics.net_simulated_incremental_value_minor
            ),
            "incremental_recovered_orders": metrics.incremental_recovered_orders,
            "safely_suppressed_original_successes": (metrics.original_success_actions_suppressed),
            "hard_safety_violations": metrics.hard_safety_violations,
            "audit_completeness_pct": metrics.audit_completeness_pct,
            "abstentions": metrics.abstentions,
            "model_abstentions": model_abstentions,
            "actions_executed": metrics.actions_executed,
            "net_lift_vs_b3_minor": (
                metrics.net_simulated_incremental_value_minor
                - b3.metrics.net_simulated_incremental_value_minor
            ),
            "paired_interval_vs_b3_minor": {
                "low": comparison.confidence_interval.low_minor,
                "high": comparison.confidence_interval.high_minor,
                "confidence": comparison.confidence_interval.confidence,
                "cluster_unit": comparison.confidence_interval.cluster_unit,
                "supports_improvement": comparison.supports_improvement,
            },
            "manifest": {
                "seed": report.manifest.seed,
                "case_count": report.manifest.case_count,
                "dataset_hash": report.manifest.dataset_hash,
                "policy_version": report.manifest.policy_version,
                "model_version": report.manifest.model_version,
                "code_revision": report.manifest.code_revision,
            },
            "diagnosis_model": {
                "artifact_version": PINNED_BUNDLED_VERSION,
                "role": "non_authoritative_failure_classification",
                "dataset_label": "Frozen synthetic held-out engineering smoke set",
                "merchant_performance_claimed": False,
                "metrics": _diagnosis_holdout_metrics(),
            },
        }

    def submit(
        self,
        *,
        merchant_id: str,
        idempotency_key: str,
        request: ReplayRunRequest,
    ) -> dict[str, Any]:
        """Evaluate once per merchant/key and reject semantic key reuse.

        The in-process registry is the development adapter. A deployed API uses
        the same contract backed by the ``evaluation_runs`` table so the key and
        request digest survive restarts and multiple replicas.
        """

        if not isinstance(merchant_id, str) or not merchant_id.strip():
            raise ValueError("merchant_id is required")
        if (
            not isinstance(idempotency_key, str)
            or idempotency_key != idempotency_key.strip()
            or not 16 <= len(idempotency_key) <= 128
        ):
            raise ValueError("idempotency_key must contain 16 to 128 characters")
        if not isinstance(request, ReplayRunRequest):
            raise TypeError("request must be ReplayRunRequest")

        registry_key = (merchant_id, idempotency_key)
        request_digest = request.request_digest
        with self._submission_lock:
            previous = self._submissions.get(registry_key)
            if previous is not None:
                previous_digest, previous_response = previous
                if previous_digest != request_digest:
                    raise ReplayIdempotencyConflict(
                        "idempotency key is already bound to another replay request"
                    )
                return deepcopy(previous_response)

            response = self.overview(request)
            self._submissions[registry_key] = (request_digest, deepcopy(response))
            return deepcopy(response)


@lru_cache(maxsize=32)
def _cached_evaluate(
    seed: int,
    case_count: int,
    bootstrap_samples: int,
    policy_version: str,
    model_version: str,
    code_revision: str,
) -> EvaluationReport:
    return evaluate(
        seed=seed,
        case_count=case_count,
        bootstrap_samples=bootstrap_samples,
        policy_version=policy_version,
        model_version=model_version,
        code_revision=code_revision,
    )


@lru_cache(maxsize=1)
def _diagnosis_holdout_metrics() -> dict[str, object]:
    model = DiagnosisModel(BUNDLED_ARTIFACT)
    return evaluate_holdout(model, HELD_OUT_CORPUS).to_primitive()
