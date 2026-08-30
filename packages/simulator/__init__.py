"""Deterministic, dependency-free RetryWise offline evaluation simulator."""

from .engine import VirtualClock, run_policy
from .evaluator import evaluate
from .generator import generate_dataset
from .models import (
    ActionKind,
    EvaluationReport,
    EventKind,
    FailureCause,
    Scenario,
    ScenarioDataset,
    ScenarioEvent,
)
from .policies import POLICY_DISPLAY_NAMES, policy_catalog

__all__ = [
    "POLICY_DISPLAY_NAMES",
    "ActionKind",
    "EvaluationReport",
    "EventKind",
    "FailureCause",
    "Scenario",
    "ScenarioDataset",
    "ScenarioEvent",
    "VirtualClock",
    "evaluate",
    "generate_dataset",
    "policy_catalog",
    "run_policy",
]
