from __future__ import annotations

from typing import Any

from .graph import build_attack_graph
from .lifecycle import diff_snapshots
from .report import render_html as render_report
from .rules import evaluate_inventory, load_ruleset
from .updates import load_and_verify_rule_bundle


def collect_inventory(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .collector import collect_inventory as _collect_inventory

    return _collect_inventory(*args, **kwargs)


def evaluate_snapshot(
    inventory: dict[str, Any],
    ruleset: dict[str, Any] | None = None,
    severity_threshold: str = "low",
) -> list[dict[str, Any]]:
    return evaluate_inventory(inventory, ruleset or load_ruleset(), severity_threshold)


def find_attack_paths(
    inventory: dict[str, Any],
    ruleset: dict[str, Any] | None = None,
    severity_threshold: str = "low",
) -> list[dict[str, Any]]:
    return evaluate_snapshot(inventory, ruleset, severity_threshold)


__all__ = [
    "build_attack_graph",
    "collect_inventory",
    "diff_snapshots",
    "evaluate_snapshot",
    "find_attack_paths",
    "load_and_verify_rule_bundle",
    "render_report",
]
