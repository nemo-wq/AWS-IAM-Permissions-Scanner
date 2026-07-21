"""AWS IAM Exposure Review.

Local-first AWS IAM exposure and privilege escalation assessment tooling.
"""

__version__ = "0.2.0"

from .api import (
    build_attack_graph,
    collect_inventory,
    diff_snapshots,
    evaluate_snapshot,
    find_attack_paths,
    load_and_verify_rule_bundle,
    render_report,
)

__all__ = [
    "build_attack_graph",
    "collect_inventory",
    "diff_snapshots",
    "evaluate_snapshot",
    "find_attack_paths",
    "load_and_verify_rule_bundle",
    "render_report",
]
