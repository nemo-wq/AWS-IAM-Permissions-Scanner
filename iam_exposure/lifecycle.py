from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from typing import Any

from .models import SCHEMA_VERSION

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STATUS_RANK = {"potential": 0, "likely": 1, "confirmed": 2}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def finding_fingerprint(finding: dict[str, Any], account_id: str | None = None) -> str:
    permissions = sorted(
        {
            str(item.get("permission", "")).lower()
            for item in finding.get("evidence", [])
            if isinstance(item, dict) and item.get("permission")
        }
    )
    identity = {
        "account_id": account_id or finding.get("account_id") or "unknown",
        "rule_id": finding.get("id", "unknown"),
        "principal_type": finding.get("principal_type", "unknown"),
        "principal": finding.get("principal", "unknown"),
        "permissions": permissions,
        "target": finding.get("target_resource") or finding.get("target_capability") or finding.get("category", "other"),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def add_fingerprints(findings: Iterable[dict[str, Any]], account_id: str | None = None) -> list[dict[str, Any]]:
    result = []
    for finding in findings:
        item = dict(finding)
        item["fingerprint"] = finding.get("fingerprint") or finding_fingerprint(item, account_id)
        result.append(item)
    return result


def diff_findings(
    previous: Iterable[dict[str, Any]],
    current: Iterable[dict[str, Any]],
    *,
    account_id: str | None = None,
    collection_complete: bool = True,
    previous_ruleset_id: str | None = None,
    current_ruleset_id: str | None = None,
) -> dict[str, Any]:
    before = {item["fingerprint"]: item for item in add_fingerprints(previous, account_id)}
    after = {item["fingerprint"]: item for item in add_fingerprints(current, account_id)}
    changes: list[dict[str, Any]] = []
    current_findings: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    initial_scan = not before
    rules_changed = bool(previous_ruleset_id and current_ruleset_id and previous_ruleset_id != current_ruleset_id)

    for fingerprint, finding in after.items():
        item = dict(finding)
        previous_finding = before.get(fingerprint)
        if previous_finding is None:
            lifecycle = "new"
            reason = "baseline" if initial_scan else ("rule_change" if rules_changed else "environment_change")
        elif previous_finding.get("lifecycle") == "resolved":
            lifecycle = "reopened"
            reason = "environment_change"
        else:
            lifecycle = _change_direction(previous_finding, item)
            reason = "environment_change" if lifecycle != "open" else "unchanged"
        item["lifecycle"] = lifecycle
        item["change_reason"] = reason
        current_findings.append(item)
        if lifecycle != "open":
            changes.append(_change_event(item, lifecycle, reason, previous_finding))

    for fingerprint, finding in before.items():
        if fingerprint in after:
            continue
        lifecycle = "resolved" if collection_complete else "unverified"
        item = dict(finding)
        item["lifecycle"] = lifecycle
        item["change_reason"] = "environment_change" if collection_complete else "collection_degraded"
        resolved.append(item)
        changes.append(_change_event(item, lifecycle, item["change_reason"], finding))

    current_findings.sort(
        key=lambda finding: (-SEVERITY_RANK.get(finding.get("severity", "info"), 0), finding.get("principal", ""), finding.get("id", ""))
    )
    changes.sort(
        key=lambda change: (_lifecycle_sort(change["lifecycle"]), -SEVERITY_RANK.get(change["finding"].get("severity", "info"), 0))
    )
    counts = Counter(change["lifecycle"] for change in changes)
    return {
        "schema_version": SCHEMA_VERSION,
        "collection_complete": collection_complete,
        "previous_ruleset_id": previous_ruleset_id,
        "current_ruleset_id": current_ruleset_id,
        "counts": dict(counts),
        "changes": changes,
        "current_findings": current_findings,
        "resolved_findings": resolved,
    }


def diff_snapshots(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    collection_complete: bool | None = None,
) -> dict[str, Any]:
    current_inventory = current.get("inventory", current)
    account_id = current_inventory.get("account", {}).get("account_id")
    if collection_complete is None:
        coverage = current.get("coverage") or current_inventory.get("collection", {}).get("coverage", {})
        collection_complete = bool(coverage.get("complete", not current_inventory.get("collection", {}).get("warnings", [])))
    return diff_findings(
        previous.get("findings", []),
        current.get("findings", []),
        account_id=account_id,
        collection_complete=collection_complete,
        previous_ruleset_id=previous.get("ruleset_id"),
        current_ruleset_id=current.get("ruleset_id"),
    )


def _change_direction(previous: dict[str, Any], current: dict[str, Any]) -> str:
    before = (
        SEVERITY_RANK.get(previous.get("severity", "info"), 0),
        STATUS_RANK.get(previous.get("status", "potential"), 0),
        CONFIDENCE_RANK.get(previous.get("confidence", "medium"), 1),
    )
    after = (
        SEVERITY_RANK.get(current.get("severity", "info"), 0),
        STATUS_RANK.get(current.get("status", "potential"), 0),
        CONFIDENCE_RANK.get(current.get("confidence", "medium"), 1),
    )
    if after > before:
        return "worsened"
    if after < before:
        return "improved"
    return "open"


def _change_event(finding: dict[str, Any], lifecycle: str, reason: str, previous: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "fingerprint": finding["fingerprint"],
        "lifecycle": lifecycle,
        "reason": reason,
        "finding": finding,
        "previous": previous,
    }


def _lifecycle_sort(lifecycle: str) -> int:
    return {"worsened": 0, "new": 1, "reopened": 2, "improved": 3, "resolved": 4, "unverified": 5}.get(lifecycle, 6)
