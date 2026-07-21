from __future__ import annotations

import hashlib
import json
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Any

REQUIRED_RULE_FIELDS = {
    "id",
    "name",
    "category",
    "severity",
    "required_permissions",
    "source",
    "business_impact",
    "recommendation",
}


def load_and_verify_rule_bundle(
    source: str | Path | dict[str, Any],
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    if isinstance(source, dict):
        data = source
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    else:
        raw = _read_source(str(source))
        data = json.loads(raw.decode("utf-8"))
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        raise ValueError(f"Rule bundle digest mismatch: expected {expected_sha256}, got {digest}")
    validate_rule_bundle(data)
    result = dict(data)
    result["sha256"] = digest
    return result


def validate_rule_bundle(bundle: dict[str, Any]) -> None:
    if not isinstance(bundle, dict):
        raise ValueError("Rule bundle must be a JSON object")
    if not bundle.get("id") or not bundle.get("name"):
        raise ValueError("Rule bundle requires id and name")
    rules = bundle.get("rules")
    if not isinstance(rules, list):
        raise ValueError("Rule bundle rules must be a list")
    seen = set()
    for index, rule in enumerate(rules):
        missing = REQUIRED_RULE_FIELDS - set(rule)
        if missing:
            raise ValueError(f"Rule at index {index} is missing: {', '.join(sorted(missing))}")
        if rule["id"] in seen:
            raise ValueError(f"Duplicate rule id: {rule['id']}")
        seen.add(rule["id"])
        if rule.get("severity") not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError(f"Rule {rule['id']} has an invalid severity")
        _require_string_list(rule, "required_permissions")
        _require_string_list(rule, "source")


def install_rule_bundle(
    source: str | Path,
    destination: Path,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    bundle = load_and_verify_rule_bundle(source, expected_sha256=expected_sha256)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    return bundle


def _read_source(source: str) -> bytes:
    if source.startswith("https://"):
        request = urllib.request.Request(source, headers={"User-Agent": "iam-exposure-review"})
        with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
            return response.read()
    if source.startswith("http://"):
        raise ValueError("Rule updates require HTTPS or a local file")
    return Path(source).expanduser().read_bytes()


def _require_string_list(rule: dict[str, Any], field: str) -> None:
    value: Iterable[Any] = rule.get(field, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Rule {rule.get('id', '<unknown>')} field {field} must be a list of strings")
