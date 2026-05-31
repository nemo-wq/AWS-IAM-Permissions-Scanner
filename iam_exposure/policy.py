from __future__ import annotations

import fnmatch
from typing import Any, Dict, Iterable, List


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not document:
        return []
    return [s for s in as_list(document.get("Statement")) if isinstance(s, dict)]


def normalize_action(action: str) -> str:
    return str(action).strip().lower()


def action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(normalize_action(action), normalize_action(pattern))


def any_action_matches(patterns: Iterable[str], action: str) -> bool:
    return any(action_matches(pattern, action) for pattern in patterns)


def extract_allow_grants(
    document: Dict[str, Any],
    source: str,
    principal_type: str,
    principal_name: str,
    inherited_via: str | None = None,
) -> List[Dict[str, Any]]:
    grants: List[Dict[str, Any]] = []
    for index, statement in enumerate(statements(document)):
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        actions = [str(a) for a in as_list(statement.get("Action"))]
        not_actions = [str(a) for a in as_list(statement.get("NotAction"))]
        resources = [str(r) for r in as_list(statement.get("Resource") or "*")]
        grants.append(
            {
                "principal_type": principal_type,
                "principal_name": principal_name,
                "source": source,
                "inherited_via": inherited_via,
                "statement_index": index,
                "actions": actions,
                "not_actions": not_actions,
                "resources": resources,
                "conditions": statement.get("Condition", {}),
                "raw_statement": statement,
            }
        )
    return grants


def grant_allows(grant: Dict[str, Any], action: str) -> bool:
    actions = grant.get("actions") or []
    not_actions = grant.get("not_actions") or []
    if actions and any_action_matches(actions, action):
        return True
    if not_actions and not any_action_matches(not_actions, action):
        return True
    return False


def resource_is_broad(resources: Iterable[str]) -> bool:
    broad = {"*", "arn:aws:*:*:*:*", "arn:aws:iam::*:*"}
    return any(str(resource) in broad or str(resource).endswith(":*") for resource in resources)


def principal_from_trust_statement(statement: Dict[str, Any]) -> List[str]:
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    values: List[str] = []
    if isinstance(principal, dict):
        for item in principal.values():
            values.extend(str(v) for v in as_list(item))
    elif principal is not None:
        values.append(str(principal))
    return values
