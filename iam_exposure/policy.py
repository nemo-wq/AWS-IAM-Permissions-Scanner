from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from typing import Any

CONSTRAINT_SCOPES = {"permissions-boundary", "scp", "session"}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    if not document:
        return []
    return [statement for statement in as_list(document.get("Statement")) if isinstance(statement, dict)]


def normalize_action(action: str) -> str:
    return str(action).strip().lower()


def action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(normalize_action(action), normalize_action(pattern))


def any_action_matches(patterns: Iterable[str], action: str) -> bool:
    return any(action_matches(pattern, action) for pattern in patterns)


def extract_policy_grants(
    document: dict[str, Any],
    source: str,
    principal_type: str,
    principal_name: str,
    inherited_via: str | None = None,
    *,
    policy_scope: str = "identity",
) -> list[dict[str, Any]]:
    grants: list[dict[str, Any]] = []
    for index, statement in enumerate(statements(document)):
        effect = str(statement.get("Effect", "")).lower()
        if effect not in {"allow", "deny"}:
            continue
        grants.append(
            {
                "principal_type": principal_type,
                "principal_name": principal_name,
                "source": source,
                "inherited_via": inherited_via,
                "policy_scope": policy_scope,
                "effect": effect,
                "statement_index": index,
                "actions": [str(action) for action in as_list(statement.get("Action"))],
                "not_actions": [str(action) for action in as_list(statement.get("NotAction"))],
                "resources": [str(resource) for resource in as_list(statement.get("Resource") or "*")],
                "not_resources": [str(resource) for resource in as_list(statement.get("NotResource"))],
                "conditions": statement.get("Condition", {}),
                "raw_statement": statement,
            }
        )
    return grants


def extract_allow_grants(
    document: dict[str, Any],
    source: str,
    principal_type: str,
    principal_name: str,
    inherited_via: str | None = None,
) -> list[dict[str, Any]]:
    return [
        grant
        for grant in extract_policy_grants(document, source, principal_type, principal_name, inherited_via)
        if grant["effect"] == "allow"
    ]


def grant_allows(grant: dict[str, Any], action: str) -> bool:
    effect = grant.get("effect", "allow")
    if effect != "allow":
        return False
    return grant_action_matches(grant, action)


def grant_action_matches(grant: dict[str, Any], action: str) -> bool:
    actions = grant.get("actions") or []
    not_actions = grant.get("not_actions") or []
    if actions and any_action_matches(actions, action):
        return True
    return bool(not_actions and not any_action_matches(not_actions, action))


def grant_resource_matches(grant: dict[str, Any], resource: str | None) -> bool:
    resources = grant.get("resources") or ["*"]
    not_resources = grant.get("not_resources") or []
    if resource is None:
        return True
    if not_resources and any(_arn_matches(pattern, resource) for pattern in not_resources):
        return False
    return any(_arn_matches(pattern, resource) for pattern in resources)


def effective_grant_for_action(
    grants: Iterable[dict[str, Any]],
    action: str,
    *,
    resource: str | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    all_grants = list(grants)
    candidates = [
        grant
        for grant in all_grants
        if grant.get("effect", "allow") == "allow"
        and grant.get("policy_scope", "identity") not in CONSTRAINT_SCOPES
        and grant_action_matches(grant, action)
        and grant_resource_matches(grant, resource)
    ]
    for candidate in candidates:
        uncertainties: set[str] = set()
        candidate_condition = condition_matches(candidate.get("conditions", {}), context)
        if candidate_condition is False:
            continue
        if candidate_condition is None:
            uncertainties.add("allow-condition-not-evaluated")
        if resource is None and not resource_is_broad(candidate.get("resources", [])):
            uncertainties.add("resource-scope-requires-target-validation")

        blocked = False
        denied_by = []
        for deny in _matching_denies(all_grants, action, resource, candidate):
            if resource is None and deny.get("not_resources"):
                uncertainties.add("deny-notresource-requires-target-validation")
                continue
            condition = condition_matches(deny.get("conditions", {}), context)
            if condition is True:
                blocked = True
                denied_by.append(deny.get("source"))
            elif condition is None:
                uncertainties.add("conditional-deny-not-evaluated")
        if blocked:
            continue

        for scope in CONSTRAINT_SCOPES:
            scoped = [grant for grant in all_grants if grant.get("policy_scope") == scope]
            if not scoped:
                continue
            scoped_denies = [grant for grant in scoped if grant.get("effect") == "deny"]
            if any(
                grant_action_matches(grant, action)
                and grant_resource_matches(grant, resource)
                and not (resource is None and grant.get("not_resources"))
                and condition_matches(grant.get("conditions", {}), context) is True
                for grant in scoped_denies
            ):
                blocked = True
                denied_by.extend(grant.get("source") for grant in scoped_denies)
                break
            scoped_allows = [grant for grant in scoped if grant.get("effect", "allow") == "allow"]
            require_allow = scope in {"permissions-boundary", "session"} or bool(scoped_allows)
            if require_allow:
                matching = [
                    grant for grant in scoped_allows if grant_action_matches(grant, action) and grant_resource_matches(grant, resource)
                ]
                if not matching:
                    blocked = True
                    break
                conditions = [condition_matches(grant.get("conditions", {}), context) for grant in matching]
                if all(result is False for result in conditions):
                    blocked = True
                    break
                if any(result is None for result in conditions):
                    uncertainties.add(f"{scope}-condition-not-evaluated")
        if blocked:
            continue
        return {
            "grant": candidate,
            "constrained": bool(uncertainties),
            "uncertainties": sorted(uncertainties),
            "denied_by": denied_by,
        }
    return None


def condition_matches(conditions: dict[str, Any], context: dict[str, Any] | None) -> bool | None:
    if not conditions:
        return True
    if context is None:
        return None
    for operator, clauses in conditions.items():
        if not isinstance(clauses, dict):
            return None
        for key, expected in clauses.items():
            actual = context.get(key)
            if actual is None:
                return None
            values = [str(value) for value in as_list(expected)]
            actual_values = [str(value) for value in as_list(actual)]
            name = operator.lower()
            if name in {"stringequals", "arnequals"} and not any(value in values for value in actual_values):
                return False
            if name in {"stringlike", "arnlike"} and not any(
                fnmatch.fnmatchcase(value, pattern) for value in actual_values for pattern in values
            ):
                return False
            if name == "bool" and not any(value.lower() in {item.lower() for item in values} for value in actual_values):
                return False
            if name not in {"stringequals", "arnequals", "stringlike", "arnlike", "bool"}:
                return None
    return True


def resource_is_broad(resources: Iterable[str]) -> bool:
    broad = {"*", "arn:aws:*:*:*:*", "arn:aws:iam::*:*"}
    return any(str(resource) in broad or str(resource).endswith(":*") for resource in resources)


def principal_from_trust_statement(statement: dict[str, Any]) -> list[str]:
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    values: list[str] = []
    if isinstance(principal, dict):
        for item in principal.values():
            values.extend(str(value) for value in as_list(item))
    elif principal is not None:
        values.append(str(principal))
    return values


def _matching_denies(
    grants: Iterable[dict[str, Any]],
    action: str,
    resource: str | None,
    candidate: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        grant
        for grant in grants
        if grant.get("effect") == "deny"
        and grant_action_matches(grant, action)
        and grant_resource_matches(grant, resource)
        and _resources_overlap(candidate, grant)
    ]


def _resources_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_resources = left.get("resources") or ["*"]
    right_resources = right.get("resources") or ["*"]
    if resource_is_broad(left_resources) or resource_is_broad(right_resources):
        return True
    return any(_arn_matches(a, b) or _arn_matches(b, a) for a in left_resources for b in right_resources)


def _arn_matches(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase(str(value), str(pattern))
