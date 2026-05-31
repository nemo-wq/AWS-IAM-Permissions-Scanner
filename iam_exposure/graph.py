from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List


def build_attack_graph(inventory: Dict[str, Any]) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def add_node(node_id: str, node_type: str, label: str, **attrs: Any) -> None:
        node = nodes.setdefault(node_id, {"id": node_id, "type": node_type, "label": label})
        node.update(attrs)

    def add_edge(source: str, target: str, edge_type: str, label: str | None = None, **attrs: Any) -> None:
        edge = {"from": source, "to": target, "type": edge_type}
        if label:
            edge["label"] = label
        edge.update(attrs)
        edges.append(edge)

    for principal in inventory.get("principals", []):
        principal_id = _principal_id(principal["type"], principal["name"])
        add_node(principal_id, "principal", principal["name"], principal_type=principal["type"])

    for group in inventory.get("groups", []):
        group_id = f"group:{group['name']}"
        add_node(group_id, "group", group["name"])

    for role in inventory.get("roles", []):
        role_id = f"role:{role['name']}"
        add_node(role_id, "role", role["name"])

    for user in inventory.get("users", []):
        user_id = f"user:{user['name']}"
        add_node(user_id, "user", user["name"])

        for group_name in user.get("groups", []):
            group_id = f"group:{group_name}"
            add_node(group_id, "group", group_name)
            add_edge(user_id, group_id, "member-of", "member-of")

        for key in user.get("access_keys", []):
            key_id = f"access-key:{key.get('access_key_id', 'unknown')}"
            add_node(
                key_id,
                "access-key",
                key.get("access_key_id", "unknown"),
                status=key.get("status"),
                age_days=key.get("age_days"),
            )
            add_edge(user_id, key_id, "credential", key.get("status", "key"))

        if user.get("password_enabled"):
            profile_id = f"login-profile:{user['name']}"
            add_node(profile_id, "login-profile", user["name"])
            add_edge(user_id, profile_id, "console-login", "password")

    for role in inventory.get("roles", []):
        role_id = f"role:{role['name']}"
        trust_policy = role.get("trust_policy", {})
        for statement in _statements(trust_policy):
            principals = _principals_from_statement(statement)
            if str(statement.get("Effect", "")).lower() != "allow":
                continue
            for principal in principals:
                trusted_id = _trust_node_id(principal)
                add_node(trusted_id, "trusted-principal", principal)
                add_edge(trusted_id, role_id, "trusts", "sts:AssumeRole")

    for policy in inventory.get("managed_policies", []):
        policy_id = _managed_policy_id(policy)
        add_node(policy_id, "policy", policy.get("PolicyName") or policy.get("Arn") or policy_id, arn=policy.get("Arn"))

    for grant in inventory.get("grants", []):
        principal_id = _principal_id(grant["principal_type"], grant["principal_name"])
        grant_node_id = f"grant:{grant['source']}:{grant.get('statement_index', 'na')}"
        add_node(grant_node_id, "grant", grant["source"], inherited_via=grant.get("inherited_via"))
        add_edge(principal_id, grant_node_id, "grants", grant.get("inherited_via") or grant["source"])

        policy_node_id = _policy_node_id_from_source(grant["source"])
        add_node(policy_node_id, "policy-source", grant["source"])
        add_edge(grant_node_id, policy_node_id, "originates-from")

        for action in grant.get("actions", []):
            action_id = f"action:{action}"
            add_node(action_id, "action", action)
            add_edge(policy_node_id, action_id, "allows", action)

    for finding in inventory.get("access_analyzer_findings", []):
        resource_id = f"resource:{finding.get('resource', finding.get('id', 'unknown'))}"
        add_node(resource_id, "resource", finding.get("resource", finding.get("id", "unknown")))
        finding_id = f"aa:{finding.get('id', resource_id)}"
        add_node(finding_id, "access-analyzer-finding", finding.get("id", "finding"), finding_type=finding.get("findingType"))
        add_edge(finding_id, resource_id, "analyzes", finding.get("findingType", "finding"))

    return {"nodes": list(nodes.values()), "edges": edges}


def graph_statistics(graph: Dict[str, Any]) -> Dict[str, Any]:
    counts = defaultdict(int)
    for node in graph.get("nodes", []):
        counts[node.get("type", "unknown")] += 1
    return {
        "nodes": len(graph.get("nodes", [])),
        "edges": len(graph.get("edges", [])),
        "principal_nodes": counts.get("principal", 0),
        "user_nodes": counts.get("user", 0),
        "group_nodes": counts.get("group", 0),
        "role_nodes": counts.get("role", 0),
        "policy_nodes": counts.get("policy", 0),
        "action_nodes": counts.get("action", 0),
        "grant_nodes": counts.get("grant", 0),
        "trusted_principal_nodes": counts.get("trusted-principal", 0),
        "access_key_nodes": counts.get("access-key", 0),
    }


def _principal_id(principal_type: str, principal_name: str) -> str:
    return f"{principal_type}:{principal_name}"


def _trust_node_id(principal: str) -> str:
    return f"trusted:{principal}"


def _managed_policy_id(policy: Dict[str, Any]) -> str:
    return f"policy:managed:{policy.get('Arn') or policy.get('PolicyName')}"


def _policy_node_id_from_source(source: str) -> str:
    return f"policy-source:{source}"


def _statements(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    statements = document.get("Statement") if isinstance(document, dict) else []
    if statements is None:
        return []
    if isinstance(statements, list):
        return [statement for statement in statements if isinstance(statement, dict)]
    if isinstance(statements, dict):
        return [statements]
    return []


def _principals_from_statement(statement: Dict[str, Any]) -> List[str]:
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        principals: List[str] = []
        for value in principal.values():
            if isinstance(value, list):
                principals.extend(str(item) for item in value)
            elif value is not None:
                principals.append(str(value))
        return principals
    if principal is None:
        return []
    return [str(principal)]
