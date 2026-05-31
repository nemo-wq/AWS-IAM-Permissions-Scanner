from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .policy import grant_allows, principal_from_trust_statement, resource_is_broad, statements

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: str
    confidence: str
    required_permissions: List[str]
    optional_permissions: List[str]
    prerequisites: List[str]
    source: List[str]
    business_impact: str
    recommendation: str


def load_ruleset(name: str = "bundled") -> Dict[str, Any]:
    if name not in {"bundled", "pathfinding-snapshot"}:
        raise ValueError("ruleset must be 'bundled' or 'pathfinding-snapshot'")
    path = Path(__file__).with_name("data") / "ruleset.json"
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rules_from_ruleset(ruleset: Dict[str, Any]) -> List[Rule]:
    return [
        Rule(
            id=rule["id"],
            name=rule["name"],
            category=rule["category"],
            severity=rule["severity"],
            confidence=rule.get("confidence", "medium"),
            required_permissions=rule.get("required_permissions", []),
            optional_permissions=rule.get("optional_permissions", []),
            prerequisites=rule.get("prerequisites", []),
            source=rule.get("source", []),
            business_impact=rule.get("business_impact", ""),
            recommendation=rule.get("recommendation", ""),
        )
        for rule in ruleset.get("rules", [])
    ]


def evaluate_inventory(
    inventory: Dict[str, Any],
    ruleset: Dict[str, Any],
    severity_threshold: str = "low",
) -> List[Dict[str, Any]]:
    threshold = SEVERITY_ORDER[severity_threshold]
    rules = rules_from_ruleset(ruleset)
    grants = inventory.get("grants", [])
    findings: List[Dict[str, Any]] = []

    for principal in inventory.get("principals", []):
        principal_grants = [
            grant for grant in grants if grant.get("principal_name") == principal["name"]
            and grant.get("principal_type") == principal["type"]
        ]
        for rule in rules:
            if SEVERITY_ORDER[rule.severity] < threshold:
                continue
            matched = _match_required_permissions(rule.required_permissions, principal_grants)
            if not matched:
                continue
            findings.append(_permission_finding(rule, principal, matched, inventory))

    findings.extend(_credential_findings(inventory, threshold))
    findings.extend(_trust_findings(inventory, threshold))
    findings.extend(_access_analyzer_findings(inventory, threshold))
    findings.sort(
        key=lambda finding: (
            -SEVERITY_ORDER[finding["severity"]],
            finding["principal"],
            finding["id"],
        )
    )
    return findings


def _match_required_permissions(required: List[str], grants: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matched: List[Dict[str, Any]] = []
    for permission in required:
        grant = next((candidate for candidate in grants if grant_allows(candidate, permission)), None)
        if not grant:
            return []
        matched.append({"permission": permission, "grant": _grant_evidence(grant)})
    return matched


def _permission_finding(
    rule: Rule,
    principal: Dict[str, Any],
    matched: List[Dict[str, Any]],
    inventory: Dict[str, Any],
) -> Dict[str, Any]:
    status = "confirmed"
    if any("passable role" in p.lower() for p in rule.prerequisites):
        status = _passrole_status(principal, inventory)
    return {
        "id": rule.id,
        "title": rule.name,
        "category": rule.category,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "status": status,
        "principal": principal["name"],
        "principal_type": principal["type"],
        "source": rule.source,
        "business_impact": rule.business_impact,
        "recommended_action": rule.recommendation,
        "attack_path": _attack_path(principal, matched),
        "evidence": matched,
        "prerequisites": rule.prerequisites,
    }


def _passrole_status(principal: Dict[str, Any], inventory: Dict[str, Any]) -> str:
    passable_roles = []
    for grant in inventory.get("grants", []):
        if grant.get("principal_name") != principal["name"] or grant.get("principal_type") != principal["type"]:
            continue
        if grant_allows(grant, "iam:PassRole"):
            passable_roles.extend(grant.get("resources", []))
    if not passable_roles:
        return "potential"
    if "*" in passable_roles or any(resource_is_broad([resource]) for resource in passable_roles):
        return "likely"
    role_arns = {role.get("arn") for role in inventory.get("roles", [])}
    return "likely" if any(role in role_arns for role in passable_roles) else "potential"


def _grant_evidence(grant: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": grant.get("source"),
        "inherited_via": grant.get("inherited_via"),
        "actions": grant.get("actions", []),
        "not_actions": grant.get("not_actions", []),
        "resources": grant.get("resources", []),
        "conditions": grant.get("conditions", {}),
        "statement_index": grant.get("statement_index"),
    }


def _attack_path(principal: Dict[str, Any], matched: List[Dict[str, Any]]) -> str:
    parts = [f"{principal['type']}:{principal['name']}"]
    for item in matched:
        source = item["grant"]["source"]
        inherited = item["grant"].get("inherited_via")
        if inherited:
            parts.append(f"{inherited} -> {source} -> {item['permission']}")
        else:
            parts.append(f"{source} -> {item['permission']}")
    return " -> ".join(parts)


def _credential_findings(inventory: Dict[str, Any], threshold: int) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for user in inventory.get("users", []):
        for key in user.get("access_keys", []):
            age = key.get("age_days")
            if key.get("status") == "Active" and age is not None and age >= 90:
                findings.append(
                    {
                        "id": "credential.active-access-key-over-90-days",
                        "title": "Long-lived active IAM access key",
                        "category": "credential-and-legacy-iam-risk",
                        "severity": "medium",
                        "confidence": "high",
                        "status": "confirmed",
                        "principal": user["name"],
                        "principal_type": "user",
                        "source": ["AWS IAM best practices", "Datadog State of Cloud Security 2025"],
                        "business_impact": "Long-lived access keys increase the blast radius of developer workstation, CI, or repository compromise.",
                        "recommended_action": "Rotate or remove the key, prefer temporary credentials, and move human users to federation/IAM Identity Center where possible.",
                        "attack_path": f"user:{user['name']} -> active access key age {age} days",
                        "evidence": [{"access_key_id": key.get("access_key_id"), "age_days": age, "last_used": key.get("last_used")}],
                        "prerequisites": [],
                    }
                )
        if user.get("password_enabled") and not user.get("mfa_enabled"):
            findings.append(
                {
                    "id": "credential.console-password-without-mfa",
                    "title": "IAM console user without MFA",
                    "category": "credential-and-legacy-iam-risk",
                    "severity": "high",
                    "confidence": "high",
                    "status": "confirmed",
                    "principal": user["name"],
                    "principal_type": "user",
                    "source": ["AWS IAM best practices"],
                    "business_impact": "A phished or reused password can provide direct console access without a second factor.",
                    "recommended_action": "Require MFA immediately and migrate human access to federated SSO where practical.",
                    "attack_path": f"user:{user['name']} -> console password -> no MFA",
                    "evidence": [{"password_enabled": True, "mfa_enabled": False}],
                    "prerequisites": [],
                }
            )
    return [finding for finding in findings if SEVERITY_ORDER[finding["severity"]] >= threshold]


def _trust_findings(inventory: Dict[str, Any], threshold: int) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if threshold > SEVERITY_ORDER["high"]:
        return findings
    account_id = inventory.get("account", {}).get("account_id")
    for role in inventory.get("roles", []):
        for statement in statements(role.get("trust_policy", {})):
            if str(statement.get("Effect", "")).lower() != "allow":
                continue
            principals = principal_from_trust_statement(statement)
            condition = statement.get("Condition", {})
            external = _is_external_principal(principals, account_id)
            if ("*" in principals or external) and not _has_external_id_condition(condition):
                findings.append(
                    {
                        "id": "trust.external-assume-role-without-external-id",
                        "title": "External or broad role trust without ExternalId",
                        "category": "cross-account-and-third-party-trust",
                        "severity": "high",
                        "confidence": "medium",
                        "status": "likely",
                        "principal": role["name"],
                        "principal_type": "role",
                        "source": ["WithSecure IAMGraph research", "AWS IAM confused deputy guidance", "Datadog cloud security research"],
                        "business_impact": "A third-party or broad trust relationship can become a lateral movement or supply-chain entry point if not tightly scoped.",
                        "recommended_action": "Scope trusted principals tightly, require sts:ExternalId for third parties, and review whether this role still needs cross-account trust.",
                        "attack_path": f"external principal -> sts:AssumeRole -> role:{role['name']}",
                        "evidence": [{"trusted_principals": principals, "condition": condition}],
                        "prerequisites": ["Trusted principal has or obtains sts:AssumeRole permission."],
                    }
                )
    return findings


def _is_external_principal(principals: Iterable[str], account_id: str | None) -> bool:
    if not account_id:
        return any(":root" in principal or ":role/" in principal or ":user/" in principal for principal in principals)
    return any(
        principal.startswith("arn:aws:iam::") and f"::{account_id}:" not in principal
        for principal in principals
    )


def _has_external_id_condition(condition: Dict[str, Any]) -> bool:
    text = json.dumps(condition).lower()
    return "sts:externalid" in text


def _access_analyzer_findings(inventory: Dict[str, Any], threshold: int) -> List[Dict[str, Any]]:
    if threshold > SEVERITY_ORDER["medium"]:
        return []
    findings = []
    for item in inventory.get("access_analyzer_findings", []):
        findings.append(
            {
                "id": "aws.access-analyzer-" + str(item.get("id", "finding")).lower(),
                "title": "AWS IAM Access Analyzer finding",
                "category": "aws-native-enrichment",
                "severity": "medium",
                "confidence": "high",
                "status": "confirmed",
                "principal": item.get("resource", "unknown"),
                "principal_type": "resource",
                "source": ["AWS IAM Access Analyzer"],
                "business_impact": item.get("findingType", "AWS identified access analyzer exposure."),
                "recommended_action": "Review the native Access Analyzer finding and remediate according to resource ownership and business need.",
                "attack_path": str(item.get("resource", "unknown")),
                "evidence": [item],
                "prerequisites": [],
            }
        )
    return findings
