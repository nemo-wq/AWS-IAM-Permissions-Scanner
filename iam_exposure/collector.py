from __future__ import annotations

import base64
import csv
import io
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from .graph import build_attack_graph, graph_statistics
from .models import SCHEMA_VERSION
from .policy import extract_policy_grants


def collect_inventory(
    profile: str | None = None,
    role_arn: str | None = None,
    region: str | None = None,
    account_alias: str | None = None,
    include_aws_managed_policies: bool = False,
) -> dict[str, Any]:
    session = _session(profile, role_arn, region)
    iam = session.client("iam")
    sts = session.client("sts")
    warnings: list[str] = []
    account = _account_metadata(sts, iam, account_alias, warnings)
    details = _authorization_details(iam, include_aws_managed_policies, warnings)
    inventory = _normalize(details, account, warnings)
    _enrich_users(iam, inventory, warnings)
    _enrich_organizations(session, inventory, warnings)
    _enrich_access_analyzer(session, region or session.region_name or "us-east-1", inventory, warnings)
    _enrich_instance_profiles(iam, inventory, warnings)
    attack_graph = build_attack_graph(inventory)
    critical_warnings = [
        warning for warning in warnings if "full IAM authorization details" in warning or "group details were not collected" in warning
    ]
    inventory["collection"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "role_arn": role_arn,
        "region": region or session.region_name,
        "include_aws_managed_policies": include_aws_managed_policies,
        "warnings": warnings,
        "coverage": {
            "complete": not critical_warnings,
            "collected": ["iam-authorization", "credential-metadata", "trust-policies"],
            "missing": ["iam-authorization"] if critical_warnings else [],
            "warnings": warnings,
        },
    }
    inventory["attack_graph"] = attack_graph
    inventory["graph_statistics"] = graph_statistics(attack_graph)
    return inventory


def _session(profile: str | None, role_arn: str | None, region: str | None) -> boto3.Session:
    try:
        base = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
    except ProfileNotFound as error:
        raise SystemExit(f"AWS profile not found: {profile}") from error
    if not role_arn:
        return base
    sts = base.client("sts")
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="iam-exposure-review")
    creds = assumed["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region or base.region_name,
    )


def _account_metadata(sts: Any, iam: Any, account_alias: str | None, warnings: list[str]) -> dict[str, Any]:
    try:
        identity = sts.get_caller_identity()
    except NoCredentialsError as error:
        raise SystemExit("No AWS credentials found. Configure an AWS profile, SSO session, or environment credentials.") from error
    aliases = _safe_call(lambda: iam.list_account_aliases().get("AccountAliases", []), warnings, "iam:ListAccountAliases") or []
    return {
        "account_id": identity.get("Account"),
        "caller_arn": identity.get("Arn"),
        "alias": account_alias or (aliases[0] if aliases else None),
    }


def _authorization_details(iam: Any, include_aws_managed_policies: bool, warnings: list[str]) -> dict[str, list[dict[str, Any]]]:
    details: dict[str, list[dict[str, Any]]] = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    filters = ["User", "Group", "Role", "LocalManagedPolicy"]
    if include_aws_managed_policies:
        filters.append("AWSManagedPolicy")
    try:
        paginator = iam.get_paginator("get_account_authorization_details")
        for page in paginator.paginate(Filter=filters):
            for key in details:
                details[key].extend(page.get(key, []))
    except ClientError as error:
        warnings.append(f"Unable to collect full IAM authorization details: {_error_message(error)}")
    return details


def _normalize(details: dict[str, list[dict[str, Any]]], account: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    users: list[dict[str, Any]] = []
    groups: dict[str, dict[str, Any]] = {}
    roles: list[dict[str, Any]] = []
    principals: list[dict[str, Any]] = []
    grants: list[dict[str, Any]] = []
    credential_state_default = False
    managed_policies: dict[str, dict[str, Any]] = {
        policy["Arn"]: policy for policy in details.get("Policies", []) if isinstance(policy.get("Arn"), str)
    }

    for group in details.get("GroupDetailList", []):
        name = group["GroupName"]
        normalized = {
            "name": name,
            "arn": group.get("Arn"),
            "inline_policies": group.get("GroupPolicyList", []),
            "attached_policies": group.get("AttachedManagedPolicies", []),
        }
        groups[name] = normalized
        for policy in normalized["inline_policies"]:
            grants.extend(
                extract_policy_grants(policy.get("PolicyDocument", {}), f"group-inline:{name}/{policy.get('PolicyName')}", "group", name)
            )
        grants.extend(_managed_policy_grants(normalized["attached_policies"], managed_policies, "group", name, None))

    for user in details.get("UserDetailList", []):
        name = user["UserName"]
        normalized = {
            "name": name,
            "arn": user.get("Arn"),
            "user_id": user.get("UserId"),
            "created": _json_date(user.get("CreateDate")),
            "groups": user.get("GroupList", []),
            "inline_policies": user.get("UserPolicyList", []),
            "attached_policies": user.get("AttachedManagedPolicies", []),
            "permissions_boundary": user.get("PermissionsBoundary"),
            "access_keys": [],
            "mfa_enabled": False,
            "password_enabled": credential_state_default,
        }
        users.append(normalized)
        principals.append({"type": "user", "name": name, "arn": user.get("Arn")})
        for policy in normalized["inline_policies"]:
            grants.extend(
                extract_policy_grants(policy.get("PolicyDocument", {}), f"user-inline:{name}/{policy.get('PolicyName')}", "user", name)
            )
        grants.extend(_managed_policy_grants(normalized["attached_policies"], managed_policies, "user", name, None))
        grants.extend(_permissions_boundary_grants(normalized["permissions_boundary"], managed_policies, "user", name))
        for group_name in normalized["groups"]:
            inherited_group = groups.get(group_name)
            if not inherited_group:
                warnings.append(f"User {name} references group {group_name}, but group details were not collected.")
                continue
            for policy in inherited_group["inline_policies"]:
                grants.extend(
                    extract_policy_grants(
                        policy.get("PolicyDocument", {}),
                        f"group-inline:{group_name}/{policy.get('PolicyName')}",
                        "user",
                        name,
                        inherited_via=f"group:{group_name}",
                    )
                )
            grants.extend(
                _managed_policy_grants(inherited_group["attached_policies"], managed_policies, "user", name, f"group:{group_name}")
            )

    for role in details.get("RoleDetailList", []):
        name = role["RoleName"]
        normalized = {
            "name": name,
            "arn": role.get("Arn"),
            "role_id": role.get("RoleId"),
            "created": _json_date(role.get("CreateDate")),
            "trust_policy": role.get("AssumeRolePolicyDocument", {}),
            "inline_policies": role.get("RolePolicyList", []),
            "attached_policies": role.get("AttachedManagedPolicies", []),
            "permissions_boundary": role.get("PermissionsBoundary"),
            "instance_profiles": [profile.get("Arn") for profile in role.get("InstanceProfileList", [])],
        }
        roles.append(normalized)
        principals.append({"type": "role", "name": name, "arn": role.get("Arn")})
        for policy in normalized["inline_policies"]:
            grants.extend(
                extract_policy_grants(policy.get("PolicyDocument", {}), f"role-inline:{name}/{policy.get('PolicyName')}", "role", name)
            )
        grants.extend(_managed_policy_grants(normalized["attached_policies"], managed_policies, "role", name, None))
        grants.extend(_permissions_boundary_grants(normalized["permissions_boundary"], managed_policies, "role", name))

    return {
        "schema_version": SCHEMA_VERSION,
        "account": account,
        "users": users,
        "groups": list(groups.values()),
        "roles": roles,
        "principals": principals,
        "managed_policies": list(managed_policies.values()),
        "grants": grants,
        "organizations": {},
        "service_control_policies": [],
        "resource_policies": [],
        "session_policies": [],
        "access_analyzer_findings": [],
        "instance_profiles": [],
        "comparison": {},
        "warnings": warnings,
    }


def _managed_policy_grants(
    attached: Iterable[dict[str, Any]],
    managed_policies: dict[str, dict[str, Any]],
    principal_type: str,
    principal_name: str,
    inherited_via: str | None,
) -> list[dict[str, Any]]:
    grants: list[dict[str, Any]] = []
    for attached_policy in attached:
        policy_arn = attached_policy.get("PolicyArn")
        policy = managed_policies.get(policy_arn) if isinstance(policy_arn, str) else None
        source = f"managed:{attached_policy.get('PolicyName')}:{policy_arn}"
        if not policy:
            grants.append(
                {
                    "principal_type": principal_type,
                    "principal_name": principal_name,
                    "source": source,
                    "inherited_via": inherited_via,
                    "policy_scope": "identity",
                    "effect": "allow",
                    "statement_index": None,
                    "actions": ["*"] if attached_policy.get("PolicyName") == "AdministratorAccess" else [],
                    "not_actions": [],
                    "resources": ["*"],
                    "not_resources": [],
                    "conditions": {},
                    "raw_statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    if attached_policy.get("PolicyName") == "AdministratorAccess"
                    else {},
                }
            )
            continue
        document = _default_policy_document(policy)
        grants.extend(extract_policy_grants(document, source, principal_type, principal_name, inherited_via))
    return grants


def _permissions_boundary_grants(
    boundary: dict[str, Any] | None,
    managed_policies: dict[str, dict[str, Any]],
    principal_type: str,
    principal_name: str,
) -> list[dict[str, Any]]:
    if not boundary:
        return []
    arn = boundary.get("PermissionsBoundaryArn") or boundary.get("PolicyArn")
    policy = managed_policies.get(arn) if isinstance(arn, str) else None
    if not policy:
        return []
    return extract_policy_grants(
        _default_policy_document(policy),
        f"permissions-boundary:{arn}",
        principal_type,
        principal_name,
        policy_scope="permissions-boundary",
    )


def _default_policy_document(policy: dict[str, Any]) -> dict[str, Any]:
    default = policy.get("DefaultVersionId")
    versions = policy.get("PolicyVersionList", [])
    for version in versions:
        if version.get("VersionId") == default or version.get("IsDefaultVersion"):
            return version.get("Document", {})
    return versions[0].get("Document", {}) if versions else {}


def _enrich_users(iam: Any, inventory: dict[str, Any], warnings: list[str]) -> None:
    credential_rows = _credential_report(iam, warnings)
    by_name = {row.get("user"): row for row in credential_rows}
    now = datetime.now(timezone.utc)
    for user in inventory["users"]:
        name = user["name"]
        user["mfa_enabled"] = bool(
            _safe_call(
                lambda name=name: iam.list_mfa_devices(UserName=name).get("MFADevices", []),
                warnings,
                f"iam:ListMFADevices:{name}",
            )
            or []
        )
        user["password_enabled"] = bool(
            _safe_call(
                lambda name=name: iam.get_login_profile(UserName=name),
                [],
                f"iam:GetLoginProfile:{name}",
            )
            or False
        )
        keys = (
            _safe_call(
                lambda name=name: iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []),
                warnings,
                f"iam:ListAccessKeys:{name}",
            )
            or []
        )
        normalized_keys = []
        for key in keys:
            create_date = key.get("CreateDate")
            age_days = (now - create_date).days if create_date else None
            last_used = (
                _safe_call(
                    lambda key_id=key["AccessKeyId"]: iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {}),
                    warnings,
                    f"iam:GetAccessKeyLastUsed:{name}",
                )
                or {}
            )
            normalized_keys.append(
                {
                    "access_key_id": key.get("AccessKeyId"),
                    "status": key.get("Status"),
                    "created": _json_date(create_date),
                    "age_days": age_days,
                    "last_used": _jsonable(last_used),
                }
            )
        user["access_keys"] = normalized_keys
        row = by_name.get(name, {})
        if row:
            user["credential_report"] = row
            user["password_enabled"] = user["password_enabled"] or row.get("password_enabled") == "true"
            user["mfa_enabled"] = user["mfa_enabled"] or row.get("mfa_active") == "true"


def _credential_report(iam: Any, warnings: list[str]) -> list[dict[str, str]]:
    try:
        iam.generate_credential_report()
        response = iam.get_credential_report()
        content = response["Content"]
        if isinstance(content, bytes):
            decoded = content.decode("utf-8")
        else:
            decoded = base64.b64decode(content).decode("utf-8")
        return list(csv.DictReader(io.StringIO(decoded)))
    except ClientError as error:
        warnings.append(f"Unable to collect IAM credential report: {_error_message(error)}")
    return []


def _enrich_organizations(session: boto3.Session, inventory: dict[str, Any], warnings: list[str]) -> None:
    try:
        org = session.client("organizations")
        inventory["organizations"] = _jsonable(org.describe_organization().get("Organization", {}))
        policies = _collect_service_control_policies(org, inventory.get("account", {}).get("account_id"))
        inventory["service_control_policies"] = policies
        for policy in policies:
            inventory["grants"].extend(
                extract_policy_grants(
                    policy.get("document", {}),
                    f"scp:{policy.get('id')}:{policy.get('name')}",
                    "global",
                    "*",
                    policy_scope="scp",
                )
            )
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code in {"AWSOrganizationsNotInUseException", "OrganizationsNotInUseException"}:
            return
        warnings.append(f"Unable to collect Organizations metadata or SCPs: {_error_message(error)}")
    except Exception as error:
        warnings.append(f"Unable to collect Organizations metadata: {error}")


def _collect_service_control_policies(org: Any, account_id: str | None) -> list[dict[str, Any]]:
    if not account_id:
        return []
    targets = [account_id]
    child_id = account_id
    while True:
        response = org.list_parents(ChildId=child_id)
        parents = response.get("Parents", [])
        if not parents:
            break
        parent_id = parents[0].get("Id")
        if not parent_id or parent_id in targets:
            break
        targets.append(parent_id)
        child_id = parent_id

    policies: dict[str, dict[str, Any]] = {}
    for target in targets:
        token = None
        while True:
            kwargs = {"TargetId": target, "Filter": "SERVICE_CONTROL_POLICY"}
            if token:
                kwargs["NextToken"] = token
            response = org.list_policies_for_target(**kwargs)
            for summary in response.get("Policies", []):
                policy_id = summary.get("Id")
                if not policy_id or policy_id in policies:
                    continue
                described = org.describe_policy(PolicyId=policy_id).get("Policy", {})
                content = described.get("Content") or "{}"
                policies[policy_id] = {
                    "id": policy_id,
                    "name": described.get("PolicySummary", {}).get("Name") or summary.get("Name"),
                    "target_ids": [target],
                    "document": json.loads(content) if isinstance(content, str) else content,
                }
            token = response.get("NextToken")
            if not token:
                break
    return list(policies.values())


def _enrich_access_analyzer(session: boto3.Session, region: str, inventory: dict[str, Any], warnings: list[str]) -> None:
    try:
        analyzer = session.client("accessanalyzer", region_name=region)
        analyzers = analyzer.list_analyzers(type="ACCOUNT").get("analyzers", [])
        findings = []
        for item in analyzers:
            arn = item.get("arn")
            paginator = analyzer.get_paginator("list_findings")
            for page in paginator.paginate(analyzerArn=arn, filter={"status": {"eq": ["ACTIVE"]}}):
                findings.extend(page.get("findings", []))
        inventory["access_analyzer_findings"] = _jsonable(findings)
    except Exception as error:
        warnings.append(f"Unable to collect IAM Access Analyzer findings: {error}")


def _enrich_instance_profiles(iam: Any, inventory: dict[str, Any], warnings: list[str]) -> None:
    profiles = []
    try:
        paginator = iam.get_paginator("list_instance_profiles")
        for page in paginator.paginate():
            profiles.extend(page.get("InstanceProfiles", []))
    except ClientError as error:
        warnings.append(f"Unable to collect instance profiles: {_error_message(error)}")
    inventory["instance_profiles"] = _jsonable(profiles)


def _safe_call(fn: Any, warnings: list[str], label: str) -> Any:
    try:
        return fn()
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code not in {"NoSuchEntity", "NoSuchEntityException"}:
            warnings.append(f"Unable to call {label}: {_error_message(error)}")
    except Exception as error:
        warnings.append(f"Unable to call {label}: {error}")
    return None


def _error_message(error: ClientError) -> str:
    err = error.response.get("Error", {})
    return f"{err.get('Code', 'ClientError')}: {err.get('Message', str(error))}"


def _json_date(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else value


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value
