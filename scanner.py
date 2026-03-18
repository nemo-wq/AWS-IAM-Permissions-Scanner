from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3


@dataclass
class IAMScanner:
    profile: str | None = None
    region: str | None = None

    def __post_init__(self) -> None:
        session = boto3.Session(profile_name=self.profile, region_name=self.region)
        self.client = session.client("iam")

    def _paginate(self, operation_name: str, result_key: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Generic paginator helper that always returns full result sets."""
        paginator = self.client.get_paginator(operation_name)
        items: list[dict[str, Any]] = []
        for page in paginator.paginate(**kwargs):
            items.extend(page.get(result_key, []))
        return items

    def _normalize_statements(self, statements: Any) -> list[dict[str, Any]]:
        if isinstance(statements, dict):
            return [statements]
        if isinstance(statements, list):
            return [s for s in statements if isinstance(s, dict)]
        return []

    def _extract_actions(self, statement: dict[str, Any]) -> list[str]:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            return [actions]
        if isinstance(actions, list):
            return [str(a) for a in actions]
        return []

    def _statement_view(self, statement: dict[str, Any]) -> dict[str, Any]:
        return {
            "sid": statement.get("Sid"),
            "effect": statement.get("Effect"),
            "actions": self._extract_actions(statement),
            "resource": statement.get("Resource"),
            "condition": statement.get("Condition"),
        }

    def scan(self) -> dict[str, Any]:
        users = self._paginate("get_account_authorization_details", "UserDetailList", Filter=["User"])
        groups = self._paginate("get_account_authorization_details", "GroupDetailList", Filter=["Group"])

        groups_by_name = {g["GroupName"]: g for g in groups}
        report_users: list[dict[str, Any]] = []

        for user in users:
            username = user["UserName"]
            inline_policy_names = self._paginate("list_user_policies", "PolicyNames", UserName=username)

            inline_policies: list[dict[str, Any]] = []
            for policy_name in inline_policy_names:
                policy = self.client.get_user_policy(UserName=username, PolicyName=policy_name)
                statements = self._normalize_statements(policy["PolicyDocument"].get("Statement"))
                inline_policies.append(
                    {
                        "name": policy_name,
                        "statements": [self._statement_view(s) for s in statements],
                    }
                )

            managed_policies: list[dict[str, Any]] = []
            for policy in user.get("AttachedManagedPolicies", []):
                arn = policy["PolicyArn"]
                detail = self.client.get_policy(PolicyArn=arn)
                version = detail["Policy"]["DefaultVersionId"]
                version_doc = self.client.get_policy_version(PolicyArn=arn, VersionId=version)
                statements = self._normalize_statements(version_doc["PolicyVersion"]["Document"].get("Statement"))
                managed_policies.append(
                    {
                        "name": policy["PolicyName"],
                        "arn": arn,
                        "statements": [self._statement_view(s) for s in statements],
                    }
                )

            group_membership: list[dict[str, Any]] = []
            for group_name in user.get("GroupList", []):
                group = groups_by_name.get(group_name)
                if not group:
                    continue

                group_inline: list[dict[str, Any]] = []
                for inline in group.get("GroupPolicyList", []):
                    statements = self._normalize_statements(inline["PolicyDocument"].get("Statement"))
                    group_inline.append(
                        {
                            "name": inline.get("PolicyName"),
                            "statements": [self._statement_view(s) for s in statements],
                        }
                    )

                group_managed: list[dict[str, Any]] = []
                for managed in group.get("AttachedManagedPolicies", []):
                    arn = managed["PolicyArn"]
                    detail = self.client.get_policy(PolicyArn=arn)
                    version = detail["Policy"]["DefaultVersionId"]
                    version_doc = self.client.get_policy_version(PolicyArn=arn, VersionId=version)
                    statements = self._normalize_statements(version_doc["PolicyVersion"]["Document"].get("Statement"))
                    group_managed.append(
                        {
                            "name": managed.get("PolicyName"),
                            "arn": arn,
                            "statements": [self._statement_view(s) for s in statements],
                        }
                    )

                group_membership.append(
                    {
                        "name": group_name,
                        "inline_policies": group_inline,
                        "managed_policies": group_managed,
                    }
                )

            report_users.append(
                {
                    "user_name": username,
                    "inline_policies": inline_policies,
                    "managed_policies": managed_policies,
                    "groups": group_membership,
                }
            )

        return {"user_count": len(report_users), "users": report_users}
