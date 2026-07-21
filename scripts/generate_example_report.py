from __future__ import annotations

import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from iam_exposure.graph import build_attack_graph, graph_statistics
from iam_exposure.policy import extract_policy_grants
from iam_exposure.report import write_outputs
from iam_exposure.rules import evaluate_inventory, load_ruleset

ROOT = Path(__file__).parents[1]


def policy(actions, source, principal, inherited_via=None):
    document = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": actions, "Resource": "*"}}
    return extract_policy_grants(document, source, "user", principal, inherited_via)


def synthetic_inventory():
    grants = []
    grants.extend(policy("iam:AttachUserPolicy", "group-inline:Platform/Escalate", "alice", "group:Platform"))
    grants.extend(policy(["iam:PassRole", "lambda:CreateFunction"], "user-inline:bob/Deploy", "bob"))
    inventory = {
        "schema_version": "2.0",
        "account": {
            "account_id": "111111111111",
            "alias": "Example Production",
            "caller_arn": "arn:aws:sts::111111111111:assumed-role/IAMExposureReviewReadOnly/example",
        },
        "users": [
            {"name": "alice", "groups": ["Platform"], "access_keys": [], "password_enabled": False, "mfa_enabled": True},
            {
                "name": "bob",
                "groups": [],
                "access_keys": [{"access_key_id": "AKIAEXAMPLEONLY", "status": "Active", "age_days": 184, "last_used": {}}],
                "password_enabled": False,
                "mfa_enabled": True,
            },
        ],
        "groups": [{"name": "Platform"}],
        "roles": [
            {
                "name": "PrivilegedLambda",
                "arn": "arn:aws:iam::111111111111:role/PrivilegedLambda",
                "trust_policy": {
                    "Statement": {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                },
            },
            {
                "name": "VendorSupport",
                "arn": "arn:aws:iam::111111111111:role/VendorSupport",
                "trust_policy": {
                    "Statement": {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::222222222222:root"}, "Action": "sts:AssumeRole"}
                },
            },
        ],
        "principals": [
            {"type": "user", "name": "alice"},
            {"type": "user", "name": "bob"},
            {"type": "role", "name": "PrivilegedLambda"},
            {"type": "role", "name": "VendorSupport"},
        ],
        "managed_policies": [],
        "grants": grants,
        "access_analyzer_findings": [],
        "collection": {
            "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "warnings": ["Access Analyzer enrichment was not enabled in this synthetic example."],
            "coverage": {
                "complete": True,
                "collected": ["iam-authorization", "credential-metadata", "trust-policies"],
                "missing": [],
                "warnings": [],
            },
        },
    }
    return inventory


def main():
    inventory = synthetic_inventory()
    ruleset = load_ruleset()
    findings = evaluate_inventory(inventory, ruleset)
    graph = build_attack_graph(inventory, findings)
    inventory["attack_graph"] = graph
    inventory["graph_statistics"] = graph_statistics(graph)
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp)
        write_outputs(output, inventory, findings, ruleset, ["html"])
        shutil.copyfile(output / "report.html", ROOT / "docs" / "example-report.html")
    print(f"Updated {ROOT / 'docs' / 'example-report.html'}")


if __name__ == "__main__":
    main()
