from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from . import __version__
from .report import write_outputs
from .rules import SEVERITY_ORDER, evaluate_inventory, load_ruleset


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="iam-exposure", description="AWS IAM Exposure Review")
    parser.add_argument("--version", action="version", version=f"iam-exposure {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Collect AWS IAM inventory, evaluate exposure rules, and write a report")
    scan.add_argument("--profile", help="AWS profile name to use")
    scan.add_argument("--role-arn", help="Optional role ARN to assume before scanning")
    scan.add_argument("--region", help="AWS region for regional enrichment APIs")
    scan.add_argument("--output", required=True, help="Output directory for report artifacts")
    scan.add_argument("--format", default="html,json", help="Comma-separated output formats: html,json,csv,sarif")
    scan.add_argument("--severity-threshold", choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get), default="low")
    scan.add_argument("--account-alias", help="Friendly account name to display in reports")
    scan.add_argument("--ruleset", choices=["bundled", "pathfinding-snapshot"], default="bundled")
    scan.add_argument("--include-aws-managed-policies", action="store_true")
    scan.add_argument("--no-color", action="store_true", help="Accepted for script compatibility; output is plain text")
    scan.set_defaults(func=_scan)
    args = parser.parse_args(argv)
    args.func(args)


def _scan(args: argparse.Namespace) -> None:
    from .collector import collect_inventory

    formats = [item.strip().lower() for item in args.format.split(",") if item.strip()]
    invalid = sorted(set(formats) - {"html", "json", "csv", "sarif"})
    if invalid:
        raise SystemExit(f"Unsupported output format(s): {', '.join(invalid)}")
    ruleset = load_ruleset(args.ruleset)
    inventory = collect_inventory(
        profile=args.profile,
        role_arn=args.role_arn,
        region=args.region,
        account_alias=args.account_alias,
        include_aws_managed_policies=args.include_aws_managed_policies,
    )
    findings = evaluate_inventory(inventory, ruleset, args.severity_threshold)
    write_outputs(Path(args.output), inventory, findings, ruleset, formats)
    counts = _counts(findings)
    print(
        f"Wrote AWS IAM Exposure Review to {args.output} "
        f"({len(findings)} findings: {json.dumps(counts, sort_keys=True)})"
    )


def _counts(findings: list[dict]) -> dict:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {key: value for key, value in counts.items() if value}
