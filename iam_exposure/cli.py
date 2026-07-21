from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import __version__
from .graph import build_attack_graph, graph_statistics
from .lifecycle import diff_findings
from .report import write_outputs
from .rules import SEVERITY_ORDER, evaluate_inventory, load_ruleset
from .updates import install_rule_bundle, load_and_verify_rule_bundle


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="iam-exposure", description="AWS IAM Exposure Review")
    parser.add_argument("--version", action="version", version=f"iam-exposure {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Collect AWS IAM inventory, evaluate exposure rules, and write a report")
    scan.add_argument("--profile", help="AWS profile name to use")
    scan.add_argument("--role-arn", help="Optional role ARN to assume before scanning")
    scan.add_argument("--region", help="AWS region for regional enrichment APIs")
    scan.add_argument("--output", required=True, help="Output directory for report artifacts")
    scan.add_argument("--format", default="html,json", help="Comma-separated output formats: html,json,csv,sarif")
    scan.add_argument("--severity-threshold", choices=sorted(SEVERITY_ORDER, key=lambda item: SEVERITY_ORDER[item]), default="low")
    scan.add_argument("--account-alias", help="Friendly account name to display in reports")
    scan.add_argument("--ruleset", default="bundled", help="bundled, pathfinding-snapshot, or a verified local JSON bundle")
    scan.add_argument("--include-aws-managed-policies", action="store_true")
    scan.add_argument("--no-color", action="store_true", help="Accepted for script compatibility; output is plain text")
    scan.set_defaults(func=_scan)

    diff = subparsers.add_parser("diff", help="Compare findings from two report folders, finding files, or snapshots")
    diff.add_argument("before", help="Previous report directory or JSON file")
    diff.add_argument("after", help="Current report directory or JSON file")
    diff.add_argument("--output", help="Optional file for the change set; stdout is used when omitted")
    diff.add_argument(
        "--allow-resolve-with-warnings", action="store_true", help="Allow resolutions even when collection coverage is incomplete"
    )
    diff.set_defaults(func=_diff)

    rules = subparsers.add_parser("rules", help="Inspect and verify versioned rule bundles")
    rule_commands = rules.add_subparsers(dest="rules_command", required=True)
    rules_list = rule_commands.add_parser("list", help="List rules and source attribution")
    rules_list.add_argument("--ruleset", default="bundled")
    rules_list.set_defaults(func=_rules_list)
    rules_verify = rule_commands.add_parser("verify", help="Validate a rule bundle and optionally verify its SHA-256 digest")
    rules_verify.add_argument("source", nargs="?", default="bundled")
    rules_verify.add_argument("--sha256")
    rules_verify.set_defaults(func=_rules_verify)
    rules_update = rule_commands.add_parser("update", help="Install an explicitly selected HTTPS or local rule bundle")
    rules_update.add_argument("--source", required=True)
    rules_update.add_argument("--sha256", required=True, help="Expected SHA-256 digest published with the bundle")
    rules_update.add_argument("--output", default=str(Path.home() / ".config" / "iam-exposure" / "ruleset.json"))
    rules_update.set_defaults(func=_rules_update)

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
    graph = build_attack_graph(inventory, findings)
    inventory["attack_graph"] = graph
    inventory["graph_statistics"] = graph_statistics(graph)
    write_outputs(Path(args.output), inventory, findings, ruleset, formats)
    counts = _counts(findings)
    print(f"Wrote AWS IAM Exposure Review to {args.output} ({len(findings)} findings: {json.dumps(counts, sort_keys=True)})")


def _diff(args: argparse.Namespace) -> None:
    before = _read_report_input(Path(args.before))
    after = _read_report_input(Path(args.after))
    warnings = after.get("inventory", {}).get("collection", {}).get("warnings", [])
    coverage = after.get("inventory", {}).get("collection", {}).get("coverage", {})
    complete = args.allow_resolve_with_warnings or bool(coverage.get("complete", not warnings))
    result = diff_findings(
        before.get("findings", []),
        after.get("findings", []),
        account_id=after.get("inventory", {}).get("account", {}).get("account_id"),
        collection_complete=complete,
        previous_ruleset_id=before.get("ruleset_id"),
        current_ruleset_id=after.get("ruleset_id"),
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote finding changes to {args.output}")
    else:
        print(rendered)


def _rules_list(args: argparse.Namespace) -> None:
    ruleset = load_ruleset(args.ruleset)
    print(f"{ruleset.get('name')} ({ruleset.get('id')})")
    for rule in ruleset.get("rules", []):
        sources = ", ".join(rule.get("source", []))
        print(f"{rule.get('id')}\t{rule.get('severity')}\t{rule.get('category')}\t{sources}")


def _rules_verify(args: argparse.Namespace) -> None:
    source: Any = load_ruleset("bundled") if args.source == "bundled" else args.source
    bundle = load_and_verify_rule_bundle(source, expected_sha256=args.sha256)
    print(f"Verified {bundle.get('id')} with {len(bundle.get('rules', []))} rules (sha256 {bundle['sha256']})")


def _rules_update(args: argparse.Namespace) -> None:
    destination = Path(args.output).expanduser()
    bundle = install_rule_bundle(args.source, destination, expected_sha256=args.sha256)
    print(f"Installed {bundle.get('id')} with {len(bundle.get('rules', []))} rules to {destination}")


def _read_report_input(path: Path) -> dict[str, Any]:
    if path.is_dir():
        findings = _read_json(path / "findings.json", default=[])
        inventory = _read_json(path / "inventory.json", default={})
        ruleset = _read_json(path / "ruleset.json", default={})
        return {"findings": findings, "inventory": inventory, "ruleset_id": ruleset.get("id")}
    data = _read_json(path)
    if isinstance(data, list):
        return {"findings": data, "inventory": {}, "ruleset_id": None}
    if "findings" in data:
        return data
    ruleset = load_ruleset()
    return {
        "findings": evaluate_inventory(data, ruleset),
        "inventory": data,
        "ruleset_id": ruleset.get("id"),
    }


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.exists() and default is not None:
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {key: value for key, value in counts.items() if value}
