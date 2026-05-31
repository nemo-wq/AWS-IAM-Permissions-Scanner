# AWS IAM Exposure Review

AWS IAM Exposure Review is a local-first AWS IAM security assessment tool for penetration testers, red teamers, and small cyber teams. It collects read-only IAM authorization data, detects high-risk IAM permissions and privilege escalation paths, and writes a static HTML dashboard/report with practitioner evidence and leadership-friendly risk reduction context.

The v1 focus is not generic CSPM. It is research-backed IAM attack-path review inspired by Rhino Security Labs, NCC Group/PMapper, Bishop Fox, Cloudsplaining, HackTricks, pathfinding.cloud, WithSecure IAMGraph research, Datadog cloud security research, and AWS IAM guidance.

## What It Produces

- `report.html`: static dashboard/report for sharing with clients or leadership.
- `findings.json`: structured machine-readable findings.
- `findings.csv`: triage-friendly export for spreadsheets and consultants.
- `findings.sarif`: SARIF export for tooling and workflow integrations.
- `inventory.json`: normalized IAM inventory.
- `ruleset.json`: bundled rule metadata used for the scan.
- `graph.json`: attack graph for downstream visualization or analysis.
- `summary.json`: scan summary and risk breakdown.
- `history.json`: scan trend history for repeated runs in the same folder.
- `evidence/collection-warnings.json`: collection limitations and optional permission failures.

## Example Report

View the synthetic [example report](docs/example-report.html) to see the dashboard, charts, attack-path evidence, and remediation layout.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Run

Use an existing AWS profile, SSO session, or assumed role with read-only IAM permissions.

```bash
iam-exposure scan --profile default --output ./reports/demo --format html,json,csv,sarif
```

The legacy entrypoint still works:

```bash
python aws_perms.py scan --profile default --output ./reports/demo
```

Useful options:

```bash
iam-exposure scan \
  --profile assessment \
  --role-arn arn:aws:iam::123456789012:role/SecurityAudit \
  --region ap-southeast-2 \
  --output ./reports/client-a \
  --format html,json \
  --severity-threshold low \
  --account-alias client-a \
  --ruleset bundled \
  --include-aws-managed-policies
```

## Rule Coverage

The bundled offline ruleset covers:

- Direct administrator-equivalent access.
- IAM self-escalation actions such as policy version changes, inline policy writes, policy attachment, group membership changes, and trust-policy mutation.
- Principal access paths such as access-key and console-login profile creation.
- `iam:PassRole` paths through EC2, Lambda, ECS, CloudFormation, CodeBuild, Glue, SageMaker, and App Runner.
- Existing-resource pivots through Lambda, CodeBuild, and SSM.
- Cross-account and third-party trust risks, including broad external trust without `sts:ExternalId`.
- Credential and legacy IAM risk such as long-lived active access keys and console users without MFA.

Rules include source attribution so findings explain whether they map to public research, AWS guidance, or project logic. The tool ships a bundled snapshot for deterministic offline scans; online rule updates are intentionally out of scope for v1.

## Safety Model

- Local-only execution.
- No telemetry.
- No hosted backend.
- No AWS resource mutation.
- No exploit commands in reports.
- Optional AWS API failures degrade into collection warnings.

## Tests

```bash
python -m unittest discover -s tests
```
