# AWS IAM Exposure Review

AWS IAM Exposure Review is a local-first AWS attack-path assessment tool for penetration testers, red teamers, security engineers, and small cloud security teams.

It answers four questions:

1. Which principal can gain more access?
2. Which inherited permissions, trust, and resource prerequisites create the path?
3. How confident is the conclusion after boundaries, denies, SCPs, conditions, and collection gaps are considered?
4. What appeared, worsened, improved, or disappeared since the previous complete scan?

The project focuses on IAM privilege escalation and evidence rather than broad CSPM or compliance coverage. Rule attribution includes Rhino Security Labs, NCC Group/PMapper, Bishop Fox, Cloudsplaining, HackTricks, pathfinding.cloud, WithSecure IAMGraph research, Datadog Security Labs, and AWS guidance.

## Example Report

View the synthetic [live example report](https://nemo-wq.github.io/AWS-IAM-Permissions-Scanner/example-report.html), or open the [offline report](docs/example-report.html) directly from a clone. It includes the executive summary, change view, charts, path filters, inherited permission evidence, and remediation detail without customer data or remote assets.

## Install

AWS IAM Exposure Review requires Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## Scan An AWS Account

Use an existing AWS profile, SSO session, or read-only assumed role:

```bash
iam-exposure scan \
  --profile assessment \
  --output ./reports/client-a \
  --format html,json,csv,sarif
```

Assume a dedicated role when reviewing another account:

```bash
iam-exposure scan \
  --profile assessment \
  --role-arn arn:aws:iam::123456789012:role/IAMExposureReviewReadOnly \
  --region ap-southeast-2 \
  --output ./reports/client-a
```

The auditable reference policy is in [`iam_exposure/data/reference-scan-role-policy.json`](iam_exposure/data/reference-scan-role-policy.json). A cross-account CloudFormation template with `ExternalId` enforcement is available at [`docs/reference-scan-role.yaml`](docs/reference-scan-role.yaml).

The legacy entry point remains available:

```bash
python aws_perms.py scan --profile assessment --output ./reports/client-a
```

## Compare Assessments

Repeated scans in the same output directory automatically produce lifecycle changes and trend history. You can also compare any two report folders:

```bash
iam-exposure diff ./reports/before ./reports/after --output ./changes.json
```

Paths receive stable fingerprints and one of these lifecycle states:

- `new`, `open`, or `reopened`;
- `worsened` or `improved` when severity, confidence, or exploitability changes;
- `resolved` only after a complete compatible scan;
- `unverified` when degraded collection prevents a safe resolution conclusion.

## Inspect And Update Rules

The bundled rules are deterministic and work offline:

```bash
iam-exposure rules list
iam-exposure rules verify
```

Updates are never automatic. Install a local or HTTPS bundle only with its published SHA-256 digest:

```bash
iam-exposure rules update \
  --source ./ruleset.json \
  --sha256 <published-digest>
```

## Outputs

- `report.html`: self-contained executive and practitioner report.
- `findings.json`: current findings with fingerprints and lifecycle state.
- `changes.json`: new, worsened, improved, resolved, reopened, and unverified paths.
- `inventory.json`: normalized authorization inventory.
- `graph.json`: typed principal, policy, action, resource, path, and capability graph.
- `summary.json`: chart data, risk counts, coverage, and trends.
- `history.json`: recent assessment trend points.
- `ruleset.json`: exact rules used for the assessment.
- `findings.csv` and `findings.sarif`: workflow integration exports.
- `evidence/collection-warnings.json`: collection limitations.

These files may contain sensitive account IDs, ARNs, principal names, policy evidence, and attack paths. Common output locations and filenames are excluded from Git by default.

## Effective Permission Model

The evaluator accounts for:

- inline and managed identity policies;
- user-to-group inheritance;
- explicit denies;
- permissions boundaries;
- service control policies when Organizations access is available;
- session and resource policy scopes when included by inventory enrichment;
- `Action`, `NotAction`, `Resource`, `NotResource`, and common conditions;
- PassRole targets, service prerequisites, credentials, and external trust.

Conditions and target-specific policies cannot always be proven from static account metadata. The report records these uncertainties and lowers the path to `potential` instead of silently treating it as confirmed.

See the [coverage matrix](docs/COVERAGE.md), [rule standard](docs/RULES.md), and synthetic [benchmark scenarios](benchmarks/scenarios).

## Public Python API

Versioned interfaces are exported from `iam_exposure` and `iam_exposure.api`:

```python
from iam_exposure import (
    build_attack_graph,
    collect_inventory,
    diff_snapshots,
    evaluate_snapshot,
    find_attack_paths,
    load_and_verify_rule_bundle,
    render_report,
)
```

Hosted products should consume released package versions instead of copying the detection engine. The open-source package does not require an account, commercial license, hosted backend, or telemetry.

## Security And Trust

- Read-only collection and no AWS mutation.
- No exploit commands in generated reports.
- No telemetry or hidden uploads.
- Explicit, digest-pinned rule updates.
- HTML escaping for collected AWS and rule content.
- Resolution protection when collection is incomplete.

Review the [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), and [security policy](SECURITY.md) before using the tool with sensitive environments.

## Development

```bash
python -m unittest discover -s tests
ruff check iam_exposure tests scripts
mypy iam_exposure
bandit -q -r iam_exposure
python -m build
```

Regenerate the synthetic report with:

```bash
python -m scripts.generate_example_report
```

Contributions are welcome under the [Apache-2.0 license](LICENSE). Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting rule or engine changes.
