# Threat Model

## Protected Assets

- AWS account identifiers, principal names, role trust, policy documents, and attack-path evidence.
- Local AWS credential sources used by boto3.
- Integrity and provenance of detection rules and released packages.

## Trust Boundaries

- The scanner process and the operator's workstation.
- AWS STS and read-only AWS service APIs.
- Local report output, which may contain sensitive authorization metadata.
- Optional rule bundle sources explicitly selected by the operator.

## Principal Threats

- A report or inventory is accidentally published or attached to an issue.
- A compromised rule bundle causes false conclusions or unsafe report content.
- Incomplete collection silently closes a real attack path.
- Incorrect IAM semantics overstate or understate exploitability.
- Secrets are recorded in logs, fixtures, package artifacts, or repository history.

## Controls

- No telemetry, uploads, mutation, or exploit execution.
- Reports and common output names are excluded from Git by default.
- Rule updates require HTTPS or a local file plus an expected SHA-256 digest.
- Resolutions require complete IAM authorization coverage; degraded scans produce `unverified` changes.
- Reports escape AWS and rule content before rendering.
- CI tests positive and negative policy semantics, scans dependencies, and verifies package contents.

## Known Limitations

IAM conditions cannot always be resolved without request context. Such paths are marked potential and include uncertainty evidence. Resource and session policies are supported by the model but only affect conclusions when supplied by a collector or fixture. The scanner is an assessment aid, not proof that an exploit will succeed.
