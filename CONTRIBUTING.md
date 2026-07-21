# Contributing

Thank you for helping improve AWS IAM attack-path analysis.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m unittest discover -s tests
ruff check iam_exposure tests scripts
mypy iam_exposure
```

## Pull Requests

- Keep changes scoped and include tests for behavior changes.
- Use synthetic account IDs, ARNs, users, roles, and policies in fixtures.
- Never submit credentials, real customer inventory, assessment reports, or exploit output.
- Add source attribution and licensing notes for new research-backed rules.
- Explain whether a rule is confirmed, likely, or potential and which prerequisites affect that decision.
- Update `CHANGELOG.md` for user-visible changes.

## Detection Rules

New rules require a stable ID, original wording, research references, business impact, remediation, deterministic positive and negative fixtures, and documented collection requirements. See `docs/RULES.md`.

By contributing, you agree that your contribution is licensed under Apache-2.0.
