# AWS IAM Permissions Scan

This project scans AWS IAM permissions assigned to users directly and through group membership.

## What's improved

- **Reliable pagination support** for IAM list APIs, including:
  - `get_account_authorization_details` for full user/group collection
  - `list_user_policies` for full inline policy name collection
- **Refactored scanner engine** (`scanner.py`) reusable from both CLI and web app.
- **Web GUI** using Flask for running scans from a browser.

## Requirements

- Python 3.10+
- AWS credentials configured locally (for example via `aws configure`)
- IAM read permissions (for example, AWS managed policy `SecurityAudit`)

Install dependencies:

```bash
pip3 install -r requirements.txt
```

## CLI Usage

Run pretty text output:

```bash
python aws_perms.py
```

Run JSON output:

```bash
python aws_perms.py --json
```

Use a specific AWS profile:

```bash
python aws_perms.py --profile my-profile
```

## Web App Usage

Start the web app:

```bash
python app.py
```

Then open:

- `http://127.0.0.1:5000`

Enter an optional AWS profile and click **Run Scan**.

## Notes

- IAM is a global service; region is optional and mainly present for session compatibility.
- Managed policy statements can be large depending on your account's policy set.
