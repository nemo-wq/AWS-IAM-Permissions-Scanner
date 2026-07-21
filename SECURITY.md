# Security Policy

## Supported Versions

Security fixes are applied to the latest minor release. Users should upgrade before reporting an issue that is already fixed in a newer release.

| Version | Supported |
| --- | --- |
| 0.2.x | Yes |
| 0.1.x | No |

## Reporting A Vulnerability

Do not open a public issue for a vulnerability, credential exposure, or a report containing customer AWS metadata. Use GitHub's private vulnerability reporting feature from the repository Security tab.

Include the affected version, impact, reproduction conditions, and a minimal synthetic example. Do not include production credentials, account inventories, or customer reports. Maintainers will acknowledge a complete report within five business days and coordinate disclosure after a fix is available.

## Product Boundaries

The scanner is read-only and local-first. It does not execute exploitation steps, mutate AWS resources, upload scan data, or enable telemetry. Rule updates require an explicit command and integrity digest.
