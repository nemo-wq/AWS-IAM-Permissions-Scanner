# Detection Rule Standard

Each bundled rule contains:

- stable `id`, `name`, `category`, `severity`, and `confidence`;
- required and optional permissions;
- environmental prerequisites;
- original business impact and remediation wording;
- research attribution and upstream licensing notes.

Rule matches are separated from environmental validation. A permission combination may be:

- **confirmed** when collected evidence establishes the required path;
- **likely** when the permission chain exists and a broad or matching target is present;
- **potential** when conditions, resource targets, service trust, or optional collection require validation.

Rules must not include exploit commands. Defensive reproduction should use synthetic policies, IAM simulation, or a purpose-built test account.

Bundled rules are deterministic. Explicit updates are schema-validated and digest-pinned; automatic network updates are not performed.
