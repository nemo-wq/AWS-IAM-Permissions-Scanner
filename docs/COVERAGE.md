# Coverage Matrix

| Area | Current status | Confidence behavior |
| --- | --- | --- |
| User, group, and role identity policies | Supported | Confirmed when unconstrained |
| Managed and inline policy inheritance | Supported | Evidence includes policy and group lineage |
| Explicit identity denies | Supported | Matching unconditional denies block a path |
| Permissions boundaries | Supported when policy document is collected | Missing target context lowers confidence |
| Service control policies | Supported when Organizations access is available | Missing Organizations access is reported |
| Session and resource policies | Model supported | Evaluated when supplied by inventory enrichment |
| Common IAM conditions | Partially evaluated | Unknown request context produces potential paths |
| `NotAction` and `NotResource` | Supported | Unknown target scope is recorded as uncertainty |
| PassRole service paths | Bundled for common compute and automation services | Role/resource prerequisites affect status |
| Credential and third-party trust risk | Supported | Uses IAM credential and trust metadata |
| Multi-account transitive traversal | In development | Cross-account trust is reported without full organization traversal |

The public benchmark under `benchmarks/scenarios` records deterministic positive and negative expectations. Coverage claims should be updated with the benchmark.
