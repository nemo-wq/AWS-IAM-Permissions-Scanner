# Architecture

AWS IAM Exposure Review is a local pipeline with explicit boundaries:

```text
AWS read-only APIs
    -> normalized inventory
    -> effective permission evaluation
    -> typed attack graph
    -> research-attributed path rules
    -> stable findings and lifecycle comparison
    -> offline HTML/JSON/CSV/SARIF evidence
```

## Public Modules

- `collector`: gathers IAM authorization, credential metadata, trust, Access Analyzer, instance profile, organization, and SCP context where permitted.
- `policy`: normalizes statements and evaluates allow, deny, boundary, SCP, session, resource, condition, and target uncertainty.
- `graph`: creates typed nodes and relationships for principals, policy sources, grants, actions, resources, paths, and gained capabilities.
- `rules`: evaluates versioned attack-path rules and emits explainable evidence.
- `lifecycle`: creates stable path fingerprints and compares complete scans.
- `report`: writes self-contained assessment artifacts without external assets or tracking.
- `updates`: validates rule schemas and explicit SHA-256-pinned updates.

## Compatibility Boundary

The supported Python API is exported from `iam_exposure.api` and the package root. Dictionary outputs are versioned by `schema_version`; fields may be added in a minor release, while removals require a major release.

Hosted products must consume a released package version. The open-source package does not import hosted-service code, enforce commercial licenses, or contact a production service.
