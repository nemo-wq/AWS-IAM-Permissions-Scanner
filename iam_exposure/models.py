from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "2.0"


@dataclass(frozen=True)
class CollectionCoverage:
    complete: bool
    collected: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuleBundle:
    id: str
    name: str
    schema_version: str
    rules: list[dict[str, Any]]
    description: str = ""
    digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttackPath:
    fingerprint: str
    rule_id: str
    principal: str
    principal_type: str
    category: str
    severity: str
    confidence: str
    status: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    target_capability: str = ""

    @classmethod
    def from_finding(cls, finding: dict[str, Any]) -> AttackPath:
        return cls(
            fingerprint=finding["fingerprint"],
            rule_id=finding["id"],
            principal=finding.get("principal", "unknown"),
            principal_type=finding.get("principal_type", "unknown"),
            category=finding.get("category", "other"),
            severity=finding.get("severity", "info"),
            confidence=finding.get("confidence", "medium"),
            status=finding.get("status", "potential"),
            steps=finding.get("path_steps", []),
            target_capability=finding.get("target_capability", finding.get("title", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ChangeEvent:
    fingerprint: str
    lifecycle: str
    reason: str
    finding: dict[str, Any]
    previous: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanSnapshot:
    account_id: str
    generated_at: str
    inventory: dict[str, Any]
    findings: list[dict[str, Any]]
    ruleset_id: str
    coverage: CollectionCoverage
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["coverage"] = self.coverage.to_dict()
        return result
