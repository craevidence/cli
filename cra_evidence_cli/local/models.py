"""Shared models for the local no-key check pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cra_evidence_cli.local.disclaimer import advisory_block

SEVERITY_ORDER = {
    "unknown": 0,
    "negligible": 0,
    "low": 1,
    "medium": 2,
    "moderate": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class Component:
    name: str
    version: str | None = None
    purl: str | None = None
    supplier: str | None = None
    licenses: list[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    package: str
    version: str | None
    severity: str = "unknown"
    aliases: set[str] = field(default_factory=set)
    fixed_versions: list[str] = field(default_factory=list)
    purl: str | None = None
    title: str | None = None
    references: list[str] = field(default_factory=list)
    epss_probability: float | None = None
    known_exploited: bool | None = None
    source: str = "unknown"
    ignored_by_policy: bool = False

    @property
    def cve_aliases(self) -> set[str]:
        values = {self.id, *self.aliases}
        return {value.upper() for value in values if value.upper().startswith("CVE-")}

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "package": self.package,
            "version": self.version,
            "severity": self.severity.lower(),
            "aliases": sorted(self.aliases),
            "cve_aliases": sorted(self.cve_aliases),
            "fixed_versions": self.fixed_versions,
            "purl": self.purl,
            "title": self.title,
            "references": self.references,
            "epss_probability": self.epss_probability,
            "known_exploited": self.known_exploited,
            "source": self.source,
            "ignored_by_policy": self.ignored_by_policy,
        }


@dataclass
class CoverageSource:
    source: str
    status: str
    as_of: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status,
            "as_of": self.as_of,
            "detail": self.detail,
        }


@dataclass
class LocalCheckResult:
    target: str
    target_type: str
    sbom_path: Path | None
    components: list[Component]
    findings: list[Finding]
    dimensions: list[dict[str, Any]]
    coverage: list[CoverageSource]
    provenance: dict[str, Any]
    attributions: list[str]
    sources_consulted: list[str]
    baseline: dict[str, Any] | None = None
    suppressions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        summary = summarize_findings(self.findings)
        return {
            "schema_version": "craevidence.local_check.v1",
            "target": {"type": self.target_type, "value": self.target},
            "summary": summary,
            "components": {
                "count": len(self.components),
                "items": [component.__dict__ for component in self.components],
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "cra_readiness_signal": {
                "denominator": (
                    "This local snapshot checks SBOM, vulnerability and enrichment signals. "
                    "Organisational evidence and sign-off must be reviewed separately."
                ),
                "dimensions": self.dimensions,
                "cannot_tell_you": cannot_tell_you(),
            },
            "coverage": [source.to_dict() for source in self.coverage],
            "suppressions": self.suppressions,
            "provenance": self.provenance,
            "sources_consulted": self.sources_consulted,
            "attributions": self.attributions,
            "baseline": self.baseline,
            "exit_note": "Exit 0 means no configured blocking findings in this local snapshot.",
            "advisory": advisory_block(),
        }


def normalize_severity(value: str | None) -> str:
    if not value:
        return "unknown"
    lowered = value.lower()
    if lowered == "moderate":
        return "medium"
    return lowered


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    summary = {
        "total": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
        "known_exploited": 0,
    }
    for finding in findings:
        severity = normalize_severity(finding.severity)
        if severity in summary:
            summary[severity] += 1
        else:
            summary["unknown"] += 1
        if finding.known_exploited is True:
            summary["known_exploited"] += 1
    return summary


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cannot_tell_you() -> list[str]:
    return [
        "Intended purpose, foreseeable misuse, and CRA product classification.",
        "Whether secure-by-default design controls are implemented and enforced.",
        "Whether the product risk assessment has been completed and approved.",
        "Whether vulnerability handling, notification, and support processes operate in practice.",
        "Whether technical file review or sign-off has been completed.",
    ]
