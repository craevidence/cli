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
    cpe: str | None = None
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
    identifier_coverage: dict[str, Any] | None = None

    def to_dict(self, exit_code: int = 0) -> dict[str, Any]:
        summary = summarize_findings(self.findings)
        if exit_code:
            exit_note = (
                f"Exit {exit_code}: configured blocking threshold exceeded in this local snapshot."
            )
        else:
            exit_note = "Exit 0 means no configured blocking findings in this local snapshot."
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
            "identifier_coverage": self.identifier_coverage,
            "suppressions": self.suppressions,
            "provenance": self.provenance,
            "sources_consulted": self.sources_consulted,
            "attributions": self.attributions,
            "baseline": self.baseline,
            "exit_note": exit_note,
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


# The local check measures field presence independently of the selected scanner.
# Its note must not reuse the server's validated matching-identifier wording.
_IDENTIFIER_FIELD_INCOMPLETE_NOTE = (
    "Some components do not contain a non-blank PURL or CPE string. This "
    "field-presence count does not validate PURL types or CPE syntax "
    "and does not show which components the selected scanner could query. The "
    "Grype path may generate CPE candidates from names and versions when CPEs "
    "are absent; the OSV.dev fallback queries only declared PURLs. A "
    "zero-finding result does not mean those components are clean."
)

_IDENTIFIER_FIELD_COMPLETE_NOTE = (
    "Every component contains a non-blank PURL or CPE string. This field-presence "
    "count does not validate PURL types or CPE syntax and does not establish "
    "that the selected scanner could use every value. A zero-finding result does "
    "not mean the components are safe or free of vulnerabilities beyond "
    "what the consulted sources reported above."
)


def identifier_coverage(components: list[Component]) -> dict[str, Any] | None:
    """How many parsed components contain a non-blank PURL or CPE string.

    This is a field-presence count, independent of which scanner ran. It does
    not check whether a PURL's type resolves to an ecosystem the scanner can
    query, and it does not check whether a CPE is syntactically well-formed or
    identifies anything. An unsupported PURL type or malformed CPE therefore
    still counts as a populated field, never as a matching identifier.

    CRA Evidence's server reports a separate matching-identifier metric with
    PURL-ecosystem and CPE-syntax validation. Treat that server result and this
    local field-presence count as different measurements, not interchangeable.

    Returns None when there are no components to measure.
    """
    total = len(components)
    if total == 0:
        return None
    components_with_identifier_field = sum(
        1
        for component in components
        if any(
            isinstance(value, str) and bool(value.strip())
            for value in (component.purl, component.cpe)
        )
    )
    all_components_have_identifier_field = components_with_identifier_field == total
    note = (
        _IDENTIFIER_FIELD_COMPLETE_NOTE
        if all_components_have_identifier_field
        else _IDENTIFIER_FIELD_INCOMPLETE_NOTE
    )
    return {
        "total_components": total,
        "components_with_identifier_field": components_with_identifier_field,
        "all_components_have_identifier_field": all_components_have_identifier_field,
        "note": note,
    }
