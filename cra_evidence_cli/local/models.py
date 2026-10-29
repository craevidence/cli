"""Shared models for the local no-key check pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cra_evidence_cli.local.disclaimer import advisory_block
from cra_evidence_cli.local.inventory_coverage import InventoryCoverage
from cra_evidence_cli.local.version_applicability import (
    REASON_UNVERSIONED,
    REASON_VERSION_CONFLICT,
)

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
    vex_conflict: str | None = None
    indicative_reason: str | None = None
    applicability_evidence: dict[str, Any] | None = None
    epss_cve: str | None = None
    epss_date: str | None = None
    epss_source: str | None = None

    @property
    def is_indicative(self) -> bool:
        return self.indicative_reason is not None

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
            "epss_cve": self.epss_cve,
            "epss_date": self.epss_date,
            "epss_source": self.epss_source,
            "known_exploited": self.known_exploited,
            "source": self.source,
            "ignored_by_policy": self.ignored_by_policy,
            "vex_conflict": self.vex_conflict,
        }

    def to_indicative_dict(self) -> dict[str, Any]:
        """Report entry for a candidate whose component version is not confirmed.

        Exploitation and EPSS signals are left out: they describe a vulnerability
        in a confirmed version, which this candidate is not.
        """
        omitted = {
            "known_exploited", "epss_probability", "epss_cve", "epss_date", "epss_source",
            "ignored_by_policy", "vex_conflict",
        }
        entry = {key: value for key, value in self.to_dict().items() if key not in omitted}
        entry["quality_reason"] = self.indicative_reason
        entry["applicability_evidence"] = self.applicability_evidence
        return entry


@dataclass(frozen=True)
class SearchedDistro:
    """One operating-system scope the engine searched for a package."""

    name: str
    version: str = ""
    label: str = ""
    channel: str = ""
    exact: bool = False

    def display(self) -> str:
        text = " ".join(part for part in (self.name, self.version or self.label) if part)
        return f"{text} ({self.channel} channel)" if self.channel else text

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "label": self.label,
            "channel": self.channel,
            "exact": self.exact,
        }


@dataclass(frozen=True)
class UnassessedPackage:
    name: str | None
    version: str | None
    purl: str | None
    reason: str
    matcher: str = ""
    searched_distros: tuple[SearchedDistro, ...] = ()
    candidate_count: int | None = None
    candidate_ids: tuple[str, ...] | None = None
    malformed_detail: bool = False


# Reason codes for packages not checked because the SBOM data or the
# vulnerability database lacked what the search needs. Every other code, including
# one this CLI does not know, means the assessment failed.
NOT_CHECKED_REASONS = (
    "unknown-package-version",
    "no-package-ecosystem",
    "missing-distro",
    "distro-release-not-in-db",
    "invalid-rpm-purl-epoch",
)
ASSESSMENT_FAILED_REMEDY = (
    "The scanner could not check these packages. Scan again; if it persists, report it."
)
_NOT_CHECKED_REMEDIES = {
    "invalid-rpm-purl-epoch": (
        "Repair the RPM PURL: use one numeric epoch qualifier that agrees with any "
        "epoch in its version, then scan again."
    ),
    "unknown-package-version": (
        "Add the resolved version (for example, generate the SBOM from the lock file "
        "or build output) and scan again."
    ),
    "missing-distro": (
        "Add the package's actual operating-system distribution and release to the SBOM, "
        "then scan again."
    ),
    "no-package-ecosystem": (
        "Give the package a typed purl (pkg:type/name@version) or a CPE and scan again."
    ),
}


def unassessed_category(reason: str) -> str:
    return "not_checked" if reason in NOT_CHECKED_REASONS else "assessment_failed"


def unassessed_remedy(package: UnassessedPackage) -> str:
    if package.reason == "distro-release-not-in-db":
        scopes = [scope.display() for scope in package.searched_distros]
        if len(scopes) > 1:
            scope_text = f"scopes {', '.join(scopes)}"
        elif scopes:
            scope_text = f"scope {scopes[0]}"
        else:
            scope_text = "scope"
        return (
            f"The vulnerability database has no entry for the requested operating-system "
            f"{scope_text}. Either the advisory data does not cover that release, or the "
            "operating-system identity in the SBOM is not the intended one."
        )
    return _NOT_CHECKED_REMEDIES.get(package.reason, ASSESSMENT_FAILED_REMEDY)


def unassessed_report(packages: list[UnassessedPackage] | None) -> dict[str, Any] | None:
    """Packages the engine did not check, grouped by category and reason code.

    None means no engine assessment was made, so nothing was measured. Counts are
    distinct packages, not engine entries: one package reported by two matchers
    counts once.
    """
    if packages is None:
        return None

    def key(package: UnassessedPackage) -> tuple[str, str, str]:
        return (package.name or "", package.version or "", package.purl or "")

    categories: dict[str, dict[str, set[tuple[str, str, str]]]] = {
        "not_checked": {},
        "assessment_failed": {},
    }
    for package in packages:
        reasons = categories[unassessed_category(package.reason)]
        reasons.setdefault(package.reason, set()).add(key(package))
    entries = sorted(
        packages,
        key=lambda p: (
            unassessed_category(p.reason) != "not_checked",
            p.reason,
            *key(p),
            p.matcher,
        ),
    )
    return {
        "total_packages": len({key(package) for package in packages}),
        **{
            category: {
                "total_packages": len(set().union(*reasons.values())),
                "by_reason": {reason: len(keys) for reason, keys in sorted(reasons.items())},
            }
            for category, reasons in categories.items()
        },
        "entries": [
            {
                "name": package.name,
                "version": package.version,
                "purl": package.purl,
                "matcher": package.matcher,
                "reason": package.reason,
                "category": unassessed_category(package.reason),
                "remedy": unassessed_remedy(package),
                "searched_distros": [scope.to_dict() for scope in package.searched_distros],
                "candidate_vulnerability_count": package.candidate_count,
                "candidate_vulnerability_ids": (
                    None if package.candidate_ids is None else list(package.candidate_ids)
                ),
            }
            for package in entries
        ],
    }


@dataclass
class CoverageSource:
    source: str
    status: str
    as_of: str | None = None
    detail: str | None = None
    unassessed_packages: list[UnassessedPackage] = field(default_factory=list)

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
    indicative_findings: list[Finding] = field(default_factory=list)
    unassessed_packages: list[UnassessedPackage] | None = None
    inventory_coverage: InventoryCoverage | None = None
    sbom_observations: dict[str, Any] | None = None
    sbom_graph_observations: dict[str, Any] | None = None

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
            "indicative_summary": summarize_indicative(self.indicative_findings),
            "indicative_findings": [
                finding.to_indicative_dict() for finding in self.indicative_findings
            ],
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
            "sbom_observations": self.sbom_observations,
            "sbom_graph_observations": self.sbom_graph_observations,
            "suppressions": self.suppressions,
            "provenance": self.provenance,
            "sources_consulted": self.sources_consulted,
            "attributions": self.attributions,
            "baseline": self.baseline,
            "unassessed_packages": unassessed_report(self.unassessed_packages),
            "inventory_coverage": (
                None if self.inventory_coverage is None else self.inventory_coverage.to_dict()
            ),
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


def partition_by_applicability(
    findings: list[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into confirmed ones and indicative candidates."""
    confirmed = [finding for finding in findings if not finding.is_indicative]
    indicative = [finding for finding in findings if finding.is_indicative]
    return confirmed, indicative


def summarize_indicative(findings: list[Finding]) -> dict[str, int]:
    return {
        "total": len(findings),
        "unversioned": sum(1 for f in findings if f.indicative_reason == REASON_UNVERSIONED),
        "version_conflict": sum(
            1 for f in findings if f.indicative_reason == REASON_VERSION_CONFLICT
        ),
    }


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
