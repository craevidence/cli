"""Review dimensions for the local no-key check."""

from __future__ import annotations

from typing import Any

from cra_evidence_cli.local.enrich import stale_status
from cra_evidence_cli.local.models import Component, CoverageSource, Finding, summarize_findings

RESULT_NEEDS_REVIEW = "Needs Review"
RESULT_ACTION_REQUIRED = "Action required"
RESULT_UNKNOWN = "Unknown - stale, re-run online"


def build_dimensions(
    components: list[Component],
    findings: list[Finding],
    coverage: list[CoverageSource],
    sbom_quality: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build local review dimensions.

    ``citation_ids`` are CLI-local, human-readable labels for reviewers. They
    are not a bundled CRA source index and are not machine-traceable.
    """
    summary = summarize_findings(findings)
    vuln_status = RESULT_ACTION_REQUIRED if findings else RESULT_NEEDS_REVIEW
    if any(
        source.status == "stale"
        for source in coverage
        if source.source in {"grype-db", "cisa-kev"}
    ):
        vuln_status = RESULT_UNKNOWN

    dimensions: list[dict[str, Any]] = [
        {
            "entry_id": "cra:annex-i-part-ii-1",
            "title": "SBOM exists and is machine-readable",
            "result": RESULT_NEEDS_REVIEW if components else RESULT_ACTION_REQUIRED,
            "citation_ids": ["annex_I.part-ii-item-1", "annex_VII.item-2-b", "annex_VII.item-8"],
            "message": (
                f"Parsed {len(components)} SBOM components. Presence is stored for review; "
                "this local check cannot auto-confirm the legal obligation."
            ),
        },
        {
            "entry_id": "cra:annex-i-part-i-2-a",
            "title": "Known vulnerability snapshot",
            "result": vuln_status,
            "citation_ids": ["annex_I.part-i-item-2-a", "art_013.002"],
            "message": _vulnerability_message(summary),
        },
        {
            "entry_id": "cra:annex-i-part-ii-2",
            "title": "Remediation information",
            "result": RESULT_ACTION_REQUIRED
            if any(item.fixed_versions for item in findings)
            else RESULT_NEEDS_REVIEW,
            "citation_ids": ["annex_I.part-ii-item-2"],
            "message": (
                "Published upstream fix versions are advisory; "
                "verify they apply to your build."
            ),
        },
        {
            "entry_id": "cra:art-13-5",
            "title": "Third-party component inventory",
            "result": RESULT_NEEDS_REVIEW if components else RESULT_ACTION_REQUIRED,
            "citation_ids": ["art_013.005"],
            "message": (
                "Component inventory supports due diligence review "
                "but does not prove it occurred."
            ),
        },
    ]

    if sbom_quality and sbom_quality.get("score") is not None:
        weakest = ", ".join(sbom_quality.get("weakest") or []) or "n/a"
        dimensions.append(
            {
                "entry_id": "cra:annex-i-part-ii-1-quality",
                "title": "SBOM quality (BSI TR-03183-2 v2 proxy)",
                "result": RESULT_NEEDS_REVIEW,
                "citation_ids": ["annex_I.part-ii-item-1"],
                "message": (
                    f"sbomqs BSI score {sbom_quality['score']}/100 - a proxy for SBOM "
                    "completeness, non-binding, not CRA conformance. "
                    f"Weakest fields: {weakest}."
                ),
            }
        )

    return dimensions


def mark_stale_sources(coverage: list[CoverageSource]) -> None:
    for source in coverage:
        if source.status != "present":
            continue
        if source.source in {"cisa-kev", "first-epss"} and stale_status(source.as_of, 7):
            source.status = "stale"
        if source.source == "grype-db" and stale_status(source.as_of, 30):
            source.status = "stale"


def assert_no_cra_pass(dimensions: list[dict[str, Any]]) -> None:
    for item in dimensions:
        if str(item.get("entry_id", "")).startswith("cra:") and item.get("result") == "Passed":
            msg = "CRA-mapped local check dimension cannot be Passed"
            raise AssertionError(msg)


_EUVD_NOTE = (
    "KEV flags US-catalogued known-exploited CVEs; it is enrichment, not the CRA "
    "Article 3(41)/(42) determination. The European Vulnerability Database "
    "(EUVD, established by Art 12(2) of Directive (EU) 2022/2555) is not queried here."
)


def _vulnerability_message(summary: dict[str, int]) -> str:
    if summary["total"]:
        return (
            f"Found {summary['total']} vulnerabilities "
            f"(critical={summary['critical']}, high={summary['high']}, "
            f"medium={summary['medium']}, known-exploited={summary['known_exploited']}). "
            f"{_EUVD_NOTE}"
        )
    return (
        "No component matched the consulted vulnerability sources in this local snapshot. "
        "This does not establish Annex I Part I(2)(a) conformity, which is conditioned on the "
        f"Article 13(2) risk assessment. {_EUVD_NOTE}"
    )
