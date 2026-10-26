"""Coverage gaps reported by CRA Evidence: packages a vulnerability scan could not check.

A coverage gap is a package the scan could not check because the SBOM entry lacks
a version or a package type the scanner supports, or because the advisory data has
no entry for the operating-system release it names. Gaps are reported apart from
scan failures. The vulnerability counts do not cover these packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from rich.markup import escape

from cra_evidence_cli.exceptions import CoverageGapsFound

REASON_LABELS = {
    "unknown-package-version": "no version in the SBOM",
    "no-package-ecosystem": "no package type the scanner supports",
    "distro-release-not-in-db": "operating-system release not in the advisory data",
}

FLAG = "--fail-on-coverage-gaps"


@dataclass(frozen=True)
class CoverageGaps:
    """One coverage-gap object as received.

    ``state`` is "absent" (the server sent no object), "invalid" (the object
    could not be read), "none" or "gaps". Counts and remedies are filled only
    for "none" and "gaps".
    """

    state: str
    total: int = 0
    counts_by_reason: dict[str, int] = field(default_factory=dict)
    remedy: list[str] = field(default_factory=list)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def read_coverage_gaps(value: object) -> CoverageGaps:
    """Validate a ``coverage_gaps`` object from a server response."""
    if value is None:
        return CoverageGaps("absent")
    if not isinstance(value, dict):
        return CoverageGaps("invalid")
    state = value.get("state")
    total = value.get("total")
    counts = value.get("counts_by_reason", {})
    remedy = value.get("remedy", [])
    if (
        state not in ("none", "gaps")
        or not _is_count(total)
        or (state == "gaps") != (total > 0)
        or not isinstance(counts, dict)
        or not all(isinstance(k, str) and _is_count(v) for k, v in counts.items())
        or not isinstance(remedy, list)
        or not all(isinstance(item, str) for item in remedy)
    ):
        return CoverageGaps("invalid")
    return CoverageGaps(state, total, dict(counts), list(remedy))


def summary_coverage_gaps(vulnerability_summary: object) -> CoverageGaps:
    """Coverage gaps of a ``vulnerability_summary`` object."""
    if not isinstance(vulnerability_summary, dict):
        return CoverageGaps("absent")
    return read_coverage_gaps(vulnerability_summary.get("coverage_gaps"))


def _by_count(counts: dict[str, int]) -> list[tuple[str, int]]:
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _reason_label(code: str) -> str:
    label = REASON_LABELS.get(code)
    return f"{label} ({code})" if label else code


def coverage_gap_lines(gaps: CoverageGaps) -> list[str]:
    """Plain-language lines (Rich markup escaped) for a coverage-gap object.

    An absent object gives no lines, so an older server is never shown as
    reporting no gaps.
    """
    if gaps.state == "absent":
        return []
    if gaps.state == "invalid":
        return ["Coverage gaps: reported in a form this CLI cannot read."]
    if gaps.state == "none":
        return ["Coverage gaps: none reported."]
    lines = [
        (
            f"Coverage gaps: {gaps.total} package(s) not checked for vulnerabilities. "
            "The vulnerability counts do not cover them."
        )
    ]
    for code, count in _by_count(gaps.counts_by_reason):
        lines.append(f"  {count} with {escape(_reason_label(code))}")
    lines.extend(f"  Next step: {escape(item)}" for item in gaps.remedy)
    return lines


def print_coverage_gaps(console, gaps: CoverageGaps, heading: str | None = None) -> None:
    lines = coverage_gap_lines(gaps)
    if not lines:
        return
    if heading:
        console.print(heading)
    for line in lines:
        console.print(line, soft_wrap=True)


def enforce_coverage_gaps(vulnerability_summary: object, fail_on: str) -> None:
    """Fail the ``--fail-on-coverage-gaps`` gate unless the server reported no gaps.

    An absent or unreadable object fails too: without it the CLI cannot confirm
    that every package was checked.
    """
    gaps = summary_coverage_gaps(vulnerability_summary)
    if gaps.state == "none":
        return
    if gaps.state == "gaps":
        reasons = ", ".join(
            f"{count} {escape(code)}" for code, count in _by_count(gaps.counts_by_reason)
        )
        detail = f" ({reasons})" if reasons else ""
        msg = (
            f"{gaps.total} package(s) could not be checked for vulnerabilities"
            f"{detail}, so {FLAG} fails the --fail-on '{fail_on}' gate. The next "
            "step for each reason is listed with the coverage gaps."
        )
    elif gaps.state == "absent":
        msg = (
            "The server did not report coverage gaps for this version, so "
            f"{FLAG} cannot confirm that every package was checked."
        )
    else:
        msg = (
            "The server reported coverage gaps in a form this CLI cannot read, "
            f"so {FLAG} cannot confirm that every package was checked."
        )
    raise CoverageGapsFound(msg)
