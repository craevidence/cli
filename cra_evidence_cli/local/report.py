"""Renderers for local no-key check output."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from rich.console import Console
from rich.text import Text

from cra_evidence_cli.local.inventory_coverage import (
    CODE_DECLARED_UNRESOLVED,
    CODE_DEPENDENCY_GRAPH_UNRESOLVED,
    code_heading,
    only_dependency_graph_gaps,
)
from cra_evidence_cli.local.models import ASSESSMENT_FAILED_REMEDY, LocalCheckResult
from cra_evidence_cli.styles import (
    STYLE_BLOCKER,
    STYLE_LABEL,
    STYLE_MUTED,
    STYLE_OK,
    STYLE_TITLE,
    severity_style,
    status_style,
)


def _is_temp_path(path_str: str) -> bool:
    """Return True if the path looks like an OS temp-directory path."""
    return path_str.startswith("/tmp") or path_str.startswith("/var/tmp")  # noqa: S108


def sarif_path_uri(path: str) -> str:
    """Encode a filesystem path as a relative or absolute SARIF URI."""
    return quote(path, safe="/")


def _resolve_sarif_sbom_uri(result: LocalCheckResult) -> str:
    """Resolve the SBOM URI for SARIF physicalLocation entries.

    Prefer a retained copy over the consumed source. Paths starting with
    /tmp or /var/tmp use 'sbom.json' instead.
    """
    sbom_output = result.provenance.get("sbom_output")
    if sbom_output:
        s = str(sbom_output)
        if not _is_temp_path(s):
            return sarif_path_uri(s)
        return "sbom.json"
    if result.target_type in ("directory", "image"):
        return "sbom.json"
    if result.sbom_path is not None:
        path_str = str(result.sbom_path)
        if not _is_temp_path(path_str):
            return sarif_path_uri(path_str)
    return "sbom.json"


def render(
    result: LocalCheckResult,
    output_format: str,
    verbose: bool = False,
    exit_code: int = 0,
) -> str:
    data = result.to_dict(exit_code=exit_code)
    if output_format == "json":
        return json.dumps(data, indent=2, sort_keys=True)
    if output_format == "sarif":
        sbom_uri = _resolve_sarif_sbom_uri(result)
        return json.dumps(_sarif(data, sbom_uri=sbom_uri), indent=2, sort_keys=True)
    if output_format == "markdown":
        return _markdown(data, verbose, exit_code)
    return _text(data, verbose, exit_code)


def print_text_report(
    console: Console,
    result: LocalCheckResult,
    verbose: bool = False,
    exit_code: int = 0,
) -> None:
    data = result.to_dict(exit_code=exit_code)
    summary = data["summary"]

    console.print(Text("Local SBOM Check", style=STYLE_TITLE))
    if verbose:
        console.print()
        console.print(data["cra_readiness_signal"]["denominator"])

    console.print()
    console.print(Text("Summary", style=STYLE_TITLE))
    console.print(_summary_text(data["components"]["count"], summary, _indicative_total(data)))
    _print_identifier_coverage(console, data)
    for line in _osv_partial_lines(data):
        console.print(line, style=STYLE_MUTED, markup=False)
    _print_unassessed(console, data)
    _print_inventory_coverage(console, data)
    _print_sbom_observations(console, data, verbose)
    _print_sbom_graph_observations(console, data, verbose)

    console.print()
    console.print(Text("Top actions", style=STYLE_TITLE))
    actions = _top_action_records(data)
    if actions:
        for action in actions:
            console.print(_action_text(action, data["coverage"]))
    else:
        console.print("- Keep the SBOM and vulnerability source snapshots current.")

    _print_suppressions(console, data)
    _print_vex_conflicts(console, data)
    _print_ignored(console, data)
    _print_indicative(console, data)
    _print_baseline(console, data)

    if verbose:
        console.print()
        console.print(Text("Reviewed dimensions", style=STYLE_TITLE))
        for item in data["cra_readiness_signal"]["dimensions"]:
            console.print(_dimension_text(item))
            console.print(f"  {item['message']}")
        console.print()
        console.print(Text("What this local snapshot cannot tell you", style=STYLE_TITLE))
        for item in data["cra_readiness_signal"]["cannot_tell_you"]:
            console.print(f"- {item}")
        console.print()
        console.print("Data provenance: run with --output json for the full machine report.")
    else:
        console.print()
        console.print(
            "Run with -v for reviewed dimensions and scope notes; "
            "--output json for the full machine report."
        )

    console.print()
    console.print(Text(_exit_line(data, exit_code), style=STYLE_MUTED))


def _text(data: dict[str, Any], verbose: bool = False, exit_code: int = 0) -> str:
    summary = data["summary"]
    lines = ["Local SBOM Check"]
    if verbose:
        lines.extend(["", data["cra_readiness_signal"]["denominator"]])
    lines.extend(
        [
            "",
            "Summary",
            (
                f"Components: {data['components']['count']} | Vulnerabilities: {summary['total']} "
                f"(critical={summary['critical']}, high={summary['high']},"
                f" medium={summary['medium']}) | "
                f"Known-exploited: {summary['known_exploited']}"
                f"{_indicative_count_suffix(data)}"
            ),
        ]
    )
    lines.extend(_identifier_coverage_lines(data))
    lines.extend(_osv_partial_lines(data))
    lines.extend(_unassessed_lines(data))
    lines.extend(_inventory_coverage_lines(data))
    lines.extend(_sbom_observation_lines(data, verbose))
    lines.extend(_sbom_graph_observation_lines(data, verbose))
    lines.extend(
        [
            "",
            "Top actions",
            *_top_actions(data),
        ]
    )
    suppressions = data.get("suppressions") or []
    if suppressions:
        lines.extend(["", f"Suppressed via VEX: {len(suppressions)}"])
        for item in suppressions:
            note = ""
            if item.get("kev_conflict"):
                note = "  WARNING: this is a known-exploited (KEV) finding suppressed by VEX"
            lines.append(
                f"- {item['vuln_id']} ({item['status']}; product={item.get('product') or '*'}; "
                f"justification={item.get('justification') or 'n/a'})"
            )
            if note:
                lines.append(note)
    lines.extend(_vex_conflict_lines(data))
    ignored = [f for f in data["findings"] if f.get("ignored_by_policy")]
    if ignored:
        shown = ", ".join(sorted(f["id"] for f in ignored)[:5])
        more = "…" if len(ignored) > 5 else ""
        lines.extend(
            [
                "",
                f"Ignored by policy (shown, not gated): {len(ignored)} ({shown}{more})",
            ]
        )
    lines.extend(_indicative_lines(data))
    baseline = data.get("baseline")
    if baseline:
        new = baseline.get("new_vulnerabilities") or []
        removed = baseline.get("removed_vulnerabilities") or []
        new_text = f" ({', '.join(new[:5])}{'…' if len(new) > 5 else ''})" if new else ""
        lines.extend(
            [
                "",
                "Changed since baseline",
                f"- New vulnerabilities: {len(new)}{new_text}",
                f"- Baseline findings absent now: {len(removed)}",
                *_reclassified_lines(baseline),
                *_not_reassessed_lines(baseline),
            ]
        )
        if removed:
            lines.append(
                "Absence alone does not prove remediation; package identity or scan coverage "
                "may have changed."
            )
    if verbose:
        # Verbose adds review detail. The per-dimension
        # citation ids, scan-source provenance, and attribution stay in JSON and
        # SARIF output, never in this text.
        lines.extend(["", "Reviewed dimensions"])
        for item in data["cra_readiness_signal"]["dimensions"]:
            lines.append(f"- {item['result']}: {item['title']}")
            lines.append(f"  {item['message']}")
        lines.extend(["", "What this local snapshot cannot tell you"])
        lines.extend(f"- {item}" for item in data["cra_readiness_signal"]["cannot_tell_you"])
        lines.extend(["", "Data provenance: run with --output json for the full machine report."])
    else:
        lines.extend(
            [
                "",
                (
                    "Run with -v for reviewed dimensions and scope notes; "
                    "--output json for the full machine report."
                ),
            ]
        )
    lines.extend(["", _exit_line(data, exit_code)])
    return "\n".join(lines)


def _markdown(data: dict[str, Any], verbose: bool = False, exit_code: int = 0) -> str:
    text = _text(data, verbose, exit_code)
    return "# " + text.replace("\n\n", "\n\n## ")


def _summary_text(component_count: int, summary: dict[str, int], indicative: int = 0) -> Text:
    text = Text()
    text.append("Components: ")
    text.append(str(component_count), style=STYLE_LABEL)
    text.append(" | Vulnerabilities: ")
    total_style = STYLE_BLOCKER if summary["critical"] or summary["high"] else STYLE_OK
    text.append(str(summary["total"]), style=total_style)
    text.append(" (critical=")
    text.append(str(summary["critical"]), style=_count_style("critical", summary["critical"]))
    text.append(", high=")
    text.append(str(summary["high"]), style=_count_style("high", summary["high"]))
    text.append(", medium=")
    text.append(str(summary["medium"]), style=_count_style("medium", summary["medium"]))
    text.append(") | Known-exploited: ")
    text.append(
        str(summary["known_exploited"]),
        style=STYLE_BLOCKER if summary["known_exploited"] else STYLE_OK,
    )
    if indicative:
        text.append(f" | Indicative, not counted: {indicative}", style=STYLE_MUTED)
    return text


def _count_style(severity: str, count: int) -> str:
    return severity_style(severity, count)


def _top_action_records(data: dict[str, Any]) -> list[dict[str, Any]]:
    findings = data["findings"]
    if not findings:
        return []
    return sorted(
        findings,
        key=lambda item: (
            item["known_exploited"] is True,
            item.get("epss_probability") or 0.0,
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(item["severity"], 0),
            bool(item["fixed_versions"]),
        ),
        reverse=True,
    )[:3]


def _epss_label(finding: dict[str, Any], coverage: list[dict[str, Any]]) -> str | None:
    refresh = next(
        (source["status"] for source in coverage if source["source"] == "first-epss"), None
    )
    reason = None
    if refresh == "unavailable":
        reason = "FIRST refresh unavailable"
    elif refresh in {"present", "stale", "unknown"}:
        reason = "no matching FIRST row returned"
    probability = finding.get("epss_probability")
    if isinstance(probability, (int, float)):
        label = (
            f"EPSS {probability:.2f} (CVE: {finding.get('epss_cve') or 'unknown'}; "
            f"date: {finding.get('epss_date') or 'unknown'}; "
            f"source: {finding.get('epss_source') or 'unknown'}"
        )
        if finding.get("epss_source") == "grype-db" and finding["cve_aliases"] and reason:
            label += f"; {reason}"
        return label + ")"
    if finding["cve_aliases"] and reason:
        return f"EPSS unavailable ({reason})"
    return None


def _action_text(finding: dict[str, Any], coverage: list[dict[str, Any]]) -> Text:
    text = Text("- ")
    text.append(str(finding["package"]), style=STYLE_TITLE)
    version = finding.get("version")
    if version:
        text.append(f" {version}")
    marks = []
    if finding.get("known_exploited") is True:
        marks.append(("known-exploited", STYLE_BLOCKER))
    epss_label = _epss_label(finding, coverage)
    if epss_label:
        marks.append((epss_label, STYLE_LABEL))
    if marks:
        text.append(" [")
        for index, (label, style) in enumerate(marks):
            if index:
                text.append(", ")
            text.append(label, style=style)
        text.append("]")
    text.append(":")
    fixed_versions = finding["fixed_versions"]
    if fixed_versions:
        text.append(" upgrade to ")
        text.append(", ".join(fixed_versions[:3]), style=STYLE_OK)
    else:
        text.append(" triage and verify whether an upstream fix applies")
    return text


def _dimension_text(item: dict[str, Any]) -> Text:
    result = str(item["result"])
    text = Text("- ")
    text.append(result, style=status_style(result))
    text.append(f": {item['title']}")
    return text


def _print_suppressions(console: Console, data: dict[str, Any]) -> None:
    suppressions = data.get("suppressions") or []
    if not suppressions:
        return
    console.print()
    console.print(Text(f"Suppressed via VEX: {len(suppressions)}", style=STYLE_TITLE))
    for item in suppressions:
        console.print(
            f"- {item['vuln_id']} ({item['status']}; product={item.get('product') or '*'}; "
            f"justification={item.get('justification') or 'n/a'})"
        )
        if item.get("kev_conflict"):
            console.print(
                "  WARNING: this is a known-exploited (KEV) finding suppressed by VEX",
                style=STYLE_BLOCKER,
            )


def _vex_conflict_lines(data: dict[str, Any]) -> list[str]:
    conflicts = [finding for finding in data["findings"] if finding.get("vex_conflict")]
    if not conflicts:
        return []
    return [
        "",
        f"VEX conflicts retained: {len(conflicts)}",
        *[f"- {finding['id']}: {finding['vex_conflict']}" for finding in conflicts],
    ]


def _print_vex_conflicts(console: Console, data: dict[str, Any]) -> None:
    lines = _vex_conflict_lines(data)
    if not lines:
        return
    console.print()
    console.print(Text(lines[1], style=STYLE_TITLE))
    for line in lines[2:]:
        console.print(line)


def _print_ignored(console: Console, data: dict[str, Any]) -> None:
    ignored = [f for f in data["findings"] if f.get("ignored_by_policy")]
    if not ignored:
        return
    shown = ", ".join(sorted(f["id"] for f in ignored)[:5])
    more = "..." if len(ignored) > 5 else ""
    console.print()
    console.print(f"Ignored by policy (shown, not gated): {len(ignored)} ({shown}{more})")


def _print_baseline(console: Console, data: dict[str, Any]) -> None:
    baseline = data.get("baseline")
    if not baseline:
        return
    new = baseline.get("new_vulnerabilities") or []
    removed = baseline.get("removed_vulnerabilities") or []
    new_text = f" ({', '.join(new[:5])}{'...' if len(new) > 5 else ''})" if new else ""
    console.print()
    console.print(Text("Changed since baseline", style=STYLE_TITLE))
    console.print(f"- New vulnerabilities: {len(new)}{new_text}")
    console.print(f"- Baseline findings absent now: {len(removed)}")
    for line in (*_reclassified_lines(baseline), *_not_reassessed_lines(baseline)):
        console.print(line, markup=False)
    if removed:
        console.print(
            "Absence alone does not prove remediation; package identity or scan coverage "
            "may have changed."
        )


_INDICATIVE_SHOWN = 10
_INDICATIVE_REASON_TEXT = {
    "unversioned": "version missing",
    "version_conflict": "conflicting versions",
}


def _indicative_total(data: dict[str, Any]) -> int:
    return len(data.get("indicative_findings") or [])


def _indicative_count_suffix(data: dict[str, Any]) -> str:
    total = _indicative_total(data)
    return f" | Indicative, not counted: {total}" if total else ""


def _indicative_lines(data: dict[str, Any]) -> list[str]:
    """Candidates whose component version is missing or contradictory.

    They are listed apart from the confirmed findings and never counted or gated.
    """
    items = data.get("indicative_findings") or []
    if not items:
        return []
    lines = [
        "",
        f"Indicative candidates, version not confirmed (not counted, not gated): {len(items)}",
        (
            "These matches rest on a missing or conflicting component version, so they are "
            "not confirmed vulnerabilities. Give the SBOM component its exact version and re-run."
        ),
    ]
    for item in items[:_INDICATIVE_SHOWN]:
        reason = _INDICATIVE_REASON_TEXT.get(item["quality_reason"], item["quality_reason"])
        version = item.get("version") or "(no version)"
        lines.append(f"- {item['package']} {version}: {item['id']}, {reason}")
    if len(items) > _INDICATIVE_SHOWN:
        lines.append(f"- ... and {len(items) - _INDICATIVE_SHOWN} more; see --output json")
    return lines


def _print_indicative(console: Console, data: dict[str, Any]) -> None:
    lines = _indicative_lines(data)
    if not lines:
        return
    console.print()
    console.print(Text(lines[1], style=STYLE_TITLE))
    for line in lines[2:]:
        console.print(line, markup=False)


def _reclassified_lines(baseline: dict[str, Any]) -> list[str]:
    reclassified = baseline.get("reclassified_vulnerabilities") or []
    if not reclassified:
        return []
    shown = ", ".join(reclassified[:5]) + ("..." if len(reclassified) > 5 else "")
    return [f"- Reclassified: version could not be confirmed: {len(reclassified)} ({shown})"]


def _not_reassessed_lines(baseline: dict[str, Any]) -> list[str]:
    not_reassessed = baseline.get("not_reassessed_vulnerabilities") or []
    if not not_reassessed:
        return []
    shown = ", ".join(not_reassessed[:5]) + ("..." if len(not_reassessed) > 5 else "")
    text = "package could not be assessed in this scan"
    return [f"- Not reassessed: {text}: {len(not_reassessed)} ({shown})"]


def _exit_line(data: dict[str, Any], exit_code: int) -> str:
    # The JSON exit_note keeps its wording; the human report names the real cause.
    if (
        exit_code == 15
        and data["provenance"].get("strict_failure") == "incomplete vulnerability assessment"
    ):
        return (
            "Exit 15: strict mode failed because the vulnerability assessment is incomplete, "
            "not because a blocking threshold was exceeded."
        )
    if (
        exit_code == 15
        and data["provenance"].get("strict_failure") == "unknown, stale, or unavailable source"
    ):
        return (
            "Exit 15: strict mode failed because a consulted source is unknown, stale, "
            "or unavailable."
        )
    return data["exit_note"]


_UNASSESSED_SHOWN = 5
_UNASSESSED_REASON_LABELS = {
    "unknown-package-version": "Package version unknown",
    "invalid-rpm-purl-epoch": "RPM PURL epoch invalid or ambiguous",
    "no-package-ecosystem": "Package ecosystem unknown",
    "distro-release-not-in-db": "Operating-system release not in the vulnerability database",
    "matcher-error": "Matcher error",
    "version-comparison-error": "Version comparison error",
    "matcher-panic": "Matcher stopped unexpectedly",
}
_UNASSESSED_SECTIONS = (
    ("not_checked", "Not checked for vulnerabilities", "warning", "not-checked"),
    ("assessment_failed", "Assessment failed", "error", "assessment-failed"),
)


def _unassessed_reason_label(reason: str) -> str:
    return _UNASSESSED_REASON_LABELS.get(reason, "Unrecognised reason")


def unassessed_groups(data: dict[str, Any], category: str) -> dict[str, dict[str, Any]]:
    """Entries of one category grouped by reason code, in reason order.

    Each group holds its entries, its distinct packages (with the matchers that
    reported each) and its distinct remedies.
    """
    report = data.get("unassessed_packages") or {}
    groups: dict[str, dict[str, Any]] = {}
    for entry in report.get("entries") or []:
        if entry["category"] != category:
            continue
        group = groups.setdefault(
            entry["reason"], {"entries": [], "packages": {}, "remedies": []}
        )
        group["entries"].append(entry)
        key = (entry["name"] or "", entry["version"] or "", entry["purl"] or "")
        matchers = group["packages"].setdefault(key, [])
        if entry["matcher"] not in matchers:
            matchers.append(entry["matcher"])
        if entry["remedy"] not in group["remedies"]:
            group["remedies"].append(entry["remedy"])
    return dict(sorted(groups.items()))


def package_count(count: int) -> str:
    return f"{count} package" if count == 1 else f"{count} packages"


def unassessed_package_label(key: tuple[str, str, str]) -> str:
    name, version, purl = key
    return f"{name or purl} {version or '(no version)'}"


def _unassessed_lines(data: dict[str, Any]) -> list[str]:
    """Packages the engine did not check, with the next step for each reason.

    Shown whenever the engine reported any, because the vulnerability counts do
    not cover them.
    """
    report = data.get("unassessed_packages")
    if not report:
        return []
    lines: list[str] = []
    for category, heading, _, _ in _UNASSESSED_SECTIONS:
        total = report[category]["total_packages"]
        if not total:
            continue
        lines.extend(
            [
                "",
                f"{heading}: {package_count(total)}",
                "The vulnerability counts above do not cover these packages.",
            ]
        )
        if category == "assessment_failed":
            lines.append(ASSESSMENT_FAILED_REMEDY)
        for reason, group in unassessed_groups(data, category).items():
            packages = group["packages"]
            lines.append(
                f"- {_unassessed_reason_label(reason)} ({reason}): {package_count(len(packages))}"
            )
            if category == "not_checked":
                lines.extend(f"  {remedy}" for remedy in group["remedies"])
            for key, matchers in list(packages.items())[:_UNASSESSED_SHOWN]:
                lines.append(
                    f"  - {unassessed_package_label(key)} (matcher: {', '.join(matchers)})"
                )
            if len(packages) > _UNASSESSED_SHOWN:
                lines.append(
                    f"  - ... and {len(packages) - _UNASSESSED_SHOWN} more; see --output json"
                )
    return lines


def _print_unassessed(console: Console, data: dict[str, Any]) -> None:
    lines = _unassessed_lines(data)
    for index, line in enumerate(lines):
        if not line:
            console.print()
        elif index and not lines[index - 1]:
            console.print(Text(line, style=STYLE_TITLE))
        else:
            console.print(line, markup=False)


_INVENTORY_SHOWN = 10


def _inventory_groups(coverage: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {code: [] for code in sorted(coverage["counts"])}
    for entry in coverage["entries"]:
        groups.setdefault(entry["code"], []).append(entry)
    return groups


def _inventory_coverage_lines(data: dict[str, Any]) -> list[str]:
    """Files the SBOM generator reported as not resolved or not fully read.

    Shown when the SBOM's coverage statement names any, or cannot be interpreted.
    An absent statement, as in SBOMs from other generators, prints nothing.
    """
    coverage = data.get("inventory_coverage")
    if not coverage:
        return []
    if coverage["status"] == "uninterpretable":
        return [
            "",
            "Inventory coverage: could not be interpreted",
            f"The SBOM's inventory coverage statement is not shown: {coverage['detail']}.",
        ]
    total = sum(coverage["counts"].values())
    if coverage["status"] != "reported" or not total:
        return []
    lines = [
        "",
        (
            f"Inventory coverage: incomplete, {total} coverage-gap entries reported by the SBOM "
            "generator"
        ),
        (
            "Dependency targets are ambiguous or missing. Package entries are retained "
            "and no dependency edges were guessed. Exit codes are unchanged."
            if only_dependency_graph_gaps(coverage["counts"])
            else "Packages from these files may be missing from the SBOM, so the vulnerability "
            "counts above do not cover them. Exit codes are unchanged."
        ),
    ]
    for code, entries in _inventory_groups(coverage).items():
        count = coverage["counts"].get(code, 0)
        lines.append(f"- {code_heading(code)} ({code}): {count}")
        for entry in entries[:_INVENTORY_SHOWN]:
            lines.append(f"  - {entry['path']}: {entry['reason']}")
        hidden = count - min(len(entries), _INVENTORY_SHOWN)
        if hidden > 0:
            lines.append(f"  - ... and {hidden} more; see --output json")
    return lines


def _print_inventory_coverage(console: Console, data: dict[str, Any]) -> None:
    lines = _inventory_coverage_lines(data)
    for index, line in enumerate(lines):
        if not line:
            console.print()
        elif index and not lines[index - 1]:
            console.print(Text(line, style=STYLE_TITLE))
        else:
            console.print(line, markup=False)


def _inventory_notifications(data: dict[str, Any], sbom_uri: str) -> list[dict[str, Any]]:
    coverage = data.get("inventory_coverage")
    if not coverage:
        return []
    location = [{"physicalLocation": {"artifactLocation": {"uri": sbom_uri}}}]
    if coverage["status"] == "uninterpretable":
        return [
            {
                "level": "warning",
                "descriptor": {"id": "craevidence/inventory-coverage/uninterpretable"},
                "message": {
                    "text": "The SBOM inventory coverage statement could not be interpreted: "
                    f"{coverage['detail']}."
                },
                "locations": location,
            }
        ]
    if coverage["status"] != "reported":
        return []
    notifications = []
    for code, entries in _inventory_groups(coverage).items():
        count = coverage["counts"].get(code, 0)
        if not count:
            continue
        # Only a dependency manifest is reported at most once; other codes can count a file
        # once per reporting component.
        unit = (
            "dependency manifest(s)" if code == CODE_DECLARED_UNRESOLVED else "coverage-gap entries"
        )
        detail = (
            "Dependency targets are ambiguous or missing. Package entries are retained "
            "and no dependency edges were guessed."
            if code == CODE_DEPENDENCY_GRAPH_UNRESOLVED
            else "Packages from these files may be missing from the SBOM."
        )
        notifications.append(
            {
                "level": "warning",
                "descriptor": {"id": f"craevidence/inventory-coverage/{code}"},
                "message": {
                    "text": f"{code_heading(code)} ({code}): {count} {unit} reported by the "
                    f"SBOM generator. {detail}"
                },
                "locations": location,
                "properties": {"entries": entries, "count": count},
            }
        )
    return notifications


def _sarif_invocations(data: dict[str, Any], sbom_uri: str) -> list[dict[str, Any]]:
    """Packages the engine did not check, and files the SBOM generator reported, as
    tool execution notifications.

    They describe the run, not the analysed SBOM, so they are never results.
    """
    notifications = []
    for category, heading, level, prefix in _UNASSESSED_SECTIONS:
        for reason, group in unassessed_groups(data, category).items():
            text = (
                f"{heading}, {_unassessed_reason_label(reason)} ({reason}): "
                f"{package_count(len(group['packages']))}. {' '.join(group['remedies'])}"
            )
            notifications.append(
                {
                    "level": level,
                    "descriptor": {"id": f"craevidence/{prefix}/{reason}"},
                    "message": {"text": text},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": sbom_uri}}}],
                    "properties": {"packages": group["entries"]},
                }
            )
    notifications.extend(_inventory_notifications(data, sbom_uri))
    if not notifications:
        return []
    return [
        {
            "executionSuccessful": all(item["level"] != "error" for item in notifications),
            "toolExecutionNotifications": notifications,
        }
    ]


def _identifier_coverage_lines(data: dict[str, Any]) -> list[str]:
    """Plain-text lines for identifier field presence when it is measured.

    Printed for both complete and incomplete coverage, not only when partial:
    a reader who never sees this line cannot tell full field presence apart
    from a CLI version that does not measure it.
    """
    coverage = data.get("identifier_coverage")
    if not coverage:
        return []
    return [
        (
            "Identifier field presence: "
            f"{coverage['components_with_identifier_field']}/"
            f"{coverage['total_components']} components contain a non-blank "
            "PURL or CPE string."
        ),
        coverage["note"],
    ]


def _print_identifier_coverage(console: Console, data: dict[str, Any]) -> None:
    for line in _identifier_coverage_lines(data):
        console.print(line, style=STYLE_MUTED)


def _sarif(data: dict[str, Any], sbom_uri: str = "sbom.json") -> dict[str, Any]:
    results = []
    for finding in data["findings"]:
        level = "error" if finding["severity"] in {"critical", "high"} else "warning"
        results.append(
            {
                "ruleId": finding["id"],
                "level": level,
                "message": {
                    "text": f"{finding['package']} {finding.get('version') or ''}: "
                    f"{finding.get('title') or finding['id']}"
                },
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": sbom_uri}}}],
                "properties": finding,
            }
        )
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "craevidence local check",
                "informationUri": "https://craevidence.com",
                "properties": {
                    "coverage": data["coverage"],
                    "identifierCoverage": data.get("identifier_coverage"),
                    "provenance": data["provenance"],
                    "attributions": data["attributions"],
                    "vexSuppressions": data.get("suppressions") or [],
                    "indicativeCandidates": data.get("indicative_findings") or [],
                    "inventoryCoverage": data.get("inventory_coverage"),
                    "sbomObservations": data.get("sbom_observations"),
                    "sbomGraphObservations": data.get("sbom_graph_observations"),
                    "advisory": data["advisory"],
                },
            }
        },
        "results": results,
    }
    invocations = _sarif_invocations(data, sbom_uri)
    if invocations:
        run["invocations"] = invocations
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }


def _top_actions(data: dict[str, Any]) -> list[str]:
    findings = data["findings"]
    if not findings:
        return ["- Keep the SBOM and vulnerability source snapshots current."]
    actions = []
    for finding in _top_action_records(data):
        fixed_text = (
            f" upgrade to {', '.join(finding['fixed_versions'][:3])}"
            if finding["fixed_versions"]
            else " triage and verify whether an upstream fix applies"
        )
        marks = []
        if finding.get("known_exploited") is True:
            marks.append("known-exploited")
        epss_label = _epss_label(finding, data["coverage"])
        if epss_label:
            marks.append(epss_label)
        mark_text = f" [{', '.join(marks)}]" if marks else ""
        actions.append(
            f"- {finding['package']} {finding.get('version') or ''}{mark_text}:{fixed_text}"
        )
    return actions


def _sbom_observation_lines(data: dict[str, Any], verbose: bool = False) -> list[str]:
    observations = data.get("sbom_observations")
    if observations is None:
        return []
    versions = observations["version_fields"]
    identifiers = observations["identifier_fields"]["without_nonblank_identifier"]
    labels = {
        "absent": "Version field absent",
        "null": "Version field explicitly null",
        "blank": "Version field blank",
        "invalid_type": "Version field is not a string",
    }
    groups = [(label, versions[state]) for state, label in labels.items()]
    groups.append(("No nonblank PURL/CPE counted", identifiers))
    lines = []
    for label, group in groups:
        if not group["count"]:
            continue
        locations = ", ".join(group["locations"])
        if group["omitted"]:
            locations += f"; {group['omitted']} more"
        lines.append(f"{label}: {group['count']} ({locations}).")
    if any(versions[state]["count"] for state in ("absent", "null", "blank")):
        lines.append(
            "Add the resolved component version from lock or build metadata when available."
        )
    if versions["invalid_type"]["count"]:
        lines.append(
            "Correct the field from authoritative package metadata; "
            "do not stringify an object or guess a release."
        )
    if any(versions[state]["count"] for state in labels):
        lines.append("A version in a PURL or CPE is assessed separately by the scanner.")
    if identifiers["count"]:
        lines.append(
            "Review the component's identifier fields using authoritative package metadata."
        )
    if not lines:
        if not verbose:
            return []
        count = observations["component_count"]
        if count:
            lines.append(
                f"All {count} parsed components have nonblank version strings and "
                "a nonblank PURL or CPE counted by this check."
            )
        else:
            lines.append("Inspected 0 component entries.")
    lines.append(
        "These field observations do not establish inventory completeness or scanner coverage."
    )
    return ["", "SBOM observations", *lines]


def _print_sbom_observations(
    console: Console, data: dict[str, Any], verbose: bool = False
) -> None:
    lines = _sbom_observation_lines(data, verbose)
    if not lines:
        return
    console.print()
    console.print(Text(lines[1], style=STYLE_TITLE))
    for line in lines[2:]:
        console.print(line, markup=False)


def _osv_partial_lines(data: dict[str, Any]) -> list[str]:
    for source in data["coverage"]:
        if source["source"] == "osv.dev" and source["status"] == "partial":
            detail = source["detail"]
            return ["OSV.dev coverage is partial." + (f" {detail}" if detail else "")]
    return []


def _sbom_graph_observation_lines(data: dict[str, Any], verbose: bool = False) -> list[str]:
    observations = data.get("sbom_graph_observations")
    if observations is None:
        return []
    status = observations["status"]
    lines = []
    if status in {"not_assessed", "uninterpretable"}:
        if status == "not_assessed" and not verbose:
            return []
        limitation = observations["limitation"]
        label = "Not assessed" if status == "not_assessed" else "Could not interpret this scope"
        lines.append(f"{label}: {limitation['code']} at {limitation['location']}.")
    else:
        groups = (
            ("Repeated local definition occurrences", "repeated_local_identifiers",
             "Assign distinct local SPDXIDs and update their references."),
            (
                "Unresolved local relationship endpoint occurrences",
                "unresolved_local_relationship_endpoints",
                "Correct the endpoint or supply its intended local definition.",
            ),
        )
        for label, key, remedy in groups:
            group = observations[key]
            if not group["count"]:
                continue
            locations = ", ".join(group["locations"])
            if group["omitted"]:
                locations += f"; {group['omitted']} more"
            lines.append(f"{label}: {group['count']} ({locations}).")
            lines.append(remedy)
        if not lines:
            if not verbose:
                return []
            lines.append(
                f"Inspected {observations['definition_occurrences']} local definition occurrences "
                f"and {observations['local_relationship_endpoint_occurrences']} local relationship "
                f"endpoint occurrences; relationships member {observations['relationships_state']}."
            )
    lines.append(
        "These local definition and relationship endpoint observations do not validate the SBOM "
        "or establish inventory completeness, dependency meaning or scanner coverage."
    )
    return ["", "SPDX 2.3 graph observations", *lines]


def _print_sbom_graph_observations(
    console: Console, data: dict[str, Any], verbose: bool = False
) -> None:
    lines = _sbom_graph_observation_lines(data, verbose)
    if not lines:
        return
    console.print()
    console.print(Text(lines[1], style=STYLE_TITLE))
    for line in lines[2:]:
        console.print(line, markup=False)
