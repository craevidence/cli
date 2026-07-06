"""Renderers for local no-key check output."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.text import Text

from cra_evidence_cli.local.models import LocalCheckResult
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


def _resolve_sarif_sbom_uri(result: LocalCheckResult) -> str:
    """Resolve the SBOM URI for SARIF physicalLocation entries.

    Returns the user-supplied SBOM path when the run scored an existing SBOM,
    the --sbom-output path when recorded in provenance, or 'sbom.json' as a
    safe fallback. Never returns an absolute temp-directory path.
    """
    if result.sbom_path is not None:
        path_str = str(result.sbom_path)
        if not _is_temp_path(path_str):
            return path_str
    sbom_output = result.provenance.get("sbom_output")
    if sbom_output:
        s = str(sbom_output)
        if not _is_temp_path(s):
            return s
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
        return _markdown(data, verbose)
    return _text(data, verbose)


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
    console.print(_summary_text(data["components"]["count"], summary))

    console.print()
    console.print(Text("Top actions", style=STYLE_TITLE))
    actions = _top_action_records(data)
    if actions:
        for action in actions:
            console.print(_action_text(action))
    else:
        console.print("- Keep the SBOM and vulnerability source snapshots current.")

    _print_suppressions(console, data)
    _print_ignored(console, data)
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
    console.print(Text(data["exit_note"], style=STYLE_MUTED))


def _text(data: dict[str, Any], verbose: bool = False) -> str:
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
            ),
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
                f"- Removed vulnerabilities: {len(removed)}",
            ]
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
                "Run with -v for reviewed dimensions and scope notes; "
                "--output json for the full machine report.",
            ]
        )
    lines.extend(["", data["exit_note"]])
    return "\n".join(lines)


def _markdown(data: dict[str, Any], verbose: bool = False) -> str:
    text = _text(data, verbose)
    return "# " + text.replace("\n\n", "\n\n## ")


def _summary_text(component_count: int, summary: dict[str, int]) -> Text:
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


def _action_text(finding: dict[str, Any]) -> Text:
    text = Text("- ")
    text.append(str(finding["package"]), style=STYLE_TITLE)
    version = finding.get("version")
    if version:
        text.append(f" {version}")
    marks = []
    if finding.get("known_exploited") is True:
        marks.append(("known-exploited", STYLE_BLOCKER))
    epss = finding.get("epss_probability")
    if isinstance(epss, (int, float)):
        marks.append((f"EPSS {epss:.2f}", STYLE_LABEL))
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
    console.print(f"- Removed vulnerabilities: {len(removed)}")


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
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": sbom_uri}}}
                ],
                "properties": finding,
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "craevidence local check",
                        "informationUri": "https://craevidence.com",
                        "properties": {
                            "coverage": data["coverage"],
                            "provenance": data["provenance"],
                            "attributions": data["attributions"],
                            "vexSuppressions": data.get("suppressions") or [],
                            "advisory": data["advisory"],
                        },
                    }
                },
                "results": results,
            }
        ],
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
        epss = finding.get("epss_probability")
        if isinstance(epss, (int, float)):
            marks.append(f"EPSS {epss:.2f}")
        mark_text = f" [{', '.join(marks)}]" if marks else ""
        actions.append(
            f"- {finding['package']} {finding.get('version') or ''}{mark_text}:{fixed_text}"
        )
    return actions
