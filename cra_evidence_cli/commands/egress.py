"""Command: egress-check -- local advisory scan for remote data-processing indicators.

Scans an SBOM and (when given a project directory) source files to identify
SDKs that transmit data externally and hard-coded external URLs. The scan is
100% local; no network calls are made. Findings are advisory only and always
exit 0 on success.

This tool inventories external-interface and data-flow review candidates. It
does not determine encryption, data minimisation, or GDPR status.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from cra_evidence_cli.display import warn_unsupported_output_format
from cra_evidence_cli.local.disclaimer import (
    advisory_block,
)
from cra_evidence_cli.local.egress import EgressReport, evaluate
from cra_evidence_cli.local.sbom import SBOMParseError, load_sbom

_CRA_MAPPING = "External interface and data-flow review"


def _render_text(report: EgressReport, verbose: bool = False) -> str:
    lines: list[str] = [
        "Remote data processing scan",
        "",
    ]

    # Split SDK hits by category bucket for readability.
    telemetry_categories = {"error-reporting", "analytics", "telemetry"}
    telemetry_sdks = [sdk for sdk in report.sdks if sdk.category in telemetry_categories]
    other_sdks = [sdk for sdk in report.sdks if sdk.category not in telemetry_categories]

    def _section(title: str, sdks: list) -> None:
        # By default only categories with hits are shown; -v lists empties too.
        if sdks:
            lines.append(f"{title} ({len(sdks)}):")
            for sdk in sdks:
                ver = f" {sdk.version}" if sdk.version else ""
                lines.append(f"  - {sdk.name}{ver}  [{sdk.category}]: {sdk.description}")
            lines.append("")
        elif verbose:
            lines.append(f"{title} (0): none detected")
            lines.append("")

    _section("Telemetry / analytics SDKs", telemetry_sdks)
    _section("Cloud / data SDKs", other_sdks)

    if report.network_libs:
        net_lib_str = ", ".join(report.network_libs)
        lines.append(f"Network-capable libraries ({len(report.network_libs)}): {net_lib_str}")
        lines.append("")
    elif verbose:
        lines.append("Network-capable libraries (0): none")
        lines.append("")

    if not report.sdks and not report.network_libs and not verbose:
        lines.append("No telemetry, analytics, cloud, or network SDKs detected.")
        lines.append("")

    if report.source_scanned:
        cap_note = (
            f" (capped at {len(report.endpoints)}; more may exist)"
            if report.endpoints_capped
            else ""
        )
        lines.append(
            f"External endpoints in source (candidates, review): "
            f"{len(report.endpoints)}{cap_note}"
        )
        for ep in report.endpoints[:20]:
            lines.append(f"  - {ep.host}  {ep.file}:{ep.line}")
        if len(report.endpoints) > 20:
            more = len(report.endpoints) - 20
            lines.append(f"  ... and {more} more (use --output json for full list)")
    else:
        lines.append(
            "Source not scanned (pass a project directory to scan source for external endpoints)."
        )

    if verbose:
        lines.append("")
        lines.append(
            "This means your product may expose external interfaces or transmit data externally. "
            "Review the result with your attack-surface and data-flow documentation. "
            "This is not evidence of encryption, minimisation, personal-data processing, "
            "or unlawful processing. GDPR may also apply."
        )

    return "\n".join(lines)


def _render_json(report: EgressReport) -> str:
    return json.dumps(
        {
            "schema_version": "craevidence.egress.v1",
            "report": report.to_dict(),
            "cra_mapping": _CRA_MAPPING,
            "advisory": advisory_block(),
        },
        indent=2,
    )


def _render_sarif(report: EgressReport) -> str:
    results = []

    for sdk in report.sdks:
        rule_id = f"EGRESS-SDK-{sdk.name}"
        results.append(
            {
                "ruleId": rule_id,
                "level": "note",
                "message": {
                    "text": (
                        f"{sdk.name} {sdk.version or ''} [{sdk.category}]: {sdk.description}"
                    ).strip()
                },
                "properties": sdk.to_dict(),
            }
        )

    for ep in report.endpoints:
        results.append(
            {
                "ruleId": "EGRESS-ENDPOINT",
                "level": "note",
                "message": {"text": f"External URL {ep.url} in {ep.file}:{ep.line}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": ep.file},
                            "region": {"startLine": ep.line},
                        }
                    }
                ],
                "properties": ep.to_dict(),
            }
        )

    sarif: dict[str, object] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "craevidence egress-check",
                        "informationUri": "https://craevidence.com",
                        "properties": {
                            "cra_mapping": _CRA_MAPPING,
                            "advisory": advisory_block(),
                        },
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


@click.command("egress-check")
@click.argument("path", required=False, type=click.Path(path_type=Path), default=Path("."))
@click.option(
    "--sbom",
    "sbom_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to an existing CycloneDX or SPDX SBOM file.",
)
@click.option(
    "-o",
    "--output-file",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the report to this file instead of stdout.",
)
@click.option(
    "-v",
    "--verbose",
    "verbose_opt",
    is_flag=True,
    help="Show the CRA attack-surface review note. The default output is concise.",
)
@click.pass_context
def egress_check(
    ctx: click.Context,
    path: Path,
    sbom_file: Path | None,
    output_file: Path | None,
    verbose_opt: bool = False,
) -> None:
    """Scan for remote data-processing indicators (advisory, no API key needed).

    Examines an SBOM for known telemetry, analytics, error-reporting, and
    cloud-provider SDKs, and (when given a project directory) walks source files
    for hard-coded external URLs. No network calls are made.

    This is an inventory for review, not a compliance verdict. Exit code is
    always 0 on a successful run.
    """
    output_format = ctx.obj["config"].output_format
    verbose = verbose_opt or ctx.obj.get("verbose", False)

    components = []
    source_root: Path | None = None

    if sbom_file is not None:
        try:
            components, _ = load_sbom(sbom_file)
        except SBOMParseError as exc:
            msg = str(exc)
            raise click.ClickException(msg) from exc
        # Source tree not provided; layer-3 scan is skipped.
        source_root = None

    elif path.is_file():
        try:
            components, _ = load_sbom(path)
        except SBOMParseError as exc:
            msg = str(exc)
            raise click.ClickException(msg) from exc
        source_root = None

    else:
        # Directory: generate an SBOM offline then also scan source.
        from cra_evidence_cli.sbom_generator import (  # noqa: PLC0415
            SBOMGenerationError,
            cleanup_generated_sbom,
            generate_sbom_from_directory,
        )

        try:
            generated = generate_sbom_from_directory(str(path), verbose=False, offline=True)
        except SBOMGenerationError as exc:
            msg = str(exc)
            raise click.ClickException(msg) from exc
        except Exception as exc:
            msg = str(exc)
            raise click.ClickException(msg) from exc

        try:
            components, _ = load_sbom(generated.file_path)
        except SBOMParseError:
            # A directory with no resolvable dependency manifest yields no
            # components; continue with a source-only egress scan rather than
            # aborting (the source URL scan does not need an SBOM).
            components = []
        finally:
            # One private temp directory per generated SBOM; remove it once
            # parsed so runs do not accumulate sbom_* directories.
            cleanup_generated_sbom(generated.file_path)

        source_root = path

    report = evaluate(components, source_root)

    warn_unsupported_output_format(output_format, ("text", "json", "sarif"))
    if output_format == "json":
        rendered = _render_json(report)
    elif output_format == "sarif":
        rendered = _render_sarif(report)
        if output_file is not None:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(rendered)
            click.echo(f"Wrote sarif report to {output_file}", err=True)
        else:
            click.echo(rendered)
        sys.exit(0)
    else:
        rendered = _render_text(report, verbose)

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered)
        click.echo(f"Wrote {output_format} report to {output_file}", err=True)
    else:
        click.echo(rendered)

    sys.exit(0)
