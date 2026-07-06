"""End-of-life check command (advisory, no API key required).

Parses an SBOM - either from a file or generated from a directory - then
checks each component against the endoflife.date public API. Components
not listed by endoflife.date are counted as "no endoflife.date data" and
are not evaluated for EOL status.

This command is advisory only and always exits 0 on a successful run, even
when past-EOL components are found. EOL status does not gate CI pipelines;
it is informational. Only genuine parse or usage errors produce a non-zero
exit code.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from cra_evidence_cli.display import warn_unsupported_output_format
from cra_evidence_cli.local.disclaimer import (
    advisory_block,
)
from cra_evidence_cli.local.eol import EolReport, evaluate_components
from cra_evidence_cli.local.sbom import SBOMParseError, load_sbom


def _render_text(report: EolReport, verbose: bool = False) -> str:
    lines = ["End-of-life check"]

    lines.append(
        f"Components: {report.total_components} | "
        f"Recognized by endoflife.date: {report.recognized} | "
        f"Active support: {report.active_count} | "
        f"Security-only: {report.security_only_count} | "
        f"Unknown support: {report.unknown_count} | "
        f"Past EOL: {report.eol_count}"
    )
    eol_findings = [f for f in report.findings if f.is_eol]
    for finding in eol_findings:
        lines.append(
            f"- {finding.component} {finding.version or ''} is past EOL "
            f"(cycle {finding.cycle}, eol {finding.eol_date}) "
            f"[product: {finding.product}]"
        )
    security_only = [f for f in report.findings if f.status == "security-only"]
    for finding in security_only:
        lines.append(
            f"- {finding.component} {finding.version or ''} is in security-only "
            f"support (active support ended {finding.support_date}, "
            f"cycle {finding.cycle}) [product: {finding.product}]"
        )
    unknown = [f for f in report.findings if f.status == "unknown"]
    for finding in unknown:
        version = f" {finding.version}" if finding.version else ""
        lines.append(
            f"- {finding.component}{version} is recognized as {finding.product}, "
            "but no matching support cycle was found."
        )

    lines.append(
        "EOL status is not the same as vulnerable. "
        "Components not listed by endoflife.date were not evaluated."
    )
    if verbose:
        lines.append(
            "Upstream dependency EOL can be one input when reviewing product support "
            "periods. This report does not produce or verify the manufacturer's "
            "published support commitment. Verify against the vendor's stated "
            "support dates."
        )
    return "\n".join(lines)


def _render_json(report: EolReport) -> str:
    return json.dumps(
        {
            "schema_version": "craevidence.eol.v1",
            "report": report.to_dict(),
            "advisory": advisory_block(),
        },
        indent=2,
    )


def _render_sarif(report: EolReport, sbom_uri: str = "sbom.json") -> str:
    results = []
    location = {"physicalLocation": {"artifactLocation": {"uri": sbom_uri}}}
    for finding in report.findings:
        if finding.is_eol:
            message = (
                f"{finding.component} {finding.version or ''} is past end-of-life "
                f"(cycle {finding.cycle}, eol {finding.eol_date})"
            )
            results.append(
                {
                    "ruleId": f"EOL-{finding.product}",
                    "level": "warning",
                    "message": {"text": message},
                    "locations": [location],
                    "properties": finding.to_dict(),
                }
            )
        elif finding.status == "security-only":
            message = (
                f"{finding.component} {finding.version or ''} is in security-only "
                f"support (active support ended {finding.support_date})"
            )
            results.append(
                {
                    "ruleId": f"EOL-SUPPORT-{finding.product}",
                    "level": "note",
                    "message": {"text": message},
                    "locations": [location],
                    "properties": finding.to_dict(),
                }
            )

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "craevidence eol-check",
                        "informationUri": "https://craevidence.com",
                        "properties": {
                            "advisory": advisory_block(),
                        },
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


@click.command("eol-check")
@click.argument(
    "path",
    default=Path("."),
    type=click.Path(path_type=Path),
    required=False,
)
@click.option(
    "--sbom",
    "sbom_file",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to an existing SBOM file (CycloneDX or SPDX JSON).",
)
@click.option(
    "-o",
    "--output-file",
    "output_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Write output to a file instead of stdout.",
)
@click.option(
    "-v",
    "--verbose",
    "verbose_opt",
    is_flag=True,
    help="Show the CRA support-period framing. The default output is concise.",
)
@click.pass_context
def eol_check(
    ctx: click.Context,
    path: Path,
    sbom_file: Path | None,
    output_file: Path | None,
    verbose_opt: bool = False,
) -> None:
    """Check SBOM components for end-of-life status (advisory, no API key needed).

    Resolves components from an SBOM file or by generating one from a
    directory, then checks each against the endoflife.date public API.
    Components not tracked by endoflife.date are counted as having no
    endoflife.date data available - that is the expected outcome for most
    SBOM components.

    This check is advisory only. EOL status is not the same as vulnerable.
    The command always exits 0 on a successful run, even when past-EOL
    components are found.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = verbose_opt or ctx.obj.get("verbose", False)

    warn_unsupported_output_format(output_format, ("text", "json", "sarif"))

    # Track the SBOM URI for SARIF output (never use absolute temp paths).
    sbom_uri = "sbom.json"

    # Resolve components from SBOM or directory.
    try:
        if sbom_file is not None:
            components, _ = load_sbom(sbom_file)
            sbom_str = str(sbom_file)
            if not sbom_str.startswith("/tmp") and not sbom_str.startswith("/var/tmp"):  # noqa: S108
                sbom_uri = sbom_str
        elif path.is_file():
            components, _ = load_sbom(path)
            path_str = str(path)
            if not path_str.startswith("/tmp") and not path_str.startswith("/var/tmp"):  # noqa: S108
                sbom_uri = path_str
        else:
            from cra_evidence_cli.sbom_generator import (
                SBOMGenerationError,
                cleanup_generated_sbom,
                generate_sbom_from_directory,
            )
            try:
                gen = generate_sbom_from_directory(
                    str(path), verbose=verbose, offline=True
                )
                try:
                    components, _ = load_sbom(gen.file_path)
                    # Directory-generated SBOMs live in a temp path; keep sbom_uri as fallback.
                finally:
                    # One private temp directory per generated SBOM; remove it
                    # once parsed so runs do not accumulate sbom_* directories.
                    cleanup_generated_sbom(gen.file_path)
            except SBOMGenerationError as exc:
                raise click.ClickException(str(exc)) from exc
    except SBOMParseError as exc:
        raise click.ClickException(str(exc)) from exc

    # Evaluate against endoflife.date. A failure to reach the product list
    # is caught here and reported as a warning; the command still exits 0.
    try:
        report = evaluate_components(components)
    except Exception as exc:
        click.echo(
            f"Warning: could not reach endoflife.date ({exc}). "
            "Skipping EOL lookup.",
            err=True,
        )
        report = EolReport(
            findings=[],
            total_components=len(components),
            recognized=0,
            eol_count=0,
        )

    # Render output.
    if output_format == "json":
        rendered = _render_json(report)
    elif output_format == "sarif":
        rendered = _render_sarif(report, sbom_uri=sbom_uri)
    else:
        rendered = _render_text(report, verbose)

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered, encoding="utf-8")
        click.echo(f"EOL report written to {output_file}.", err=True)
    else:
        click.echo(rendered)
