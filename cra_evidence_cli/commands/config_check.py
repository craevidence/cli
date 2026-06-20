"""Secure-by-default configuration audit command (advisory, no API key required).

Surfaces a curated set of insecure-default and attack-surface patterns in
Dockerfiles, Terraform, and Kubernetes/Compose manifests. Deliberately narrow:
it is NOT a full IaC scanner (use Checkov, KICS, or hadolint for breadth), and a
clean result does not prove a secure-by-default configuration. Advisory by
default (exit 0); pass --fail-on-match to gate CI (exit 19).
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from cra_evidence_cli.local.config_audit import ConfigReport, evaluate
from cra_evidence_cli.local.disclaimer import (
    advisory_block,
)

_CRA_NOTE = (
    "Findings are candidates to review, not a determination. This is not a full "
    "IaC scanner; use Checkov, KICS, or hadolint for breadth. A clean result does "
    "not prove a secure-by-default configuration."
)

_CONFIG_EXIT_CODE = 19


def _render_text(report: ConfigReport, verbose: bool = False) -> str:
    lines = ["Secure-by-default configuration audit"]
    lines.append(
        f"Files scanned: {report.files_scanned} | Findings: {len(report.findings)}"
    )
    if report.capped:
        lines.append(
            f"Note: scan stopped at the {len(report.findings)}-finding cap; results are partial."
        )
    for finding in report.findings:
        where = f"{finding.location}:{finding.line}" if finding.line else finding.location
        lines.append(f"- {finding.rule}: {finding.message} ({where})")
    if not report.findings:
        lines.append("No curated misconfiguration patterns matched.")
    if verbose:
        lines.append(_CRA_NOTE)
    return "\n".join(lines)


def _render_json(report: ConfigReport) -> str:
    return json.dumps(
        {
            "schema_version": "craevidence.config_audit.v1",
            "report": report.to_dict(),
            "advisory": advisory_block(),
        },
        indent=2,
    )


def _render_sarif(report: ConfigReport) -> str:
    results = []
    for finding in report.findings:
        physical: dict = {"artifactLocation": {"uri": finding.location}}
        if finding.line:
            physical["region"] = {"startLine": finding.line}
        results.append(
            {
                "ruleId": f"CONFIG-{finding.rule}",
                "level": "warning",
                "message": {"text": finding.message},
                "locations": [{"physicalLocation": physical}],
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
                        "name": "craevidence config-check",
                        "informationUri": "https://craevidence.com",
                        "properties": {"advisory": advisory_block()},
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


@click.command("config-check")
@click.argument(
    "path",
    default=Path("."),
    type=click.Path(exists=True, path_type=Path),
    required=False,
)
@click.option(
    "--fail-on-match",
    "fail_on_match",
    is_flag=True,
    default=False,
    help="Exit 19 if any finding is reported (for CI gating). Advisory (exit 0) by default.",
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
    help="Show scope notes. The default output is concise.",
)
@click.pass_context
def config_check(
    ctx: click.Context,
    path: Path,
    fail_on_match: bool,
    output_file: Path | None,
    verbose_opt: bool = False,
) -> None:
    """Audit Dockerfile/Terraform/Kubernetes config for insecure defaults (no API key needed).

    Surfaces a curated set of secure-by-default and attack-surface patterns
    (root containers, privileged/host-network pods, world-open ingress, public
    storage ACLs). It is deliberately narrow and is not a Checkov/KICS/hadolint
    replacement; use those for full coverage.

    Findings are candidates to review, not a determination. A clean result does
    not prove a secure-by-default configuration. Advisory by default and exits 0
    even when findings are reported; pass --fail-on-match to exit 19 so a CI job
    can gate on it.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = verbose_opt or ctx.obj.get("verbose", False)

    report = evaluate(path)

    if output_format == "json":
        rendered = _render_json(report)
    elif output_format == "sarif":
        rendered = _render_sarif(report)
    else:
        rendered = _render_text(report, verbose)

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered, encoding="utf-8")
        click.echo(f"Config audit report written to {output_file}.", err=True)
    else:
        click.echo(rendered)

    if fail_on_match and report.findings:
        ctx.exit(_CONFIG_EXIT_CODE)
