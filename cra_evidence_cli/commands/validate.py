"""
Validate command for SBOM files.
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import CRAEvidenceError

console = Console()


@click.command("validate")
@click.option(
    "--sbom",
    "sbom_path",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to SBOM file to validate",
)
@click.pass_context
def validate_sbom_command(
    ctx: click.Context,
    sbom_path: Path,
) -> None:
    """Validate an SBOM file against the CRA Evidence ingestion pipeline."""
    config = ctx.obj["config"]

    try:
        validate_config(config)

        client = CRAEvidenceClient(config)

        result = asyncio.run(client.validate_sbom(sbom_path))

        if config.output_format == "json":
            console.print_json(json.dumps(result, indent=2))
            return

        # Text output
        valid = result.get("valid", False)
        if valid:
            console.print("[bold green]Valid[/bold green]")
        else:
            console.print("[bold red]Invalid[/bold red]")

        fmt = result.get("format")
        spec = result.get("spec_version")
        if fmt or spec:
            console.print(f"Format: {fmt or 'unknown'}  Spec: {spec or 'unknown'}")

        component_count = result.get("component_count")
        purl_pct = result.get("purl_coverage_pct")
        if component_count is not None:
            console.print(f"Packages: {component_count}  PURL coverage: {purl_pct}%")

        versionless = result.get("versionless_count", 0) or 0
        if versionless > 0:
            console.print(
                f"[yellow]Warning:[/yellow] {versionless} versionless package(s) "
                "will be skipped by scanner"
            )

        for warning in result.get("warnings") or []:
            console.print(f"[yellow]Warning:[/yellow] {warning}")

        for error in result.get("errors") or []:
            console.print(f"[red]Error:[/red] {error}")

        if not valid:
            sys.exit(1)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
