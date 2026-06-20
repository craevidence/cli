"""
Export command - Export technical file bundle.
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
err_console = Console(stderr=True)

# Valid export formats
EXPORT_FORMATS = ["technical-file", "compliance-report", "sbom-data"]


def _sanitize_filename(name: str) -> str:
    """Remove path traversal characters from a filename component."""
    return name.replace("/", "_").replace("..", "_").replace("\x00", "")


@click.command("export")
@click.option(
    "--product",
    required=True,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "version_number",
    required=True,
    help="Version number",
)
@click.option(
    "--format",
    "export_format",
    type=click.Choice(EXPORT_FORMATS, case_sensitive=False),
    default="technical-file",
    help="Export format (default: technical-file)",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(path_type=Path),
    help="Output file path (auto-generated if not specified)",
)
@click.pass_context
def export(
    ctx: click.Context,
    product: str,
    version_number: str,
    export_format: str,
    output_path: Path | None,
) -> None:
    """
    Export technical file bundle for a version.

    Exports:
    - technical-file: Complete CRA technical file (Annex VII) as ZIP
    - compliance-report: Compliance status report as PDF
    - sbom-data: SBOM data in original format

    """
    config = ctx.obj["config"]
    output_format = config.output_format

    # Generate default output path if not specified
    if not output_path:
        extension = {
            "technical-file": "zip",
            "compliance-report": "pdf",
            "sbom-data": "json",
        }.get(export_format, "zip")
        safe_product = _sanitize_filename(product)
        safe_version = _sanitize_filename(version_number)
        output_path = Path(f"{safe_product}-{safe_version}-{export_format}.{extension}")

    try:
        validate_config(config)

        err_console.print(f"[cyan]Exporting {export_format}[/cyan]")

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.download_export(
                product=product,
                version=version_number,
                export_format=export_format,
                output_path=output_path,
            )
        )

        # Output
        if output_format == "json":
            console.print_json(json.dumps(data, indent=2))
        else:
            size_kb = data.get("size_bytes", 0) / 1024
            console.print(
                f"\n[green]Export complete[/green]\n"
                f"File: {data.get('file_path', output_path)}\n"
                f"Size: {size_kb:.1f} KB\n"
                f"Format: {export_format}\n"
            )

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
