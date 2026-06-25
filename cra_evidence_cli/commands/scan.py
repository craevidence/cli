"""
Scan command - Trigger vulnerability scan for a version.
"""

import asyncio
import json
import sys

import click
from rich.console import Console
from rich.table import Table

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import CRAEvidenceError, VulnerabilityThresholdExceeded
from cra_evidence_cli.repo_config import resolve_identity

console = Console()
err_console = Console(stderr=True)


def format_scan_output(data: dict, output_format: str) -> None:
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    # Text format
    console.print("\n[bold]Vulnerability Scan Results[/bold]\n")

    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    # Scan status
    status = data.get("status", "unknown")
    status_style = {
        "completed": "green",
        "in_progress": "yellow",
        "failed": "red",
        "queued": "dim",
    }.get(status, "white")
    table.add_row("Status", f"[{status_style}]{status}[/{status_style}]")

    if data.get("scan_id"):
        table.add_row("Scan ID", data["scan_id"])

    # Vulnerabilities
    if data.get("vulnerabilities"):
        vulns = data["vulnerabilities"]
        table.add_row("", "")
        table.add_row("[bold]Vulnerabilities[/bold]", "")

        critical = vulns.get("critical", 0)
        high = vulns.get("high", 0)
        medium = vulns.get("medium", 0)
        low = vulns.get("low", 0)

        if critical > 0:
            table.add_row("  Critical", f"[red bold]{critical}[/red bold]")
        else:
            table.add_row("  Critical", f"[dim]{critical}[/dim]")

        if high > 0:
            table.add_row("  High", f"[red]{high}[/red]")
        else:
            table.add_row("  High", f"[dim]{high}[/dim]")

        if medium > 0:
            table.add_row("  Medium", f"[yellow]{medium}[/yellow]")
        else:
            table.add_row("  Medium", f"[dim]{medium}[/dim]")

        table.add_row("  Low", f"[dim]{low}[/dim]")

    console.print(table)
    console.print()


def check_vulnerability_threshold(
    data: dict,
    fail_on: str | None,
) -> None:
    if not fail_on or not data.get("vulnerabilities"):
        return

    vulns = data["vulnerabilities"]

    critical = vulns.get("critical", 0)
    high = vulns.get("high", 0)
    medium = vulns.get("medium", 0)

    if critical > 0 and fail_on in ("critical", "high", "medium"):
        msg = "critical"
        raise VulnerabilityThresholdExceeded(msg, critical, exit_code=10)

    if high > 0 and fail_on in ("high", "medium"):
        msg = "high"
        raise VulnerabilityThresholdExceeded(msg, high, exit_code=11)

    if medium > 0 and fail_on == "medium":
        msg = "medium"
        raise VulnerabilityThresholdExceeded(msg, medium, exit_code=12)


@click.command("scan")
@click.option(
    "--product",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "version_number",
    default=None,
    help="Version number",
)
@click.option(
    "--component",
    default=None,
    help=(
        "Optional product component slug. Restricts the scan to the latest "
        "SBOM attributed to this component (multi-repo products). If "
        "omitted, the latest SBOM for the version is used."
    ),
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium"], case_sensitive=False),
    help="Fail if vulnerabilities of this severity or higher are found",
)
@click.pass_context
def scan(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    component: str | None,
    fail_on: str | None,
) -> None:
    """
    Trigger vulnerability scan for a version.

    Scans the SBOM associated with a version for known vulnerabilities
    using the configured vulnerability database.

    Exit codes:
    - 0: Success (no threshold exceeded)
    - 10: Critical vulnerabilities found (with --fail-on critical)
    - 11: High vulnerabilities found (with --fail-on high)
    - 12: Medium vulnerabilities found (with --fail-on medium)

    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        product, version_number, component = resolve_identity(product, version_number, component)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(e.exit_code)

    try:
        validate_config(config)

        client = CRAEvidenceClient(config)

        suffix = f" [{component}]" if component else ""
        err_console.print(
            f"[cyan]Scanning {product} v{version_number}{suffix}...[/cyan]"
        )

        data = asyncio.run(
            client.trigger_scan(
                product=product,
                version=version_number,
                component=component,
            )
        )

        format_scan_output(data, output_format)

        # Check vulnerability threshold
        check_vulnerability_threshold(data, fail_on)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
