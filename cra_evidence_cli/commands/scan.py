"""
Scan command - Trigger vulnerability scan for a version.
"""

import asyncio
import json
import sys
import time

import click
from rich.console import Console
from rich.table import Table

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import (
    APIError,
    CRAEvidenceError,
    VulnerabilityThresholdExceeded,
)
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
        "running": "yellow",
        "pending": "yellow",
        "failed": "red",
        "disabled": "dim",
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


def wait_for_scan_completion(
    client: CRAEvidenceClient,
    product: str,
    version: str,
    timeout: int,
    poll_interval: int = 5,
) -> dict:
    """
    Poll the version status endpoint until the scan reaches a terminal state.

    The scan runs asynchronously on the server, so a freshly triggered scan
    reports pending or running until it finishes.

    Args:
        client: API client
        product: Product slug or ID
        version: Version number
        timeout: Maximum seconds to wait for the scan to finish
        poll_interval: Seconds between status checks

    Returns:
        Vulnerability summary (severity counts) from the completed scan

    Raises:
        APIError: If the scan fails or does not finish within the timeout
    """
    deadline = time.monotonic() + timeout
    err_console.print(
        f"[cyan]Waiting for scan to complete (timeout: {timeout}s)...[/cyan]"
    )
    while True:
        status_data = asyncio.run(
            client.get_version_status(product=product, version=version)
        )
        scan_state = status_data.get("scan_state") or "none"
        if scan_state == "completed":
            return status_data.get("vulnerability_summary") or {}
        if scan_state == "failed":
            msg = "Vulnerability scan failed; the --fail-on gate cannot be evaluated."
            raise APIError(message=msg)
        if time.monotonic() >= deadline:
            msg = (
                f"Scan did not complete within {timeout} seconds "
                f"(last state: {scan_state}). Increase --scan-timeout, or gate "
                "in a later pipeline stage with 'craevidence status --fail-on'."
            )
            raise APIError(message=msg)
        err_console.print(
            f"[dim]Scan {scan_state}; checking again in {poll_interval}s...[/dim]"
        )
        time.sleep(poll_interval)


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
@click.option(
    "--scan-timeout",
    "scan_timeout",
    type=click.IntRange(min=1),
    default=300,
    show_default=True,
    help=(
        "Maximum seconds to wait for the scan to finish when --fail-on is "
        "set. The scan runs asynchronously on the server, so the gate polls "
        "the status endpoint until the scan completes or the timeout elapses."
    ),
)
@click.pass_context
def scan(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    component: str | None,
    fail_on: str | None,
    scan_timeout: int,
) -> None:
    """
    Trigger vulnerability scan for a version.

    Scans the SBOM associated with a version for known vulnerabilities
    using the configured vulnerability database. The scan runs
    asynchronously on the server; with --fail-on, the command waits for the
    scan to finish (up to --scan-timeout seconds) before evaluating the gate.

    Exit codes:
    - 0: Success (no threshold exceeded)
    - 3: Scan failed, scan disabled, or scan did not finish before --scan-timeout
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

        # Vulnerability gate: wait for the asynchronous scan to finish,
        # then check the counts against the threshold.
        if fail_on:
            status = data.get("status")
            if status in ("failed", "disabled"):
                msg = (
                    f"Vulnerability scan {status}; the --fail-on gate "
                    "cannot be evaluated."
                )
                raise APIError(message=msg)
            else:
                vuln_summary = wait_for_scan_completion(
                    client, product, version_number, scan_timeout
                )
                check_vulnerability_threshold(
                    {"vulnerabilities": vuln_summary}, fail_on
                )

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
