"""
Compare command - Compare two versions of a product.
"""

import asyncio
import json
import sys

import click
from rich.console import Console
from rich.table import Table

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import CRAEvidenceError

console = Console()


def format_compare_output(data: dict, output_format: str) -> None:
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    # Text format
    console.print("\n[bold]Version Comparison[/bold]\n")

    # Summary
    version_a = data.get("version_a", {})
    version_b = data.get("version_b", {})
    console.print(
        f"Comparing: {version_a.get('number', 'N/A')} -> {version_b.get('number', 'N/A')}\n"
    )

    # Component changes summary
    summary = data.get("summary", {})
    table = Table(show_header=False, box=None)
    table.add_column("Change", style="cyan")
    table.add_column("Count", style="white")

    added = summary.get("added", 0)
    removed = summary.get("removed", 0)
    modified = summary.get("modified", 0)
    unchanged = summary.get("unchanged", 0)

    if added > 0:
        table.add_row("Added", f"[green]+{added}[/green]")
    else:
        table.add_row("Added", f"[dim]+{added}[/dim]")

    if removed > 0:
        table.add_row("Removed", f"[red]-{removed}[/red]")
    else:
        table.add_row("Removed", f"[dim]-{removed}[/dim]")

    if modified > 0:
        table.add_row("Modified", f"[yellow]~{modified}[/yellow]")
    else:
        table.add_row("Modified", f"[dim]~{modified}[/dim]")

    table.add_row("Unchanged", f"[dim]{unchanged}[/dim]")

    console.print(table)

    # Detailed changes
    if "changes" in data:
        changes = data["changes"]

        if changes.get("added"):
            console.print("\n[bold green]Added Packages:[/bold green]")
            for comp in changes["added"][:10]:  # Limit to 10
                name = comp.get("name", "Unknown")
                version = comp.get("version", "")
                console.print(f"  [green]+[/green] {name} {version}")
            if len(changes["added"]) > 10:
                console.print(f"  [dim]... and {len(changes['added']) - 10} more[/dim]")

        if changes.get("removed"):
            console.print("\n[bold red]Removed Packages:[/bold red]")
            for comp in changes["removed"][:10]:  # Limit to 10
                name = comp.get("name", "Unknown")
                version = comp.get("version", "")
                console.print(f"  [red]-[/red] {name} {version}")
            if len(changes["removed"]) > 10:
                console.print(f"  [dim]... and {len(changes['removed']) - 10} more[/dim]")

        if changes.get("modified"):
            console.print("\n[bold yellow]Modified Packages:[/bold yellow]")
            for comp in changes["modified"][:10]:  # Limit to 10
                name = comp.get("name", "Unknown")
                old_ver = comp.get("old_version", "")
                new_ver = comp.get("new_version", "")
                console.print(f"  [yellow]~[/yellow] {name}: {old_ver} -> {new_ver}")
            if len(changes["modified"]) > 10:
                console.print(f"  [dim]... and {len(changes['modified']) - 10} more[/dim]")

    # Vulnerability diff
    if data.get("vulnerability_diff"):
        vuln_diff = data["vulnerability_diff"]
        console.print("\n[bold]Vulnerability Changes:[/bold]")

        new_vulns = vuln_diff.get("new", 0)
        fixed_vulns = vuln_diff.get("fixed", 0)

        if new_vulns > 0:
            console.print(f"  New: [red]+{new_vulns}[/red]")
        else:
            console.print(f"  New: [dim]+{new_vulns}[/dim]")

        if fixed_vulns > 0:
            console.print(f"  Fixed: [green]-{fixed_vulns}[/green]")
        else:
            console.print(f"  Fixed: [dim]-{fixed_vulns}[/dim]")

    console.print()


@click.command("compare")
@click.option(
    "--product",
    required=True,
    help="Product slug or ID",
)
@click.option(
    "--version-a",
    required=True,
    help="First version number (base)",
)
@click.option(
    "--version-b",
    required=True,
    help="Second version number (target)",
)
@click.pass_context
def compare(
    ctx: click.Context,
    product: str,
    version_a: str,
    version_b: str,
) -> None:
    """
    Compare two versions of a product.

    Shows differences in:
    - Components (added, removed, modified)
    - Vulnerabilities (new, fixed)

    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)

        if ctx.obj.get("verbose"):
            console.print(
                f"[dim]Comparing {product} v{version_a} with v{version_b}[/dim]"
            )

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.compare_versions(
                product=product,
                version_a=version_a,
                version_b=version_b,
            )
        )

        format_compare_output(data, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
