"""
Maturity command - advisory CRA secure-development maturity scorecard.

Read-only. Prints the same scorecard the web UI shows. Advisory: it has no
`--fail-on` gate, so it NEVER fails a pipeline based on the maturity result.
(Genuine errors - bad credentials, product not found, network/5xx - still exit
non-zero so misconfiguration is not silently hidden.)
"""

import asyncio
import json
import sys

import click
from rich.console import Console
from rich.markup import escape

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import CRAEvidenceError
from cra_evidence_cli.local.disclaimer import advisory_block

console = Console()

_STATUS_GLYPH = {
    "met": "[green]✓[/green]",
    "not_met": "[red]✗[/red]",
    "not_applicable": "[dim]-[/dim]",
    "unknown": "[yellow]?[/yellow]",
}


def render_maturity_practices(data: dict) -> str:
    """Render practices as a flat list that stays readable at any width.

    One line per practice (status glyph + title), then an indented
    ``CRA ref: detail`` line. Scope and confidence stay in the JSON output.
    """
    practices = data.get("practices", [])
    met = sum(1 for p in practices if p.get("status") == "met")
    applicable = sum(1 for p in practices if p.get("status") != "not_applicable")
    lines = [f"[bold]Practices[/bold] ({met}/{applicable} met)"]
    for p in practices:
        glyph = _STATUS_GLYPH.get(p.get("status", "unknown"), "[white]?[/white]")
        lines.append(f"  {glyph} {escape(p.get('title', ''))}")
        refs = ", ".join(p.get("cra_refs", []))
        meta = ": ".join(part for part in (refs, p.get("detail", "")) if part)
        if meta:
            lines.append(f"      [dim]{escape(meta)}[/dim]")
    return "\n".join(lines)


@click.command("maturity")
@click.option("--product", required=True, help="Product slug or ID")
@click.option(
    "--version",
    "version_number",
    required=False,
    default=None,
    help="Version number (optional; defaults to the product's reference version)",
)
@click.pass_context
def maturity(ctx: click.Context, product: str, version_number: str | None) -> None:
    """
    Show the advisory CRA secure-development maturity scorecard.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        if version_number:
            data = asyncio.run(
                client.get_version_maturity(product=product, version=version_number)
            )
        else:
            data = asyncio.run(client.get_product_maturity(product=product))

        if output_format == "json":
            if isinstance(data, dict):
                data["advisory"] = advisory_block()
            console.print_json(json.dumps(data, indent=2))
            return

        console.print(
            f"[bold]{escape(data.get('scope_label', ''))}[/bold]: "
            f"{data.get('overall_band', '')} ({data.get('overall_pct', 0)}%)"
        )
        ref = data.get("reference_version_label")
        if ref:
            released = " (released)" if data.get("reference_version_released") else ""
            console.print(f"[dim]Reference version: {escape(ref)}{released}[/dim]")

        for fam in data.get("families", []):
            console.print(
                f"  {fam.get('label')}: {fam.get('coverage_pct')}% "
                f"({fam.get('met')}/{fam.get('applicable')}) - {fam.get('band')}"
            )

        console.print(render_maturity_practices(data))
        console.print(
            "[dim]Inspired by OWASP SAMM v2 (CC BY-SA 4.0). "
            "Advisory only - not a readiness verdict.[/dim]"
        )

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(getattr(e, "exit_code", 1))
