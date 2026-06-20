"""
Release state commands - Set release lifecycle state for versions.
"""

import asyncio
import json
import sys

import click
from rich.console import Console

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import CRAEvidenceError

console = Console()

# Valid release states accepted by the API.
RELEASE_STATES = ["draft", "pending_review", "approved", "released", "deprecated", "end_of_life"]


@click.command("release")
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
    "--state",
    required=True,
    type=click.Choice(RELEASE_STATES, case_sensitive=False),
    help="Release lifecycle state",
)
@click.option(
    "--superseded-by",
    "superseded_by",
    default=None,
    help="Version number of the successor version (e.g. v1.1). "
         "Records succession and archives this version. Only valid with deprecated/end_of_life.",
)
@click.pass_context
def set_release_state(
    ctx: click.Context,
    product: str,
    version_number: str,
    state: str,
    superseded_by: str | None,
) -> None:
    """
    Set release lifecycle state for a version.

    States:
    - draft: Initial state, under development
    - pending_review: Submitted for approval
    - approved: Approved but not yet released
    - released: Publicly available
    - deprecated: Superseded by newer version (still supported)
    - end_of_life: No longer supported

    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)

        if ctx.obj.get("verbose"):
            console.print(
                f"[dim]Setting release state for {product} v{version_number} to {state}[/dim]"
            )

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.set_release_state(
                product=product,
                version=version_number,
                state=state.lower(),
                superseded_by=superseded_by,
            )
        )

        # Output
        if output_format == "json":
            console.print_json(json.dumps(data, indent=2))
        else:
            console.print(
                f"\n[green]Release state updated[/green]\n"
                f"Product: {product}\n"
                f"Version: {version_number}\n"
                f"State: [bold]{state}[/bold]\n"
            )
            if superseded_by:
                console.print(
                    f"[cyan]Superseded by:[/cyan] {superseded_by} (version archived)\n"
                )

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
