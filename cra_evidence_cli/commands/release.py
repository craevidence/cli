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
from cra_evidence_cli.coverage_gaps import print_coverage_gaps, read_coverage_gaps
from cra_evidence_cli.exceptions import CRAEvidenceError

console = Console()

# Valid release states accepted by the API.
RELEASE_STATES = ["draft", "pending_review", "approved", "released", "deprecated", "end_of_life"]

RELEASE_ANYWAY_REASON_MIN = 10
RELEASE_ANYWAY_REASON_MAX = 2000


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
@click.option(
    "--release-anyway",
    "release_anyway",
    is_flag=True,
    default=False,
    help=(
        "With --state released: release even though a vulnerability scan problem "
        "blocks the release. Requires --reason. The reason and the scan problems "
        "are recorded with the release."
    ),
)
@click.option(
    "--reason",
    "reason",
    default=None,
    help=(
        "Reason for releasing despite the scan problems, 10 to 2000 characters. "
        "Only valid with --release-anyway."
    ),
)
@click.pass_context
def set_release_state(
    ctx: click.Context,
    product: str,
    version_number: str,
    state: str,
    superseded_by: str | None,
    release_anyway: bool,
    reason: str | None,
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

    --release-anyway --reason TEXT asks to release despite vulnerability scan
    problems only; every other release check still applies.

    """
    if superseded_by and state.lower() not in ("deprecated", "end_of_life"):
        msg = "--superseded-by is only valid with --state deprecated or --state end_of_life."
        raise click.UsageError(msg)
    if reason is not None and not release_anyway:
        msg = "--reason is only valid with --release-anyway."
        raise click.UsageError(msg)
    if release_anyway:
        if state.lower() != "released":
            msg = "--release-anyway is only valid with --state released."
            raise click.UsageError(msg)
        length = len((reason or "").strip())
        if not RELEASE_ANYWAY_REASON_MIN <= length <= RELEASE_ANYWAY_REASON_MAX:
            msg = (
                "--release-anyway requires --reason with 10 to 2000 characters, "
                "not counting leading and trailing spaces."
            )
            raise click.UsageError(msg)

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
                release_anyway_reason=reason if release_anyway else None,
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
                if state.lower() == "deprecated":
                    console.print(
                        f"[cyan]Superseded by:[/cyan] {superseded_by} (version archived)\n"
                    )
                else:
                    console.print(
                        f"[cyan]Superseded by:[/cyan] {superseded_by}\n"
                    )
            _print_release_scan_record(data, release_anyway)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


def _print_release_scan_record(data: dict, release_anyway: bool) -> None:
    recorded = data.get("release_anyway_recorded")
    if recorded is True:
        console.print(
            "Released anyway: your reason and the scan problems were recorded "
            "with the release.\n"
        )
    elif release_anyway and recorded is False:
        console.print(
            "No scan problem blocked this release, so no release-anyway reason "
            "was recorded.\n"
        )
    elif release_anyway:
        console.print(
            "[yellow]The server did not confirm that the release-anyway reason "
            "was recorded.[/yellow]\n"
        )
    gaps = read_coverage_gaps(data.get("coverage_gaps"))
    if gaps.state != "absent":
        print_coverage_gaps(console, gaps, heading="[bold]Recorded with the release:[/bold]")
        console.print()
