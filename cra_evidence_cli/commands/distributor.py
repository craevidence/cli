"""
Distributor Verification commands for CRA Article 20 compliance.

These commands help distributors perform due care verification
before making products available on the EU market.
"""

import asyncio
import json
import sys

import click
from rich.console import Console
from rich.table import Table

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.display import humanize_identifier
from cra_evidence_cli.exceptions import CRAEvidenceError

console = Console()
err_console = Console(stderr=True)

# Valid evidence types for CE marking
EVIDENCE_TYPES = ["photo", "document", "reference", "attestation", "not_applicable"]


def format_verification_output(data: dict, output_format: str) -> None:
    """Format and display verification output."""
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    # Text format - create a nice display
    console.print()

    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Verification ID", data.get("verification_number", "N/A"))
    table.add_row("Product", data.get("product_name", data.get("external_product_name", "N/A")))

    status = data.get("status", "draft")
    status_style = {
        "draft": "yellow",
        "verified": "green",
        "issues_found": "yellow",
        "stop_ship": "red bold",
    }.get(status, "white")
    table.add_row("Status", f"[{status_style}]{humanize_identifier(status)}[/{status_style}]")

    completion = data.get("completion_percentage", 0)
    comp_style = "green" if completion == 100 else "yellow" if completion >= 50 else "red"
    table.add_row("Completion", f"[{comp_style}]{completion}%[/{comp_style}]")

    # Checklist status
    table.add_row("", "")
    table.add_row("[bold]Checklist[/bold]", "")

    checklist_steps = data.get("checklist_steps", [])
    for step_info in checklist_steps:
        if not step_info.get("applicable", True):
            continue
        completed = step_info.get("completed", False)
        icon = "[green]\u2713[/green]" if completed else "[red]\u2717[/red]"
        label = step_info.get("label") or step_info.get("step", "").replace("_", " ").title()
        table.add_row(f"  {label}", icon)

    console.print(table)
    console.print()


def format_list_output(data: list, output_format: str) -> None:
    """Format and display list of verifications."""
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    if not data:
        console.print("[dim]No verifications found.[/dim]")
        return

    table = Table(title="Distributor Verifications")
    table.add_column("ID", style="cyan")
    table.add_column("Product")
    table.add_column("Status")
    table.add_column("Completion")
    table.add_column("Created")

    for item in data:
        status = item.get("status", "draft")
        status_style = {
            "draft": "yellow",
            "verified": "green",
            "issues_found": "yellow",
            "stop_ship": "red",
        }.get(status, "white")

        completion = item.get("completion_percentage", 0)
        comp_style = "green" if completion == 100 else "yellow" if completion >= 50 else "red"

        table.add_row(
            item.get("verification_number", "N/A"),
            item.get("product_name", "N/A")[:20],
            f"[{status_style}]{humanize_identifier(status)}[/{status_style}]",
            f"[{comp_style}]{completion}%[/{comp_style}]",
            item.get("created_at", "N/A")[:10] if item.get("created_at") else "N/A",
        )

    console.print(table)


@click.group("distributor")
def distributor() -> None:
    """
    Distributor verification commands (CRA Article 20).

    These commands help distributors perform due care verification
    before making products available on the EU market.
    """
    pass


@distributor.command("create")
@click.option(
    "--product",
    help="Product slug or ID (for products in CRA Evidence)",
)
@click.option(
    "--version",
    "version_number",
    help="Version number (for products in CRA Evidence)",
)
@click.option(
    "--external-product",
    "external_product_name",
    help="External product name (for products not in CRA Evidence)",
)
@click.option(
    "--external-manufacturer",
    "external_manufacturer_name",
    help="External manufacturer name",
)
@click.option(
    "--product-identifier",
    help="Product identifier (SKU, model number)",
)
@click.pass_context
def create_verification(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    external_product_name: str | None,
    external_manufacturer_name: str | None,
    product_identifier: str | None,
) -> None:
    """
    Create a new distributor verification checklist.

    You can either link to a product in CRA Evidence (--product, --version)
    or create a verification for an external product (--external-product).

    """
    config = ctx.obj["config"]
    output_format = config.output_format

    # Validate: either internal or external product
    if not product and not external_product_name:
        msg = "Either --product or --external-product is required."
        raise click.UsageError(
            msg
        )
    if product and external_product_name:
        msg = "Cannot use both --product and --external-product."
        raise click.UsageError(
            msg
        )
    if product and not version_number:
        msg = "--version is required when using --product."
        raise click.UsageError(
            msg
        )

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.create_distributor_verification(
                product=product,
                version=version_number,
                external_product_name=external_product_name,
                external_manufacturer_name=external_manufacturer_name,
                product_identifier=product_identifier,
            )
        )

        err_console.print("[green]Verification created[/green]")
        format_verification_output(data, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@distributor.command("update")
@click.argument("verification_id")
@click.option(
    "--ce-marking/--no-ce-marking",
    "ce_marking_present",
    default=None,
    help="CE marking verification status",
)
@click.option(
    "--ce-location",
    help="Location of CE marking (e.g., 'on product', 'on packaging')",
)
@click.option(
    "--ce-evidence-type",
    type=click.Choice(EVIDENCE_TYPES, case_sensitive=False),
    help="Type of evidence for CE marking",
)
@click.option(
    "--ce-reference-url",
    help="URL to manufacturer CE documentation",
)
@click.option(
    "--ce-attestation",
    help="Attestation notes for CE marking verification",
)
@click.option(
    "--ce-notes",
    help="Additional notes for CE marking",
)
@click.option(
    "--eu-doc/--no-eu-doc",
    "eu_doc_accessible",
    default=None,
    help="EU Declaration of Conformity accessible",
)
@click.option(
    "--eu-doc-location",
    help="Location of EU DoC (e.g., 'in box', 'website URL')",
)
@click.option(
    "--manufacturer-contact/--no-manufacturer-contact",
    "manufacturer_contact_present",
    default=None,
    help="Manufacturer contact information present",
)
@click.option(
    "--manufacturer-name",
    help="Manufacturer name",
)
@click.option(
    "--manufacturer-address",
    help="Manufacturer address",
)
@click.option(
    "--from-outside-eu/--from-eu",
    "product_from_outside_eu",
    default=None,
    help="Product is from outside EU",
)
@click.option(
    "--importer-contact/--no-importer-contact",
    "importer_contact_present",
    default=None,
    help="Importer contact information present",
)
@click.option(
    "--importer-name",
    help="Importer name",
)
@click.option(
    "--no-issues/--has-issues",
    "no_obvious_issues",
    default=None,
    help="No obvious compliance issues found",
)
@click.option(
    "--issues-description",
    help="Description of any issues found",
)
@click.pass_context
def update_verification(
    ctx: click.Context,
    verification_id: str,
    ce_marking_present: bool | None,
    ce_location: str | None,
    ce_evidence_type: str | None,
    ce_reference_url: str | None,
    ce_attestation: str | None,
    ce_notes: str | None,
    eu_doc_accessible: bool | None,
    eu_doc_location: str | None,
    manufacturer_contact_present: bool | None,
    manufacturer_name: str | None,
    manufacturer_address: str | None,
    product_from_outside_eu: bool | None,
    importer_contact_present: bool | None,
    importer_name: str | None,
    no_obvious_issues: bool | None,
    issues_description: str | None,
) -> None:
    """
    Update a distributor verification checklist.

    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        # Build update data
        update_data = {}

        # CE marking updates
        if ce_marking_present is not None:
            update_data["ce_marking_present"] = ce_marking_present
        if ce_location:
            update_data["ce_marking_location"] = ce_location
        if ce_evidence_type:
            update_data["ce_marking_evidence_type"] = ce_evidence_type
        if ce_reference_url:
            update_data["ce_marking_reference_url"] = ce_reference_url
        if ce_attestation:
            update_data["ce_marking_attestation_notes"] = ce_attestation
        if ce_notes:
            update_data["ce_marking_notes"] = ce_notes

        # EU Doc updates
        if eu_doc_accessible is not None:
            update_data["eu_doc_accessible"] = eu_doc_accessible
        if eu_doc_location:
            update_data["eu_doc_location"] = eu_doc_location

        # Manufacturer updates
        if manufacturer_contact_present is not None:
            update_data["manufacturer_contact_present"] = manufacturer_contact_present
        if manufacturer_name:
            update_data["manufacturer_name"] = manufacturer_name
        if manufacturer_address:
            update_data["manufacturer_address"] = manufacturer_address

        # Importer updates
        if product_from_outside_eu is not None:
            update_data["product_from_outside_eu"] = product_from_outside_eu
        if importer_contact_present is not None:
            update_data["importer_contact_present"] = importer_contact_present
        if importer_name:
            update_data["importer_name"] = importer_name

        # Issues updates
        if no_obvious_issues is not None:
            update_data["no_obvious_issues"] = no_obvious_issues
        if issues_description:
            update_data["issues_description"] = issues_description

        if not update_data:
            msg = "At least one update option is required."
            raise click.UsageError(msg)

        data = asyncio.run(
            client.update_distributor_verification(
                verification_id=verification_id,
                update_data=update_data,
            )
        )

        err_console.print("[green]Verification updated[/green]")
        format_verification_output(data, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@distributor.command("complete")
@click.argument("verification_id")
@click.pass_context
def complete_verification(
    ctx: click.Context,
    verification_id: str,
) -> None:
    """
    Mark a verification as complete (verified).

    All checklist items must be completed before marking as verified.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.complete_distributor_verification(verification_id)
        )

        err_console.print("[green]Verification marked complete[/green]")
        format_verification_output(data, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@distributor.command("stop-ship")
@click.argument("verification_id")
@click.option(
    "--reason",
    required=True,
    help="Reason for stop-ship (significant risk description)",
)
@click.pass_context
def stop_ship(
    ctx: click.Context,
    verification_id: str,
    reason: str,
) -> None:
    """
    Mark a product for stop-ship due to significant risk.

    Per CRA Article 20(3), distributors must stop distribution
    if they believe a product presents a significant risk.

    Note: To notify authorities or manufacturers, use the web interface.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.stop_ship_verification(
                verification_id=verification_id,
                reason=reason,
            )
        )

        err_console.print("[red bold]Product marked for stop-ship[/red bold]")
        err_console.print(f"[red]Reason: {reason}[/red]")
        err_console.print(
            "[red]Per CRA Article 20(3), this product must not be made available "
            "on the EU market until the issue is resolved.[/red]"
        )

        format_verification_output(data, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@distributor.command("list")
@click.option(
    "--status",
    type=click.Choice(["draft", "verified", "issues_found", "stop_ship"], case_sensitive=False),
    help="Filter by status",
)
@click.option(
    "--limit",
    type=int,
    default=20,
    help="Maximum number of results (default: 20)",
)
@click.pass_context
def list_verifications(
    ctx: click.Context,
    status: str | None,
    limit: int,
) -> None:
    """
    List distributor verifications.

    """
    config = ctx.obj["config"]
    output_format = config.output_format

    if limit > 100:
        msg = "--limit cannot exceed 100."
        raise click.UsageError(msg)

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.list_distributor_verifications(
                status=status,
                limit=limit,
            )
        )

        format_list_output(data, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@distributor.command("get")
@click.argument("verification_id")
@click.pass_context
def get_verification(
    ctx: click.Context,
    verification_id: str,
) -> None:
    """
    Get details of a specific verification.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.get_distributor_verification(verification_id)
        )

        format_verification_output(data, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
