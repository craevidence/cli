"""Configure public trust material for build provenance attestations."""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import CRAEvidenceError

console = Console()
# Errors go to stderr so stdout stays valid JSON (or empty) in --output json
# mode, matching the ra commands.
err_console = Console(stderr=True)


def format_trusted_key_output(data: dict, output_format: str) -> None:
    """Render the registered public key metadata returned by the API."""
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    table = Table(title="Attestation trust key registered")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Name", str(data.get("name", "N/A")))
    table.add_row("Key ID", str(data.get("id", "N/A")))
    table.add_row("Algorithm", str(data.get("key_algorithm", "N/A")))
    table.add_row("Fingerprint", str(data.get("key_fingerprint", "N/A")))
    console.print(table)


def format_attestation_verification_output(
    data: dict,
    output_format: str,
) -> None:
    """Render the stored attestation verification result."""
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    table = Table(title="Build Provenance verification")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Product", str(data.get("product", "N/A")))
    table.add_row("Version", str(data.get("version", "N/A")))
    table.add_row("Attestation ID", str(data.get("attestation_id", "N/A")))
    table.add_row("Status", str(data.get("status", "N/A")))
    table.add_row("Trust policy", str(data.get("trust_policy", "N/A")))
    console.print(table)


@click.command("trust-attestation-key")
@click.option(
    "--name",
    required=True,
    help="Name for the trusted build key",
)
@click.option(
    "--public-key",
    "public_key_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Cosign ECDSA P-256 public key file",
)
@click.pass_context
def trust_attestation_key(
    ctx: click.Context,
    name: str,
    public_key_path: Path,
) -> None:
    """Trust a Cosign public key for Build Provenance verification.

    Run this once with an organisation admin credential that has config:write.
    PEM private key files are rejected before the key is sent to
    CRA Evidence.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)
        data = asyncio.run(
            client.trust_attestation_key(
                name=name,
                public_key_path=public_key_path,
            )
        )
        format_trusted_key_output(data, output_format)
    except CRAEvidenceError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        if getattr(exc, "request_id", None):
            err_console.print(f"[dim]Request ID: {exc.request_id}[/dim]")
        sys.exit(exc.exit_code)


@click.command("verify-attestation")
@click.option("--product", required=True, help="Product slug or ID")
@click.option(
    "--version",
    "version_number",
    required=True,
    help="Existing version number",
)
@click.option(
    "--attestation",
    "attestation_id",
    default=None,
    help="Specific attestation ID; defaults to the latest for the version",
)
@click.pass_context
def verify_attestation(
    ctx: click.Context,
    product: str,
    version_number: str,
    attestation_id: str | None,
) -> None:
    """Verify stored Build Provenance using organisation trust.

    Run this after trust-attestation-key to re-check an existing pending
    Bundle or raw DSSE. Product slugs and version numbers are resolved by the
    CLI, so an attestation ID is not required for the normal workflow.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)
        data = asyncio.run(
            client.verify_attestation(
                product=product,
                version=version_number,
                attestation_id=attestation_id,
            )
        )
        format_attestation_verification_output(data, output_format)
        if data.get("status") != "valid":
            sys.exit(22)
    except CRAEvidenceError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        if getattr(exc, "request_id", None):
            err_console.print(f"[dim]Request ID: {exc.request_id}[/dim]")
        sys.exit(exc.exit_code)
