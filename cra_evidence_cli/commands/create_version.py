"""Create a draft product version without uploading new evidence.

Useful before any SBOM exists, for example to create the version that
``code-check --upload`` will attach local source-code findings to.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import date
from typing import Any, NoReturn

import click
from rich.console import Console

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.display import warn_unsupported_output_format
from cra_evidence_cli.exceptions import CRAEvidenceError, ValidationError

console = Console()
err_console = Console(stderr=True)

RELEASE_TYPES = ["feature", "security_patch", "maintenance"]


def _fail(e: CRAEvidenceError, output_format: str) -> NoReturn:
    """Print a command error and exit with its code.

    In ``--output json`` mode diagnostics go to stderr only, so stdout is
    always either valid JSON or empty and a machine consumer can tell success
    from failure without parsing text. Text mode prints to the normal console.
    """
    target = err_console if output_format == "json" else console
    target.print(f"[red]Error:[/red] {e}")
    if hasattr(e, "request_id") and e.request_id:
        target.print(f"[dim]Request ID: {e.request_id}[/dim]")
    sys.exit(e.exit_code)


def _parse_iso_date(value: str | None, flag: str) -> str | None:
    """Return an ISO YYYY-MM-DD date string, or raise ValidationError."""
    if value is None:
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        parsed = None
    if parsed is None or parsed.isoformat() != value:
        msg = f"{flag} must be an ISO date in the form YYYY-MM-DD, for example 2026-03-31."
        raise ValidationError(msg)
    return value


def _render_text(result: dict[str, Any], product: str) -> None:
    created = bool(result.get("created"))
    headline = "Product version created" if created else "Product version reused"
    console.print(f"\n[green]{headline}[/green]")
    console.print(f"Product: {product}")
    console.print(f"Version: {result.get('version_number', '')}")
    console.print(f"State: {result.get('release_state', 'unknown')}")
    if created:
        console.print("New evidence: none uploaded")
        console.print("Product-level documents may be linked automatically")
    else:
        # Describing the existing version's evidence would require a separate
        # lookup that this command does not perform.
        console.print("Evidence: not changed by this command")
    console.print("Nothing was scanned, released, or approved.\n")


@click.command("create-version")
@click.option(
    "--product",
    required=True,
    help="Product slug or ID. The product must already exist.",
)
@click.option(
    "--version",
    "version_number",
    required=True,
    help="Version number to create.",
)
@click.option(
    "--release-type",
    "release_type",
    default=None,
    type=click.Choice(RELEASE_TYPES, case_sensitive=False),
    help="Release type. Defaults to feature on the server when not passed.",
)
@click.option(
    "--environment",
    "environment",
    default=None,
    help=(
        "Environment slug for the version. A slug your organisation does not "
        "have yet is created with the development retention tier."
    ),
)
@click.option(
    "--release-notes",
    "release_notes",
    default=None,
    help="Release notes for the version.",
)
@click.option(
    "--release-date",
    "release_date",
    default=None,
    help="Release date as YYYY-MM-DD.",
)
@click.option(
    "--end-of-support-date",
    "end_of_support_date",
    default=None,
    help="End-of-support date as YYYY-MM-DD.",
)
@click.option(
    "--external-url",
    "external_url",
    default=None,
    help="External link for this version, such as a release page.",
)
@click.option(
    "--inherit-from",
    "inherit_from",
    default=None,
    help=(
        "Version number or ID whose eligible compliance artifacts should be "
        "carried over. Inheritance happens only when this flag is passed."
    ),
)
@click.option(
    "--reuse-existing",
    "reuse_existing",
    is_flag=True,
    default=False,
    help=(
        "Return the existing version instead of failing when the product "
        "already has this version number."
    ),
)
@click.pass_context
def create_version(
    ctx: click.Context,
    product: str,
    version_number: str,
    release_type: str | None,
    environment: str | None,
    release_notes: str | None,
    release_date: str | None,
    end_of_support_date: str | None,
    external_url: str | None,
    inherit_from: str | None,
    reuse_existing: bool,
) -> None:
    """Create a draft version of an existing product.

    Creates the product version without uploading new evidence. CRA Evidence
    automatically links reusable product-level documents and templates. No
    vulnerability scan runs, no release state is changed, and no risk
    assessment or due diligence is approved. Upload version evidence
    separately.

    The product must already exist. Product creation carries classification,
    ownership, and compliance context, so this command never creates one.

    Additional eligible artifacts are carried over from an earlier version
    only when --inherit-from is passed.

    An existing version number is an error by default. Pass --reuse-existing to
    return the existing version instead; the output reports whether the version
    was created or reused.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    if output_format not in ("text", "json"):
        warn_unsupported_output_format(output_format, ("text", "json"))
        output_format = "text"

    try:
        release_date = _parse_iso_date(release_date, "--release-date")
        end_of_support_date = _parse_iso_date(end_of_support_date, "--end-of-support-date")

        validate_config(config)

        client = CRAEvidenceClient(config)

        result = asyncio.run(
            client.create_product_version(
                product=product,
                version=version_number,
                release_type=release_type.lower() if release_type else None,
                environment=environment,
                release_notes=release_notes,
                release_date=release_date,
                end_of_support_date=end_of_support_date,
                external_url=external_url,
                inherit_from=inherit_from,
                reuse_existing=reuse_existing,
            )
        )

        if output_format == "json":
            console.print_json(json.dumps(result, indent=2))
        else:
            _render_text(result, product)

    except CRAEvidenceError as e:
        _fail(e, output_format)
