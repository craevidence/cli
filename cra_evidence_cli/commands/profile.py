"""
CRA Profile commands - set and show the CRA compliance profile for a product.

The CRA profile defines product-level defaults for compliance fields that are
applied to new versions when they are created (outside of inheritance).

Supports three modes:
  1. Interactive  - prompts for each field (--product only)
  2. From version - copies CRA settings from an existing version (--from-version)
  3. Direct flags - non-interactive CI/CD mode (explicit flag values)
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

# Valid conformity assessment types accepted by the API.
CONFORMITY_TYPES = [
    "self_assessment",
    "third_party_type_examination",
    "third_party_full_qa",
    "eu_certification",
]

CONFORMITY_TYPE_LABELS = {
    "self_assessment": "Self Assessment (Article 32)",
    "third_party_type_examination": "Third-Party Type Examination (Module B, Article 33)",
    "third_party_full_qa": "Third-Party Full QA (Module H, Article 33)",
    "eu_certification": "EU Type Examination / Certification (Article 34)",
}

# All valid attestation keys accepted by the API.
ALL_ATTESTATION_KEYS = [
    "risk_based_design_confirmed",
    "no_known_vulns_confirmed",
    "secure_updates_confirmed",
    "vulnerability_info_sharing_confirmed",
    "secure_by_default_confirmed",
    "confidentiality_confirmed",
    "integrity_confirmed",
    "data_minimisation_confirmed",
    "availability_confirmed",
    "service_availability_confirmed",
    "attack_surface_reviewed",
    "mitigation_confirmed",
    "logging_confirmed",
    "security_updates_ensured",
    "credential_protection_confirmed",
    "hardware_credential_mgmt_confirmed",
    "access_control_confirmed",
    "unauthorised_access_protection_confirmed",
    "security_event_notification_confirmed",
    "auto_updates_confirmed",
]

ATTESTATION_SECTIONS = {
    "Security Design": ["risk_based_design_confirmed", "no_known_vulns_confirmed"],
    "Security Properties": [
        "secure_by_default_confirmed", "confidentiality_confirmed",
        "integrity_confirmed", "data_minimisation_confirmed",
        "availability_confirmed", "service_availability_confirmed",
        "attack_surface_reviewed", "mitigation_confirmed",
        "logging_confirmed", "security_updates_ensured",
    ],
    "Identity & Access": [
        "credential_protection_confirmed", "hardware_credential_mgmt_confirmed",
        "access_control_confirmed", "unauthorised_access_protection_confirmed",
        "security_event_notification_confirmed",
    ],
    "Updates & Vuln Handling": [
        "secure_updates_confirmed", "auto_updates_confirmed",
        "vulnerability_info_sharing_confirmed",
    ],
}

ATTESTATION_LABELS = {
    "risk_based_design_confirmed": "Risk-based cybersecurity design (1)",
    "no_known_vulns_confirmed": "No known exploitable vulnerabilities (2)",
    "secure_by_default_confirmed": "Secure by default configuration (2.1)",
    "confidentiality_confirmed": "Data confidentiality / encryption (2.2)",
    "integrity_confirmed": "Data integrity protection (2.3)",
    "data_minimisation_confirmed": "Data minimisation (2.4)",
    "availability_confirmed": "Availability measures (2.5)",
    "service_availability_confirmed": "Service availability (2.6)",
    "attack_surface_reviewed": "Attack surface minimisation (2.7)",
    "mitigation_confirmed": "Security mitigations (2.8)",
    "logging_confirmed": "Logging capability (2.9)",
    "security_updates_ensured": "Security updates ensured (2.10)",
    "credential_protection_confirmed": "Credential protection (3.1)",
    "hardware_credential_mgmt_confirmed": "Hardware credential management (3.2)",
    "access_control_confirmed": "Access control mechanisms (3.3)",
    "unauthorised_access_protection_confirmed": "Unauthorised access protection (3.4)",
    "security_event_notification_confirmed": "Security event notification (3.5)",
    "secure_updates_confirmed": "Secure update mechanism (4.1)",
    "auto_updates_confirmed": "Automatic updates capability (4.2)",
    "vulnerability_info_sharing_confirmed": "Vulnerability information sharing (4.3)",
}


def _format_bool(value: bool | None) -> str:
    """Format a boolean value for display."""
    if value is None:
        return "[dim]not set[/dim]"
    return "[green]yes[/green]" if value else "[red]no[/red]"


def format_profile_output(product_name: str, profile: dict | None, output_format: str) -> None:
    if output_format == "json":
        console.print_json(json.dumps(profile or {}, indent=2))
        return

    console.print(f"\n[bold]CRA Compliance Profile: {product_name}[/bold]\n")

    if not profile:
        console.print(
            "[dim]No CRA profile configured. "
            "Use 'craevidence setup-profile' to set one.[/dim]"
        )
        console.print()
        return

    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan", min_width=32)
    table.add_column("Value", style="white")

    # Conformity assessment type
    conformity_type = profile.get("default_conformity_assessment_type")
    if conformity_type:
        label = CONFORMITY_TYPE_LABELS.get(conformity_type, conformity_type)
        table.add_row("Default Conformity Assessment Type", label)
    else:
        table.add_row("Default Conformity Assessment Type", "[dim]not set[/dim]")

    # Support period
    support_years = profile.get("default_support_period_years")
    if support_years is not None:
        years_label = str(support_years)
        if support_years < 5:
            years_label = f"[yellow]{support_years} (below CRA minimum of 5)[/yellow]"
        table.add_row("Default Support Period", f"{years_label} years")
    else:
        table.add_row("Default Support Period", "[dim]not set[/dim]")

    # Boolean flags
    table.add_row("CE Marking (default)", _format_bool(profile.get("ce_marking_standard")))
    table.add_row(
        "Support Period Communicated (default)",
        _format_bool(profile.get("support_period_communicated")),
    )
    table.add_row(
        "Secure by Default Confirmed (default)",
        _format_bool(profile.get("secure_by_default_confirmed")),
    )

    # Webhook
    webhook_url = profile.get("webhook_url")
    webhook_secret = profile.get("webhook_secret")
    if webhook_url:
        table.add_row("Webhook URL", webhook_url)
        if webhook_secret:
            table.add_row("Webhook Secret", "[green]set (HMAC-SHA256 signing enabled)[/green]")
        else:
            table.add_row("Webhook Secret", "[dim]not set (unsigned webhooks)[/dim]")
    else:
        table.add_row("Webhook URL", "[dim]not set[/dim]")

    console.print(table)

    # Attestations section
    attestations = profile.get("attestations", {})
    if attestations:
        console.print()
        att_table = Table(title="Annex I Attestations", show_header=True, box=None)
        att_table.add_column("Section", style="cyan", min_width=24)
        att_table.add_column("Requirement", style="white", min_width=40)
        att_table.add_column("Status", style="white", min_width=10)

        for section_name, keys in ATTESTATION_SECTIONS.items():
            first = True
            for key in keys:
                label = ATTESTATION_LABELS.get(key, key)
                value = attestations.get(key)
                if value is True:
                    status = "[green]Confirmed[/green]"
                elif value == "not_applicable" or value == "n/a":
                    status = "[dim]N/A[/dim]"
                elif value is False:
                    status = "[red]Pending[/red]"
                else:
                    status = "[dim]not set[/dim]"
                att_table.add_row(
                    section_name if first else "",
                    label,
                    status,
                )
                first = False

        console.print(att_table)

    console.print()


@click.command("setup-profile")
@click.option(
    "--product",
    required=True,
    help="Product slug or ID",
)
@click.option(
    "--from-version",
    "from_version",
    default=None,
    help=(
        "Copy CRA settings from this version number. "
        "Populates the profile from the version's current compliance settings."
    ),
)
@click.option(
    "--conformity-type",
    "conformity_type",
    type=click.Choice(CONFORMITY_TYPES, case_sensitive=False),
    default=None,
    help="Default conformity assessment type for new versions",
)
@click.option(
    "--support-years",
    "support_years",
    type=int,
    default=None,
    help="Default support period in years (CRA minimum is 5 years)",
)
@click.option(
    "--ce-marking/--no-ce-marking",
    "ce_marking",
    default=None,
    help="Default CE marking applied flag for new versions",
)
@click.option(
    "--support-communicated/--no-support-communicated",
    "support_communicated",
    default=None,
    help="Default support period communicated flag for new versions",
)
@click.option(
    "--secure-by-default/--no-secure-by-default",
    "secure_by_default",
    default=None,
    help="Default secure-by-default confirmed flag for new versions",
)
@click.option(
    "--webhook-url",
    "webhook_url",
    default=None,
    help=(
        "URL to POST a JSON notification to when CRA status changes. "
        "Must start with https:// (or http:// for local testing). "
        "Pass an empty string to clear an existing webhook URL."
    ),
)
@click.option(
    "--webhook-secret",
    "webhook_secret",
    default=None,
    help=(
        "Secret used to sign webhook payloads with HMAC-SHA256. "
        "The signature is sent as the X-CRA-Signature header. "
        "Leave unset to keep an existing secret. "
        "Pass an empty string to clear the secret (unsigned webhooks). "
        "Treat this value like a password."
    ),
)
@click.option(
    "--confirm-all",
    "confirm_all",
    is_flag=True,
    default=False,
    help="Set all applicable Annex I attestations to confirmed",
)
@click.option(
    "--attestation",
    "attestation_pairs",
    multiple=True,
    help=(
        "Set individual attestation. Format: KEY=true|false. "
        "Can be repeated. Example: --attestation risk_based_design_confirmed=true"
    ),
)
@click.pass_context
def setup_profile(
    ctx: click.Context,
    product: str,
    from_version: str | None,
    conformity_type: str | None,
    support_years: int | None,
    ce_marking: bool | None,
    support_communicated: bool | None,
    secure_by_default: bool | None,
    webhook_url: str | None,
    webhook_secret: str | None,
    confirm_all: bool,
    attestation_pairs: tuple,
) -> None:
    """
    Set or update the CRA compliance profile for a product.

    The profile defines product-level defaults applied to new versions created
    outside inheritance. Run without flags for prompts, use --from-version to
    copy existing settings, or pass explicit flags for CI. Webhook payloads are
    signed with HMAC-SHA256 when --webhook-secret is set.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        # Mode 2: --from-version
        if from_version is not None:
            if ctx.obj.get("verbose"):
                console.print(f"[dim]Loading CRA settings from {product} v{from_version}...[/dim]")

            version_data = asyncio.run(
                client.get_version_cra_settings(product=product, version=from_version)
            )

            # Map version fields to profile fields
            conformity_type = conformity_type or version_data.get("conformity_assessment_type")
            if ce_marking is None:
                ce_marking = version_data.get("ce_marking_applied")
            if support_communicated is None:
                support_communicated = version_data.get("support_period_communicated")
            if secure_by_default is None:
                secure_by_default = version_data.get("secure_by_default_confirmed")
            # support_period_years is not a version field; don't attempt to read it

            if ctx.obj.get("verbose"):
                console.print(
                    f"[dim]Loaded: conformity_type={conformity_type}, "
                    f"ce_marking={ce_marking}, "
                    f"support_communicated={support_communicated}, "
                    f"secure_by_default={secure_by_default}[/dim]"
                )

        # Mode 1: Interactive - if no flags were provided and no --from-version
        any_flag_set = any(
            v is not None
            for v in [conformity_type, support_years, ce_marking, support_communicated,
                      secure_by_default, webhook_url, webhook_secret]
        ) or confirm_all or attestation_pairs

        if not any_flag_set and from_version is None:
            console.print("\n[bold]CRA Compliance Profile Setup[/bold]")
            console.print(
                "[dim]Configure product-level defaults for CRA compliance. "
                "These defaults are applied to new versions when created "
                "outside of inheritance.[/dim]\n"
            )

            # Conformity assessment type
            conformity_type = click.prompt(
                "Default conformity assessment type",
                type=click.Choice(CONFORMITY_TYPES, case_sensitive=False),
                default="self_assessment",
                show_choices=True,
            )

            # Support period
            support_years = click.prompt(
                "Default support period (years, CRA minimum is 5)",
                type=int,
                default=5,
            )

            # Boolean flags
            ce_marking = click.confirm("CE marking applied by default?", default=False)
            support_communicated = click.confirm(
                "Support period communicated to end users by default?", default=False
            )
            secure_by_default = click.confirm(
                "Secure-by-default confirmed by default?", default=False
            )

        # Validate support years if provided
        if support_years is not None:
            if support_years < 1 or support_years > 30:
                msg = "Support period must be between 1 and 30 years."
                raise click.UsageError(msg)
            if support_years < 5:
                console.print(
                    "[yellow]Warning: CRA Article 13(8) sets a minimum support period of "
                    "5 years (unless the product's expected use is shorter). You have "
                    "entered fewer than 5 years.[/yellow]"
                )

        # Build profile payload (only include fields that were set)
        profile: dict = {}
        if conformity_type is not None:
            profile["default_conformity_assessment_type"] = conformity_type
        if support_years is not None:
            profile["default_support_period_years"] = support_years
        if ce_marking is not None:
            profile["ce_marking_standard"] = ce_marking
        if support_communicated is not None:
            profile["support_period_communicated"] = support_communicated
        if secure_by_default is not None:
            profile["secure_by_default_confirmed"] = secure_by_default
        # Webhook: None means "don't touch", empty string means "clear"
        if webhook_url is not None:
            profile["webhook_url"] = webhook_url  # empty string clears the stored value
        if webhook_secret is not None:
            profile["webhook_secret"] = webhook_secret  # empty string clears

        # Attestations: --confirm-all or individual --attestation KEY=VALUE
        attestations: dict = {}
        if confirm_all:
            for key in ALL_ATTESTATION_KEYS:
                attestations[key] = True
            if ctx.obj.get("verbose"):
                console.print("[dim]Setting all attestations to confirmed[/dim]")
        if attestation_pairs:
            for pair in attestation_pairs:
                if "=" not in pair:
                    msg = f"Invalid attestation format: '{pair}'. Use KEY=true or KEY=false."
                    raise click.UsageError(
                        msg
                    )
                key, val = pair.split("=", 1)
                key = key.strip()
                val = val.strip().lower()
                if key not in ALL_ATTESTATION_KEYS:
                    msg = (
                        f"Unknown attestation key: '{key}'. "
                        f"Valid keys: {', '.join(ALL_ATTESTATION_KEYS[:5])}..."
                    )
                    raise click.UsageError(
                        msg
                    )
                attestations[key] = val in ("true", "1", "yes", "on")
        if attestations:
            profile["attestations"] = attestations

        if not profile:
            msg = (
                "No profile fields specified. Provide at least one flag or run "
                "without flags for interactive mode."
            )
            raise click.UsageError(
                msg
            )

        if ctx.obj.get("verbose"):
            # Redact webhook_secret before printing to avoid leaking credentials
            verbose_profile = {
                k: "****" if k == "webhook_secret" and v else v
                for k, v in profile.items()
            }
            console.print(f"[dim]Updating CRA profile for {product}: {verbose_profile}[/dim]")

        data = asyncio.run(
            client.update_cra_profile(product=product, profile=profile)
        )

        if output_format == "json":
            console.print_json(json.dumps(data, indent=2))
        else:
            console.print("[green]CRA compliance profile updated.[/green]")
            console.print(
                "[dim]New versions created outside of inheritance will use these "
                "defaults.[/dim]"
            )
            format_profile_output(product, data.get("cra_profile"), output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@click.command("show-profile")
@click.option(
    "--product",
    required=True,
    help="Product slug or ID",
)
@click.pass_context
def show_profile(
    ctx: click.Context,
    product: str,
) -> None:
    """
    Show the current CRA compliance profile for a product.

    Displays all configured profile defaults that will be applied to
    new versions created outside of inheritance.

    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)

        if ctx.obj.get("verbose"):
            console.print(f"[dim]Fetching CRA profile for {product}...[/dim]")

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.get_cra_profile(product=product)
        )

        profile = data.get("cra_profile")
        product_id = data.get("product_id", product)

        format_profile_output(str(product_id), profile, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
