"""
Main CLI entry point and command group definitions.
"""

import sys

import click
from rich.console import Console

from cra_evidence_cli import __version__
from cra_evidence_cli.commands import (
    assessment,
    check,
    compare,
    components,
    config_check,
    db,
    diagram,
    distributor,
    draft,
    egress,
    eol,
    evidence,
    export,
    gemara,
    maturity,
    profile,
    release,
    scan,
    secrets,
    status,
    upload,
    validate,
    verify,
)
from cra_evidence_cli.commands.status import wait_ready
from cra_evidence_cli.config import CRAEvidenceConfig, load_config
from cra_evidence_cli.exceptions import CRAEvidenceError

console = Console()


@click.group()
@click.option(
    "--api-key",
    envvar="CRA_EVIDENCE_API_KEY",
    help="API key for authentication",
)
@click.option(
    "--url",
    envvar="CRA_EVIDENCE_URL",
    default="https://api.craevidence.com",
    show_default=True,
    help="CRA Evidence API URL",
)
@click.option(
    "--output",
    type=click.Choice(["text", "json", "sarif", "markdown"], case_sensitive=False),
    default="text",
    help="Output format",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--oidc",
    is_flag=True,
    help="Use OIDC authentication (GitHub Actions). Requires id-token: write permission.",
)
@click.version_option(version=__version__, prog_name="craevidence")
@click.pass_context
def cli(
    ctx: click.Context,
    api_key: str | None,
    url: str,
    output: str,
    verbose: bool,
    oidc: bool,
) -> None:
    """
    CRA Evidence CLI - CI/CD integration tool for EU Cyber Resilience Act compliance.

    Upload SBOMs, HBOMs, and VEX documents to CRA Evidence from CI/CD
    pipelines. Use --api-key or CRA_EVIDENCE_API_KEY for API-key
    authentication. In GitHub Actions, --oidc uses the workflow OIDC identity.

    Commit a .cra/evidence.yaml to set the product, component, and version
    source for a repository so upload commands do not need --product or
    --version. Explicit flags and CRA_EVIDENCE_PRODUCT / CRA_EVIDENCE_VERSION /
    CRA_EVIDENCE_COMPONENT override the file.
    """
    ctx.ensure_object(dict)

    try:
        config = load_config(api_key=api_key, url=url, output_format=output, oidc_mode=oidc)
        ctx.obj["config"] = config
        ctx.obj["verbose"] = verbose
    except CRAEvidenceError as e:
        # No-key local family must survive a malformed config / stray bad env
        # var: these commands never validate or use the API key. ``evidence``
        # routes to a fully local checker for its ``check`` subcommand; its
        # keyed subcommands still validate later, so including it here is safe.
        if ctx.invoked_subcommand in (
            "assessment",
            "check",
            "db",
            "draft",
            "eol-check",
            "egress-check",
            "secrets-check",
            "config-check",
            "evidence",
            "compliance-as-code",
        ):
            ctx.obj["config"] = CRAEvidenceConfig(url=url, output_format=output)
            ctx.obj["verbose"] = verbose
            return
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(e.exit_code)


@cli.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Show CLI version information."""
    console.print(f"craevidence version {__version__}")
    if ctx.obj.get("verbose"):
        config = ctx.obj.get("config")
        if config:
            console.print(f"API URL: {config.url}")


cli.add_command(upload.upload_sbom)
cli.add_command(upload.upload_hbom)
cli.add_command(upload.upload_vex)
cli.add_command(upload.upload_document)
cli.add_command(upload.upload_sarif)
cli.add_command(upload.upload_attestation)
cli.add_command(diagram.upload_diagram)

cli.add_command(status.get_status)
cli.add_command(wait_ready)
cli.add_command(release.set_release_state)

cli.add_command(scan.scan)

cli.add_command(check.check)

cli.add_command(db.db)

cli.add_command(draft.draft)
cli.add_command(eol.eol_check)
cli.add_command(egress.egress_check)
cli.add_command(secrets.secrets_check)
cli.add_command(config_check.config_check)

cli.add_command(export.export)
cli.add_command(compare.compare)

cli.add_command(distributor.distributor)

cli.add_command(profile.setup_profile)
cli.add_command(profile.show_profile)

cli.add_command(maturity.maturity)

cli.add_command(components.components)

cli.add_command(evidence.evidence)

cli.add_command(validate.validate_sbom_command)

cli.add_command(verify.verify)

cli.add_command(gemara.gemara)

cli.add_command(assessment.assessment)


def main() -> None:
    try:
        cli(obj={})
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
