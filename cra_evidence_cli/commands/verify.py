"""
Verify command - binary SBOM verification against declared SBOM.
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import CRAEvidenceError
from cra_evidence_cli.sbom_generator import (
    SBOMGenerationError,
    cleanup_generated_sbom,
    generate_sbom_from_directory,
)

console = Console()
err_console = Console(stderr=True)


def _format_verify_output(data: dict, output_format: str) -> None:
    """Format and display binary verification results."""
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    console.print("\n[bold]Binary SBOM Verification[/bold]\n")

    coverage = data.get("coverage_ratio", 0.0)
    declared_count = data.get("declared_component_count", 0)
    binary_count = data.get("binary_component_count", 0)
    total = data.get("total_discrepancies", 0)

    # Coverage bar
    pct = coverage * 100
    coverage_style = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
    console.print(
        f"Coverage: [{coverage_style}]{pct:.1f}%[/{coverage_style}] "
        f"({binary_count} binary / {declared_count} declared)"
    )

    if total == 0:
        console.print(
            "\n[bold green]✓ No discrepancies - binary matches declared SBOM[/bold green]"
        )
        console.print()
        return

    console.print()

    only_in_declared = data.get("components_only_in_declared", [])
    only_in_binary = data.get("components_only_in_binary", [])
    mismatches = data.get("version_mismatches", [])

    if only_in_declared:
        console.print(
            f"[bold red]{len(only_in_declared)} package(s) in declared SBOM "
            f"not found in binary:[/bold red]"
        )
        for comp in only_in_declared[:20]:
            name = comp.get("name") or comp.get("purl") or "unknown"
            ver = comp.get("version") or ""
            console.print(f"  [red]-[/red] {name}{' ' + ver if ver else ''}")
        if len(only_in_declared) > 20:
            console.print(f"  [dim]... and {len(only_in_declared) - 20} more[/dim]")
        console.print()

    if only_in_binary:
        console.print(
            f"[bold yellow]{len(only_in_binary)} package(s) found in binary "
            f"but not in declared SBOM:[/bold yellow]"
        )
        for comp in only_in_binary[:20]:
            name = comp.get("name") or comp.get("purl") or "unknown"
            ver = comp.get("version") or ""
            console.print(f"  [yellow]+[/yellow] {name}{' ' + ver if ver else ''}")
        if len(only_in_binary) > 20:
            console.print(f"  [dim]... and {len(only_in_binary) - 20} more[/dim]")
        console.print()

    if mismatches:
        console.print(
            f"[bold yellow]{len(mismatches)} version mismatch(es):[/bold yellow]"
        )
        for comp in mismatches[:20]:
            name = comp.get("name") or comp.get("purl") or "unknown"
            old_v = comp.get("old_version") or "?"
            new_v = comp.get("new_version") or "?"
            console.print(f"  [yellow]~[/yellow] {name}: declared={old_v} vs binary={new_v}")
        if len(mismatches) > 20:
            console.print(f"  [dim]... and {len(mismatches) - 20} more[/dim]")
        console.print()


@click.group("verify")
def verify() -> None:
    """Binary SBOM verification commands."""


@verify.command("run")
@click.argument(
    "directory",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--product",
    required=True,
    help="Product slug or UUID (must already exist)",
)
@click.option(
    "--version",
    "version_number",
    required=True,
    help="Version number (must already exist with a declared SBOM uploaded)",
)
@click.option(
    "--format",
    "format_type",
    type=click.Choice(["cyclonedx", "spdx"], case_sensitive=False),
    default="cyclonedx",
    help="SBOM format for binary scan (default: cyclonedx)",
)
@click.option(
    "--fail-on-discrepancies",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any discrepancies are found",
)
@click.pass_context
def verify_run(
    ctx: click.Context,
    directory: Path,
    product: str,
    version_number: str,
    format_type: str,
    fail_on_discrepancies: bool,
) -> None:
    """
    Scan a directory with Syft and compare against the declared SBOM.

    DIRECTORY is the path to the rootfs or source directory to scan.

    The product and version must already exist and have a declared SBOM uploaded.
    Run 'craevidence upload-sbom' first if not already done.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = ctx.obj.get("verbose", False)
    generated_sbom_path: Path | None = None

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        # Step A: Generate binary SBOM via Syft
        err_console.print(f"[cyan]Scanning directory:[/cyan] {directory}")
        try:
            result = generate_sbom_from_directory(
                directory=str(directory),
                output_format=format_type,
                verbose=verbose,
            )
            generated_sbom_path = result.file_path
            err_console.print(
                f"[green]Generated binary SBOM:[/green] {result.component_count} packages "
                f"({result.format_type})"
            )
        except SBOMGenerationError as e:
            console.print(f"[red]SBOM generation failed:[/red] {e}")
            sys.exit(e.exit_code)

        # Step B: Upload with source_type=binary_analysis
        err_console.print("[cyan]Uploading binary SBOM[/cyan]")
        try:
            upload_response = asyncio.run(
                client.upload_sbom(
                    product=product,
                    version=version_number,
                    file_path=generated_sbom_path,
                    source_type="binary_analysis",
                    create_product=False,
                    create_version=False,
                )
            )
        except CRAEvidenceError as e:
            # Distinguish "not found" from other errors to give actionable guidance
            msg = str(e)
            if "not found" in msg.lower() or "404" in str(getattr(e, "status_code", "")):
                console.print(
                    f"[red]Product or version not found.[/red] "
                    f"Run 'craevidence upload-sbom --product {product} "
                    f"--version {version_number} --file <sbom.json>' "
                    f"to create the declared SBOM first."
                )
            else:
                console.print(f"[red]Upload failed:[/red] {e}")
            sys.exit(e.exit_code)

        version_id = str(upload_response["version"]["id"])
        binary_sbom_id = str(upload_response["artifact_id"])
        if verbose:
            err_console.print(f"[green]Uploaded.[/green] Version ID: {version_id}")

        # Step C: Compare against declared SBOM
        err_console.print("[cyan]Comparing against declared SBOM[/cyan]")
        try:
            verify_response = asyncio.run(
                client.verify_sbom(
                    version_id=version_id,
                    binary_sbom_id=binary_sbom_id,
                )
            )
        except CRAEvidenceError as e:
            console.print(f"[red]Verification failed:[/red] {e}")
            sys.exit(e.exit_code)

        # Step D: Print results
        _format_verify_output(verify_response, output_format)

        # Exit 1 if discrepancies and --fail-on-discrepancies
        if fail_on_discrepancies and verify_response.get("total_discrepancies", 0) > 0:
            console.print(
                f"[red]Failing: {verify_response['total_discrepancies']} "
                f"discrepancy(ies) found.[/red]"
            )
            sys.exit(1)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
    finally:
        # Generated SBOMs live in a private temp directory (one per run);
        # remove the whole directory so runs do not accumulate sbom_* dirs.
        if generated_sbom_path and generated_sbom_path.exists():
            cleanup_generated_sbom(generated_sbom_path)
