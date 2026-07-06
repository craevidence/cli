"""
Status commands - Get CRA compliance status for a version, or wait until it becomes ready.
"""

import asyncio
import json
import random
import sys
import time

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.display import humanize_identifier
from cra_evidence_cli.exceptions import (
    CRAEvidenceError,
    CRANonCompliantError,
    ReleasePolicyNotMetError,
    VulnerabilityThresholdExceeded,
)
from cra_evidence_cli.styles import STYLE_LABEL
from cra_evidence_cli.styles import label as style_label
from cra_evidence_cli.styles import result as style_result
from cra_evidence_cli.styles import status_style as shared_status_style

console = Console()

FAIL_ON_CHOICES = ["critical", "high", "medium", "low", "none"]


def check_fail_on(
    fail_on: str,
    vulnerability_summary: dict,
    cra_status: str,
    cra_floor_status: str | None = None,
    release_policy_status: str | None = None,
) -> None:
    """
    Check whether vulnerability counts or CRA status exceed the fail-on threshold.

    Args:
        fail_on: Severity level to fail on (critical, high, medium, low, none)
        vulnerability_summary: Dict with critical/high/medium/low counts
        cra_status: CRA status string (e.g. "ready", "incomplete")
        cra_floor_status: CRA legal-floor verdict, if supplied
        release_policy_status: Release-policy verdict, if supplied

    Raises:
        VulnerabilityThresholdExceeded: If the vulnerability threshold is exceeded
        CRANonCompliantError: If the CRA legal floor is not ready (exit 20)
        ReleasePolicyNotMetError: If the floor is met but the release policy is not (exit 24)
    """
    critical = vulnerability_summary.get("critical", 0) or 0
    high = vulnerability_summary.get("high", 0) or 0
    medium = vulnerability_summary.get("medium", 0) or 0
    low = vulnerability_summary.get("low", 0) or 0

    if critical > 0 and fail_on in ("critical", "high", "medium", "low"):
        msg = "critical"
        raise VulnerabilityThresholdExceeded(msg, critical, exit_code=10)
    if high > 0 and fail_on in ("high", "medium", "low"):
        msg = "high"
        raise VulnerabilityThresholdExceeded(msg, high, exit_code=11)
    if medium > 0 and fail_on in ("medium", "low"):
        msg = "medium"
        raise VulnerabilityThresholdExceeded(msg, medium, exit_code=12)
    if low > 0 and fail_on == "low":
        msg = "low"
        raise VulnerabilityThresholdExceeded(msg, low, exit_code=13)

    if fail_on == "none":
        return

    # Gate on the floor/release-policy split when present (exits 20/24).
    # Falls back to the single cra_status gate (exit 20) when the fields
    # are absent.
    if cra_floor_status is not None or release_policy_status is not None:
        floor = cra_floor_status or cra_status
        policy = release_policy_status or cra_status
        if floor != "ready":
            raise CRANonCompliantError(floor)
        if policy != "ready":
            raise ReleasePolicyNotMetError(policy)
        return

    if cra_status != "ready":
        raise CRANonCompliantError(cra_status)


def format_status_output(data: dict, output_format: str, verbose: bool = False) -> None:
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    # Text format
    console.print("\n[bold]CRA Compliance Status[/bold]\n")

    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    # Product/Version info
    if "product" in data:
        table.add_row("Product", data["product"].get("name", "N/A"))
    if "version" in data:
        version = data["version"]
        table.add_row("Version", version.get("number", "N/A"))

    # CRA Status
    cra_status = data.get("cra_status", "unknown")
    status_style = {
        "ready": "green",
        "incomplete": "red",
    }.get(cra_status, "white")
    table.add_row("CRA Status", f"[{status_style}]{cra_status}[/{status_style}]")

    # Release state
    release_state = data.get("release_state", "unknown")
    table.add_row(
        "Release State",
        release_state.replace("_", " ").title() if release_state else "Unknown",
    )

    # Scan state
    scan_state = data.get("scan_state")
    if scan_state:
        scan_style = {
            "completed": "green",
            "pending": "yellow",
            "running": "yellow",
            "failed": "red",
            "none": "dim",
        }.get(scan_state, "white")
        scan_label = scan_state.replace("_", " ").title()
        table.add_row("Scan State", f"[{scan_style}]{scan_label}[/{scan_style}]")

    # SBOM info
    table.add_row("", "")
    table.add_row("[bold]SBOM[/bold]", "")
    if "sbom" in data and data["sbom"]:
        sbom = data["sbom"]
        table.add_row("  Format", sbom.get("format", "N/A"))
        table.add_row("  Packages", str(sbom.get("component_count", 0)))
        if sbom.get("quality_score") is not None:
            score = sbom["quality_score"]
            score_style = "green" if score >= 80 else "yellow" if score >= 60 else "red"
            table.add_row("  Quality Score", f"[{score_style}]{score}%[/{score_style}]")
        # ProductComponent attribution. Rows omitted for products
        # without components (component_slug is None for unattributed SBOMs).
        if sbom.get("component_slug"):
            table.add_row("  Attributed to component", str(sbom["component_slug"]))
            if sbom.get("component_repository"):
                table.add_row("  Component repository", str(sbom["component_repository"]))
    else:
        table.add_row("  Status", "[dim]No SBOM uploaded[/dim]")

    # Vulnerabilities
    table.add_row("", "")
    table.add_row("[bold]Vulnerabilities[/bold]", "")
    if data.get("vulnerability_summary"):
        vulns = data["vulnerability_summary"]
        critical = vulns.get("critical", 0)
        high = vulns.get("high", 0)
        medium = vulns.get("medium", 0)
        low = vulns.get("low", 0)
        total = vulns.get("total", critical + high + medium + low)

        if total == 0:
            table.add_row("  Total", "[green]0 (clean)[/green]")
        else:
            if critical > 0:
                table.add_row("  Critical", f"[red bold]{critical}[/red bold]")
            if high > 0:
                table.add_row("  High", f"[red]{high}[/red]")
            if medium > 0:
                table.add_row("  Medium", f"[yellow]{medium}[/yellow]")
            if low > 0:
                table.add_row("  Low", f"[dim]{low}[/dim]")
    else:
        table.add_row("  Status", "[dim]No scan results[/dim]")

    # Documents checklist
    table.add_row("", "")
    table.add_row("[bold]CRA Documents[/bold]", "")
    if "documents" in data:
        docs = data["documents"]
        # documents is a dict[str, bool] keyed by document type.
        for doc_type, present in docs.items():
            icon = "[green]\u2713[/green]" if present else "[red]\u2717[/red]"
            table.add_row(f"  {humanize_identifier(doc_type)}", icon)
    else:
        table.add_row("  Status", "[dim]No documents info[/dim]")

    artifact_inventory = data.get("artifact_inventory") or {}
    if artifact_inventory:
        table.add_row("", "")
        table.add_row("[bold]Evidence Inventory[/bold]", "")
        labels = {
            "sbom": "SBOM",
            "hbom": "HBOM",
            "vex": "VEX",
            "static_analysis": "Static Analysis",
        }
        for family, item in artifact_inventory.items():
            label = labels.get(str(family), str(family).replace("_", " ").title())
            if not item.get("included", False):
                scope = item.get("required_scope") or "additional scope"
                table.add_row(f"  {escape(label)}", f"[dim]requires {escape(str(scope))}[/dim]")
                continue
            count = item.get("count")
            value = str(count) if count is not None else "included"
            latest_bits = []
            if item.get("latest_filename"):
                latest_bits.append(str(item["latest_filename"]))
            if item.get("latest_status"):
                latest_bits.append(str(item["latest_status"]))
            if latest_bits:
                value = f"{value} ([dim]{escape(' · '.join(latest_bits))}[/dim])"
            table.add_row(f"  {escape(label)}", value)

    # Risk coverage (product-class guidance; display-only - never affects --fail-on)
    risk_coverage = data.get("risk_coverage")
    if risk_coverage and risk_coverage.get("applicable"):
        table.add_row("", "")
        table.add_row("[bold]Risk Coverage[/bold]", "")
        if risk_coverage.get("has_structured_ra"):
            pct = risk_coverage.get("pct", 0)
            style = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
            resolved = risk_coverage.get("resolved_count", 0)
            total = risk_coverage.get("expected_count", 0)
            table.add_row(
                "  Class threats addressed",
                f"[{style}]{resolved}/{total} ({pct}%)[/{style}]",
            )
        elif risk_coverage.get("has_ra_doc"):
            table.add_row("  Status", "[green]Documented (uploaded, not scored)[/green]")
        else:
            table.add_row("  Status", "[dim]Not started[/dim]")
        missing = risk_coverage.get("missing") or []
        for title in missing[:5]:
            table.add_row("  Missing", f"[dim]{escape(str(title))}[/dim]")
        if len(missing) > 5:
            table.add_row("", f"[dim]+{len(missing) - 5} more[/dim]")
        table.add_row("", "[dim]guidance only, does not affect --fail-on[/dim]")

    retained_sources = [
        artifact
        for artifact in data.get("document_artifacts", [])
        if artifact.get("gemara_source_download_url") and artifact.get("id")
    ]
    console.print(table)
    # Surface blocking reasons when the version is not CRA-ready.
    _cra = data.get("cra_status")
    _missing = data.get("cra_missing_items") or []
    if _cra and _cra != "ready" and _missing:
        console.print()
        not_ready_style = shared_status_style("not-ready")
        if verbose:
            console.print(
                f"[bold {not_ready_style}]Not ready - blocking items:[/bold {not_ready_style}]"
            )
            for item in _missing:
                console.print(f"  [red]•[/red] {escape(str(item))}")
        else:
            console.print(
                f"{style_result('Not ready', not_ready_style)} - "
                f"{len(_missing)} requirement(s) "
                "outstanding. Run with -v for the full list."
            )

    # Vulnerability blockers grouped by policy layer.
    _blockers = data.get("vuln_blockers") or []
    if _blockers:
        _floor = [b for b in _blockers if b.get("source") == "cra_required"]
        _policy = [b for b in _blockers if b.get("source") == "default_policy"]
        console.print()
        console.print("[bold]Vulnerability blockers by policy layer[/bold]")
        if _floor:
            console.print("  [red]CRA required[/red] (legal floor):")
            for b in _floor:
                _id = b.get("cve_id") or b.get("identifier") or "?"
                console.print(
                    f"    [red]•[/red] {escape(str(_id))}: "
                    f"{escape(str(b.get('reason', '')))}"
                )
        if _policy:
            console.print("  [yellow]CRA Evidence default policy[/yellow] (above the floor):")
            for b in _policy:
                _id = b.get("cve_id") or b.get("identifier") or "?"
                console.print(
                    f"    [yellow]•[/yellow] {escape(str(_id))}: "
                    f"{escape(str(b.get('reason', '')))}"
                )
        _floor_status = data.get("cra_floor_status")
        if _floor_status:
            console.print(
                f"  [dim]CRA legal-floor status: {escape(str(_floor_status))}[/dim]"
            )
    if retained_sources:
        console.print()
        console.print("[bold]Retained Source YAML[/bold]")
        for artifact in retained_sources:
            document_id = str(artifact["id"])
            doc_type = humanize_identifier(artifact.get("doc_type") or "document")
            filename = artifact.get("filename")
            label = doc_type
            if filename:
                label = f"{label} ({filename})"
            command = (
                "craevidence compliance-as-code download-source "
                f"--document-id {document_id} --output <output.yaml>"
            )
            console.print(f"  {style_result(label, STYLE_LABEL)}")
            console.print(f"  {escape(command)}", soft_wrap=True)
            console.print(
                f"  {style_label('API URL')} "
                f"[dim]{escape(str(artifact['gemara_source_download_url']))}[/dim]",
                soft_wrap=True,
            )
    console.print()


@click.command("status")
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
    "--fail-on",
    "fail_on",
    type=click.Choice(FAIL_ON_CHOICES),
    default="none",
    show_default=True,
    help=(
        "Exit with a non-zero code if vulnerabilities at or above this severity are found, "
        "or if CRA status is not ready. Choices: critical, high, medium, low, none."
    ),
)
@click.pass_context
def get_status(
    ctx: click.Context,
    product: str,
    version_number: str,
    fail_on: str,
) -> None:
    """
    Get CRA compliance status for a version.

    Shows readiness status, SBOM metadata, vulnerability summary, and required
    document checklist information. Use the global --output json option before
    the command for machine-readable output.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        validate_config(config)

        if ctx.obj.get("verbose"):
            console.print(f"[dim]Getting status for {product} v{version_number}[/dim]")

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.get_version_status(
                product=product,
                version=version_number,
            )
        )

        format_status_output(data, output_format, ctx.obj.get("verbose", False))

        if fail_on != "none":
            cra_status = data.get("cra_status", "incomplete")
            vulnerability_summary = data.get("vulnerability_summary") or {}
            check_fail_on(
                fail_on,
                vulnerability_summary,
                cra_status,
                cra_floor_status=data.get("cra_floor_status"),
                release_policy_status=data.get("release_policy_status"),
            )

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@click.command("wait-ready")
@click.option(
    "--product",
    required=True,
    help="Product slug or UUID",
)
@click.option(
    "--version",
    "version_number",
    required=True,
    help="Version number to wait on",
)
@click.option(
    "--timeout",
    default=300,
    type=int,
    show_default=True,
    help="Maximum seconds to wait before giving up",
)
@click.option(
    "--interval",
    default=10,
    type=int,
    show_default=True,
    help="Seconds between status polls",
)
@click.pass_context
def wait_ready(
    ctx: click.Context,
    product: str,
    version_number: str,
    timeout: int,
    interval: int,
) -> None:
    """
    Wait for a version to become CRA-ready.

    Polls the CRA status API every INTERVAL seconds until the version's CRA
    status becomes "ready" or the timeout is exceeded.

    Exits with code 0 when CRA status is "ready".
    Exits with code 1 on timeout or unrecoverable error.

    Designed for use in CI/CD pipelines after uploading artifacts.
    """
    config = ctx.obj["config"]
    verbose = ctx.obj.get("verbose", False)

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        console.print(
            f"Waiting for [bold]{product}[/bold] v[bold]{version_number}[/bold] "
            f"to become CRA ready "
            f"(timeout: {timeout}s, interval: {interval}s)..."
        )

        start = time.monotonic()
        current_interval = interval
        consecutive_failures = 0

        while True:
            elapsed = time.monotonic() - start

            if elapsed >= timeout:
                console.print(
                    f"[red]Timeout:[/red] version not CRA-ready after {int(elapsed)}s."
                )
                sys.exit(1)

            try:
                data = asyncio.run(
                    client.get_version_status(
                        product=product,
                        version=version_number,
                    )
                )
                # Reset backoff on success
                consecutive_failures = 0
                current_interval = interval

            except CRAEvidenceError as poll_err:
                consecutive_failures += 1

                # Handle 429 rate limit: respect Retry-After header if available
                retry_after = None
                if hasattr(poll_err, "status_code") and poll_err.status_code == 429:
                    if hasattr(poll_err, "retry_after"):
                        retry_after = poll_err.retry_after

                if retry_after is not None:
                    wait_duration = retry_after + random.uniform(0, 2)  # noqa: S311
                    console.print(
                        f"  [{int(elapsed):>4}s] Rate limited (429) - waiting {wait_duration:.1f}s "
                        f"(Retry-After: {retry_after}s)..."
                    )
                else:
                    # Exponential backoff with jitter on consecutive failures
                    backoff = min(current_interval * (2 ** (consecutive_failures - 1)), timeout / 2)
                    wait_duration = backoff + random.uniform(0, 2)  # noqa: S311
                    console.print(
                        f"  [{int(elapsed):>4}s] Poll error: {poll_err} - "
                        f"retrying in {wait_duration:.1f}s..."
                    )

                if verbose:
                    if hasattr(poll_err, "request_id") and poll_err.request_id:
                        console.print(f"  [dim]Request ID: {poll_err.request_id}[/dim]")

                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    console.print(
                        f"[red]Timeout:[/red] version not CRA-ready after {timeout}s."
                    )
                    sys.exit(1)
                time.sleep(min(wait_duration, remaining))
                continue

            cra_status = data.get("cra_status", "incomplete")
            # Gate readiness on the release-policy verdict, falling back to
            # cra_status when the field is absent.
            release_policy_status = data.get("release_policy_status")
            gate_status = release_policy_status or cra_status

            if gate_status == "ready":
                gate_label = "Policy Status" if release_policy_status else "CRA Status"
                console.print(
                    f"  [{int(elapsed):>4}s] [bold green]{gate_label}: READY[/bold green] "
                    f"- readiness gate passed."
                )
                sys.exit(0)

            # Show progress on each non-ready poll
            scan_state = data.get("scan_state")
            scan_note = (
                f" (scan: {scan_state.replace('_', ' ').title()})"
                if scan_state and scan_state not in ("none", "completed")
                else ""
            )
            progress_label = "Policy Status" if release_policy_status else "Status"
            status_part = f"[yellow]{gate_status}[/yellow]{scan_note}"
            console.print(
                f"  [{int(elapsed):>4}s] {progress_label}: {status_part}"
                f" - next check in {current_interval + random.uniform(0, 2):.1f}s..."  # noqa: S311
            )

            # Surface blocking reasons on each non-ready poll.
            for item in (data.get("cra_missing_items") or [])[:8]:
                console.print(f"         [dim]• {escape(str(item))}[/dim]")

            # Check remaining time before sleeping
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                console.print(
                    f"[red]Timeout:[/red] version not CRA-ready after {timeout}s."
                )
                sys.exit(1)

            sleep_for = min(current_interval + random.uniform(0, 2), remaining)  # noqa: S311
            time.sleep(sleep_for)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
