"""
Read-only evidence discovery commands.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.display import humanize_identifier
from cra_evidence_cli.evidence_checker.engine import (
    EvidenceCheckerError,
    run_evidence_check,
    write_checker_outputs,
)
from cra_evidence_cli.exceptions import CRAEvidenceError

console = Console()


def _print_json(data: Any) -> None:
    console.print_json(json.dumps(data, indent=2))


def _handle_error(error: CRAEvidenceError) -> None:
    console.print(f"[red]Error:[/red] {error}")
    if getattr(error, "request_id", None):
        console.print(f"[dim]Request ID: {error.request_id}[/dim]")
    sys.exit(error.exit_code)


def _client_from_context(ctx: click.Context) -> tuple[CRAEvidenceClient, str]:
    config = ctx.obj["config"]
    validate_config(config)
    return CRAEvidenceClient(config), config.output_format


def _format_score(value: Any) -> str:
    if value is None:
        return "N/A"
    return f"{value}%"


def format_hboms_output(items: list[dict[str, Any]], output_format: str) -> None:
    if output_format == "json":
        _print_json(items)
        return

    table = Table(title="HBOMs")
    table.add_column("ID")
    table.add_column("Filename")
    table.add_column("Format")
    table.add_column("Components", justify="right")
    table.add_column("Quality", justify="right")
    table.add_column("Created")

    for item in items:
        table.add_row(
            str(item.get("id", "")),
            str(item.get("filename", "")),
            str(item.get("format", "")),
            str(item.get("component_count", 0)),
            _format_score(item.get("quality_score")),
            str(item.get("created_at", "")),
        )

    console.print(table if items else "[dim]No HBOMs found[/dim]")


def format_vex_output(items: list[dict[str, Any]], output_format: str) -> None:
    if output_format == "json":
        _print_json(items)
        return

    table = Table(title="VEX Documents")
    table.add_column("ID")
    table.add_column("Filename")
    table.add_column("Format")
    table.add_column("Vulns", justify="right")
    table.add_column("Affected", justify="right")
    table.add_column("Not Affected", justify="right")
    table.add_column("Quality", justify="right")
    table.add_column("Created")

    for item in items:
        table.add_row(
            str(item.get("id", "")),
            str(item.get("filename", "")),
            str(item.get("format", "")),
            str(item.get("vulnerability_count", 0)),
            str(item.get("affected_count", 0)),
            str(item.get("not_affected_count", 0)),
            _format_score(item.get("quality_score")),
            str(item.get("created_at", "")),
        )

    console.print(table if items else "[dim]No VEX documents found[/dim]")


def format_static_analysis_output(data: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        _print_json(data)
        return

    summary = data.get("summary") or {}
    findings = data.get("findings") or []

    summary_table = Table(title="Static Analysis Summary")
    summary_table.add_column("Field")
    summary_table.add_column("Value", justify="right")
    for key in (
        "total_results",
        "critical_count",
        "error_count",
        "warning_count",
        "note_count",
        "none_count",
        "suppressed_count",
        "unsuppressed_count",
        "files_affected",
        "unique_rules",
    ):
        summary_table.add_row(key.replace("_", " ").title(), str(summary.get(key, 0)))
    console.print(summary_table)

    if not findings:
        console.print("[dim]No static-analysis findings found[/dim]")
        return

    findings_table = Table(title="Static Analysis Findings")
    findings_table.add_column("Severity")
    findings_table.add_column("Tool")
    findings_table.add_column("Rule")
    findings_table.add_column("Location")
    findings_table.add_column("Suppressed")
    findings_table.add_column("Message")

    for item in findings:
        location = str(item.get("file_path") or "")
        if item.get("start_line"):
            location = f"{location}:{item['start_line']}" if location else str(item["start_line"])
        findings_table.add_row(
            str(item.get("severity", "")),
            str(item.get("tool_name", "")),
            str(item.get("rule_id", "")),
            location,
            "yes" if item.get("suppressed") else "no",
            str(item.get("message", "")),
        )

    console.print(findings_table)


def format_documents_output(data: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        _print_json(data)
        return

    docs = data.get("documents") or {}
    artifacts = data.get("document_artifacts") or []

    docs_table = Table(title="Document Checklist")
    docs_table.add_column("Document")
    docs_table.add_column("Present")
    for doc_type, present in docs.items():
        docs_table.add_row(humanize_identifier(doc_type), "yes" if present else "no")
    console.print(docs_table if docs else "[dim]No document checklist found[/dim]")

    if not artifacts:
        console.print("[dim]No document artifacts found[/dim]")
        return

    artifact_table = Table(title="Document Artifacts")
    artifact_table.add_column("ID")
    artifact_table.add_column("Type")
    artifact_table.add_column("Filename")
    artifact_table.add_column("Review")
    for item in artifacts:
        artifact_table.add_row(
            str(item.get("id", "")),
            humanize_identifier(item.get("doc_type", "")),
            str(item.get("filename", "")),
            humanize_identifier(item.get("review_status", "")),
        )
    console.print(artifact_table)


def format_inventory_output(data: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        _print_json(data)
        return

    inventory = data.get("artifact_inventory") or {}
    table = Table(title="Evidence Inventory")
    table.add_column("Family")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    table.add_column("Latest")

    labels = {
        "sbom": "SBOM",
        "hbom": "HBOM",
        "vex": "VEX",
        "static_analysis": "Static Analysis",
    }
    for family, item in inventory.items():
        if item.get("included", False):
            status = "included"
        else:
            required_scope = item.get("required_scope") or "additional scope"
            status = f"requires {required_scope}"
        table.add_row(
            labels.get(str(family), str(family).replace("_", " ").title()),
            status,
            str(item.get("count", "")),
            str(item.get("latest_filename") or item.get("latest_status") or ""),
        )

    console.print(table if inventory else "[dim]No evidence inventory found[/dim]")


def format_check_output(
    result: dict[str, Any],
    paths: dict[str, Path],
    output_format: str,
) -> None:
    """Render local checker summary."""
    payload = {
        "summary": result["summary"],
        "outputs": {key: str(path) for key, path in paths.items()},
    }
    if output_format == "json":
        _print_json(payload)
        return

    summary = result["summary"]
    table = Table(title="Evidence Check")
    table.add_column("Field")
    table.add_column("Value", justify="right")
    table.add_row("Total", str(summary["total"]))
    table.add_row("Passed", str(summary["passed"]))
    table.add_row("Failed", str(summary["failed"]))
    table.add_row("Needs review", str(summary["needs_review"]))
    console.print(table)

    console.print("[dim]Outputs[/dim]")
    console.print(f"Structured evaluation log: {paths['evaluation_log']}")
    console.print(f"JSON diagnostics:       {paths['results_json']}")
    console.print(f"Markdown report:        {paths['report_md']}")


def _document_artifact_metadata(status: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = status.get("document_artifacts") or []
    metadata: list[dict[str, Any]] = []
    for item in artifacts:
        metadata.append(
            {
                "id": item.get("id"),
                "doc_type": item.get("doc_type"),
                "filename": item.get("filename"),
                "review_status": item.get("review_status"),
            }
        )
    return metadata


@click.group()
def evidence() -> None:
    """Read evidence inventory metadata."""


@evidence.command("check")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Local evidence checker YAML config.",
)
@click.option(
    "--out-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("craevidence-check"),
    show_default=True,
    help="Directory for EvaluationLog, JSON diagnostics, and Markdown report.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["failed", "needs-review", "none"], case_sensitive=False),
    default="failed",
    show_default=True,
    help="Exit non-zero when checks reach this outcome.",
)
@click.pass_context
def check(ctx: click.Context, config_path: Path, out_dir: Path, fail_on: str) -> None:
    """Run deterministic local evidence checks and write review-only compliance YAML."""
    output_format = ctx.obj["config"].output_format
    try:
        result = run_evidence_check(config_path)
        paths = write_checker_outputs(result, out_dir)
        format_check_output(result, paths, output_format)
    except EvidenceCheckerError as error:
        raise click.UsageError(str(error)) from error

    summary = result["summary"]
    if fail_on == "failed" and summary["failed"]:
        sys.exit(2)
    if fail_on == "needs-review" and (summary["failed"] or summary["needs_review"]):
        sys.exit(3)


@evidence.command("list")
@click.option("--product", required=True, help="Product slug or ID")
@click.option("--version", required=True, help="Version number")
@click.pass_context
def list_inventory(ctx: click.Context, product: str, version: str) -> None:
    """Show scope-aware evidence inventory from version status."""
    try:
        client, output_format = _client_from_context(ctx)
        status = asyncio.run(client.get_version_status(product=product, version=version))
        inventory = {
            "artifact_inventory": status.get("artifact_inventory") or {},
            "documents": status.get("documents") or {},
        }
        format_inventory_output(inventory, output_format)
    except CRAEvidenceError as error:
        _handle_error(error)


@evidence.command("hboms")
@click.option("--product", required=True, help="Product slug or ID")
@click.option("--version", required=True, help="Version number or ID")
@click.pass_context
def hboms(ctx: click.Context, product: str, version: str) -> None:
    """List HBOM metadata for a version."""
    try:
        client, output_format = _client_from_context(ctx)
        items = asyncio.run(client.list_hboms(product=product, version=version))
        format_hboms_output(items, output_format)
    except CRAEvidenceError as error:
        _handle_error(error)


@evidence.command("vex")
@click.option("--product", required=True, help="Product slug or ID")
@click.option("--version", required=True, help="Version number or ID")
@click.pass_context
def vex(ctx: click.Context, product: str, version: str) -> None:
    """List VEX document metadata for a version."""
    try:
        client, output_format = _client_from_context(ctx)
        items = asyncio.run(client.list_vex_documents(product=product, version=version))
        format_vex_output(items, output_format)
    except CRAEvidenceError as error:
        _handle_error(error)


@evidence.command("static-analysis")
@click.option("--product", required=True, help="Product slug or ID")
@click.option("--version", required=True, help="Version number or ID")
@click.option("--limit", type=click.IntRange(1, 1000), default=100, show_default=True)
@click.option("--offset", type=click.IntRange(0), default=0, show_default=True)
@click.option("--tool-name", help="Filter by tool name")
@click.option("--severity", help="Filter by severity")
@click.option("--rule-id", help="Filter by rule ID")
@click.option("--file-path", help="Filter by file path")
@click.option("--suppressed/--unsuppressed", default=None, help="Filter suppression state")
@click.option("--min-severity-rank", type=click.IntRange(0, 4), help="Minimum severity rank")
@click.option("--summary-only", is_flag=True, help="Only show summary metadata")
@click.pass_context
def static_analysis(
    ctx: click.Context,
    product: str,
    version: str,
    limit: int,
    offset: int,
    tool_name: str | None,
    severity: str | None,
    rule_id: str | None,
    file_path: str | None,
    suppressed: bool | None,
    min_severity_rank: int | None,
    summary_only: bool,
) -> None:
    """List static-analysis summary and finding metadata for a version."""
    try:
        client, output_format = _client_from_context(ctx)
        summary = asyncio.run(client.get_static_analysis_summary(product=product, version=version))
        findings: list[dict[str, Any]] = []
        if not summary_only:
            findings = asyncio.run(
                client.list_static_analysis_results(
                    product=product,
                    version=version,
                    limit=limit,
                    offset=offset,
                    tool_name=tool_name,
                    severity=severity,
                    rule_id=rule_id,
                    file_path=file_path,
                    suppressed=suppressed,
                    min_severity_rank=min_severity_rank,
                )
            )
        format_static_analysis_output(
            {"summary": summary, "findings": findings},
            output_format,
        )
    except CRAEvidenceError as error:
        _handle_error(error)


@evidence.command("documents")
@click.option("--product", required=True, help="Product slug or ID")
@click.option("--version", required=True, help="Version number")
@click.pass_context
def documents(ctx: click.Context, product: str, version: str) -> None:
    """Show document inventory metadata from version status."""
    try:
        client, output_format = _client_from_context(ctx)
        status = asyncio.run(client.get_version_status(product=product, version=version))
        inventory = {
            "documents": status.get("documents") or {},
            "document_artifacts": _document_artifact_metadata(status),
            "artifact_inventory": (status.get("artifact_inventory") or {}).get("documents"),
        }
        format_documents_output(inventory, output_format)
    except CRAEvidenceError as error:
        _handle_error(error)
