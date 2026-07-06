"""
`craevidence upload-diagram`: upload a Mermaid architecture diagram.

CRA Annex VII, point 2(a) requires a description of the system architecture
explaining how software components build on or feed into each other and
integrate into the overall processing as part of the technical documentation.
Customers maintain a Mermaid `.mmd` file in their repository; this command
either renders it to PNG via `mmdc` (mermaid-cli) and uploads the PNG, or
falls back to uploading the raw `.mmd` source when `mmdc` is not on PATH
(or when `--no-render` is set).

The underlying upload reuses `client.upload_document` with
`document_type=architecture_diagram`; no new platform endpoint.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import click
from rich.console import Console

from cra_evidence_cli.ci_detect import merge_ci_metadata
from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.commands.upload import (
    format_output,
    validate_classification,
    warn_default_category,
)
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import CRAEvidenceError
from cra_evidence_cli.repo_config import resolve_identity

console = Console()


def _render_mermaid_to_png(source: Path) -> Path:
    """Run mmdc to render the Mermaid source to a PNG. Returns PNG path.

    Raises CRAEvidenceError when mmdc exits non-zero so the caller can
    decide between failing or falling back to raw .mmd upload.
    """
    out_path = Path(tempfile.mkdtemp(prefix="cra-diagram-")) / f"{source.stem}.png"
    try:
        result = subprocess.run(  # noqa: S603
            ["mmdc", "-i", str(source), "-o", str(out_path)],  # noqa: S607
            capture_output=True, text=True, timeout=60,
        )
    except FileNotFoundError as exc:
        msg = "mmdc (mermaid-cli) not found on PATH"
        raise CRAEvidenceError(
            msg, exit_code=2,
        ) from exc
    if result.returncode != 0:
        msg = f"mmdc failed (exit {result.returncode}): {result.stderr.strip()}"
        raise CRAEvidenceError(
            msg,
            exit_code=2,
        )
    if not out_path.exists():
        msg = f"mmdc returned 0 but produced no PNG at {out_path}"
        raise CRAEvidenceError(
            msg, exit_code=2,
        )
    return out_path


@click.command("upload-diagram")
@click.option("--product", default=None, help="Product slug or ID")
@click.option(
    "--version", "version_number", default=None, help="Version number",
)
@click.option(
    "--file", "file_path", required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to Mermaid source file (.mmd)",
)
@click.option(
    "--render/--no-render", default=True,
    help=(
        "Render the .mmd to PNG via mmdc before upload (default). "
        "Use --no-render to upload the raw .mmd source instead."
    ),
)
@click.option(
    "--create-product/--no-create-product", default=True,
    help="Auto-create product if it doesn't exist (default: enabled)",
)
@click.option(
    "--create-version/--no-create-version", default=True,
    help="Auto-create version if it doesn't exist (default: enabled)",
)
# CI metadata: same auto-detect contract as upload-document
@click.option("--commit", "commit_sha", help="Git commit SHA (auto-detected in CI)")
@click.option("--branch", help="Git branch (auto-detected in CI)")
@click.option("--pipeline-id", help="CI pipeline ID (auto-detected in CI)")
@click.option("--repository", help="Repository URL/name (auto-detected in CI)")
@click.option("--repo-path", help="Repo subdirectory for monorepo support")
@click.option("--no-ci-detect", is_flag=True, help="Disable CI auto-detection")
@click.pass_context
def upload_diagram(
    ctx: click.Context,
    product: str,
    version_number: str,
    file_path: Path,
    render: bool,
    create_product: bool,
    create_version: bool,
    commit_sha: str | None,
    branch: str | None,
    pipeline_id: str | None,
    repository: str | None,
    repo_path: str | None,
    no_ci_detect: bool,
) -> None:
    """
    Upload a Mermaid architecture diagram as `architecture_diagram`
    technical documentation.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = ctx.obj.get("verbose", False)

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)

    if file_path.suffix.lower() not in {".mmd", ".mermaid"}:
        console.print(
            f"[yellow]Warning:[/yellow] expected a .mmd file; got "
            f"'{file_path.suffix}'. Proceeding anyway."
        )

    try:
        validate_config(config)
    except CRAEvidenceError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(exc.exit_code)

    upload_path = file_path
    cleanup_path: Path | None = None
    if render:
        if shutil.which("mmdc") is None:
            console.print(
                "[yellow]Warning:[/yellow] mmdc not found on PATH, uploading "
                "raw .mmd source. Install mermaid-cli "
                "(`npm install -g @mermaid-js/mermaid-cli`) to upload a "
                "rendered PNG instead."
            )
        else:
            try:
                upload_path = _render_mermaid_to_png(file_path)
                cleanup_path = upload_path
                if verbose:
                    console.print(f"[dim]Rendered PNG: {upload_path}[/dim]")
            except CRAEvidenceError as exc:
                console.print(
                    f"[yellow]Warning:[/yellow] {exc}. Falling back to raw "
                    ".mmd upload."
                )

    ci_metadata = merge_ci_metadata(
        cli_commit=commit_sha,
        cli_branch=branch,
        cli_pipeline_id=pipeline_id,
        cli_repository=repository,
        cli_repo_path=repo_path,
        auto_detect=not no_ci_detect,
    )

    # Diagram is always non-CRA-classified content; preserve the same
    # default-category warning behaviour as other uploads for consistency.
    category, subcategory = validate_classification(None, None)
    warn_default_category(product, create_product, category, subcategory)

    try:
        client = CRAEvidenceClient(config)
        data = asyncio.run(
            client.upload_document(
                product=product,
                version=version_number,
                file_path=upload_path,
                document_type="architecture_diagram",
                create_product=create_product,
                create_version=create_version,
                commit_sha=ci_metadata.get("commit_sha"),
                branch=ci_metadata.get("branch"),
                pipeline_id=ci_metadata.get("pipeline_id"),
                repository=ci_metadata.get("repository"),
                repo_path=ci_metadata.get("repo_path"),
            )
        )
        format_output(data, output_format, verbose)
    except CRAEvidenceError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        if hasattr(exc, "request_id") and exc.request_id:
            console.print(f"[dim]Request ID: {exc.request_id}[/dim]")
        sys.exit(exc.exit_code)
    finally:
        if cleanup_path and cleanup_path.exists():
            cleanup_path.unlink(missing_ok=True)
            parent = cleanup_path.parent
            if parent.exists() and parent.name.startswith("cra-diagram-"):
                try:
                    parent.rmdir()
                except OSError:
                    pass
