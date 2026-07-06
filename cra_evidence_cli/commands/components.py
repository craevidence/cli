"""
`cra components` subcommand group.

Read-only commands for inspecting which components a product has and
which have already pushed evidence for the latest version. Lets CI
self-check coverage before declaring a release ready.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import click
import httpx
from rich.console import Console
from rich.table import Table

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.exceptions import APIError, AuthenticationError, CRAEvidenceError

console = Console()


@click.group()
def components() -> None:
    """Inspect product components (multi-repo support)."""


@components.command("list")
@click.option(
    "--product",
    required=True,
    help="Product slug or UUID",
)
@click.option(
    "--include-archived",
    is_flag=True,
    default=False,
    help="Include soft-archived components in the output",
)
@click.pass_context
def components_list(
    ctx: click.Context,
    product: str,
    include_archived: bool,
) -> None:
    """
    List components registered for a product.

    Shows the slug, repository, and whether each component has at least
    one SBOM in the product's most recent version.
    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = ctx.obj.get("verbose", False)

    client = CRAEvidenceClient(config)
    try:
        data = asyncio.run(
            _fetch_components(
                client=client,
                product=product,
                include_archived=include_archived,
            )
        )
    except CRAEvidenceError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)

    if output_format == "json":
        click.echo(json.dumps(data, indent=2, default=str))
        return

    if not data:
        console.print("[yellow]No components registered for this product.[/yellow]")
        if verbose:
            console.print(
                "[dim]Components are auto-created on first CI push when "
                "--repository is set, or registered manually in the UI.[/dim]"
            )
        return

    table = Table(title=f"Components for product '{product}'")
    table.add_column("Slug", style="cyan")
    table.add_column("Name")
    table.add_column("Repository")
    table.add_column("Subpath", style="dim")
    table.add_column("SBOMs (latest)", justify="right")
    table.add_column("Owner", style="dim")
    table.add_column("Status", style="dim")

    for c in data:
        sbom_count = c.get("sbom_count_latest_version", 0)
        owner = c.get("owner") or {}
        status_parts = []
        if c.get("auto_created"):
            status_parts.append("auto")
        if c.get("archived_at"):
            status_parts.append("archived")
        table.add_row(
            c["slug"],
            c["name"],
            c.get("vcs_uri") or "-",
            c.get("repo_path") or "",
            str(sbom_count) if sbom_count else "[red]0[/red]",
            owner.get("email") or owner.get("name") or "-",
            ", ".join(status_parts) or "active",
        )
    console.print(table)


async def _fetch_components(
    *,
    client: CRAEvidenceClient,
    product: str,
    include_archived: bool,
) -> list[dict[str, Any]]:
    # OIDC mode: token exchange must happen before the first authenticated call.
    await client._ensure_access_token()
    headers = client._get_headers()
    base_url = client.base_url

    async with httpx.AsyncClient(timeout=client.timeout) as http:
        product_uuid = product
        # A UUID is exactly 36 chars with dashes. Anything else looks like
        # a slug - resolve by listing products and matching slug exactly.
        # The API's `q` filter is a fuzzy text search and doesn't guarantee
        # exact matches.
        if not (len(product) == 36 and product.count("-") == 4):
            r = await http.get(
                f"{base_url}/api/v1/products",
                headers=headers,
            )
            if r.status_code == 401:
                msg = "Authentication failed (401). Check your API key or OIDC token."
                raise AuthenticationError(msg)
            if r.status_code != 200:
                msg = (
                    f"Failed to resolve product '{product}': "
                    f"HTTP {r.status_code}"
                )
                raise APIError(msg, status_code=r.status_code)
            matches = r.json()
            match = next(
                (p for p in matches if p.get("slug") == product),
                None,
            )
            if not match:
                msg = f"Product '{product}' not found"
                raise APIError(msg, status_code=404)
            product_uuid = match["id"]

        params: dict[str, Any] = {}
        if include_archived:
            params["include_archived"] = "true"
        r = await http.get(
            f"{base_url}/api/v1/products/{product_uuid}/components",
            headers=headers,
            params=params,
        )
        if r.status_code == 401:
            msg = "Authentication failed (401). Check your API key or OIDC token."
            raise AuthenticationError(msg)
        if r.status_code != 200:
            msg = f"Failed to list components: HTTP {r.status_code} {r.text}"
            raise APIError(msg, status_code=r.status_code)
        return r.json()
