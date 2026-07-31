"""
Risk assessment commands - Show the structured risk assessment status for a version.
"""

import asyncio
import json
import sys
from typing import Any, NoReturn

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from cra_evidence_cli.assessment.select import is_interactive
from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.display import warn_unsupported_output_format
from cra_evidence_cli.exceptions import (
    APIError,
    CRAEvidenceError,
    RiskAssessmentReviewPending,
)
from cra_evidence_cli.local.disclaimer import DISCLAIMER_TEXT
from cra_evidence_cli.repo_config import resolve_identity
from cra_evidence_cli.styles import status_style as shared_status_style

console = Console()
err_console = Console(stderr=True)

FAIL_ON_CHOICES = ["unreviewed", "none"]

# Safety bound on how many times `ra review` will re-open a superseded cycle
# in one run before giving up. Each refresh is user-driven (a disposition
# POST raced a 409), so hitting this in practice would mean the evidence is
# changing faster than a human can review it.
_MAX_CYCLE_REFRESHES = 10


def _pct_style(pct: int) -> str:
    if pct >= 80:
        return "green"
    if pct >= 50:
        return "yellow"
    return "red"


def format_risk_assessment_output(data: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        console.print_json(
            json.dumps(
                {
                    "risk_assessment": data,
                    "advisory": {"disclaimer": DISCLAIMER_TEXT},
                },
                indent=2,
            )
        )
        return

    console.print("\n[bold]Risk Assessment Status[/bold]\n")

    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    assessment_status = data.get("assessment_status", "unknown")
    a_style = shared_status_style(assessment_status)
    table.add_row(
        "Assessment Status",
        f"[{a_style}]{escape(str(assessment_status))}[/{a_style}]",
    )

    review_status = data.get("review_status", "unknown")
    r_style = shared_status_style(review_status)
    table.add_row(
        "Review Status",
        f"[{r_style}]{escape(str(review_status))}[/{r_style}]",
    )

    completion = data.get("completion_pct")
    if completion is not None:
        c_style = _pct_style(int(completion))
        table.add_row("Completion", f"[{c_style}]{completion}%[/{c_style}]")

    inherited_from = data.get("inherited_from")
    if inherited_from:
        table.add_row("", "")
        table.add_row("[bold]Inherited From[/bold]", "")
        source_version = inherited_from.get("source_version")
        if source_version:
            table.add_row("  Source Version", escape(str(source_version)))
        signed_at = inherited_from.get("signed_at")
        if signed_at:
            table.add_row("  Signed At", escape(str(signed_at)))

    table.add_row("", "")
    table.add_row("[bold]Sign-off[/bold]", "")
    signed_off = data.get("signed_off") or {}
    signed_by = signed_off.get("signed_by")
    signed_at = signed_off.get("signed_at")
    if signed_by or signed_at:
        table.add_row("  Signed By", escape(str(signed_by or "unknown")))
        table.add_row("  Signed At", escape(str(signed_at or "unknown")))
    else:
        table.add_row("  Status", "[dim]not signed[/dim]")

    counts = data.get("counts") or {}
    if counts:
        table.add_row("", "")
        table.add_row("[bold]Counts[/bold]", "")
        table.add_row("  Assets", str(counts.get("assets", 0)))
        table.add_row("  Threats", str(counts.get("threats", 0)))
        table.add_row("  Risks", str(counts.get("risks", 0)))

    part_ii_coverage = data.get("part_ii_coverage")
    if part_ii_coverage and part_ii_coverage.get("applicable"):
        table.add_row("", "")
        table.add_row("[bold]Part II Coverage[/bold]", "")
        pct = part_ii_coverage.get("pct", 0)
        style = _pct_style(int(pct))
        resolved = part_ii_coverage.get("resolved_count", 0)
        total = part_ii_coverage.get("expected_count", 0)
        table.add_row(
            "  Obligations addressed",
            f"[{style}]{resolved}/{total} ({pct}%)[/{style}]",
        )
        missing = part_ii_coverage.get("missing") or []
        for title in missing[:5]:
            table.add_row("  Missing", f"[dim]{escape(str(title))}[/dim]")
        if len(missing) > 5:
            table.add_row("", f"[dim]+{len(missing) - 5} more[/dim]")

    table.add_row(
        "",
        "[dim]guidance only, review state is not a compliance verdict[/dim]",
    )

    console.print(table)
    console.print()


def _print_no_assessment_note(product: str, version: str, output_format: str) -> None:
    if output_format == "json":
        console.print_json(
            json.dumps(
                {
                    "risk_assessment": None,
                    "advisory": {"disclaimer": DISCLAIMER_TEXT},
                    "note": "no risk assessment recorded yet for this version",
                },
                indent=2,
            )
        )
        return

    console.print("\n[bold]Risk Assessment Status[/bold]\n")
    console.print(
        f"[dim]No risk assessment recorded yet for "
        f"{escape(str(product))} v{escape(str(version))}.[/dim]"
    )
    console.print(
        "[dim]Absence is governed by the existing readiness gates, "
        "not by --fail-on here.[/dim]"
    )
    console.print()


def _item_detail_lines(item: dict[str, Any]) -> list[str]:
    """A short, plain-language description of one review item's detail.

    Deliberately narrow: shows the fields a reviewer needs to make a call,
    not the full detail dict (which varies by item kind and is meant for
    machine consumption via --output json).
    """
    kind = item.get("kind", "")
    detail = item.get("detail") or {}
    lines: list[str] = []

    if kind in ("component_added", "component_removed"):
        name = detail.get("name") or ""
        version = detail.get("version") or ""
        if name or version:
            lines.append(f"component: {name} {version}".strip())
        if detail.get("supplier"):
            lines.append(f"supplier: {detail.get('supplier')}")
    elif kind == "component_updated":
        lines.append(
            f"component: {detail.get('name') or ''} "
            f"{detail.get('old_version') or ''} to {detail.get('new_version') or ''}"
        )
    elif kind == "vex_status_changed":
        lines.append(f"finding: {detail.get('cve_id') or ''}")
        lines.append(
            f"status: {detail.get('old_status') or ''} to {detail.get('new_status') or ''}"
        )
    elif kind == "vuln_candidate":
        lines.append(f"finding: {detail.get('cve_id') or ''} on {detail.get('component') or ''}")
        severity = detail.get("severity") or "unknown"
        cvss = detail.get("cvss")
        lines.append(f"severity: {severity}" + (f" (score {cvss})" if cvss is not None else ""))
        if detail.get("kev"):
            lines.append("known to be actively exploited")
        if detail.get("why"):
            lines.append(f"why it matters: {detail.get('why')}")
    elif kind == "context_changed":
        label = detail.get("label") or detail.get("key") or "context"
        lines.append(f"{label}: {detail.get('baseline')} to {detail.get('current')}")
    elif kind in ("hardware_added", "hardware_removed"):
        lines.append(f"hardware: {detail.get('name') or ''}")
        if detail.get("part_number"):
            lines.append(f"part number: {detail.get('part_number')}")
    elif kind == "hardware_changed":
        lines.append(f"hardware: {detail.get('name') or ''}")
        lines.append(
            f"firmware: {detail.get('old_firmware') or ''} to {detail.get('new_firmware') or ''}"
        )
    elif kind == "evidence_stale":
        lines.append(f"risk entry: {detail.get('risk_number') or ''}")
        lines.append(f"reason: {detail.get('reason') or 'unknown'}")
        if detail.get("filename"):
            lines.append(f"file: {detail.get('filename')}")
    elif kind == "release_question":
        if detail.get("hint"):
            lines.append(str(detail.get("hint")))

    return [line for line in lines if line.strip()]


def _prompt_note(label: str, *, required: bool = False) -> str | None:
    """Prompt for a one-line note on stderr; returns None for an empty answer."""
    while True:
        value = click.prompt(label, default="", show_default=False, err=True).strip()
        if value or not required:
            return value or None
        err_console.print("  [red]A reason is required.[/red]")


def _prompt_item(item: dict[str, Any]) -> tuple[str, str | None] | None:
    """Prompt for one item's disposition. Returns None when the item is skipped.

    All prompt chrome goes to stderr so stdout stays clean for --output json.
    Raises click.Abort / EOFError when the input stream closes; callers stop
    the walk rather than treating that as an error.
    """
    kind = item.get("kind", "")
    title = str(item.get("title") or item.get("item_id") or "")
    err_console.print(f"\n[bold]{escape(title)}[/bold]")
    for line in _item_detail_lines(item):
        err_console.print(f"  [dim]{escape(line)}[/dim]")

    if kind == "release_question":
        err_console.print(
            "  [y] yes, changed and handled   [enter/n] no change   [s] skip"
        )
        choice = click.prompt(
            "  answer", default="n", show_default=False, err=True
        ).strip().lower()
        if choice == "s":
            return None
        if choice == "y":
            note = _prompt_note("  what changed, and how it was assessed")
            return "added_risk", note
        return "accepted", None

    err_console.print(
        "  [a] covered, note why   [r] new risk needed   "
        "[n] not relevant, say why   [s] skip"
    )
    choice = click.prompt(
        "  choice", default="s", show_default=False, err=True
    ).strip().lower()
    if choice == "a":
        note = _prompt_note("  why this is covered")
        return "accepted", note
    if choice == "r":
        note = _prompt_note("  note")
        err_console.print(
            "  [dim]The risk entry itself is completed in the web app.[/dim]"
        )
        return "added_risk", note
    if choice == "n":
        justification = _prompt_note("  why the product is not affected", required=True)
        return "not_affected", justification
    return None


def _is_missing_ra_404(e: APIError) -> bool:
    """True when a 404 means "no risk assessment recorded yet", not a typo.

    The server tells apart what a 404 is actually about via the error
    body's ``details``: a missing risk assessment carries
    ``resource_type: "Risk assessment"`` (the read endpoint additionally
    carries ``product_level_assessment_exists``), while an unknown product
    or version carries ``resource_type: "Product"`` or ``"Version"``
    instead. Only the risk-assessment shape should be swallowed into "no
    assessment yet, exit 0"; a typo in --product/--version must fail loudly.
    """
    details = e.error_details or {}
    return (
        "product_level_assessment_exists" in details
        or details.get("resource_type") == "Risk assessment"
    )


def _fail(e: CRAEvidenceError, output_format: str) -> NoReturn:
    """Print a top-level command error and exit with its code.

    In ``--output json`` mode, diagnostics go to stderr only, so stdout
    stays empty (never a mix of Rich text and JSON, and never JSON on one
    path but text on another): a machine consumer can always tell success
    from failure by whether stdout parses as JSON, without also having to
    ignore leading error text. Text mode is unchanged: the message (and any
    request ID) print to the normal console.

    Deliberate exception, not routed through this helper: gate exits
    (exit 28, review pending) are outcomes, not errors. They print the full
    machine payload as valid JSON on stdout and signal the gate through the
    exit code plus a stderr notice, so CI can both parse the state and fail
    the job from one invocation. Only genuine failures (config, identity,
    API errors) leave stdout empty.
    """
    target = err_console if output_format == "json" else console
    target.print(f"[red]Error:[/red] {e}")
    if hasattr(e, "request_id") and e.request_id:
        target.print(f"[dim]Request ID: {e.request_id}[/dim]")
    sys.exit(e.exit_code)


def _open_cycle_or_none(
    client: CRAEvidenceClient, product: str, version: str
) -> dict[str, Any] | None:
    """Open or refresh the review cycle; None when there is nothing to review.

    A 422 here means the assessment has no open review and is not currently
    flagged for one (already reviewed, never assessed, or nothing pinned
    yet): not an error, just nothing to do right now.
    """
    try:
        return asyncio.run(client.open_ra_review_cycle(product, version))
    except APIError as e:
        if e.status_code == 422:
            return None
        raise


def _get_delta_or_none(
    client: CRAEvidenceClient, product: str, version: str
) -> dict[str, Any] | None:
    """Read the current review delta; None when there is nothing to review.

    Pure GET: never opens, refreshes, or otherwise persists a review cycle.
    A 404 for a missing risk assessment (see ``_is_missing_ra_404``) means
    there is nothing to review yet, mirroring ``_open_cycle_or_none``'s 422
    handling for the open-cycle POST. Any other error, including a 404 for
    an unknown product or version, propagates so a typo fails loudly.
    """
    try:
        return asyncio.run(client.get_ra_delta(product=product, version=version))
    except APIError as e:
        if e.status_code == 404 and _is_missing_ra_404(e):
            return None
        raise


def _print_no_review_needed(product: str, version: str, output_format: str) -> None:
    if output_format == "json":
        console.print_json(
            json.dumps(
                {
                    "review": None,
                    "advisory": {"disclaimer": DISCLAIMER_TEXT},
                    "note": "the review recorded no changes to assess",
                },
                indent=2,
            )
        )
        return

    console.print("\n[bold]Risk Assessment Review[/bold]\n")
    console.print(
        f"[dim]The review recorded no changes to assess for "
        f"{escape(str(product))} v{escape(str(version))}.[/dim]"
    )
    console.print()


def _emit_review_report(
    output_format: str,
    product: str,
    version: str,
    resolved: int,
    total: int,
    unresolved_item_ids: list[str],
) -> None:
    if output_format == "json":
        console.print_json(
            json.dumps(
                {
                    "review": {
                        "product": product,
                        "version": version,
                        "resolved_count": resolved,
                        "total": total,
                        "unresolved_item_ids": unresolved_item_ids,
                    },
                    "advisory": {"disclaimer": DISCLAIMER_TEXT},
                },
                indent=2,
            )
        )
        return

    console.print("\n[bold]Risk Assessment Review[/bold]\n")
    console.print(f"Resolved {resolved}/{total} review item{'s' if total != 1 else ''}.")
    if unresolved_item_ids:
        count = len(unresolved_item_ids)
        console.print(
            f"[yellow]{count} item{'s' if count != 1 else ''} still "
            f"need{'' if count != 1 else 's'} a decision.[/yellow]"
        )
    console.print(
        "[dim]Finalize is a separate step, done by an organisation admin "
        "(web app, or `ra finalize` with a key that has the finalize "
        "scope).[/dim]"
    )
    console.print()


def _run_interactive_review(
    client: CRAEvidenceClient,
    product: str,
    version: str,
    cycle: dict[str, Any],
) -> dict[str, Any]:
    """Walk unresolved items interactively, recording dispositions.

    Returns the last-known cycle dict (id/digest/items/resolution). A 409
    CYCLE_SUPERSEDED response on a disposition POST means the evidence moved
    underneath the review: the cycle is re-opened and the walk continues
    against the fresh item list. Closed input (Ctrl-D, or an aborted prompt)
    stops the walk early; dispositions already recorded are kept.
    """
    for _ in range(_MAX_CYCLE_REFRESHES):
        items_by_id = {item["item_id"]: item for item in (cycle.get("items") or [])}
        resolution = cycle.get("resolution") or {}
        unresolved_ids = list(resolution.get("unresolved_item_ids") or [])

        superseded = False
        for item_id in unresolved_ids:
            item = items_by_id.get(item_id)
            if item is None:
                continue
            try:
                outcome = _prompt_item(item)
            except (click.Abort, EOFError):
                err_console.print("\n  input closed, stopping the review.")
                return cycle

            if outcome is None:
                continue
            disposition, justification = outcome

            try:
                result = asyncio.run(
                    client.record_ra_disposition(
                        product=product,
                        version=version,
                        cycle_id=cycle["id"],
                        expected_digest=cycle["digest"],
                        item_id=item_id,
                        disposition=disposition,
                        justification=justification,
                    )
                )
            except APIError as e:
                if e.status_code == 409:
                    err_console.print(
                        "  [yellow]The evidence changed since this review "
                        "started; the review list was refreshed.[/yellow]"
                    )
                    cycle = asyncio.run(client.open_ra_review_cycle(product, version))
                    superseded = True
                    break
                raise
            # Rebind rather than mutate cycle["resolution"] in place: cycle is
            # the caller's object (ultimately one JSON-decoded server
            # response), and mutating it out from under the caller is a
            # footgun independent of any test concern.
            cycle = {**cycle, "resolution": result.get("resolution", cycle.get("resolution"))}

        if not superseded:
            return cycle

    msg = "The review list kept changing; re-run `ra review` to continue."
    raise CRAEvidenceError(msg)


@click.group("ra")
def ra() -> None:
    """Risk assessment commands.

    Typical flow: `ra status` to see the state, `ra review` to record a
    decision on each pending change, then `ra finalize` (organisation
    admins) to complete the review. Also available as `risk-assessment`.
    """


@ra.command("status")
@click.option(
    "--product",
    "-p",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "-V",
    "version_number",
    default=None,
    help="Version number",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(FAIL_ON_CHOICES),
    default="none",
    show_default=True,
    help=(
        "Exit non-zero when the risk assessment review status is still "
        "'needs_review'. Choices: unreviewed, none. Has no effect when no "
        "risk assessment exists yet for the version."
    ),
)
@click.pass_context
def ra_status(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    fail_on: str,
) -> None:
    """
    Show the structured risk assessment status for a product version.

    Reports assessment status, review status, completion, inherited-from
    metadata when the version's risk assessment was carried over from an
    earlier version, sign-off summary, asset/threat/risk counts, and Part II
    process coverage when the server includes it in the response.

    This is a review aid. A 'reviewed' review status records that someone
    recorded a decision; it is not a sign-off and not a compliance verdict.

    When no risk assessment has been recorded yet for the version, the
    command prints a note and exits 0. Absence is governed by the existing
    readiness gates (see the status command), not by --fail-on here, so
    --fail-on unreviewed does not turn a missing assessment into a failure.

    Product and version resolve in this order: the flag, then
    CRA_EVIDENCE_PRODUCT / CRA_EVIDENCE_VERSION, then .cra/evidence.yaml.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        _fail(e, output_format)

    if output_format not in ("text", "json"):
        warn_unsupported_output_format(output_format, ("text", "json"))
        output_format = "text"

    try:
        validate_config(config)

        client = CRAEvidenceClient(config)

        try:
            data = asyncio.run(
                client.get_risk_assessment(
                    product=product,
                    version=version_number,
                )
            )
        except APIError as e:
            if e.status_code == 404 and _is_missing_ra_404(e):
                _print_no_assessment_note(product, version_number, output_format)
                return
            raise

        format_risk_assessment_output(data, output_format)

        if fail_on == "unreviewed" and data.get("review_status") == "needs_review":
            _fail(RiskAssessmentReviewPending(), output_format)

    except CRAEvidenceError as e:
        _fail(e, output_format)


@ra.command("review")
@click.option(
    "--product",
    "-p",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "-V",
    "version_number",
    default=None,
    help="Version number",
)
@click.option(
    "--non-interactive",
    "non_interactive",
    is_flag=True,
    default=False,
    help=(
        "Never prompt. Reports how many review items still need a decision "
        "and exits 28 if any remain, 0 if none do. Records nothing: "
        "judgment stays with a human."
    ),
)
@click.pass_context
def ra_review(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    non_interactive: bool,
) -> None:
    """
    Walk the open risk assessment review cycle for a product version, item by item.

    In an interactive terminal, opens (or refreshes) the review cycle for the
    version, then prompts once per unresolved item: a new or removed
    component, a component version change, a changed VEX status, a
    vulnerability candidate, a context change, a stale evidence citation, or
    one of the release questions. Recording a disposition for an item marks
    it resolved; it is not a compliance verdict, only a record that someone
    looked at it and made a call. If the evidence changes underneath the
    review (another pipeline run moved it), the review list is refreshed
    automatically and the walk continues.

    With --non-interactive, or when the session is not a terminal, this
    command never prompts and never opens, refreshes, or otherwise records
    anything: it only reads the current review state and reports how many
    items still need a decision, exiting 28 if any do.

    Finalizing the review cycle (closing it once every item has a
    disposition) is a separate step: see `ra finalize`.

    Product and version resolve in this order: the flag, then
    CRA_EVIDENCE_PRODUCT / CRA_EVIDENCE_VERSION, then .cra/evidence.yaml.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        _fail(e, output_format)

    if output_format not in ("text", "json"):
        warn_unsupported_output_format(output_format, ("text", "json"))
        output_format = "text"

    interactive = (not non_interactive) and is_interactive()

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        if not interactive:
            # Read-only path: a pure GET, never the open-cycle POST. Nothing
            # is created, refreshed, or superseded just to report a count.
            delta = _get_delta_or_none(client, product, version_number)
            if delta is None or not delta.get("items"):
                _print_no_review_needed(product, version_number, output_format)
                return

            if delta.get("preview"):
                # No cycle open yet: every previewed item would need a
                # decision if a cycle were opened now.
                items = delta.get("items") or []
                resolved_count = 0
                total = len(items)
                unresolved_ids = [item["item_id"] for item in items]
            else:
                resolution = delta.get("resolution") or {}
                resolved_count = resolution.get("resolved_count", 0)
                total = resolution.get("total", 0)
                unresolved_ids = list(resolution.get("unresolved_item_ids") or [])

            _emit_review_report(
                output_format,
                product,
                version_number,
                resolved_count,
                total,
                unresolved_ids,
            )
            if unresolved_ids:
                count = len(unresolved_ids)
                msg = (
                    f"{count} review item{'s' if count != 1 else ''} still "
                    f"need{'' if count != 1 else 's'} a decision for "
                    f"{product} v{version_number}."
                )
                _fail(RiskAssessmentReviewPending(msg), output_format)
            return

        cycle = _open_cycle_or_none(client, product, version_number)
        if cycle is None or not cycle.get("items"):
            _print_no_review_needed(product, version_number, output_format)
            return

        cycle = _run_interactive_review(client, product, version_number, cycle)
        resolution = cycle.get("resolution") or {}
        _emit_review_report(
            output_format,
            product,
            version_number,
            resolution.get("resolved_count", 0),
            resolution.get("total", 0),
            resolution.get("unresolved_item_ids") or [],
        )

    except CRAEvidenceError as e:
        _fail(e, output_format)


@ra.command("finalize")
@click.option(
    "--product",
    "-p",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "-V",
    "version_number",
    default=None,
    help="Version number",
)
@click.pass_context
def ra_finalize(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
) -> None:
    """
    Finalize the open risk assessment review cycle for a product version.

    Requires every item in the open cycle to already carry a disposition
    (see `ra review`); closes the cycle and marks the assessment reviewed.
    Finalizing requires an organisation admin or owner role, from a human
    session or an API key holding the finalize scope.

    Finalizing records that the review is complete and closed; it is not a
    sign-off. Sign-off remains a separate human step in the web app.

    Product and version resolve in this order: the flag, then
    CRA_EVIDENCE_PRODUCT / CRA_EVIDENCE_VERSION, then .cra/evidence.yaml.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        _fail(e, output_format)

    if output_format not in ("text", "json"):
        warn_unsupported_output_format(output_format, ("text", "json"))
        output_format = "text"

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        cycle = asyncio.run(
            client.get_ra_delta(product=product, version=version_number)
        )
        if cycle.get("preview") or cycle.get("id") is None:
            msg = (
                f"There is no open review cycle for {product} v"
                f"{version_number}; nothing to finalize."
            )
            raise CRAEvidenceError(msg)

        result = asyncio.run(
            client.finalize_ra_review(
                product=product,
                version=version_number,
                cycle_id=cycle["id"],
            )
        )

        if output_format == "json":
            console.print_json(
                json.dumps(
                    {
                        "finalize": result,
                        "advisory": {"disclaimer": DISCLAIMER_TEXT},
                    },
                    indent=2,
                )
            )
        else:
            console.print("\n[bold]Risk Assessment Review[/bold]\n")
            console.print(
                f"[green]The assessment for {escape(str(product))} v"
                f"{escape(str(version_number))} is now marked reviewed.[/green]"
            )
            console.print(
                "[dim]Sign-off remains a separate human step in the web "
                "app.[/dim]"
            )
            console.print()

    except CRAEvidenceError as e:
        _fail(e, output_format)
