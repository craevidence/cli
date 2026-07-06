"""No-key local CRA assessment commands.

  - assessment templates: list the bundled product-type starters.
  - assessment new:        scaffold an applicability matrix plus starter risk and
                           control catalogs from a template, with a multi-select.
  - assessment check:      lint an applicability matrix for Annex I gaps and gate CI.

Everything here runs client-side with no API key and never contacts a server. The
matrix and catalogs are starters the developer completes; passing the gate checks
structured gaps only and is not an audit.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml

from cra_evidence_cli.assessment.config import (
    DEFAULT_MATRIX_PATH,
    ExceptionsFile,
    GateConfig,
    load_exceptions,
    load_gate_config,
)
from cra_evidence_cli.assessment.detect import detect_template
from cra_evidence_cli.assessment.gate import GateResult, evaluate_gate
from cra_evidence_cli.assessment.matrix import (
    MatrixError,
    dump_matrix,
    load_matrix,
    write_exclusive,
)
from cra_evidence_cli.assessment.select import multiselect
from cra_evidence_cli.assessment.templates import (
    Template,
    TemplateError,
    build_applicability_matrix,
    build_control_catalog,
    build_risk_catalog,
    list_templates,
    load_template,
)
from cra_evidence_cli.display import warn_unsupported_output_format
from cra_evidence_cli.exceptions import ValidationError
from cra_evidence_cli.local.disclaimer import DRAFT_WATERMARK, assert_disclaimer_present

_GATE_DISCLAIMER = (
    "This gate checks structured Annex I gaps only. It is not an audit, and exit 0 "
    "does not prove compliance."
)


@click.group("assessment")
@click.pass_context
def assessment(ctx: click.Context) -> None:
    """Build and check a local CRA Annex I assessment. No API key required."""
    ctx.ensure_object(dict)


@assessment.command("templates")
@click.pass_context
def templates_cmd(ctx: click.Context) -> None:
    """List the bundled product-type starter templates."""
    output_format = ctx.obj["config"].output_format
    warn_unsupported_output_format(output_format, ("text", "json"))
    items = list_templates()
    if output_format == "json":
        click.echo(
            json.dumps(
                [{"id": t.id, "title": t.title, "description": t.description} for t in items],
                indent=2,
            )
        )
        return
    click.echo("Available assessment templates:")
    width = max((len(t.id) for t in items), default=0)
    for template in items:
        click.echo(f"  {template.id.ljust(width)}  {template.title}")
    click.echo("\nStart one with: craevidence assessment new --template <id>")


def _resolve_template(template_id: str | None, path: Path) -> Template:
    if template_id:
        return load_template(template_id)
    detected = detect_template(path)
    if detected is None:
        available = ", ".join(t.id for t in list_templates())
        msg = (
            f"could not detect a product type from {path}. "
            f"Pass --template <id>. Available: {available}."
        )
        raise ValidationError(msg)
    click.echo(f"Detected product type: {detected} (override with --template).", err=True)
    return load_template(detected)


@assessment.command("new")
@click.argument("path", required=False, type=click.Path(path_type=Path), default=Path("."))
@click.option(
    "--template", "template_id", default=None, help="Template id (see 'assessment templates')."
)
@click.option("--product", default=None, help="Product name to embed (placeholder if omitted).")
@click.option("--org", default=None, help="Organisation name to embed.")
@click.option(
    "--output-dir",
    "output_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path(".cra"),
    show_default=True,
    help="Directory for the generated files.",
)
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Skip the multi-select and keep the recommended risks and controls.",
)
@click.pass_context
def new_cmd(
    ctx: click.Context,
    path: Path,
    template_id: str | None,
    product: str | None,
    org: str | None,
    output_dir: Path,
    non_interactive: bool,
) -> None:
    """Scaffold an applicability matrix and starter catalogs from a template.

    Writes an Annex I applicability matrix plus, for the risks and controls you
    select, a Gemara risk catalog and control catalog. Existing files are never
    overwritten. The output is a starter to complete, not a finished assessment.
    """
    try:
        template = _resolve_template(template_id, path)
    except (TemplateError, ValidationError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(getattr(exc, "exit_code", 4))

    interactive = None if not non_interactive else False

    matrix = build_applicability_matrix(template, product)
    risk_ids = multiselect(
        "Select applicable risks for this product",
        [(r.id, f"{r.title} [{r.severity}]") for r in template.risks],
        [r.id for r in template.risks if r.recommended],
        interactive=interactive,
    )
    control_ids = multiselect(
        "Select applicable controls for this product",
        [(c.id, c.title) for c in template.controls],
        [c.id for c in template.controls if c.recommended],
        interactive=interactive,
    )

    outputs: list[tuple[Path, str]] = [(output_dir / "assessment.yaml", dump_matrix(matrix))]
    if risk_ids:
        doc = build_risk_catalog(template, product, org, risk_ids)
        outputs.append((output_dir / "risk-catalog.yaml", _dump_gemara(doc)))
    if control_ids:
        doc = build_control_catalog(template, product, org, control_ids)
        outputs.append((output_dir / "control-catalog.yaml", _dump_gemara(doc)))

    existing = [str(target) for target, _ in outputs if target.exists()]
    if existing:
        click.echo(
            f"Error: refusing to overwrite existing file(s): {', '.join(existing)}. "
            f"Choose a different --output-dir or remove them first.",
            err=True,
        )
        sys.exit(4)

    for target, text in outputs:
        assert_disclaimer_present(text)
        write_exclusive(target, text)
        click.echo(f"Wrote {target}", err=True)
    click.echo(DRAFT_WATERMARK, err=True)
    click.echo(
        f"Next: complete {output_dir / 'assessment.yaml'}, then run "
        f"'craevidence assessment check'.",
        err=True,
    )


def _dump_gemara(doc: dict) -> str:
    body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    return f"# {DRAFT_WATERMARK}\n{body}"


@assessment.command("check")
@click.option(
    "--matrix",
    "matrix_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Applicability matrix to lint (default: .cra/assessment.yaml or the gate config).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Gate config (default: auto-load .cra/assessment-gate.yaml).",
)
@click.option(
    "--exceptions",
    "exceptions_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Exceptions/justifications file (default: auto-load .cra/assessment-exceptions.yaml).",
)
@click.pass_context
def check_cmd(
    ctx: click.Context,
    matrix_path: Path | None,
    config_path: Path | None,
    exceptions_path: Path | None,
) -> None:
    """Lint an applicability matrix for Annex I gaps and gate CI.

    Fails with exit 25 on any unaddressed mandatory Part I(1) or Part II duty, and
    exit 26 on a Part I(2) requirement marked not-applicable without a
    justification. Which conditions block is set by the gate config's 'fail_on';
    others are advisory and do not change the exit code.

    This gate is not an audit and exit 0 does not establish compliance.
    """
    output_format = ctx.obj["config"].output_format
    warn_unsupported_output_format(output_format, ("text", "json"))
    config = load_gate_config(config_path) or GateConfig()
    exceptions = _load_exceptions(exceptions_path, config)

    resolved_matrix = matrix_path or config.matrix_path or DEFAULT_MATRIX_PATH
    if not resolved_matrix.exists():
        msg = (
            f"no assessment matrix found at {resolved_matrix}. "
            f"Create one with 'craevidence assessment new'."
        )
        click.echo(f"Error: {msg}", err=True)
        sys.exit(5)

    try:
        matrix = load_matrix(resolved_matrix)
    except MatrixError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(4)

    result = evaluate_gate(matrix, exceptions, config.fail_on)

    if output_format == "json":
        click.echo(_render_json(resolved_matrix, result))
    else:
        _render_text(resolved_matrix, result)

    sys.exit(result.exit_code())


def _load_exceptions(explicit: Path | None, config: GateConfig) -> ExceptionsFile:
    return load_exceptions(explicit or config.exceptions_path)


def _render_json(matrix_path: Path, result: GateResult) -> str:
    return json.dumps(
        {
            "matrix": str(matrix_path),
            "exit_code": result.exit_code(),
            "blocking": [
                {"key": f.key, "annex_ref": f.annex_ref, "condition": f.condition,
                 "message": f.message}
                for f in result.blocking
            ],
            "advisory": [
                {"key": f.key, "annex_ref": f.annex_ref, "condition": f.condition,
                 "message": f.message}
                for f in result.advisory
            ],
            "disclaimer": _GATE_DISCLAIMER,
        },
        indent=2,
    )


def _render_text(matrix_path: Path, result: GateResult) -> None:
    click.echo(f"Assessment gate: {matrix_path}")
    if result.blocking:
        click.echo(f"\nBlocking gaps ({len(result.blocking)}):")
        for finding in result.blocking:
            click.echo(f"  FAIL [{finding.condition}] {finding.message}")
    if result.advisory:
        click.echo(f"\nAdvisory ({len(result.advisory)}):")
        for finding in result.advisory:
            click.echo(f"  note [{finding.condition}] {finding.message}")
    if not result.blocking:
        click.echo("\nNo blocking gaps.")
    click.echo(f"\n{_GATE_DISCLAIMER}")
