"""No-key local draft generation commands.

Produces skeleton documents for the developer to complete. Every output is
clearly watermarked as a draft. No command here reads an API key or contacts CRA Evidence.
Most run with no network at all;
risk-assessment additionally runs the local vulnerability scan to seed findings,
which by default uses the network for vulnerability data.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import click

from cra_evidence_cli.commands.check import run_local_check
from cra_evidence_cli.exceptions import CRAEvidenceError, ScanEngineUnavailable
from cra_evidence_cli.local.csaf import build_csaf_advisory, build_csaf_vex
from cra_evidence_cli.local.disclaimer import (
    DRAFT_WATERMARK,
    advisory_block,
    assert_disclaimer_present,
)
from cra_evidence_cli.local.models import utc_now_iso
from cra_evidence_cli.local.osv import OSVClientError
from cra_evidence_cli.local.sbom import SBOMParseError
from cra_evidence_cli.local.securitytxt import SecurityTxtReport, validate_security_txt
from cra_evidence_cli.sbom_generator import SBOMGenerationError


@click.group("draft")
@click.pass_context
def draft(ctx: click.Context) -> None:
    """Generate skeleton compliance documents for manual review and completion.

    All outputs are watermarked drafts. Review and edit them before use.
    No API key is required.
    """
    ctx.ensure_object(dict)


# draft vex


def _build_openvex(findings: list) -> dict:
    """Build an OpenVEX v0.2.0 skeleton (one under_investigation statement per finding)."""
    statements = []
    for finding in findings:
        stmt: dict = {
            "vulnerability": {"name": finding.id},
            "status": "under_investigation",
        }
        if finding.aliases:
            stmt["vulnerability"]["aliases"] = sorted(finding.aliases)
        if finding.purl:
            stmt["products"] = [{"@id": finding.purl}]
        statements.append(stmt)
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://openvex.dev/docs/public/vex-{uuid.uuid4().hex}",
        "author": "REPLACE WITH YOUR NAME OR ORG",
        "role": "Document Creator",
        "timestamp": utc_now_iso(),
        "version": 1,
        "tooling": "CRA Evidence CLI draft vex",
        "advisory": advisory_block(),
        "statements": statements,
    }


@draft.command("vex")
@click.argument("path", required=False, type=click.Path(path_type=Path), default=Path("."))
@click.option("--image", help="Container image reference to scan.")
@click.option(
    "--sbom",
    "sbom_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Pre-generated SBOM file to use as scan input.",
)
@click.option(
    "-o",
    "--output-file",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the VEX skeleton to this file instead of stdout.",
)
@click.option(
    "--format",
    "vex_format",
    type=click.Choice(["openvex", "csaf"]),
    default="openvex",
    show_default=True,
    help="VEX output format. csaf emits a CSAF 2.0 VEX document.",
)
@click.pass_context
def vex(
    ctx: click.Context,
    path: Path,
    image: str | None,
    sbom_file: Path | None,
    output_file: Path | None,
    vex_format: str,
) -> None:
    """Produce a VEX skeleton (OpenVEX or CSAF) from local scan findings.

    Runs the same scan pipeline as 'check', then emits one VEX statement per
    finding with status 'under_investigation'. Choose the format with --format
    (openvex by default, or csaf for a CSAF 2.0 VEX document). Fill in the
    justification or impact_statement for each entry, then pass the completed
    file back to 'check --vex' to suppress findings.

    The output is not an audit artifact and does not prove non-exploitability.
    The developer must evaluate each finding and supply an accurate status.
    """
    if sum(1 for item in (bool(image), bool(sbom_file)) if item) > 1:
        msg = "Use only one input mode: PATH, --image, or --sbom."
        raise click.UsageError(msg)

    try:
        result = run_local_check(
            target_path=path,
            image=image,
            sbom_file=sbom_file,
            baseline=None,
            strict=False,
            sbom_quality=False,
            verbose=bool(ctx.obj.get("verbose")),
            vex_file=None,
            ignore_ids=None,
            sbom_output=None,
        )
    except ScanEngineUnavailable as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(exc.exit_code)
    except (SBOMGenerationError, SBOMParseError, OSVClientError, CRAEvidenceError) as exc:
        raise click.ClickException(str(exc)) from exc

    if result.provenance.get("engine") == "osv-online":
        click.echo(
            "Note: Grype was not found, so package coordinates were queried against "
            "OSV.dev over the network.",
            err=True,
        )

    if not result.findings:
        if vex_format == "csaf":
            click.echo(
                "No findings detected; nothing to write. A CSAF VEX document "
                "requires at least one vulnerability.",
                err=True,
            )
            return
        click.echo(
            "No findings detected; the VEX skeleton will have no statements.",
            err=True,
        )

    if vex_format == "csaf":
        doc = build_csaf_vex(result.findings)
        label = "CSAF VEX"
    else:
        doc = _build_openvex(result.findings)
        label = "OpenVEX"

    json_text = json.dumps(doc, indent=2)
    assert_disclaimer_present(json_text)

    n = len(result.findings)
    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json_text, encoding="utf-8")
        click.echo(DRAFT_WATERMARK, err=True)
        click.echo(f"Wrote {n} {label} statement(s) to {output_file}", err=True)
    else:
        click.echo(json_text)
        click.echo(DRAFT_WATERMARK, err=True)


# draft advisory


@draft.command("advisory")
@click.argument("path", required=False, type=click.Path(path_type=Path), default=Path("."))
@click.option("--image", help="Container image reference to scan.")
@click.option(
    "--sbom",
    "sbom_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Pre-generated SBOM file to use as scan input.",
)
@click.option(
    "-o",
    "--output-file",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the advisory skeleton to this file instead of stdout.",
)
@click.pass_context
def advisory(
    ctx: click.Context,
    path: Path,
    image: str | None,
    sbom_file: Path | None,
    output_file: Path | None,
) -> None:
    """Produce a CSAF 2.0 security advisory skeleton from local scan findings.

    Runs the same scan pipeline as 'check', then emits a draft CSAF 2.0 advisory
    (document.category csaf_security_advisory) with one vulnerability entry per
    finding. Each entry carries placeholder notes, a vendor_fix remediation, and
    a product_status referencing the affected component, for you to complete.

    This is a draft skeleton only. It does not publish, sign, distribute, or
    time-stamp an advisory. Review and complete every entry before use.
    """
    if sum(1 for item in (bool(image), bool(sbom_file)) if item) > 1:
        msg = "Use only one input mode: PATH, --image, or --sbom."
        raise click.UsageError(msg)

    try:
        result = run_local_check(
            target_path=path,
            image=image,
            sbom_file=sbom_file,
            baseline=None,
            strict=False,
            sbom_quality=False,
            verbose=bool(ctx.obj.get("verbose")),
            vex_file=None,
            ignore_ids=None,
            sbom_output=None,
        )
    except ScanEngineUnavailable as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(exc.exit_code)
    except (SBOMGenerationError, SBOMParseError, OSVClientError, CRAEvidenceError) as exc:
        raise click.ClickException(str(exc)) from exc

    if result.provenance.get("engine") == "osv-online":
        click.echo(
            "Note: Grype was not found, so package coordinates were queried against "
            "OSV.dev over the network.",
            err=True,
        )

    if not result.findings:
        click.echo(
            "No findings detected; nothing to write. A CSAF advisory requires at "
            "least one vulnerability.",
            err=True,
        )
        return

    doc = build_csaf_advisory(result.findings)
    json_text = json.dumps(doc, indent=2)
    assert_disclaimer_present(json_text)

    n = len(result.findings)
    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json_text, encoding="utf-8")
        click.echo(DRAFT_WATERMARK, err=True)
        click.echo(
            f"Wrote a CSAF advisory skeleton with {n} vulnerability entry(ies) to {output_file}",
            err=True,
        )
    else:
        click.echo(json_text)
        click.echo(DRAFT_WATERMARK, err=True)


# draft security.txt


def _expires_timestamp() -> str:
    """Return an RFC 3339 timestamp 365 days from now, formatted with a trailing Z."""
    expires = datetime.now(UTC) + timedelta(days=365)
    # Zero out sub-second precision and replace the UTC offset with Z.
    return expires.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _disclaimer_as_comments() -> str:
    """Return the draft review marker as RFC 9116 comments."""
    return "# Review before use."


_SECURITY_TXT_INVALID_EXIT = 7

def _render_security_txt_report(report: SecurityTxtReport, source_label: str) -> str:
    """Render a validation report as plain text, one issue per line plus a summary."""
    lines = [f"security.txt validation: {source_label}"]
    if not report.issues:
        lines.append("  OK: no issues found.")
    else:
        for issue in report.issues:
            lines.append(f"  {issue.severity.upper()}: {issue.message}")
    lines.append(f"{len(report.errors)} error(s), {len(report.warnings)} warning(s).")
    return "\n".join(lines)


def _run_security_txt_validate(
    ctx: click.Context, validate_path: Path, fail_on_invalid: bool
) -> None:
    if str(validate_path) == "-":
        text = sys.stdin.read()
        source_label = "<stdin>"
    else:
        text = validate_path.read_text(encoding="utf-8", errors="replace")
        source_label = str(validate_path)

    report = validate_security_txt(text)
    click.echo(_render_security_txt_report(report, source_label))

    if fail_on_invalid and report.errors:
        ctx.exit(_SECURITY_TXT_INVALID_EXIT)


@draft.command("security.txt")
@click.option(
    "--validate",
    "validate_path",
    type=click.Path(exists=True, dir_okay=False, allow_dash=True, path_type=Path),
    help="Validate an existing security.txt instead of emitting a template. Use - for stdin.",
)
@click.option(
    "--fail-on-invalid",
    "fail_on_invalid",
    is_flag=True,
    help="With --validate, exit 7 if validation finds errors. Advisory (exit 0) by default.",
)
@click.option(
    "-o",
    "--output-file",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write security.txt to this file instead of stdout.",
)
@click.pass_context
def security_txt(
    ctx: click.Context,
    validate_path: Path | None,
    fail_on_invalid: bool,
    output_file: Path | None,
) -> None:
    """Emit an RFC 9116 security.txt template, or validate an existing one.

    By default this prints a security.txt template with placeholder values
    (example.com) for you to edit before publishing to
    /.well-known/security.txt. Pass --validate <path> (or - for stdin) to check
    an existing file instead: it reports a missing Contact field, a missing,
    unparseable, or stale Expires date, and any leftover placeholder values.

    This output is a starter template, not a published policy.
    """
    if validate_path is not None:
        if output_file is not None:
            msg = "--output-file cannot be combined with --validate."
            raise click.UsageError(msg)
        _run_security_txt_validate(ctx, validate_path, fail_on_invalid)
        return

    if fail_on_invalid:
        msg = "--fail-on-invalid only applies together with --validate."
        raise click.UsageError(msg)

    disclaimer_comments = _disclaimer_as_comments()
    expires = _expires_timestamp()

    body = (
        "# security.txt (RFC 9116). draft / review before publishing.\n"
        f"{disclaimer_comments}\n"
        "# Publish a contact address and policy URL after review.\n"
        f"Contact: mailto:security@example.com\n"
        f"Expires: {expires}\n"
        f"Policy: https://example.com/.well-known/cvd-policy\n"
        f"Preferred-Languages: en\n"
        f"Canonical: https://example.com/.well-known/security.txt\n"
    )

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(body, encoding="utf-8")
        click.echo(DRAFT_WATERMARK, err=True)
        click.echo(f"Wrote security.txt to {output_file}", err=True)
    else:
        click.echo(body, nl=False)
        click.echo(DRAFT_WATERMARK, err=True)


# draft risk-assessment / draft threat-model


def _resolve_components(
    path: Path, sbom_file: Path | None, verbose: bool
) -> tuple[list, Path | None]:
    """Parse components from an SBOM file, an SBOM path, or a directory SBOM."""
    from cra_evidence_cli.local.sbom import SBOMParseError, load_sbom

    try:
        if sbom_file is not None:
            components, _ = load_sbom(sbom_file)
            resolved_sbom = sbom_file
        elif path.is_file():
            components, _ = load_sbom(path)
            resolved_sbom = path
        else:
            from cra_evidence_cli.sbom_generator import (
                SBOMGenerationError,
                generate_sbom_from_directory,
            )

            try:
                gen = generate_sbom_from_directory(str(path), verbose=verbose, offline=True)
            except SBOMGenerationError as exc:
                raise click.ClickException(str(exc)) from exc
            try:
                components, _ = load_sbom(gen.file_path)
                resolved_sbom = Path(gen.file_path)
            except SBOMParseError:
                # A directory with no resolvable dependency manifest yields no
                # components; scaffold with an empty inventory instead of failing.
                components = []
                resolved_sbom = None
    except SBOMParseError as exc:
        raise click.ClickException(str(exc)) from exc
    return components, resolved_sbom


def _finding_dicts_for_risk(
    path: Path, sbom_path: Path | None, ctx: click.Context
) -> tuple[list[dict], int]:
    if sbom_path is None:
        return [], 0
    try:
        result = run_local_check(
            target_path=path,
            image=None,
            sbom_file=sbom_path,
            baseline=None,
            strict=False,
            sbom_quality=False,
            verbose=bool(ctx.obj.get("verbose")),
            vex_file=None,
            ignore_ids=None,
            sbom_output=None,
        )
    except (
        ScanEngineUnavailable,
        SBOMGenerationError,
        SBOMParseError,
        OSVClientError,
        CRAEvidenceError,
    ) as exc:
        click.echo(f"Warning: could not seed vulnerability risks from local scan: {exc}", err=True)
        return [], 0
    findings = result.findings
    return (
        [
            {
                "name": finding.package,
                "version": finding.version,
                "purl": finding.purl,
                "vulnerability_id": finding.id,
                "severity": finding.severity,
                "title": finding.title,
            }
            for finding in findings[:10]
        ],
        len(findings),
    )


def _slug(value: str) -> str:
    """Lowercase slug: alphanumerics kept, every other run collapsed to one hyphen."""
    out: list[str] = []
    prev_dash = False
    for ch in (value or "").lower():
        if ch.isalnum():
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    return "".join(out).strip("-") or "item"


def _dump_and_emit(doc: dict, output_file: Path | None, label: str) -> None:
    import yaml

    body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    extra = ""
    if label.startswith("RiskCatalog"):
        extra = "# This is a deterministic starter draft, not a reasoned risk assessment.\n"
    text = f"# {DRAFT_WATERMARK}\n{extra}{body}"
    assert_disclaimer_present(text)
    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(text, encoding="utf-8")
        click.echo(DRAFT_WATERMARK, err=True)
        click.echo(f"Wrote {label} to {output_file}", err=True)
    else:
        click.echo(text, nl=False)
        click.echo(DRAFT_WATERMARK, err=True)


def _emit_scaffold(
    gemara_type: str,
    ctx: click.Context,
    path: Path,
    sbom_file: Path | None,
    product: str | None,
    org: str | None,
    output_file: Path | None,
) -> None:
    from cra_evidence_cli.commands.gemara import TEMPLATE_BUILDERS

    components, resolved_sbom = _resolve_components(path, sbom_file, bool(ctx.obj.get("verbose")))
    comp_dicts = [{"name": c.name, "version": c.version, "purl": c.purl} for c in components]
    if gemara_type == "RiskCatalog":
        finding_dicts, finding_count = _finding_dicts_for_risk(path, resolved_sbom, ctx)
        if finding_count > 10:
            click.echo(
                "Warning: seeding the first 10 vulnerability findings; "
                "review the scan output for the full list.",
                err=True,
            )
        if finding_dicts:
            comp_dicts = finding_dicts
    if len(comp_dicts) > 10:
        click.echo(
            f"Warning: seeding the first 10 of {len(comp_dicts)} components; "
            "review the SBOM for the full inventory.",
            err=True,
        )
    product_obj = {"name": product or "<product>", "slug": product or "product"}
    doc = TEMPLATE_BUILDERS[gemara_type](product_obj, org or "", comp_dicts)
    _dump_and_emit(doc, output_file, f"{gemara_type} scaffold")


# STRIDE is posed as a single bracketed question so each entry stays a prompt the
# human answers, never a finished or assessed threat.
_STRIDE_PROMPT = (
    "[Assess STRIDE on this flow: spoofing, tampering, repudiation, information "
    "disclosure, denial of service, elevation of privilege. Describe the realistic "
    "threats and their controls.]"
)


def _threat_catalog_from_diagram(
    product: dict, org_name: str, diagram: object, components: list[dict]
) -> dict:
    """Build a ThreatCatalog seeded from a parsed Mermaid architecture diagram.

    Nodes become capabilities, each data flow (edge) becomes one threat carrying a
    bracketed STRIDE prompt, and subgraphs become trust-boundary groups, with
    boundary-crossing flows seeded first. Every threat description stays a
    bracketed question; nothing here is a finished or assessed threat.
    """
    nodes = diagram.nodes

    def label_of(node_id: str) -> str:
        node = nodes.get(node_id)
        return node.label if node else node_id

    def boundary_of(node_id: str) -> str | None:
        return diagram.node_boundary.get(node_id)

    def crosses(edge: object) -> bool:
        return boundary_of(edge.src) != boundary_of(edge.dst)

    groups = [
        {
            "id": "data-flows",
            "title": "Data flows",
            "description": (
                "Flows and components from the architecture diagram. "
                "[Confirm the scope and trust assumptions.]"
            ),
        },
        {
            "id": "cross-boundary",
            "title": "Cross-boundary data flows",
            "description": (
                "Flows that cross a trust boundary. "
                "[Confirm the controls at each boundary crossing.]"
            ),
        },
    ]
    for boundary_id, boundary_title in diagram.boundaries.items():
        groups.append(
            {
                "id": _slug(boundary_id),
                "title": boundary_title,
                "description": (
                    f"Trust boundary: components inside '{boundary_title}'. "
                    "[Confirm the boundary and its controls.]"
                ),
            }
        )

    threats: list[dict] = []
    counter = 0

    def next_id() -> str:
        nonlocal counter
        counter += 1
        return f"T{counter:02d}"

    if nodes:
        threats.append(
            {
                "id": next_id(),
                "title": "Architecture components in scope",
                "description": (
                    "[Confirm this component inventory and the trust assumptions for each.]"
                ),
                "group": "data-flows",
                "capabilities": [
                    {
                        "reference-id": "CAP",
                        "entries": [{"reference-id": node_id} for node_id in nodes],
                    }
                ],
            }
        )

    # Collapse duplicate edges (same src, dst and label) so a diagram that draws
    # the same flow twice does not produce duplicate threat prompts.
    seen_edges: set = set()
    unique_edges = []
    for edge in diagram.edges:
        key = (edge.src, edge.dst, edge.label)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        unique_edges.append(edge)
    ordered = [e for e in unique_edges if crosses(e)] + [
        e for e in unique_edges if not crosses(e)
    ]
    for edge in ordered:
        src_b, dst_b = boundary_of(edge.src), boundary_of(edge.dst)
        if crosses(edge):
            group = "cross-boundary"
            where = f"crosses {src_b or 'external'} -> {dst_b or 'external'}"
        elif src_b:
            group = _slug(src_b)
            where = f"within {src_b}"
        else:
            group = "data-flows"
            where = "outside trust boundaries"
        channel = f" over {edge.label}" if edge.label else ""
        title = (
            f"Threat on data flow: {label_of(edge.src)} -> {label_of(edge.dst)} "
            f"({where}){channel}"
        )
        threats.append(
            {
                "id": next_id(),
                "title": title,
                "description": _STRIDE_PROMPT,
                "group": group,
                "capabilities": [
                    {
                        "reference-id": "CAP",
                        "entries": [
                            {"reference-id": edge.src},
                            {"reference-id": edge.dst},
                        ],
                    }
                ],
            }
        )

    for node_id, node in nodes.items():
        if node.shape == "datastore":
            boundary = boundary_of(node_id)
            threats.append(
                {
                    "id": next_id(),
                    "title": f"Threat on data at rest: {node.label}",
                    "description": (
                        "[Assess confidentiality and integrity of stored data: encryption "
                        "at rest, access control, backups. Describe the threats and controls.]"
                    ),
                    "group": _slug(boundary) if boundary else "data-flows",
                    "capabilities": [
                        {"reference-id": "CAP", "entries": [{"reference-id": node_id}]}
                    ],
                }
            )

    comp_names = [c.get("name") for c in components if c.get("name")][:10]
    if comp_names:
        threats.append(
            {
                "id": next_id(),
                "title": "Threat from third-party components",
                "description": (
                    "[Assess supply-chain threats for these dependencies: known "
                    "vulnerabilities, malicious updates, provenance. Describe the controls.]"
                ),
                "group": "data-flows",
                "capabilities": [
                    {
                        "reference-id": "CAP",
                        "entries": [{"reference-id": name} for name in comp_names],
                    }
                ],
            }
        )

    threats.append(
        {
            "id": next_id(),
            "title": "[Describe a threat this diagram does not capture]",
            "description": (
                "[Add threats not represented by the architecture diagram, for example "
                "physical access, social engineering, or insider threats.]"
            ),
            "group": "data-flows",
            "capabilities": [{"reference-id": "CAP", "entries": []}],
        }
    )

    return {
        "title": f"{product.get('name') or 'Product'} - Threat Catalog",
        "metadata": {
            "id": f"{_slug(product.get('slug') or 'product')}-threat-catalog",
            "type": "ThreatCatalog",
            "gemara-version": "1.0.0",
            "description": "Threats for this product, seeded from the architecture diagram.",
            "version": "1.0.0",
            "author": {
                "id": "security-team",
                "name": org_name or "Security Team",
                "type": "Human",
            },
            "mapping-references": [
                {
                    "id": "CAP",
                    "title": "Product capabilities",
                    "version": "1.0.0",
                    "description": "Local capability identifiers from the architecture diagram.",
                }
            ],
        },
        "groups": groups,
        "threats": threats,
    }


@draft.command("risk-assessment")
@click.argument("path", required=False, type=click.Path(path_type=Path), default=Path("."))
@click.option(
    "--sbom",
    "sbom_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Pre-generated SBOM to seed the risk subjects.",
)
@click.option("--product", default=None, help="Product name to embed (placeholder if omitted).")
@click.option("--org", default=None, help="Organisation name to embed.")
@click.option(
    "-o",
    "--output-file",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the YAML scaffold to this file instead of stdout.",
)
@click.pass_context
def risk_assessment(
    ctx: click.Context,
    path: Path,
    sbom_file: Path | None,
    product: str | None,
    org: str | None,
    output_file: Path | None,
) -> None:
    """Scaffold a RiskCatalog seeded from your SBOM components.

    This is a deterministic starter draft, not a reasoned risk assessment. It
    seeds risk entries from real component names and from a local vulnerability
    scan, so you can fill in impacts and judgements. The scan uses the same
    engine as 'check' and by default uses the network for vulnerability data; it
    needs no API key and never contacts CRA Evidence. It produces the same
    format as 'compliance-as-code template --type risk-catalog'.
    """
    _emit_scaffold("RiskCatalog", ctx, path, sbom_file, product, org, output_file)


@draft.command("threat-model")
@click.argument("path", required=False, type=click.Path(path_type=Path), default=Path("."))
@click.option(
    "--sbom",
    "sbom_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Pre-generated SBOM to seed the threat subjects.",
)
@click.option("--product", default=None, help="Product name to embed (placeholder if omitted).")
@click.option("--org", default=None, help="Organisation name to embed.")
@click.option(
    "--diagram",
    "diagram_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Mermaid architecture diagram (.mmd) to seed threats from its data flows.",
)
@click.option(
    "-o",
    "--output-file",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the YAML scaffold to this file instead of stdout.",
)
@click.pass_context
def threat_model(
    ctx: click.Context,
    path: Path,
    sbom_file: Path | None,
    product: str | None,
    org: str | None,
    diagram_file: Path | None,
    output_file: Path | None,
) -> None:
    """Scaffold a ThreatCatalog seeded from your SBOM components.

    This is a deterministic starter draft, not a reasoned threat model. By
    default it seeds capability entries from real component names. With
    --diagram it instead reads your existing Mermaid architecture diagram and
    seeds one threat per data flow (components become capabilities, subgraphs
    become trust-boundary groups, boundary-crossing flows come first); pass
    --sbom as well to also seed a third-party-component threat. Every threat is
    a bracketed prompt for you to complete. It produces the same format as
    'compliance-as-code template --type threat-catalog', and makes no network
    call of its own and needs no API key.
    """
    if diagram_file is not None:
        from cra_evidence_cli.local.mermaid import parse_mermaid

        diagram = parse_mermaid(diagram_file.read_text(encoding="utf-8", errors="ignore"))
        comp_dicts: list[dict] = []
        if sbom_file is not None:
            from cra_evidence_cli.local.sbom import SBOMParseError, load_sbom

            try:
                components, _ = load_sbom(sbom_file)
            except SBOMParseError as exc:
                raise click.ClickException(str(exc)) from exc
            comp_dicts = [
                {"name": c.name, "version": c.version, "purl": c.purl} for c in components
            ]
        product_obj = {"name": product or "<product>", "slug": product or "product"}
        doc = _threat_catalog_from_diagram(product_obj, org or "", diagram, comp_dicts)
        _dump_and_emit(doc, output_file, "ThreatCatalog scaffold")
        return
    _emit_scaffold("ThreatCatalog", ctx, path, sbom_file, product, org, output_file)
