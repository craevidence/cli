"""
Compliance-as-code commands - author CRA compliance documents as YAML.

User-facing name: `compliance-as-code`. Internally the schema is Gemara
(OpenSSF GRC Engineering Model v1.0.0); we keep that name on-the-wire
(`metadata.type`, CUE module, document tags) so customers who recognise the
format can find it, but the CLI surface stays neutral.

Three subcommands:
  - template: generate a starter YAML locally from product/SBOM data
  - validate: run `cue vet` locally (fallback to server if CUE missing)
  - upload:   send the YAML to the CRA Evidence `/ci/upload` endpoint
"""

import asyncio
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import click
import httpx
import yaml
from rich.console import Console

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.commands.upload import enforce_structured_mapping, format_output
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.exceptions import APIError, CRAEvidenceError
from cra_evidence_cli.local.sbom import SBOMParseError, load_sbom
from cra_evidence_cli.styles import label as style_label
from cra_evidence_cli.styles import result as style_result
from cra_evidence_cli.styles import status_style

console = Console()
err_console = Console(stderr=True)

# CUE module identifier. Do NOT shorten to `@v1`; the registry rejects that
# form for v1.x schemas.
GEMARA_CUE_MODULE = "github.com/gemaraproj/gemara@v1.0.0"

# CLI-facing template types → Gemara `metadata.type` values.
TEMPLATE_TYPES = {
    "risk-catalog": "RiskCatalog",
    "policy": "Policy",
    "guidance-catalog": "GuidanceCatalog",
    "threat-catalog": "ThreatCatalog",
    "control-catalog": "ControlCatalog",
}

# Gemara type → (DocumentType, scope) mapping for upload.
# scope = "version" means the doc attaches to a specific version;
# scope = "product" means product-level (--version is ignored).
#
# Policy is intentionally absent: both vulnerability_policy and
# coordinated_disclosure_policy are valid targets, so we require the caller
# to disambiguate via --document-type. Ambiguous input is rejected rather
# than guessed.
GEMARA_TYPE_MAP: dict[str, tuple[str, str]] = {
    "RiskCatalog": ("risk_assessment", "version"),
    "ThreatCatalog": ("threat_model", "version"),
    "GuidanceCatalog": ("update_mechanism_documentation", "product"),
    "ControlCatalog": ("secure_development_policy", "product"),
    # EvaluationLog is per-build evidence of control execution.
    "EvaluationLog": ("test_report", "version"),
}

POLICY_DOC_TYPES = {"vulnerability_policy", "coordinated_disclosure_policy"}
PRODUCT_LEVEL_DOC_TYPES = {
    "vulnerability_policy",
    "coordinated_disclosure_policy",
    "update_mechanism_documentation",
    "secure_development_policy",
}


@click.group("compliance-as-code")
def gemara() -> None:
    """
    Author CRA compliance documents as YAML (compliance-as-code).

    Uploads a machine-readable YAML describing risk, threats, vulnerability
    handling, update mechanisms, internal controls, or evaluation results.
    CRA Evidence validates the schema, renders a PDF, and stores the PDF as
    the compliance artifact. PDF/DOCX uploads remain supported.
    """


def _iso_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _slug_id(product_slug: str, suffix: str) -> str:
    """Build a hyphenated identifier from a product slug, collapsing non-alphanumerics."""
    out: list[str] = []
    prev_dash = False
    for ch in (product_slug or "").lower():
        if ch.isalnum():
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    base = "".join(out).strip("-") or "org"
    return f"{base}-{suffix}"


def _risk_severity(value: object) -> str:
    text = str(value or "").lower()
    if text == "critical":
        return "Critical"
    if text == "high":
        return "High"
    if text in {"medium", "moderate"}:
        return "Medium"
    if text == "low":
        return "Low"
    return "Medium"


def _build_risk_catalog(product: dict, org_name: str, components: list[dict]) -> dict:
    finding_subjects = [c for c in components if c.get("vulnerability_id")][:10]
    component_subjects = [c.get("name") for c in components if c.get("name")][:10]
    risks = [
        {
            "id": "R01",
            "title": "Risk assessment context",
            "description": (
                "Document the cybersecurity risk assessment inputs: "
                "intended purpose [describe the intended purpose]; "
                "reasonably foreseeable use [describe expected use and misuse]; "
                "operational environment [describe deployment conditions]; "
                "assets to be protected [identify data, functions and services]; "
                "applicable security requirements [state what applies]."
            ),
            "group": "risk-assessment-context",
            "severity": "Medium",
            "impact": "[Explain how these inputs affect the risk analysis]",
        }
    ]
    next_index = 2
    if finding_subjects:
        for item in finding_subjects:
            vuln_id = item.get("vulnerability_id") or "known vulnerability"
            package = item.get("name") or item.get("package") or "component"
            version = f" {item.get('version')}" if item.get("version") else ""
            risks.append(
                {
                    "id": f"R{next_index:02d}",
                    "title": f"{vuln_id} affecting {package}",
                    "description": (
                        f"Evaluate exposure to {vuln_id} in dependency '{package}{version}'. "
                        f"[Confirm exploitability, reachability, mitigations and remediation.]"
                    ),
                    "group": "vulnerability-management",
                    "severity": _risk_severity(item.get("severity")),
                    "impact": "[Describe the business, safety and compliance impact]",
                }
            )
            next_index += 1
    else:
        for name in component_subjects:
            risks.append(
                {
                    "id": f"R{next_index:02d}",
                    "title": f"Risk related to {name}",
                    "description": f"Evaluate risk exposure for dependency '{name}'.",
                    "group": "software-supply-chain",
                    "severity": "Medium",
                    "impact": "[Describe the business and compliance impact]",
                }
            )
            next_index += 1

    risks.extend(
        [
            {
                "id": f"R{next_index:02d}",
                "title": "Update delivery and verification risk",
                "description": (
                    "[Assess whether update delivery, integrity verification, rollback "
                    "and user notification reduce cybersecurity risk.]"
                ),
                "group": "update-mechanism",
                "severity": "Medium",
                "impact": "[Describe impact if updates cannot be trusted or applied]",
            },
            {
                "id": f"R{next_index + 1:02d}",
                "title": "Vulnerability handling process risk",
                "description": (
                    "[Assess intake, triage, remediation, disclosure and advisory "
                    "publication for vulnerabilities in product and third-party components.]"
                ),
                "group": "vulnerability-management",
                "severity": "Medium",
                "impact": "[Describe impact if vulnerabilities are not handled effectively]",
            },
        ]
    )
    return {
        "title": f"{product.get('name') or 'Product'} - Risk Catalog",
        "metadata": {
            "id": _slug_id(product.get("slug") or "", "risk-catalog"),
            "type": "RiskCatalog",
            "gemara-version": "1.0.0",
            "description": "Cybersecurity risk assessment starter.",
            "version": "1.0.0",
            "author": {"id": "security-team", "name": org_name or "Security Team", "type": "Human"},
        },
        "groups": [
            {"id": "risk-assessment-context", "title": "Risk Assessment Context",
             "description": "Inputs to document before judging risk.",
             "appetite": "Low", "max-severity": "High"},
            {"id": "software-supply-chain", "title": "Software Supply Chain",
             "description": "Risks from third-party components and build pipeline.",
             "appetite": "Minimal", "max-severity": "Critical"},
            {"id": "update-mechanism", "title": "Update Mechanism",
             "description": "Risks from update delivery and verification.",
             "appetite": "Low", "max-severity": "High"},
            {"id": "vulnerability-management", "title": "Vulnerability Management",
             "description": "Risks from known CVE handling and remediation.",
             "appetite": "Low", "max-severity": "Critical"},
        ],
        "risks": risks,
    }


def _build_policy(product: dict, org_name: str) -> dict:
    return {
        "title": f"{product.get('name') or 'Product'} - Vulnerability Handling Policy",
        "metadata": {
            "id": _slug_id(product.get("slug") or "", "policy"),
            "type": "Policy",
            "gemara-version": "1.0.0",
            "description": "Vulnerability handling and coordinated disclosure policy.",
            "version": "1.0.0",
            "author": {"id": "security-team", "name": org_name or "Security Team", "type": "Human"},
        },
        "contacts": {
            "responsible": [
                {
                    "name": "Security Lead",
                    "affiliation": org_name or "",
                    "email": "security@example.com",
                }
            ],
            "accountable": [{"name": "CISO", "affiliation": org_name or ""}],
            "informed": [{"name": "Legal Team"}],
        },
        "scope": {
            "in": {
                "technologies": ["All digital products placed on the EU market"],
                "geopolitical": ["EU", "EEA"],
                "sensitivity": ["Public", "Internal", "Confidential"],
                "users": ["Security researchers", "Customers", "Partners"],
            },
        },
        "implementation-plan": {
            "evaluation-timeline": {"start": _iso_now(), "notes": "Reviewed annually."},
            "enforcement-timeline": {"start": _iso_now(), "notes": "Effective immediately."},
            "notification-process": (
                "Report vulnerabilities to security@example.com."
                " Acknowledgment within 5 business days."
            ),
        },
        "adherence": {
            "evaluation-methods": [
                {"id": "EVAL-01", "type": "Behavioral", "mode": "Manual",
                 "description": "Monthly review of open vulnerability tickets against SLA."},
            ],
            "enforcement-methods": [
                {"id": "ENF-01", "type": "Remediation", "mode": "Manual",
                 "description": "SLA breach triggers incident escalation."},
            ],
            "non-compliance": "[Describe the consequences of an SLA breach]",
        },
    }


def _build_guidance_catalog(product: dict, org_name: str) -> dict:
    return {
        "title": f"{product.get('name') or 'Product'} - Update Mechanism Documentation",
        "type": "Best Practice",
        "metadata": {
            "id": _slug_id(product.get("slug") or "", "guidance-catalog"),
            "type": "GuidanceCatalog",
            "gemara-version": "1.0.0",
            "description": "Software update mechanism documentation.",
            "version": "1.0.0",
            "author": {
                "id": "engineering-team",
                "name": org_name or "Engineering Team",
                "type": "Human",
            },
        },
        "groups": [
            {"id": "update-delivery", "title": "Update Delivery",
             "description": "How updates are packaged and delivered."},
            {"id": "update-verification", "title": "Update Verification",
             "description": "How update integrity and authenticity are verified."},
            {"id": "user-notification", "title": "User Notification",
             "description": "How users are informed of available updates."},
            {"id": "rollback", "title": "Rollback and Recovery",
             "description": "How failed updates are handled."},
        ],
        "guidelines": [
            {
                "id": "UPD.GL01",
                "title": "Authenticated update delivery",
                "objective": (
                    "Updates MUST be delivered over authenticated, encrypted channels (TLS 1.2+)."
                ),
                "group": "update-delivery",
                "state": "Active",
                "recommendations": ["Use TLS 1.3", "Never deliver updates over HTTP"],
            },
            {
                "id": "UPD.GL02",
                "title": "Cryptographic signature verification",
                "objective": "Devices MUST verify the signature before applying any update.",
                "group": "update-verification",
                "state": "Active",
                "recommendations": [
                    "Manage signing keys in an HSM",
                    "Rotate keys at least annually",
                ],
            },
            {
                "id": "UPD.GL03",
                "title": "Safe rollback",
                "objective": (
                    "On update failure, the device MUST revert to the previous working version."
                ),
                "group": "rollback",
                "state": "Active",
                "recommendations": ["Implement A/B partitioning", "Test rollback in CI"],
            },
        ],
    }


def _build_threat_catalog(product: dict, org_name: str, components: list[dict]) -> dict:
    # threats[].capabilities must be a list of MultiEntryMapping objects
    # (reference-id + entries[reference-id]). We seed with real SBOM component
    # names so the file is immediately meaningful.
    comp_names = [c.get("name") for c in components if c.get("name")][:5]
    if not comp_names:
        comp_names = ["[capability-id]"]
    return {
        "title": f"{product.get('name') or 'Product'} - Threat Catalog",
        "metadata": {
            "id": _slug_id(product.get("slug") or "", "threat-catalog"),
            "type": "ThreatCatalog",
            "gemara-version": "1.0.0",
            "description": "Threats for this product.",
            "version": "1.0.0",
            "author": {"id": "security-team", "name": org_name or "Security Team", "type": "Human"},
            "mapping-references": [
                {"id": "CAP", "title": "Product capabilities",
                 "version": "1.0.0",
                 "description": "Local capability identifiers for this product."},
            ],
        },
        "groups": [
            {"id": "supply-chain", "title": "Supply Chain", "description": "Supply chain threats."},
        ],
        "threats": [
            {
                "id": "T01",
                "title": "[Describe a top threat]",
                "description": "",
                "group": "supply-chain",
                "capabilities": [
                    {
                        "reference-id": "CAP",
                        "entries": [{"reference-id": name} for name in comp_names],
                    },
                ],
            },
        ],
    }


def _build_control_catalog(product: dict, org_name: str) -> dict:
    return {
        "title": f"{product.get('name') or 'Product'} - Control Catalog",
        "metadata": {
            "id": _slug_id(product.get("slug") or "", "control-catalog"),
            "type": "ControlCatalog",
            "gemara-version": "1.0.0",
            "description": "Implemented security controls.",
            "version": "1.0.0",
            "author": {"id": "security-team", "name": org_name or "Security Team", "type": "Human"},
            "applicability-groups": [
                {
                    "id": "all-products",
                    "title": "All products",
                    "description": "Default applicability scope for every product in this org.",
                },
            ],
        },
        "groups": [
            {"id": "secure-by-default", "title": "Secure by Default",
             "description": "Controls ensuring default-secure configuration."},
        ],
        "controls": [
            {
                "id": "C01",
                "title": "[Describe a control]",
                "objective": "[Explain what this control achieves]",
                "group": "secure-by-default",
                "state": "Active",
                "assessment-requirements": [
                    {
                        "id": "AR01",
                        "text": "[State the assessment requirement as a MUST statement]",
                        "applicability": ["all-products"],
                        "state": "Active",
                    },
                ],
            },
        ],
    }


TEMPLATE_BUILDERS = {
    "RiskCatalog": lambda product, org_name, components: (
        _build_risk_catalog(product, org_name, components)
    ),
    "Policy": lambda product, org_name, components: _build_policy(product, org_name),
    "GuidanceCatalog": lambda product, org_name, components: (
        _build_guidance_catalog(product, org_name)
    ),
    "ThreatCatalog": lambda product, org_name, components: (
        _build_threat_catalog(product, org_name, components)
    ),
    "ControlCatalog": lambda product, org_name, components: (
        _build_control_catalog(product, org_name)
    ),
}


async def _fetch_product(client: CRAEvidenceClient, product_identifier: str) -> dict:
    """Look up the full product dict (by slug or UUID) via the products list."""
    async with httpx.AsyncClient(timeout=client.timeout) as http:
        response = await http.get(
            f"{client.base_url}/api/v1/products",
            headers=client._get_headers(),
        )
    products = client._handle_response(response)
    if isinstance(products, list):
        for p in products:
            if p.get("slug") == product_identifier or p.get("id") == product_identifier:
                return p
    raise APIError(message=f"Product '{product_identifier}' not found.", status_code=404)


async def _fetch_latest_components(client: CRAEvidenceClient, product_id: str) -> list[dict]:
    """Fetch components from the most recent version's latest SBOM."""
    async with httpx.AsyncClient(timeout=client.timeout) as http:
        versions_resp = await http.get(
            f"{client.base_url}/api/v1/products/{product_id}/versions",
            headers=client._get_headers(),
        )
        versions = client._handle_response(versions_resp)
        if not isinstance(versions, list) or not versions:
            return []
        # Versions are typically returned newest-first by created_at; take the
        # first with any SBOM. Fall back to the first version.
        for v in versions:
            vid = v.get("id")
            if not vid:
                continue
            detail_resp = await http.get(
                f"{client.base_url}/api/v1/products/{product_id}/versions/{vid}",
                headers=client._get_headers(),
            )
            detail = client._handle_response(detail_resp)
            sboms = detail.get("sboms") if isinstance(detail, dict) else None
            if sboms:
                sbom_id = sboms[0].get("id")
                if sbom_id:
                    comps_resp = await http.get(
                        f"{client.base_url}/api/v1/sboms/{sbom_id}/components",
                        headers=client._get_headers(),
                        params={"limit": 50},
                    )
                    comps = client._handle_response(comps_resp)
                    if isinstance(comps, list):
                        return comps
                    if isinstance(comps, dict) and isinstance(comps.get("items"), list):
                        return comps["items"]
            break
        return []


def _write_gemara_template(output_path: Path, doc: dict) -> None:
    """Write a generated compliance YAML document and print the next-step hint."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True)
    console.print(f"{style_result('Wrote', status_style('complete'))} {output_path}")
    err_console.print(
        f"[dim]Next: edit the file, then run[/dim] "
        f"[cyan]craevidence compliance-as-code validate --file {output_path}[/cyan]"
    )


def _components_from_sbom(sbom_path: Path) -> list[dict]:
    try:
        components, _ = load_sbom(sbom_path)
    except SBOMParseError as exc:
        msg = f"Could not parse SBOM {sbom_path}: {exc}"
        raise click.UsageError(msg) from exc
    return [{"name": c.name, "version": c.version, "purl": c.purl} for c in components]


@gemara.command("template")
@click.option("--type", "template_type",
              type=click.Choice(list(TEMPLATE_TYPES.keys()), case_sensitive=False),
              required=True,
              help="Document type to scaffold.")
@click.option("--product", required=True, help="Product slug or UUID.")
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True,
              help="Output path for the generated YAML file.")
@click.option("--force", is_flag=True, help="Overwrite output file if it exists.")
@click.option("--org", "org_name_opt", default=None,
              help="Organisation name to embed (used with --offline; no API lookup).")
@click.option("--offline", is_flag=True,
              help="Build locally with a placeholder product identity; no API key or network.")
@click.option("--sbom", "sbom_file",
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="With --offline, seed RiskCatalog or ThreatCatalog subjects from a local SBOM.")
@click.option("--template", "starter_template_id", default=None,
              help="Product-type template to also seed risks from, for --type risk-catalog "
                   "(see 'assessment templates').")
@click.pass_context
def template(
    ctx: click.Context,
    template_type: str,
    product: str,
    output_path: Path,
    force: bool,
    org_name_opt: str | None,
    offline: bool,
    sbom_file: Path | None,
    starter_template_id: str | None,
) -> None:
    """
    Generate a starter compliance YAML file for a product.

    By default this fetches product name and slug from the CRA Evidence API
    and - for RiskCatalog / ThreatCatalog - pre-populates entries with real
    SBOM component names as subjects. Use --org to set the organisation name
    in the generated file; product API objects do not carry an org name. With
    --offline it builds locally from a placeholder identity, with no API key
    and no network. Add --sbom to seed subjects from a local SBOM; without
    --sbom, offline output uses placeholders for product data and subject
    matter. Install cue to validate locally.
    """
    config = ctx.obj["config"]
    gemara_type = TEMPLATE_TYPES[template_type.lower()]

    if starter_template_id and gemara_type != "RiskCatalog":
        msg = (
            "--template applies to --type risk-catalog; use 'assessment new' for the "
            "full product-type starter."
        )
        raise click.UsageError(msg)

    def _apply_starter(doc: dict) -> dict:
        if not starter_template_id:
            return doc
        from cra_evidence_cli.assessment.templates import (
            TemplateError,
            load_template,
            merge_template_risks,
        )

        try:
            return merge_template_risks(doc, load_template(starter_template_id))
        except TemplateError as exc:
            raise click.UsageError(str(exc)) from exc

    if sbom_file is not None and not offline:
        msg = "--sbom is supported with --offline template generation."
        raise click.UsageError(msg)

    if output_path.exists() and not force:
        msg = f"Output file {output_path} already exists. Use --force to overwrite."
        raise click.UsageError(msg)

    # Offline: build from a placeholder product identity with no API key and no
    # network. The keyed path below instead pre-fills real product/org/component
    # data fetched from the API.
    if offline:
        product_obj = {"name": product, "slug": product}
        components = (
            _components_from_sbom(sbom_file)
            if sbom_file is not None and gemara_type in {"RiskCatalog", "ThreatCatalog"}
            else []
        )
        doc = TEMPLATE_BUILDERS[gemara_type](product_obj, org_name_opt or "", components)
        doc = _apply_starter(doc)
        _write_gemara_template(output_path, doc)
        console.print(
            "[dim]Generated offline with a placeholder product identity. "
            "Edit the name, slug and org before use. Install cue to validate locally.[/dim]"
        )
        return

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        async def _run() -> dict:
            product_obj = await _fetch_product(client, product)
            components: list[dict] = []
            if gemara_type in {"RiskCatalog", "ThreatCatalog"}:
                try:
                    components = await _fetch_latest_components(client, str(product_obj["id"]))
                except APIError:
                    # Non-fatal: template still renders with bracketed placeholders.
                    components = []
            # Product API objects do not carry an org name; use --org when provided.
            org_name = org_name_opt or ""
            builder = TEMPLATE_BUILDERS[gemara_type]
            return builder(product_obj, org_name, components)

        doc = asyncio.run(_run())
        doc = _apply_starter(doc)
        _write_gemara_template(output_path, doc)

    except httpx.HTTPError as e:
        msg = f"Could not reach the CRA Evidence API: {e}"
        console.print(f"[red]Error:[/red] {msg}")
        sys.exit(3)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(getattr(e, "exit_code", 1))


def _read_gemara_type(file_path: Path) -> str:
    """Parse the YAML and return metadata.type, raising UsageError if missing."""
    try:
        with open(file_path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except Exception as exc:
        msg = f"Could not parse {file_path}: {exc}"
        raise click.UsageError(msg) from exc
    if not isinstance(doc, dict):
        msg = f"{file_path}: top-level YAML must be a mapping."
        raise click.UsageError(msg)
    metadata = doc.get("metadata") or {}
    gemara_type = metadata.get("type") if isinstance(metadata, dict) else None
    if not gemara_type:
        msg = f"{file_path}: missing required 'metadata.type' field."
        raise click.UsageError(msg)
    return str(gemara_type)


def _run_local_cue(file_path: Path, gemara_type: str) -> tuple[bool, list[str]]:
    """Run `cue vet` locally. Returns (valid, errors)."""
    result = subprocess.run(  # noqa: S603  # cue is an optional local validator; file_path is user-supplied
        ["cue", "vet", "-c", "-d", f"#{gemara_type}", GEMARA_CUE_MODULE, str(file_path)],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode == 0:
        return True, []
    stderr = (result.stderr or "").strip()
    errors = [line for line in stderr.splitlines() if line.strip()] or [
        "Schema validation failed."
    ]
    return False, errors


@gemara.command("validate")
@click.option("--file", "file_path", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Compliance YAML file to validate.")
@click.option("--remote", is_flag=True,
              help="Force server-side validation even if CUE is installed locally.")
@click.pass_context
def validate(ctx: click.Context, file_path: Path, remote: bool) -> None:
    """
    Validate a compliance YAML document against the CUE schema.

    Uses the local `cue` binary when available (runs without calling CRA
    Evidence, but cue may fetch the schema module from the CUE registry on
    first use). Falls back to server-side validation when CUE is not
    installed, or when --remote is given.

    Exit codes:
      0  valid
      1  schema errors (printed to stdout)
    """
    config = ctx.obj["config"]
    gemara_type = _read_gemara_type(file_path)

    use_remote = remote or shutil.which("cue") is None

    if not use_remote:
        err_console.print(f"[dim]Validating {file_path} locally against #{gemara_type}...[/dim]")
        try:
            valid, errors = _run_local_cue(file_path, gemara_type)
        except FileNotFoundError:
            use_remote = True
        except subprocess.TimeoutExpired:
            err_console.print(
                "[yellow]Local CUE validation timed out; falling back to server.[/yellow]"
            )
            use_remote = True
        else:
            _print_validate_result(file_path, gemara_type, valid, errors)
            sys.exit(0 if valid else 1)

    # Remote path
    if shutil.which("cue") is None:
        err_console.print(
            "[yellow]CUE not installed locally - validating via CRA Evidence server.[/yellow]"
        )
    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        async def _run() -> dict:
            async with httpx.AsyncClient(timeout=client.timeout) as http:
                with open(file_path, "rb") as f:
                    files = {"file": (file_path.name, f, "application/x-yaml")}
                    response = await http.post(
                        f"{client.base_url}/api/v1/gemara/validate",
                        headers=client._get_headers(),
                        files=files,
                    )
            return client._handle_response(response)

        data = asyncio.run(_run())
        valid = bool(data.get("valid"))
        errors = list(data.get("errors") or [])
        _print_validate_result(
            file_path, data.get("gemara_type") or gemara_type, valid, errors
        )
        sys.exit(0 if valid else 1)

    except httpx.HTTPError as e:
        msg = f"Could not reach the CRA Evidence API: {e}"
        console.print(f"[red]Error:[/red] {msg}")
        sys.exit(3)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(getattr(e, "exit_code", 1))


def _print_validate_result(
    file_path: Path, gemara_type: str, valid: bool, errors: list[str]
) -> None:
    if valid:
        console.print(
            f"{style_result('OK', status_style('valid'))} {file_path} - valid #{gemara_type}"
        )
        return
    console.print(f"{style_result('FAIL', status_style('failed'))} {file_path} - #{gemara_type}")
    for err in errors:
        console.print(f"  [red]-[/red] {err}")


@gemara.command("upload")
@click.option("--file", "file_path", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Compliance YAML file to upload.")
@click.option("--product", required=True, help="Product slug or UUID.")
@click.option("--version", "version_number", default=None,
              help="Version number. Required for version-specific types "
                   "(RiskCatalog, ThreatCatalog). Optional for product-level types "
                   "(Policy, GuidanceCatalog, ControlCatalog) - when omitted the "
                   "doc is attached at product level and cascades to new versions.")
@click.option("--document-type", "document_type_override", default=None,
              help="Override the auto-derived DocumentType. Required for Policy files.")
@click.option("--create-product/--no-create-product", default=True,
              help="Auto-create product if missing (default: enabled). "
                   "Ignored for product-level uploads (product must already exist).")
@click.option("--create-version/--no-create-version", default=True,
              help="Auto-create version if missing (default: enabled). "
                   "Ignored for product-level uploads.")
@click.option(
    "--require-structured-mapping",
    is_flag=True,
    default=False,
    help=(
        "Fail with exit code 21 unless the uploaded file maps structured "
        "evidence fields. Optional CI guardrail only."
    ),
)
@click.pass_context
def upload(
    ctx: click.Context,
    file_path: Path,
    product: str,
    version_number: str | None,
    document_type_override: str | None,
    create_product: bool,
    create_version: bool,
    require_structured_mapping: bool,
) -> None:
    """
    Upload a compliance YAML file to CRA Evidence.

    Reads `metadata.type` from the file and maps it to a document type. Product-
    level types (Policy, GuidanceCatalog, ControlCatalog) upload to the
    product-level endpoint and don't need --version; version-specific types
    (RiskCatalog, ThreatCatalog, EvaluationLog) require --version.

    For Policy files the underlying schema does not distinguish vulnerability
    vs coordinated-disclosure policies, so --document-type is required.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    gemara_type = _read_gemara_type(file_path)

    if gemara_type == "Policy":
        if not document_type_override:
            msg = (
                "Policy files require --document-type "
                "(vulnerability_policy or coordinated_disclosure_policy)."
            )
            raise click.UsageError(msg)
        if document_type_override not in POLICY_DOC_TYPES:
            msg = f"--document-type for Policy must be one of {sorted(POLICY_DOC_TYPES)}."
            raise click.UsageError(msg)
        document_type = document_type_override
        scope = "product"
    elif gemara_type in GEMARA_TYPE_MAP:
        default_doc_type, scope = GEMARA_TYPE_MAP[gemara_type]
        document_type = document_type_override or default_doc_type
    else:
        msg = (
            f"Unsupported schema type '{gemara_type}'. "
            f"Supported types: {sorted(list(GEMARA_TYPE_MAP) + ['Policy'])}."
        )
        raise click.UsageError(msg)

    # Routing decision:
    #  * product-level type + no --version: call POST /api/v1/products/{id}/documents
    #  * product-level type + --version given: user explicitly wants it attached to
    #    a specific version - fall through to /ci/upload for that version.
    #  * version-specific type: --version is mandatory.
    route_product_level = (
        document_type in PRODUCT_LEVEL_DOC_TYPES and not version_number
    )
    if scope == "version" and not version_number:
        msg = f"--version is required for version-specific type '{gemara_type}'."
        raise click.UsageError(msg)

    try:
        validate_config(config)
        client = CRAEvidenceClient(config)

        if route_product_level:
            console.print(
                f"[dim]{gemara_type} → product-level document "
                f"(doc_type={document_type}).[/dim]"
            )
            data = asyncio.run(
                client.upload_product_document_gemara(
                    product=product,
                    document_type=document_type,
                    file_path=file_path,
                )
            )
        else:
            data = asyncio.run(
                client.upload_document(
                    product=product,
                    version=version_number,
                    file_path=file_path,
                    document_type=document_type,
                    create_product=create_product,
                    create_version=create_version,
                )
            )

        format_output(data, output_format, bool(ctx.obj.get("verbose")))
        enforce_structured_mapping(data, require_structured_mapping)

    except httpx.HTTPError as e:
        msg = f"Could not reach the CRA Evidence API: {e}"
        console.print(f"[red]Error:[/red] {msg}")
        sys.exit(3)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@gemara.command("download-source")
@click.option(
    "--document-id",
    required=True,
    help="Document UUID for a rendered compliance document returned by upload or API workflows.",
)
@click.option(
    "--output",
    "output_path",
    required=True,
    type=click.Path(path_type=Path),
    help="Path to write the retained original source YAML.",
)
@click.option("--force", is_flag=True, help="Overwrite output file if it exists.")
@click.pass_context
def download_source(
    ctx: click.Context,
    document_id: str,
    output_path: Path,
    force: bool,
) -> None:
    """
    Download retained original source YAML for a rendered document.

    This command is read-only provenance access. It requires an explicit
    document ID and does not search products, reprocess YAML, update readiness,
    or infer compliance.
    """
    config = ctx.obj["config"]
    output_format = config.output_format

    if output_path.exists() and not force:
        msg = f"Output file {output_path} already exists. Use --force to overwrite."
        raise click.ClickException(msg)

    try:
        validate_config(config)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        client = CRAEvidenceClient(config)
        data = asyncio.run(
            client.download_gemara_source(
                document_id=document_id,
                output_path=output_path,
            )
        )

        if output_format == "json":
            console.print(json.dumps(data, indent=2))
        else:
            console.print(
                f"{style_result('Downloaded', status_style('complete'))} {data['file_path']}"
            )
            console.print(f"{style_label('Bytes')} {data['size_bytes']}")
            console.print(
                "[yellow]Provenance only:[/yellow] this file was not reprocessed "
                "and does not update readiness state."
            )

    except httpx.HTTPError as e:
        msg = f"Could not reach the CRA Evidence API: {e}"
        console.print(f"[red]Error:[/red] {msg}")
        sys.exit(3)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
