"""
Upload commands for SBOM, HBOM, and VEX documents.
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from cra_evidence_cli.ci_detect import merge_ci_metadata
from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import validate_config
from cra_evidence_cli.display import humanize_field_path, humanize_identifier
from cra_evidence_cli.exceptions import (
    CRAEvidenceError,
    SbomqsThresholdExceeded,
    SignatureVerificationUntrusted,
    StructuredEvidenceMappingRequired,
    VulnerabilityThresholdExceeded,
)
from cra_evidence_cli.repo_config import resolve_identity
from cra_evidence_cli.sbom_generator import (
    SBOMGenerationError,
    generate_sbom_from_directory,
    generate_sbom_from_image,
)
from cra_evidence_cli.sbom_signer import sign_sbom_with_sigstore
from cra_evidence_cli.sbomqs_check import format_summary, run_sbomqs
from cra_evidence_cli.styles import label as style_label
from cra_evidence_cli.styles import result as style_result
from cra_evidence_cli.styles import status_style

console = Console()
err_console = Console(stderr=True)

STRUCTURED_MAPPING_OK_OUTCOMES = {"accepted_and_mapped"}
SIGNATURE_IDENTITY_ENV = "CRA_EVIDENCE_SIGNATURE_IDENTITY"
SIGNATURE_ISSUER_ENV = "CRA_EVIDENCE_SIGNATURE_ISSUER"

# Valid values for CRA classification flags
VALID_CATEGORIES = ["default", "important_class_i", "important_class_ii", "critical"]
VALID_SUBCATEGORIES = [
    "none",
    # Annex III Class I (19 items)
    "identity_access_mgmt", "browser", "password_manager", "anti_malware",
    "vpn", "network_mgmt", "siem", "boot_manager", "pki", "network_interface",
    "operating_system", "router_modem_switch", "microprocessor_security",
    "microcontroller_security", "asic_fpga_security", "smart_home_assistant",
    "smart_home_security", "connected_toy", "personal_wearable",
    # Annex III Class II (4 items)
    "hypervisor_container", "firewall_ids_ips",
    "tamper_resistant_microprocessor", "tamper_resistant_microcontroller",
    # Annex IV Critical (3 items)
    "hardware_security_box", "smart_meter_cryptoprocessing", "smartcard_secure_element",
]
VALID_PRODUCT_TYPES = ["software", "hardware", "mixed"]
VALID_CRA_ROLES = ["manufacturer", "importer", "distributor"]
VALID_DOCUMENT_TYPES = [
    # Valid document type identifiers
    "risk_assessment",
    "eu_declaration_of_conformity",
    "user_manual",
    "technical_documentation",
    "harmonised_standards",
    "vulnerability_policy",
    "coordinated_disclosure_policy",
    "security_advisory",
    "update_mechanism_documentation",
    "secure_development_policy",
    "uii",
    "test_report",
    "third_party_audit",
    "penetration_test_report",
    "architecture_diagram",
    "threat_model",
    "conformity_certificate",
    "support_period_justification",
    "supplier_due_diligence",
    "other",
]

# Subcategory → category auto-derive mapping
SUBCATEGORY_TO_CATEGORY = {
    "none": "default",
    "identity_access_mgmt": "important_class_i",
    "browser": "important_class_i",
    "password_manager": "important_class_i",
    "anti_malware": "important_class_i",
    "vpn": "important_class_i",
    "network_mgmt": "important_class_i",
    "siem": "important_class_i",
    "boot_manager": "important_class_i",
    "pki": "important_class_i",
    "network_interface": "important_class_i",
    "operating_system": "important_class_i",
    "router_modem_switch": "important_class_i",
    "microprocessor_security": "important_class_i",
    "microcontroller_security": "important_class_i",
    "asic_fpga_security": "important_class_i",
    "smart_home_assistant": "important_class_i",
    "smart_home_security": "important_class_i",
    "connected_toy": "important_class_i",
    "personal_wearable": "important_class_i",
    "hypervisor_container": "important_class_ii",
    "firewall_ids_ips": "important_class_ii",
    "tamper_resistant_microprocessor": "important_class_ii",
    "tamper_resistant_microcontroller": "important_class_ii",
    "hardware_security_box": "critical",
    "smart_meter_cryptoprocessing": "critical",
    "smartcard_secure_element": "critical",
}


def validate_classification(
    category: str | None,
    subcategory: str | None,
) -> tuple[str | None, str | None]:
    """
    Validate and resolve category/subcategory consistency.

    If subcategory is provided, auto-derives category.
    If both provided, validates they match.

    Returns:
        (resolved_category, resolved_subcategory)

    Raises:
        click.UsageError: On mismatch
    """
    if subcategory and subcategory != "none":
        expected = SUBCATEGORY_TO_CATEGORY.get(subcategory)
        if category and category != "default" and category != expected:
            msg = (
                f"Subcategory '{subcategory}' requires category '{expected}', "
                f"not '{category}'. Remove --category or fix the mismatch."
            )
            raise click.UsageError(
                msg
            )
        return expected, subcategory

    return category, subcategory


def warn_default_category(
    product: str,
    create_product: bool,
    category: str | None,
    subcategory: str | None,
) -> None:
    """Emit stderr warning when auto-creating a product with default category."""
    if not create_product:
        return
    if category and category != "default":
        return
    if subcategory and subcategory != "none":
        return
    err_console = Console(stderr=True, file=sys.stderr)
    err_console.print(
        f'[yellow]Warning:[/yellow] Product "{product}" will be created with Default category. '
        f"If your product is listed in CRA Annex III or IV, update the classification at "
        f"your CRA Evidence product settings page.",
    )


def enforce_structured_mapping(data: dict, require_structured_mapping: bool) -> None:
    """Fail CI only when the caller explicitly requires mapped structured fields."""
    if not require_structured_mapping:
        return

    summary = data.get("evidence_summary") or {}
    parser_outcome = summary.get("parser_outcome") or "missing_evidence_summary"
    if parser_outcome not in STRUCTURED_MAPPING_OK_OUTCOMES:
        raise StructuredEvidenceMappingRequired(parser_outcome)


def _structured_outcome_label(parser_outcome: str) -> str:
    labels = {
        "accepted_and_mapped": "Mapped fields confirmed",
        "accepted_document_only": "Document stored; no mapped fields confirmed",
        "accepted_needs_review": "Document stored; review needed",
        "review_candidates_found": "Review candidates found",
        "no_supplier_candidates_found": "No supplier candidates found",
        "missing_evidence_summary": "No structured summary returned",
        "unknown": "Unknown",
    }
    return labels.get(parser_outcome, "Review needed")


def signature_trust_status(signature_verification: dict | None) -> str:
    """Return customer-facing trust state for a signature response."""
    if not signature_verification:
        return "not_verified"

    verification = signature_verification.get("verification") or signature_verification
    status = verification.get("status") or "unknown"
    if status == "valid" and verification.get("policy_enforced") is True:
        return "trusted"
    if status == "valid":
        return "valid_untrusted"
    return status


def is_signature_trusted(signature_verification: dict | None) -> bool:
    """Whether cryptography passed and signer policy was enforced."""
    return signature_trust_status(signature_verification) == "trusted"


def format_output(data: dict, output_format: str, verbose: bool = False) -> None:
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    # Text format
    console.print("\n[bold green]Upload complete[/bold green]\n")

    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    # Product/Version info
    if "product" in data:
        product = data["product"]
        table.add_row("Product", product.get("name", "N/A"))
        if product.get("created"):
            table.add_row("", "[dim](created new)[/dim]")

    if "version" in data:
        version = data["version"]
        version_label = version.get("number", "N/A")
        if version.get("created"):
            version_label += " [dim](newly created)[/dim]"
        table.add_row("Version", version_label)

    # Artifact info
    artifact_id = data.get("artifact_id") or data.get("id") or "N/A"
    artifact_type = data.get("artifact_type") or ("document" if data.get("doc_type") else "N/A")
    table.add_row("Artifact ID", artifact_id)
    table.add_row("Artifact Type", humanize_identifier(artifact_type))
    if data.get("doc_type"):
        table.add_row("Document Type", humanize_identifier(data["doc_type"]))

    if data.get("component_count") is not None:
        table.add_row("Packages", str(data["component_count"]))

    if data.get("quality_score") is not None:
        score = data["quality_score"]
        score_style = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        table.add_row("Quality Score", f"[{score_style}]{score}%[/{score_style}]")

    # ProductComponent attribution (multi-repo products). Rows omitted
    # for products with no components (component_slug is None in the response).
    component_slug = data.get("component_slug")
    if component_slug:
        suffix = " (auto-created)" if data.get("component_auto_created") else ""
        table.add_row("Attributed to component", f"{component_slug}{suffix}")
        # Render the component repository URL from the value the CLI submitted.
        component_repo = data.get("_component_repository")
        if component_repo:
            table.add_row("Component repository", component_repo)

    # Per-component split: a CycloneDX SBOM upload that contains hardware
    # components also produces a companion HBOM artifact (and vice-versa).
    companion = data.get("companion_artifact")
    if companion:
        table.add_row("", "")
        table.add_row(
            "[bold]Companion Artifact[/bold]",
            "[dim](created from per-component split)[/dim]",
        )
        table.add_row("  Type", humanize_identifier(companion.get("artifact_type", "N/A")))
        table.add_row("  ID", str(companion.get("artifact_id", "N/A")))
        if companion.get("component_count") is not None:
            table.add_row("  Components", str(companion["component_count"]))

    # Scan results
    if data.get("scan_results"):
        scan = data["scan_results"]
        vulns = scan.get("vulnerabilities") or {}

        table.add_row("", "")
        table.add_row("[bold]Vulnerabilities[/bold]", "")

        critical = vulns.get("critical", 0)
        high = vulns.get("high", 0)
        medium = vulns.get("medium", 0)
        low = vulns.get("low", 0)

        if critical > 0:
            table.add_row("  Critical", f"[red bold]{critical}[/red bold]")
        else:
            table.add_row("  Critical", f"[dim]{critical}[/dim]")

        if high > 0:
            table.add_row("  High", f"[red]{high}[/red]")
        else:
            table.add_row("  High", f"[dim]{high}[/dim]")

        if medium > 0:
            table.add_row("  Medium", f"[yellow]{medium}[/yellow]")
        else:
            table.add_row("  Medium", f"[dim]{medium}[/dim]")

        table.add_row("  Low", f"[dim]{low}[/dim]")

    console.print(table)

    _print_signature_verification_section(data)
    _print_evidence_input_section(data)
    _print_supplier_review_section(data)

    # CRA Compliance section - shown when the response includes CRA feedback
    _print_cra_compliance_section(data, verbose)

    # Warnings (non-fatal notices from the server)
    warnings = data.get("warnings") or []
    if warnings:
        console.print()
        for w in warnings:
            console.print(f"  [yellow]![/yellow] {w}")

    console.print()


def _print_signature_verification_section(data: dict) -> None:
    """Print SBOM release-integrity verification details when present."""
    signature_verification = data.get("signature_verification")
    if not signature_verification:
        return

    verification = signature_verification.get("verification") or signature_verification
    trust_status = signature_trust_status(signature_verification)
    trust_style = status_style(trust_status)

    console.print()
    console.print("[bold]Release Integrity:[/bold]")
    console.print(
        f"  {style_label('SBOM signature')} "
        f"{style_result(humanize_identifier(trust_status), trust_style)}"
    )

    signer = verification.get("signer_identity")
    issuer = verification.get("signer_issuer")
    expected_identity = verification.get("expected_identity")
    expected_issuer = verification.get("expected_issuer")

    if signer:
        console.print(f"  {style_label('Signer')} {escape(str(signer))}")
    if issuer:
        console.print(f"  {style_label('Issuer')} {escape(str(issuer))}")
    if expected_identity:
        console.print(f"  {style_label('Expected signer')} {escape(str(expected_identity))}")
    if expected_issuer:
        console.print(f"  {style_label('Expected issuer')} {escape(str(expected_issuer))}")

    tlog = verification.get("transparency_log_entry") or {}
    if tlog:
        log_index = tlog.get("log_index")
        log_id = tlog.get("log_id")
        console.print(
            f"  {style_label('Transparency log')} "
            f"index={escape(str(log_index)) if log_index is not None else 'N/A'} "
            f"id={escape(str(log_id)) if log_id else 'N/A'}"
        )

    if trust_status == "trusted":
        console.print(
            f"  {style_result('Result:', status_style('valid'))} "
            "stored SBOM bytes match the signed "
            "bundle and signer policy."
        )
    elif trust_status == "valid_untrusted":
        console.print(
            f"  {style_result('Result:', status_style('valid_untrusted'))} "
            "cryptography passed, but signer policy was not enforced."
        )
    else:
        message = verification.get("error_message")
        if message:
            console.print(
                f"  {style_result('Result:', status_style('error'))} {escape(str(message))}"
            )


def _print_evidence_input_section(data: dict) -> None:
    """Print structured evidence interpretation details when provided."""
    summary = data.get("evidence_summary")
    if not summary:
        return

    console.print()
    console.print("[bold]Structured Evidence:[/bold]")

    schema_type = summary.get("schema_type") or "unknown"
    evidence_format = summary.get("format") or "unknown"
    parser_outcome = summary.get("parser_outcome") or "unknown"
    document_type = summary.get("document_type")

    console.print(
        f"  {style_label('Format')} {humanize_identifier(evidence_format)} ({schema_type})"
    )
    if document_type:
        console.print(f"  {style_label('Document type')} {humanize_identifier(document_type)}")
    console.print(f"  {style_label('Outcome')} {_structured_outcome_label(parser_outcome)}")

    mapped_fields = summary.get("mapped_fields") or []
    if mapped_fields:
        console.print(f"  {style_label('Mapped fields')}")
        for field in mapped_fields:
            console.print(f"    [green]-[/green] {escape(humanize_field_path(field))}")
    else:
        console.print(f"  {style_label('Mapped fields')} [dim]none[/dim]")

    manual_followups = summary.get("manual_followups") or []
    if manual_followups:
        console.print(f"  {style_label('Manual / review remaining')}")
        for item in manual_followups:
            console.print(f"    [yellow]-[/yellow] {escape(str(item))}")

    source_download_url = data.get("gemara_source_download_url")
    if (
        source_download_url
        and summary.get("source") == "gemara_export"
        and summary.get("format") == "gemara_yaml"
    ):
        document_id = data.get("artifact_id") or data.get("id")
        if document_id:
            console.print(f"  {style_label('Retained source')}")
            console.print(
                "    craevidence compliance-as-code download-source "
                f"--document-id {escape(str(document_id))} --output <output.yaml>"
            )
            console.print(f"    [dim]API URL: {escape(str(source_download_url))}[/dim]")
            console.print(
                "    [dim]Provenance only; downloading it does not reprocess YAML "
                "or update readiness state.[/dim]"
            )


def _print_supplier_review_section(data: dict) -> None:
    """Print SBOM supplier review candidates when provided."""
    summary = data.get("supplier_review")
    if not summary:
        return

    console.print()
    console.print("[bold]Supplier Review:[/bold]")
    console.print(
        "  [yellow]![/yellow] SBOM supplier names are review candidates only; "
        "they do not satisfy supplier due diligence."
    )

    total_components = summary.get("total_components", 0)
    components_with_supplier = summary.get("components_with_supplier", 0)
    candidate_count = summary.get("candidate_count", 0)
    console.print(
        f"  [cyan]Components with supplier:[/cyan] "
        f"{components_with_supplier}/{total_components}"
    )
    console.print(f"  [cyan]Distinct candidates:[/cyan] {candidate_count}")

    candidates = summary.get("candidates") or []
    if candidates:
        console.print("  [cyan]Candidates:[/cyan]")
        for candidate in candidates:
            name = escape(str(candidate.get("name", "unknown")))
            count = candidate.get("component_count", 0)
            console.print(f"    [green]-[/green] {name} ({count} component(s))")
        if summary.get("truncated"):
            console.print("    [dim]Additional candidates omitted from CLI output.[/dim]")
    else:
        console.print("  [cyan]Candidates:[/cyan] [dim]none found[/dim]")

    manual_followups = summary.get("manual_followups") or []
    if manual_followups:
        console.print("  [cyan]Manual / review remaining:[/cyan]")
        for item in manual_followups:
            console.print(f"    [yellow]-[/yellow] {escape(str(item))}")


def format_attestation_output(data: dict, output_format: str) -> None:
    """Store attestations as provenance metadata unless the API returns
    verification_status == "valid".
    """
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    console.print("\n[bold green]Attestation uploaded[/bold green]\n")

    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Attestation ID", str(data.get("id", "N/A")))
    table.add_row("Version ID", str(data.get("version_id", "N/A")))
    table.add_row("Predicate Type", escape(str(data.get("predicate_type", "N/A"))))
    table.add_row("Format", escape(str(data.get("format", "N/A"))))
    table.add_row("Signatures", str(data.get("signature_count", 0)))

    verification_status = str(data.get("verification_status", "pending"))
    status_style = "green" if verification_status == "valid" else "yellow"
    table.add_row(
        "Verification Status",
        f"[{status_style}]{escape(verification_status)}[/{status_style}]",
    )

    if data.get("builder_id"):
        table.add_row("Builder", escape(str(data["builder_id"])))
    if data.get("source_repo"):
        table.add_row("Source Repo", escape(str(data["source_repo"])))
    if data.get("source_commit"):
        table.add_row("Source Commit", escape(str(data["source_commit"])))

    console.print(table)

    if verification_status != "valid":
        console.print()
        console.print(
            "[yellow]![/yellow] Stored as provenance metadata. "
            "It is not verified provenance unless verification_status is valid."
        )

    console.print()


def _print_cra_compliance_section(data: dict, verbose: bool = False) -> None:
    """
    Print the CRA Compliance section after a successful upload.

    Prints CRA status, inheritance summary, profile info, and scan state
    when cra_status is present in the response. Falls back gracefully
    when optional fields are absent.
    """
    cra_status = data.get("cra_status")
    if not cra_status:
        return

    console.print()
    console.print("[bold]CRA Compliance:[/bold]")

    # --- Inheritance summary ---
    inherited_count = data.get("inherited_documents_count")
    inherited = data.get("inherited", False)
    if inherited and inherited_count is not None:
        console.print(
            f"  [cyan]Documents:[/cyan] {inherited_count} inherited from previous version"
        )
    elif inherited:
        console.print("  [cyan]Documents:[/cyan] inherited from previous version")

    # --- Profile applied ---
    profile_applied = data.get("profile_applied", False)
    if profile_applied:
        console.print(
            "  [cyan]Profile:[/cyan] CRA profile defaults applied "
            "(CE marking, conformity, support period)"
        )

    # --- Scan status ---
    scan_results = data.get("scan_results")
    if scan_results:
        scan_status = scan_results.get("status", "unknown")
        if scan_status == "pending":
            console.print(
                "  [cyan]Scan:[/cyan] queued "
                "(results available via [dim]craevidence status[/dim])"
            )
        elif scan_status == "completed":
            vulns = scan_results.get("vulnerabilities") or {}
            critical = vulns.get("critical", 0)
            high = vulns.get("high", 0)
            if critical > 0 or high > 0:
                console.print(
                    f"  [cyan]Scan:[/cyan] completed - [red]{critical} critical, "
                    f"{high} high[/red] vulnerabilities found"
                )
            else:
                console.print(
                    "  [cyan]Scan:[/cyan] completed - "
                    "[green]no critical/high vulnerabilities[/green]"
                )
        elif scan_status == "failed":
            console.print("  [cyan]Scan:[/cyan] [red]failed[/red] - check scanner logs")
        else:
            console.print(f"  [cyan]Scan:[/cyan] {scan_status}")

    # --- CRA Status headline ---
    console.print()
    missing_items = data.get("cra_missing_items") or []
    if cra_status == "ready":
        console.print("[bold green]CRA Status: READY[/bold green]")
    else:
        console.print(f"[bold yellow]CRA Status: {cra_status.upper()}[/bold yellow]")
        if missing_items:
            if verbose:
                console.print("  [yellow]Missing requirements:[/yellow]")
                for item in missing_items:
                    console.print(f"    [red]-[/red] {item}")
            else:
                count = len(missing_items)
                console.print(
                    f"  [yellow]{count} requirement(s) outstanding.[/yellow] "
                    "Run with -v or 'craevidence status' for the full list."
                )
        # Give a forward-looking hint when a scan is still pending
        if scan_results and scan_results.get("status") == "pending":
            console.print(
                "  [dim]Will be READY once scan completes "
                "(if no critical/high vulnerabilities found)[/dim]"
            )


def format_sarif_output(data: dict, output_format: str) -> None:
    """
    Format and display output for SARIF uploads.

    The SARIF endpoint returns a different shape than /ci/upload:
    {uploaded_count, updated_count, tool_name, tool_version, run_count, issues, message}
    """
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2))
        return

    console.print("\n[bold green]Upload complete[/bold green]\n")

    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    if data.get("tool_name"):
        tool_label = data["tool_name"]
        if data.get("tool_version"):
            tool_label += f" {data['tool_version']}"
        table.add_row("Scanner", tool_label)

    if data.get("run_count") is not None:
        table.add_row("Runs", str(data["run_count"]))

    uploaded = data.get("uploaded_count", 0)
    updated = data.get("updated_count", 0)
    table.add_row("Issues uploaded", str(uploaded))
    if updated > 0:
        table.add_row("Issues updated", str(updated))

    if data.get("message"):
        table.add_row("Status", data["message"])

    console.print(table)

    issues = data.get("issues") or []
    if issues:
        console.print()
        for issue in issues[:10]:
            console.print(f"  [yellow]![/yellow] {issue}")
        if len(issues) > 10:
            console.print(f"  [dim]... and {len(issues) - 10} more[/dim]")

    console.print()


def check_vulnerability_threshold(vulnerability_summary: dict, fail_on: str) -> None:
    """Check vulnerability counts against threshold and raise if exceeded."""
    if fail_on == "none":
        return

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


def _resolve_signature_inputs(
    *,
    file_path: Path | None,
    signature_on: bool,
    signature_bundle_path: Path | None,
    signature_identity: str | None,
    signature_issuer: str | None,
) -> tuple[Path | None, str | None, str | None]:
    """Resolve signed-SBOM convenience options before upload."""
    if (
        not signature_on
        and signature_bundle_path is None
        and (signature_identity or signature_issuer)
    ):
        msg = (
            "--signature-identity and --signature-issuer require "
            "--signature-on or --signature-bundle."
        )
        raise click.UsageError(
            msg
        )

    if signature_on and not file_path:
        msg = (
            "--signature-on is supported only with --file. "
            "Sign the exact SBOM file in CI, then upload it."
        )
        raise click.UsageError(
            msg
        )

    if signature_bundle_path and not file_path:
        msg = (
            "--signature-bundle is supported only with --file. "
            "Sign the exact SBOM file in CI, then upload it."
        )
        raise click.UsageError(
            msg
        )

    should_verify_signature = signature_on or signature_bundle_path is not None
    if not should_verify_signature:
        return signature_bundle_path, signature_identity, signature_issuer

    if signature_bundle_path is None:
        signature_bundle_path = Path(f"{file_path}.sigstore.json")
    if not signature_bundle_path.exists():
        msg = (
            "--signature-on expected Sigstore bundle at "
            f"{signature_bundle_path}. Pass --signature-bundle to use a different path."
        )
        raise click.UsageError(
            msg
        )

    signature_identity = signature_identity or os.getenv(SIGNATURE_IDENTITY_ENV)
    signature_issuer = signature_issuer or os.getenv(SIGNATURE_ISSUER_ENV)

    missing = []
    if not signature_identity:
        missing.append(f"--signature-identity or {SIGNATURE_IDENTITY_ENV}")
    if not signature_issuer:
        missing.append(f"--signature-issuer or {SIGNATURE_ISSUER_ENV}")
    if missing:
        raise click.UsageError(
            "Signed SBOM verification requires "
            + " and ".join(missing)
            + "."
        )

    return signature_bundle_path, signature_identity, signature_issuer


@click.command("upload-sbom")
@click.option(
    "--product",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "version_number",
    default=None,
    help="Version number",
)
@click.option(
    "--file",
    "file_path",
    type=click.Path(exists=True, path_type=Path),
    help="Path to existing SBOM file (mutually exclusive with --image)",
)
@click.option(
    "--signature-bundle",
    "signature_bundle_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help=(
        "Path to Sigstore/Cosign bundle for the uploaded SBOM. Signer policy "
        "can be supplied with explicit flags or CRA_EVIDENCE_SIGNATURE_* env vars."
    ),
)
@click.option(
    "--signature-on",
    is_flag=True,
    help=(
        "Verify signed SBOM using <SBOM>.sigstore.json and signer policy from "
        "CRA_EVIDENCE_SIGNATURE_IDENTITY / CRA_EVIDENCE_SIGNATURE_ISSUER"
    ),
)
@click.option(
    "--sign",
    "sign_sbom",
    is_flag=True,
    help=(
        "Create a Sigstore bundle for the SBOM before upload, then verify it "
        "against the stored SBOM bytes."
    ),
)
@click.option(
    "--signature-identity",
    "signature_identity",
    help="Expected signer identity for SBOM signature trust policy",
)
@click.option(
    "--signature-issuer",
    "signature_issuer",
    help="Expected OIDC issuer for SBOM signature trust policy",
)
@click.option(
    "--fail-untrusted",
    is_flag=True,
    help="Exit non-zero unless the SBOM signature verifies as trusted",
)
@click.option(
    "--image",
    "docker_image",
    help="Docker image to generate SBOM from (e.g., nginx:latest, alpine:3.19)",
)
@click.option(
    "--source",
    "source_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help=(
        "Path to source directory to generate SBOM from. "
        "Mutually exclusive with --file and --image."
    ),
)
@click.option(
    "--format",
    "format_type",
    type=click.Choice(["cyclonedx", "spdx"], case_sensitive=False),
    default="cyclonedx",
    help="SBOM format: cyclonedx (default) or spdx.",
)
@click.option(
    "--create-product/--no-create-product",
    default=True,
    help="Auto-create product if it doesn't exist (default: enabled)",
)
@click.option(
    "--create-version/--no-create-version",
    default=True,
    help="Auto-create version if it doesn't exist (default: enabled)",
)
@click.option(
    "--scan",
    is_flag=True,
    help="Trigger vulnerability scan after upload",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    help="Fail if vulnerabilities of this severity or higher are found",
)
# CRA classification options
@click.option(
    "--category",
    type=click.Choice(VALID_CATEGORIES, case_sensitive=False),
    help="CRA product category (auto-derived from --subcategory if provided)",
)
@click.option(
    "--subcategory",
    type=click.Choice(VALID_SUBCATEGORIES, case_sensitive=False),
    help="CRA Annex III/IV product subcategory (e.g., firewall_ids_ips, vpn)",
)
@click.option(
    "--product-type",
    "product_type",
    type=click.Choice(VALID_PRODUCT_TYPES, case_sensitive=False),
    help="Product type: software, hardware, or mixed",
)
@click.option(
    "--cra-role",
    type=click.Choice(VALID_CRA_ROLES, case_sensitive=False),
    help="CRA economic operator role (default: manufacturer)",
)
@click.option(
    "--product-group",
    "product_group",
    help="Product group slug",
)
@click.option(
    "--target-markets",
    "target_markets",
    help=(
        "Comma-separated EU country codes where the product is placed on the market "
        "(required when auto-creating a product, e.g. DE,FR,ES)"
    ),
)
# CI metadata options
@click.option(
    "--commit",
    "commit_sha",
    help="Git commit SHA (auto-detected in CI environments)",
)
@click.option(
    "--branch",
    help="Git branch name (auto-detected in CI environments)",
)
@click.option(
    "--pipeline-id",
    help="CI pipeline ID (auto-detected in CI environments)",
)
@click.option(
    "--repository",
    help="Repository URL or name (auto-detected in CI environments)",
)
@click.option(
    "--repo-path",
    help="Repository subdirectory for monorepo support",
)
@click.option(
    "--no-ci-detect",
    is_flag=True,
    help="Disable automatic CI environment detection",
)
@click.option(
    "--no-inherit",
    "no_inherit",
    is_flag=True,
    default=False,
    help=(
        "Skip inheriting CRA compliance artifacts from the previous version "
        "when creating a new version"
    ),
)
@click.option(
    "--supersedes",
    "supersedes",
    default=None,
    help=(
        "Version number superseded by this upload (e.g. v1.0). "
        "Archives the old version and links them."
    ),
)
@click.option(
    "--component",
    "component_slug",
    default=None,
    help=(
        "Optional product component slug. Manual override for "
        "auto-attribution by --repository / --repo-path. Use this for "
        "vendor SBOMs or any push without git context."
    ),
)
@click.option(
    "--sbomqs-check",
    "sbomqs_check",
    is_flag=True,
    default=False,
    help=(
        "Score the SBOM against BSI TR-03183-2 v2 via the sbomqs binary "
        "before upload. Requires sbomqs on PATH "
        "(`go install github.com/interlynk-io/sbomqs@latest`). "
        "Prints score and the worst-performing checks."
    ),
)
@click.option(
    "--fail-on-score",
    "fail_on_score",
    type=click.IntRange(0, 100),
    default=None,
    help=(
        "Fail the upload (exit 14) when the sbomqs BSI TR-03183-2 v2 "
        "score is below this threshold (0-100). Requires --sbomqs-check."
    ),
)
@click.option(
    "--environment",
    type=click.Choice(["production", "staging", "development", "testing"]),
    help="Deployment environment",
)
@click.option(
    "--tags",
    help="Comma-separated tags",
)
@click.option(
    "--kernel-config",
    "kernel_config_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Optional kernel .config file for CVE filtering",
)
@click.option(
    "--firmware",
    "firmware_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Firmware binary to extract embedded kernel .config from (CONFIG_IKCONFIG=y). "
         "If --kernel-config is also provided, --kernel-config takes precedence.",
)
@click.option(
    "--release-notes",
    default=None,
    help="Release notes for this version (max 5000 chars, only applied on version creation)",
)
@click.option(
    "--release-date",
    default=None,
    help="Release date in YYYY-MM-DD format (only applied on version creation)",
)
@click.option(
    "--external-url",
    default=None,
    help="External URL e.g. GitHub release URL (max 512 chars, only applied on version creation)",
)
@click.option(
    "--release-state",
    type=click.Choice(
        ["draft", "pending_review", "approved", "released", "deprecated", "end_of_life"],
        case_sensitive=False,
    ),
    default=None,
    help=(
        "Set release lifecycle state on upload. "
        "Uses the same transition validation as the release command."
    ),
)
@click.pass_context
def upload_sbom(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    file_path: Path | None,
    signature_bundle_path: Path | None,
    signature_on: bool,
    sign_sbom: bool,
    signature_identity: str | None,
    signature_issuer: str | None,
    fail_untrusted: bool,
    docker_image: str | None,
    source_dir: Path | None,
    format_type: str,
    create_product: bool,
    create_version: bool,
    scan: bool,
    fail_on: str | None,
    # CRA classification
    category: str | None,
    subcategory: str | None,
    product_type: str | None,
    cra_role: str | None,
    product_group: str | None,
    target_markets: str | None,
    # CI metadata
    commit_sha: str | None,
    branch: str | None,
    pipeline_id: str | None,
    repository: str | None,
    repo_path: str | None,
    no_ci_detect: bool,
    no_inherit: bool,
    supersedes: str | None,
    component_slug: str | None,
    sbomqs_check: bool,
    fail_on_score: int | None,
    environment: str | None,
    tags: str | None,
    kernel_config_path: Path | None,
    firmware_path: Path | None,
    release_notes: str | None,
    release_date: str | None,
    external_url: str | None,
    release_state: str | None,
) -> None:
    """
    Upload an SBOM (Software Bill of Materials) to CRA Evidence.

    You can upload an existing SBOM file with --file, generate one from a Docker
    image with --image (requires Syft or Docker), or scan a source directory with
    --source (requires Syft).

    Products and versions are auto-created by default. Use --no-create-product or
    --no-create-version to disable.

    CI environment metadata (commit SHA, branch, pipeline ID, repository) is
    automatically detected for GitHub Actions, GitLab CI, Jenkins, Azure DevOps,
    CircleCI, and Bitbucket Pipelines. Use --no-ci-detect to disable.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = ctx.obj.get("verbose", False)

    try:
        product, version_number, component_slug = resolve_identity(
            product, version_number, component_slug
        )
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(e.exit_code)

    generated_sbom_path: Path | None = None
    generated_signature_bundle_path: Path | None = None
    _tmp_kernel_config: Path | None = None

    # Validate: exactly one of --file, --image, or --source must be provided
    source_count = sum(1 for x in [file_path, docker_image, source_dir] if x)
    if source_count == 0:
        msg = (
            "One of --file, --image, or --source is required. "
            "Use --file to upload an existing SBOM, --image to generate one from a Docker image, "
            "or --source to generate one from a source directory."
        )
        raise click.UsageError(
            msg
        )
    if source_count > 1:
        msg = "Only one of --file, --image, or --source can be used."
        raise click.UsageError(
            msg
        )

    if signature_on and sign_sbom:
        msg = (
            "Use --sign to create a bundle or --signature-on to verify an "
            "existing bundle, not both."
        )
        raise click.UsageError(
            msg
        )
    if (
        not sign_sbom
        and not signature_on
        and signature_bundle_path is None
        and (signature_identity or signature_issuer)
    ):
        msg = (
            "--signature-identity and --signature-issuer require "
            "--sign, --signature-on, or --signature-bundle."
        )
        raise click.UsageError(
            msg
        )
    if signature_on and not file_path:
        msg = (
            "--signature-on is supported only with --file. "
            "Use --sign to sign a generated SBOM."
        )
        raise click.UsageError(
            msg
        )
    if signature_bundle_path and not file_path and not sign_sbom:
        msg = (
            "--signature-bundle is supported with --file, "
            "or with --sign when the CLI generates the SBOM."
        )
        raise click.UsageError(
            msg
        )
    signature_policy_supplied = bool(
        signature_identity or os.getenv(SIGNATURE_IDENTITY_ENV)
    ) and bool(signature_issuer or os.getenv(SIGNATURE_ISSUER_ENV))
    if fail_untrusted and sign_sbom and not signature_policy_supplied:
        msg = (
            "--fail-untrusted with --sign requires a pinned signer policy. Set "
            f"--signature-identity/--signature-issuer or {SIGNATURE_IDENTITY_ENV}/"
            f"{SIGNATURE_ISSUER_ENV}. Run once without --fail-untrusted to print "
            "the current signer identity and issuer."
        )
        raise click.UsageError(
            msg
        )

    # Validate CRA classification consistency
    category, subcategory = validate_classification(category, subcategory)
    warn_default_category(product, create_product, category, subcategory)

    # --fail-on-score is only meaningful with --sbomqs-check
    if fail_on_score is not None and not sbomqs_check:
        msg = "--fail-on-score requires --sbomqs-check."
        raise click.UsageError(
            msg
        )

    try:
        validate_config(config)

        # Merge CLI flags with auto-detected CI metadata
        ci_metadata = merge_ci_metadata(
            cli_commit=commit_sha,
            cli_branch=branch,
            cli_pipeline_id=pipeline_id,
            cli_repository=repository,
            cli_repo_path=repo_path,
            auto_detect=not no_ci_detect,
        )

        # If --image is provided, generate SBOM first
        if docker_image:
            err_console.print(f"[cyan]Generating SBOM from image:[/cyan] {docker_image}")

            try:
                result = generate_sbom_from_image(
                    image=docker_image,
                    output_format=format_type,
                    verbose=verbose,
                )
                generated_sbom_path = result.file_path
                file_path = result.file_path

                err_console.print(
                    f"[green]Generated SBOM:[/green] {result.component_count} packages "
                    f"({result.format_type})"
                )
                if product_type and product_type.lower() == "hardware":
                    err_console.print(
                        "\n[yellow]Warning:[/yellow] SBOM generated via Syft scanning of a "
                        "hardware filesystem. "
                        "Coverage depends on available package metadata in the filesystem. "
                        "For hardware products, complete accuracy requires generating your SBOM "
                        "directly "
                        "from your build system (Yocto: INHERIT += \"create-spdx\", "
                        "Buildroot: make legal-info). "
                        "For containers and software, Syft provides good coverage."
                    )
            except SBOMGenerationError as e:
                console.print(f"[red]SBOM generation failed:[/red] {e}")
                sys.exit(e.exit_code)

        # If --source is provided, generate SBOM from directory
        if source_dir:
            err_console.print(f"[cyan]Generating SBOM from source directory:[/cyan] {source_dir}")

            try:
                result = generate_sbom_from_directory(
                    directory=str(source_dir),
                    output_format=format_type,
                    verbose=verbose,
                )
                generated_sbom_path = result.file_path
                file_path = result.file_path

                err_console.print(
                    f"[green]Generated SBOM:[/green] {result.component_count} packages "
                    f"({result.format_type})"
                )
                if product_type and product_type.lower() == "hardware":
                    err_console.print(
                        "\n[yellow]Warning:[/yellow] SBOM generated via Syft scanning of a "
                        "hardware filesystem. "
                        "Coverage depends on available package metadata in the filesystem. "
                        "For hardware products, complete accuracy requires generating your SBOM "
                        "directly "
                        "from your build system (Yocto: INHERIT += \"create-spdx\", "
                        "Buildroot: make legal-info). "
                        "For containers and software, Syft provides good coverage."
                    )
            except SBOMGenerationError as e:
                console.print(f"[red]SBOM generation failed:[/red] {e}")
                sys.exit(e.exit_code)

        # Extract .config from firmware binary if --firmware provided and --kernel-config not given
        if firmware_path is not None and kernel_config_path is None:
            from cra_evidence_cli.ikconfig import extract_ikconfig
            err_console.print(
                f"[cyan]Extracting kernel .config from firmware:[/cyan] {firmware_path}"
            )
            data = firmware_path.read_bytes()
            config_bytes = extract_ikconfig(data)
            if config_bytes is None:
                console.print(
                    "[yellow]Warning:[/yellow] No embedded .config found in firmware binary "
                    "(kernel may not have been compiled with CONFIG_IKCONFIG=y). "
                    "Use --kernel-config to provide your .config manually."
                )
            else:
                _tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".config")
                _tmp.write(config_bytes)
                _tmp.close()
                _tmp_kernel_config = Path(_tmp.name)
                kernel_config_path = _tmp_kernel_config
                console.print(
                    f"[green]Extracted kernel .config:[/green] {len(config_bytes):,} bytes"
                )

        if verbose:
            console.print(f"[dim]Uploading SBOM from {file_path}[/dim]")
            console.print(f"[dim]Product: {product}, Version: {version_number}[/dim]")
            if ci_metadata.get("commit_sha"):
                console.print(f"[dim]Commit: {ci_metadata['commit_sha']}[/dim]")
            if ci_metadata.get("branch"):
                console.print(f"[dim]Branch: {ci_metadata['branch']}[/dim]")

        # Opt-in BSI TR-03183-2 v2 pre-upload check. Must run BEFORE the
        # network call so a failing score short-circuits without producing
        # a server-side row. In JSON output mode, route the human summary
        # to stderr so `craevidence --output json upload-sbom ... | jq`
        # pipelines stay parseable.
        if sbomqs_check:
            sbomqs_result = run_sbomqs(file_path)
            summary = format_summary(sbomqs_result)
            if output_format == "json":
                Console(file=sys.stderr).print(summary)
            else:
                console.print(summary)
            if (
                fail_on_score is not None
                and sbomqs_result.score_out_of_100 < fail_on_score
            ):
                raise SbomqsThresholdExceeded(
                    score=sbomqs_result.score_out_of_100,
                    threshold=float(fail_on_score),
                )

        if sign_sbom:
            signature_bundle_path = signature_bundle_path or Path(
                f"{file_path}.sigstore.json"
            )
            if verbose:
                console.print(f"[dim]Signing SBOM with Sigstore: {file_path}[/dim]")
            signing_result = sign_sbom_with_sigstore(
                sbom_path=file_path,
                bundle_path=signature_bundle_path,
            )
            if generated_sbom_path and signature_bundle_path == Path(
                f"{file_path}.sigstore.json"
            ):
                generated_signature_bundle_path = signature_bundle_path
            signature_identity = signature_identity or signing_result.signer_identity
            signature_issuer = signature_issuer or signing_result.signer_issuer
            if output_format == "json":
                Console(file=sys.stderr).print(
                    f"Signed SBOM bundle: {signing_result.bundle_path}"
                )
            else:
                console.print(f"[green]Signed SBOM bundle:[/green] {signing_result.bundle_path}")
                console.print(f"[dim]Signer: {signature_identity}[/dim]")
                console.print(f"[dim]Issuer: {signature_issuer}[/dim]")

        signature_bundle_path, signature_identity, signature_issuer = _resolve_signature_inputs(
            file_path=file_path,
            signature_on=signature_on or sign_sbom,
            signature_bundle_path=signature_bundle_path,
            signature_identity=signature_identity,
            signature_issuer=signature_issuer,
        )
        if fail_untrusted and not signature_bundle_path:
            msg = "--fail-untrusted requires --sign, --signature-on, or --signature-bundle."
            raise click.UsageError(msg)

        client = CRAEvidenceClient(config)

        # Run async upload
        data = asyncio.run(
            client.upload_sbom(
                product=product,
                version=version_number,
                file_path=file_path,
                format_type=format_type,
                create_product=create_product,
                create_version=create_version,
                scan=scan,
                no_inherit=no_inherit,
                supersedes=supersedes,
                category=category,
                subcategory=subcategory,
                product_type=product_type,
                cra_role=cra_role,
                product_group=product_group,
                target_markets=target_markets,
                commit_sha=ci_metadata.get("commit_sha"),
                branch=ci_metadata.get("branch"),
                pipeline_id=ci_metadata.get("pipeline_id"),
                repository=ci_metadata.get("repository"),
                repo_path=ci_metadata.get("repo_path"),
                component=component_slug,
                environment=environment,
                tags=tags,
                kernel_config_path=kernel_config_path,
                release_notes=release_notes,
                release_date=release_date,
                external_url=external_url,
                release_state=release_state,
            )
        )

        # Pass the submitted repository URL through so format_output can
        # render the "Component repository" row.
        if isinstance(data, dict) and repository:
            data.setdefault("_component_repository", repository)

        if signature_bundle_path:
            artifact_type = str(data.get("artifact_type") or "").lower()
            artifact_id = data.get("artifact_id")
            if artifact_type != "sbom" or not artifact_id:
                msg = (
                    "SBOM signature verification requires the upload response "
                    "to include an SBOM artifact_id."
                )
                raise CRAEvidenceError(
                    msg
                )

            if verbose:
                console.print(f"[dim]Verifying SBOM signature bundle {signature_bundle_path}[/dim]")

            signature_result = asyncio.run(
                client.verify_sbom_signature(
                    sbom_id=str(artifact_id),
                    bundle_path=signature_bundle_path,
                    expected_identity=str(signature_identity),
                    expected_issuer=str(signature_issuer),
                )
            )
            data["signature_verification"] = signature_result
            data["signature_verification"]["trust_status"] = signature_trust_status(
                signature_result
            )

        # Display output
        format_output(data, output_format, verbose)

        if fail_untrusted and not is_signature_trusted(data.get("signature_verification")):
            raise SignatureVerificationUntrusted(
                signature_trust_status(data.get("signature_verification"))
            )

        # Check vulnerability threshold
        if fail_on:
            scan_results = data.get("scan_results") or {}
            vuln_summary = scan_results.get("vulnerabilities") or {}
            check_vulnerability_threshold(vuln_summary, fail_on)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
    finally:
        # Clean up generated SBOM file
        if generated_sbom_path and generated_sbom_path.exists():
            generated_sbom_path.unlink(missing_ok=True)
        if generated_signature_bundle_path and generated_signature_bundle_path.exists():
            generated_signature_bundle_path.unlink(missing_ok=True)
        # Clean up temp kernel config extracted from firmware
        if _tmp_kernel_config and _tmp_kernel_config.exists():
            _tmp_kernel_config.unlink(missing_ok=True)


@click.command("upload-hbom")
@click.option(
    "--product",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "version_number",
    default=None,
    help="Version number",
)
@click.option(
    "--file",
    "file_path",
    required=False,
    type=click.Path(exists=True, path_type=Path),
    help="Path to an existing CycloneDX HBOM JSON file (mutually exclusive with --csv)",
)
@click.option(
    "--csv",
    "csv_path",
    required=False,
    type=click.Path(exists=True, path_type=Path),
    help=(
        "Path to a components CSV (canonical HBOM schema). The CSV is parsed "
        "and built into a CycloneDX HBOM server-side. Mutually exclusive with "
        "--file. Get the schema with `craevidence upload-hbom` --csv template "
        "or the version's CSV-template download."
    ),
)
@click.option(
    "--create-product/--no-create-product",
    default=True,
    help="Auto-create product if it doesn't exist (default: enabled)",
)
@click.option(
    "--create-version/--no-create-version",
    default=True,
    help="Auto-create version if it doesn't exist (default: enabled)",
)
# CRA classification options
@click.option(
    "--category",
    type=click.Choice(VALID_CATEGORIES, case_sensitive=False),
    help="CRA product category (auto-derived from --subcategory if provided)",
)
@click.option(
    "--subcategory",
    type=click.Choice(VALID_SUBCATEGORIES, case_sensitive=False),
    help="CRA Annex III/IV product subcategory (e.g., firewall_ids_ips, vpn)",
)
@click.option(
    "--product-type",
    "product_type",
    type=click.Choice(VALID_PRODUCT_TYPES, case_sensitive=False),
    help="Product type: software, hardware, or mixed",
)
@click.option(
    "--cra-role",
    type=click.Choice(VALID_CRA_ROLES, case_sensitive=False),
    help="CRA economic operator role (default: manufacturer)",
)
@click.option(
    "--product-group",
    "product_group",
    help="Product group slug",
)
@click.option(
    "--target-markets",
    "target_markets",
    help=(
        "Comma-separated EU country codes where the product is placed on the market "
        "(required when auto-creating a product, e.g. DE,FR,ES)"
    ),
)
# CI metadata options
@click.option(
    "--commit",
    "commit_sha",
    help="Git commit SHA (auto-detected in CI environments)",
)
@click.option(
    "--branch",
    help="Git branch name (auto-detected in CI environments)",
)
@click.option(
    "--pipeline-id",
    help="CI pipeline ID (auto-detected in CI environments)",
)
@click.option(
    "--repository",
    help="Repository URL or name (auto-detected in CI environments)",
)
@click.option(
    "--repo-path",
    help="Repository subdirectory for monorepo support",
)
@click.option(
    "--no-ci-detect",
    is_flag=True,
    help="Disable automatic CI environment detection",
)
@click.option(
    "--no-inherit",
    "no_inherit",
    is_flag=True,
    default=False,
    help=(
        "Skip inheriting CRA compliance artifacts from the previous version "
        "when creating a new version"
    ),
)
@click.option(
    "--environment",
    type=click.Choice(["production", "staging", "development", "testing"]),
    help="Deployment environment",
)
@click.option(
    "--tags",
    help="Comma-separated tags",
)
@click.option(
    "--release-notes",
    default=None,
    help="Release notes for this version (max 5000 chars, only applied on version creation)",
)
@click.option(
    "--release-date",
    default=None,
    help="Release date in YYYY-MM-DD format (only applied on version creation)",
)
@click.option(
    "--external-url",
    default=None,
    help="External URL e.g. GitHub release URL (max 512 chars, only applied on version creation)",
)
@click.option(
    "--release-state",
    type=click.Choice(
        ["draft", "pending_review", "approved", "released", "deprecated", "end_of_life"],
        case_sensitive=False,
    ),
    default=None,
    help=(
        "Set release lifecycle state on upload. "
        "Uses the same transition validation as the release command."
    ),
)
@click.pass_context
def upload_hbom(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    file_path: Path | None,
    csv_path: Path | None,
    create_product: bool,
    create_version: bool,
    # CRA classification
    category: str | None,
    subcategory: str | None,
    product_type: str | None,
    cra_role: str | None,
    product_group: str | None,
    target_markets: str | None,
    # CI metadata
    commit_sha: str | None,
    branch: str | None,
    pipeline_id: str | None,
    repository: str | None,
    repo_path: str | None,
    no_ci_detect: bool,
    no_inherit: bool,
    environment: str | None,
    tags: str | None,
    release_notes: str | None,
    release_date: str | None,
    external_url: str | None,
    release_state: str | None,
) -> None:
    """
    Upload an HBOM (Hardware Bill of Materials) to CRA Evidence.

    CI environment metadata is automatically detected for GitHub Actions, GitLab CI,
    Jenkins, Azure DevOps, CircleCI, and Bitbucket Pipelines.

    Provide either an existing CycloneDX HBOM with --file, or a components CSV
    with --csv (parsed and built into an HBOM server-side).

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = ctx.obj.get("verbose", False)

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(e.exit_code)

    # Exactly one of --file / --csv is required (mirrors upload-sbom exclusivity).
    if bool(file_path) == bool(csv_path):
        msg = (
            "Provide exactly one of --file (an existing HBOM JSON) or "
            "--csv (a components CSV)."
        )
        raise click.UsageError(
            msg
        )
    upload_path = file_path or csv_path

    # Validate CRA classification consistency
    category, subcategory = validate_classification(category, subcategory)
    warn_default_category(product, create_product, category, subcategory)

    try:
        validate_config(config)

        # Merge CLI flags with auto-detected CI metadata
        ci_metadata = merge_ci_metadata(
            cli_commit=commit_sha,
            cli_branch=branch,
            cli_pipeline_id=pipeline_id,
            cli_repository=repository,
            cli_repo_path=repo_path,
            auto_detect=not no_ci_detect,
        )

        if verbose:
            console.print(f"[dim]Uploading HBOM from {upload_path}[/dim]")
            if ci_metadata.get("commit_sha"):
                console.print(f"[dim]Commit: {ci_metadata['commit_sha']}[/dim]")

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.upload_hbom(
                product=product,
                version=version_number,
                file_path=upload_path,
                create_product=create_product,
                create_version=create_version,
                no_inherit=no_inherit,
                category=category,
                subcategory=subcategory,
                product_type=product_type,
                cra_role=cra_role,
                product_group=product_group,
                target_markets=target_markets,
                commit_sha=ci_metadata.get("commit_sha"),
                branch=ci_metadata.get("branch"),
                pipeline_id=ci_metadata.get("pipeline_id"),
                repository=ci_metadata.get("repository"),
                repo_path=ci_metadata.get("repo_path"),
                environment=environment,
                tags=tags,
                release_notes=release_notes,
                release_date=release_date,
                external_url=external_url,
                release_state=release_state,
            )
        )

        format_output(data, output_format, verbose)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@click.command("upload-vex")
@click.option(
    "--product",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "version_number",
    default=None,
    help="Version number",
)
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to VEX file",
)
# CRA classification options
@click.option(
    "--category",
    type=click.Choice(VALID_CATEGORIES, case_sensitive=False),
    help="CRA product category (auto-derived from --subcategory if provided)",
)
@click.option(
    "--subcategory",
    type=click.Choice(VALID_SUBCATEGORIES, case_sensitive=False),
    help="CRA Annex III/IV product subcategory (e.g., firewall_ids_ips, vpn)",
)
@click.option(
    "--product-type",
    "product_type",
    type=click.Choice(VALID_PRODUCT_TYPES, case_sensitive=False),
    help="Product type: software, hardware, or mixed",
)
@click.option(
    "--cra-role",
    type=click.Choice(VALID_CRA_ROLES, case_sensitive=False),
    help="CRA economic operator role (default: manufacturer)",
)
@click.option(
    "--product-group",
    "product_group",
    help="Product group slug",
)
# CI metadata options
@click.option(
    "--commit",
    "commit_sha",
    help="Git commit SHA (auto-detected in CI environments)",
)
@click.option(
    "--branch",
    help="Git branch name (auto-detected in CI environments)",
)
@click.option(
    "--pipeline-id",
    help="CI pipeline ID (auto-detected in CI environments)",
)
@click.option(
    "--repository",
    help="Repository URL or name (auto-detected in CI environments)",
)
@click.option(
    "--repo-path",
    help="Repository subdirectory for monorepo support",
)
@click.option(
    "--no-ci-detect",
    is_flag=True,
    help="Disable automatic CI environment detection",
)
@click.option(
    "--no-inherit",
    "no_inherit",
    is_flag=True,
    default=False,
    help=(
        "Skip inheriting CRA compliance artifacts from the previous version "
        "when creating a new version"
    ),
)
@click.option(
    "--environment",
    type=click.Choice(["production", "staging", "development", "testing"]),
    help="Deployment environment",
)
@click.option(
    "--tags",
    help="Comma-separated tags",
)
@click.pass_context
def upload_vex(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    file_path: Path,
    # CRA classification
    category: str | None,
    subcategory: str | None,
    product_type: str | None,
    cra_role: str | None,
    product_group: str | None,
    # CI metadata
    commit_sha: str | None,
    branch: str | None,
    pipeline_id: str | None,
    repository: str | None,
    repo_path: str | None,
    no_ci_detect: bool,
    no_inherit: bool,
    environment: str | None,
    tags: str | None,
) -> None:
    """
    Upload a VEX (Vulnerability Exploitability eXchange) document to CRA Evidence.

    CI environment metadata is automatically detected for GitHub Actions, GitLab CI,
    Jenkins, Azure DevOps, CircleCI, and Bitbucket Pipelines.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = ctx.obj.get("verbose", False)

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(e.exit_code)

    # Validate CRA classification consistency
    category, subcategory = validate_classification(category, subcategory)

    try:
        validate_config(config)

        # Merge CLI flags with auto-detected CI metadata
        ci_metadata = merge_ci_metadata(
            cli_commit=commit_sha,
            cli_branch=branch,
            cli_pipeline_id=pipeline_id,
            cli_repository=repository,
            cli_repo_path=repo_path,
            auto_detect=not no_ci_detect,
        )

        if verbose:
            console.print(f"[dim]Uploading VEX from {file_path}[/dim]")
            if ci_metadata.get("commit_sha"):
                console.print(f"[dim]Commit: {ci_metadata['commit_sha']}[/dim]")

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.upload_vex(
                product=product,
                version=version_number,
                file_path=file_path,
                no_inherit=no_inherit,
                category=category,
                subcategory=subcategory,
                product_type=product_type,
                cra_role=cra_role,
                product_group=product_group,
                commit_sha=ci_metadata.get("commit_sha"),
                branch=ci_metadata.get("branch"),
                pipeline_id=ci_metadata.get("pipeline_id"),
                repository=ci_metadata.get("repository"),
                repo_path=ci_metadata.get("repo_path"),
                environment=environment,
                tags=tags,
            )
        )

        format_output(data, output_format, verbose)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@click.command("upload-sarif")
@click.option(
    "--product",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "version_number",
    default=None,
    help="Version number",
)
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to SARIF file (.json or .sarif)",
)
# CRA classification options
@click.option(
    "--category",
    type=click.Choice(VALID_CATEGORIES, case_sensitive=False),
    help="CRA product category (auto-derived from --subcategory if provided)",
)
@click.option(
    "--subcategory",
    type=click.Choice(VALID_SUBCATEGORIES, case_sensitive=False),
    help="CRA Annex III/IV product subcategory (e.g., firewall_ids_ips, vpn)",
)
@click.option(
    "--product-type",
    "product_type",
    type=click.Choice(VALID_PRODUCT_TYPES, case_sensitive=False),
    help="Product type: software, hardware, or mixed",
)
@click.option(
    "--cra-role",
    type=click.Choice(VALID_CRA_ROLES, case_sensitive=False),
    help="CRA economic operator role (default: manufacturer)",
)
@click.option(
    "--product-group",
    "product_group",
    help="Product group slug",
)
# CI metadata options
@click.option(
    "--commit",
    "commit_sha",
    help="Git commit SHA (auto-detected in CI environments)",
)
@click.option(
    "--branch",
    help="Git branch name (auto-detected in CI environments)",
)
@click.option(
    "--pipeline-id",
    help="CI pipeline ID (auto-detected in CI environments)",
)
@click.option(
    "--repository",
    help="Repository URL or name (auto-detected in CI environments)",
)
@click.option(
    "--repo-path",
    help="Repository subdirectory for monorepo support",
)
@click.option(
    "--no-ci-detect",
    is_flag=True,
    help="Disable automatic CI environment detection",
)
@click.option(
    "--no-inherit",
    "no_inherit",
    is_flag=True,
    default=False,
    help=(
        "Skip inheriting CRA compliance artifacts from the previous version "
        "when creating a new version"
    ),
)
@click.option(
    "--environment",
    type=click.Choice(["production", "staging", "development", "testing"]),
    help="Deployment environment",
)
@click.option(
    "--tags",
    help="Comma-separated tags",
)
@click.pass_context
def upload_sarif(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    file_path: Path,
    # CRA classification
    category: str | None,
    subcategory: str | None,
    product_type: str | None,
    cra_role: str | None,
    product_group: str | None,
    # CI metadata
    commit_sha: str | None,
    branch: str | None,
    pipeline_id: str | None,
    repository: str | None,
    repo_path: str | None,
    no_ci_detect: bool,
    no_inherit: bool,
    environment: str | None,
    tags: str | None,
) -> None:
    """
    Upload SARIF security scan results to CRA Evidence.

    Supports SARIF 2.1.0 output from tools like CodeQL, Semgrep, Bandit,
    govulncheck, and any other SARIF-compliant scanner.

    CI environment metadata is automatically detected for GitHub Actions, GitLab CI,
    Jenkins, Azure DevOps, CircleCI, and Bitbucket Pipelines.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = ctx.obj.get("verbose", False)

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(e.exit_code)

    # Validate CRA classification consistency
    category, subcategory = validate_classification(category, subcategory)

    try:
        validate_config(config)

        # Merge CLI flags with auto-detected CI metadata
        ci_metadata = merge_ci_metadata(
            cli_commit=commit_sha,
            cli_branch=branch,
            cli_pipeline_id=pipeline_id,
            cli_repository=repository,
            cli_repo_path=repo_path,
            auto_detect=not no_ci_detect,
        )

        if verbose:
            console.print(f"[dim]Uploading SARIF from {file_path}[/dim]")
            if ci_metadata.get("commit_sha"):
                console.print(f"[dim]Commit: {ci_metadata['commit_sha']}[/dim]")

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.upload_sarif(
                product=product,
                version=version_number,
                file_path=file_path,
                no_inherit=no_inherit,
                category=category,
                subcategory=subcategory,
                product_type=product_type,
                cra_role=cra_role,
                product_group=product_group,
                commit_sha=ci_metadata.get("commit_sha"),
                branch=ci_metadata.get("branch"),
                pipeline_id=ci_metadata.get("pipeline_id"),
                repository=ci_metadata.get("repository"),
                repo_path=ci_metadata.get("repo_path"),
                environment=environment,
                tags=tags,
            )
        )

        format_sarif_output(data, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@click.command("upload-attestation")
@click.option(
    "--product",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "version_number",
    default=None,
    help="Existing version number",
)
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to DSSE/in-toto attestation file (.json or .jsonl)",
)
@click.pass_context
def upload_attestation(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    file_path: Path,
) -> None:
    """
    Upload DSSE/in-toto attestation metadata for an existing product version.

    CRA Evidence stores the attestation as provenance metadata. It is not
    presented as verified provenance unless the API returns
    verification_status=valid.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = ctx.obj.get("verbose", False)

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(e.exit_code)

    try:
        validate_config(config)

        if verbose:
            console.print(f"[dim]Uploading attestation from {file_path}[/dim]")
            console.print(f"[dim]Product: {product}, Version: {version_number}[/dim]")

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.upload_attestation(
                product=product,
                version=version_number,
                file_path=file_path,
            )
        )

        format_attestation_output(data, output_format)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)


@click.command("upload-document")
@click.option(
    "--product",
    default=None,
    help="Product slug or ID",
)
@click.option(
    "--version",
    "version_number",
    default=None,
    help="Version number",
)
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to document file (.pdf, .docx, .txt, .md, .json, .xml, .html)",
)
@click.option(
    "--type",
    "document_type",
    required=True,
    type=click.Choice(VALID_DOCUMENT_TYPES, case_sensitive=False),
    help="Document type for the uploaded evidence.",
)
@click.option(
    "--create-product/--no-create-product",
    default=True,
    help="Auto-create product if it doesn't exist (default: enabled)",
)
@click.option(
    "--create-version/--no-create-version",
    default=True,
    help="Auto-create version if it doesn't exist (default: enabled)",
)
# CRA classification options
@click.option(
    "--category",
    type=click.Choice(VALID_CATEGORIES, case_sensitive=False),
    help="CRA product category (auto-derived from --subcategory if provided)",
)
@click.option(
    "--subcategory",
    type=click.Choice(VALID_SUBCATEGORIES, case_sensitive=False),
    help="CRA Annex III/IV product subcategory (e.g., firewall_ids_ips, vpn)",
)
@click.option(
    "--product-type",
    "product_type",
    type=click.Choice(VALID_PRODUCT_TYPES, case_sensitive=False),
    help="Product type: software, hardware, or mixed",
)
@click.option(
    "--cra-role",
    type=click.Choice(VALID_CRA_ROLES, case_sensitive=False),
    help="CRA economic operator role (default: manufacturer)",
)
@click.option(
    "--product-group",
    "product_group",
    help="Product group slug",
)
@click.option(
    "--target-markets",
    "target_markets",
    help=(
        "Comma-separated EU country codes where the product is placed on the market "
        "(required when auto-creating a product, e.g. DE,FR,ES)"
    ),
)
# CI metadata options
@click.option(
    "--commit",
    "commit_sha",
    help="Git commit SHA (auto-detected in CI environments)",
)
@click.option(
    "--branch",
    help="Git branch name (auto-detected in CI environments)",
)
@click.option(
    "--pipeline-id",
    help="CI pipeline ID (auto-detected in CI environments)",
)
@click.option(
    "--repository",
    help="Repository URL or name (auto-detected in CI environments)",
)
@click.option(
    "--repo-path",
    help="Repository subdirectory for monorepo support",
)
@click.option(
    "--no-ci-detect",
    is_flag=True,
    help="Disable automatic CI environment detection",
)
@click.option(
    "--no-inherit",
    "no_inherit",
    is_flag=True,
    default=False,
    help=(
        "Skip inheriting CRA compliance artifacts from the previous version "
        "when creating a new version"
    ),
)
@click.option(
    "--environment",
    type=click.Choice(["production", "staging", "development", "testing"]),
    help="Deployment environment",
)
@click.option(
    "--tags",
    help="Comma-separated tags",
)
@click.option(
    "--release-notes",
    default=None,
    help="Release notes for this version (max 5000 chars, only applied on version creation)",
)
@click.option(
    "--release-date",
    default=None,
    help="Release date in YYYY-MM-DD format (only applied on version creation)",
)
@click.option(
    "--external-url",
    default=None,
    help="External URL e.g. GitHub release URL (max 512 chars, only applied on version creation)",
)
@click.option(
    "--release-state",
    type=click.Choice(
        ["draft", "pending_review", "approved", "released", "deprecated", "end_of_life"],
        case_sensitive=False,
    ),
    default=None,
    help=(
        "Set release lifecycle state on upload. "
        "Uses the same transition validation as the release command."
    ),
)
@click.option(
    "--require-structured-mapping",
    is_flag=True,
    default=False,
    help=(
        "After upload, fail with exit code 21 unless structured evidence fields "
        "were accepted and mapped. Optional CI guardrail only."
    ),
)
@click.pass_context
def upload_document(
    ctx: click.Context,
    product: str | None,
    version_number: str | None,
    file_path: Path,
    document_type: str,
    create_product: bool,
    create_version: bool,
    # CRA classification
    category: str | None,
    subcategory: str | None,
    product_type: str | None,
    cra_role: str | None,
    product_group: str | None,
    target_markets: str | None,
    # CI metadata
    commit_sha: str | None,
    branch: str | None,
    pipeline_id: str | None,
    repository: str | None,
    repo_path: str | None,
    no_ci_detect: bool,
    no_inherit: bool,
    environment: str | None,
    tags: str | None,
    release_notes: str | None,
    release_date: str | None,
    external_url: str | None,
    release_state: str | None,
    require_structured_mapping: bool,
) -> None:
    """
    Upload a supporting document to CRA Evidence. Supported file types are
    .pdf, .docx, .txt, .md, .json, .xml, and .html. CI metadata is detected
    automatically when available; use --no-ci-detect to disable it.
    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = ctx.obj.get("verbose", False)

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(e.exit_code)

    # Validate CRA classification consistency
    category, subcategory = validate_classification(category, subcategory)
    warn_default_category(product, create_product, category, subcategory)

    try:
        validate_config(config)

        # Merge CLI flags with auto-detected CI metadata
        ci_metadata = merge_ci_metadata(
            cli_commit=commit_sha,
            cli_branch=branch,
            cli_pipeline_id=pipeline_id,
            cli_repository=repository,
            cli_repo_path=repo_path,
            auto_detect=not no_ci_detect,
        )

        if verbose:
            console.print(f"[dim]Uploading document from {file_path}[/dim]")
            console.print(f"[dim]Product: {product}, Version: {version_number}[/dim]")
            console.print(f"[dim]Document type: {humanize_identifier(document_type)}[/dim]")
            if ci_metadata.get("commit_sha"):
                console.print(f"[dim]Commit: {ci_metadata['commit_sha']}[/dim]")

        client = CRAEvidenceClient(config)

        data = asyncio.run(
            client.upload_document(
                product=product,
                version=version_number,
                file_path=file_path,
                document_type=document_type,
                create_product=create_product,
                create_version=create_version,
                no_inherit=no_inherit,
                category=category,
                subcategory=subcategory,
                product_type=product_type,
                cra_role=cra_role,
                product_group=product_group,
                target_markets=target_markets,
                commit_sha=ci_metadata.get("commit_sha"),
                branch=ci_metadata.get("branch"),
                pipeline_id=ci_metadata.get("pipeline_id"),
                repository=ci_metadata.get("repository"),
                repo_path=ci_metadata.get("repo_path"),
                environment=environment,
                tags=tags,
                release_notes=release_notes,
                release_date=release_date,
                external_url=external_url,
                release_state=release_state,
            )
        )

        format_output(data, output_format, verbose)
        enforce_structured_mapping(data, require_structured_mapping)

    except CRAEvidenceError as e:
        console.print(f"[red]Error:[/red] {e}")
        if hasattr(e, "request_id") and e.request_id:
            console.print(f"[dim]Request ID: {e.request_id}[/dim]")
        sys.exit(e.exit_code)
