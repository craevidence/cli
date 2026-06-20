"""Pure builders for the CSAF 2.0 documents the no-key draft commands emit.

:func:`build_csaf_vex` and :func:`build_csaf_advisory` assemble CSAF 2.0
skeletons from local scan findings: a VEX (every finding marked
``under_investigation``) and a security advisory (one vulnerability entry per
finding with placeholder notes and a remediation). Both share the document
header, the vulnerability identity mapping, the product reference, and the
product_tree assembly, so they cannot drift apart. No network, no subprocess,
no printing.

These produce a draft skeleton, not a profile-conformant advisory: the author
completes the content. The output is validated against the official CSAF 2.0
JSON schema in ``tests/test_csaf_schema.py``. An empty findings list yields a
document with no vulnerabilities, which the calling command does not emit (CSAF
requires at least one).
"""

from __future__ import annotations

import uuid

from cra_evidence_cli.local.disclaimer import DISCLAIMER_TEXT
from cra_evidence_cli.local.models import Finding, utc_now_iso


def _vuln_identity(finding: Finding) -> dict:
    """Map a finding id and its aliases onto the CSAF ``cve`` / ``ids`` fields."""
    entry: dict = {}
    if finding.id.upper().startswith("CVE-"):
        entry["cve"] = finding.id
    else:
        entry["ids"] = [{"system_name": "vulnerability", "text": finding.id}]
    if finding.aliases:
        ids = entry.setdefault("ids", [])
        ids.extend({"system_name": "alias", "text": alias} for alias in sorted(finding.aliases))
    return entry


def _product_ref(finding: Finding) -> str | None:
    """The product identifier for a finding: its purl, else its package name.

    CSAF product_status arrays must be non-empty (minItems 1), and remediations
    should reference a product, so every finding contributes a product when it
    has either a purl or a package name. The rare finding with neither carries no
    product reference.
    """
    return finding.purl or finding.package or None


def _document(category: str, generator_name: str) -> dict:
    """Build the shared CSAF document header."""
    timestamp = utc_now_iso()
    return {
        "category": category,
        "csaf_version": "2.0",
        "title": "REPLACE WITH AN ADVISORY TITLE",
        "publisher": {
            "category": "vendor",
            "name": "REPLACE WITH YOUR NAME OR ORG",
            "namespace": "https://example.com",
        },
        "tracking": {
            "id": f"CRAEVIDENCE-DRAFT-{uuid.uuid4().hex[:12]}",
            "status": "draft",
            "version": "1",
            "initial_release_date": timestamp,
            "current_release_date": timestamp,
            "revision_history": [
                {"date": timestamp, "number": "1", "summary": "Initial draft"}
            ],
            "generator": {"engine": {"name": generator_name}},
        },
        "notes": [{"category": "general", "text": DISCLAIMER_TEXT, "title": "Draft"}],
    }


def _skeleton(
    category: str,
    generator_name: str,
    vulnerabilities: list[dict],
    full_product_names: list[dict],
) -> dict:
    """Assemble the document, vulnerabilities, and (when populated) product_tree.

    CSAF requires full_product_names to be non-empty (minItems 1), so product_tree
    is attached only when at least one finding contributed a product.
    """
    doc: dict = {
        "document": _document(category, generator_name),
        "vulnerabilities": vulnerabilities,
    }
    if full_product_names:
        doc["product_tree"] = {"full_product_names": full_product_names}
    return doc


def build_csaf_vex(findings: list[Finding]) -> dict:
    """Build a CSAF 2.0 VEX skeleton parseable by our own check --vex path.

    Each finding becomes a vulnerability with product_status under_investigation;
    the user fills in a real status. under_investigation is not a suppression, so
    the skeleton round-trips through check --vex without hiding anything.
    """
    full_product_names: list[dict] = []
    seen: set[str] = set()
    vulnerabilities: list[dict] = []
    for finding in findings:
        entry = _vuln_identity(finding)
        product = _product_ref(finding)
        if product:
            if product not in seen:
                seen.add(product)
                full_product_names.append({"product_id": product, "name": product})
            entry["product_status"] = {"under_investigation": [product]}
        vulnerabilities.append(entry)
    return _skeleton("csaf_vex", "CRA Evidence CLI draft vex", vulnerabilities, full_product_names)


def build_csaf_advisory(findings: list[Finding]) -> dict:
    """Build a CSAF 2.0 security advisory skeleton from local scan findings.

    document.category is csaf_security_advisory. Each finding becomes one
    vulnerability with placeholder notes and a vendor_fix remediation the author
    completes; product_status and the remediation reference the component.
    Nothing here asserts that a vulnerability is fixed, disclosed, or that any
    user has been notified: it is a draft to fill in.
    """
    full_product_names: list[dict] = []
    seen: set[str] = set()
    vulnerabilities: list[dict] = []
    for finding in findings:
        entry = _vuln_identity(finding)
        entry["title"] = finding.title or finding.id
        entry["notes"] = [
            {
                "category": "description",
                "title": "Vulnerability description",
                "text": finding.title or "REPLACE WITH A DESCRIPTION OF THE VULNERABILITY",
            },
            {
                "category": "summary",
                "title": "Impact",
                "text": "REPLACE WITH THE IMPACT AND SEVERITY FOR USERS OF YOUR PRODUCT",
            },
        ]
        # The placeholder URL is a real (resolvable-shaped) URI so the skeleton
        # passes CSAF url-format validation; the author swaps it for the real one.
        remediation: dict = {
            "category": "vendor_fix",
            "details": (
                "REPLACE WITH REMEDIATION DETAILS, for example the fixed version "
                "and the steps users take to update."
            ),
            "url": "https://example.com/replace-with-the-fix-or-advisory-url",
        }
        product = _product_ref(finding)
        if product:
            if product not in seen:
                seen.add(product)
                full_product_names.append({"product_id": product, "name": product})
            entry["product_status"] = {"known_affected": [product]}
            remediation["product_ids"] = [product]
        entry["remediations"] = [remediation]
        references = [
            {"summary": "Reference", "url": ref} for ref in finding.references if "://" in ref
        ]
        if references:
            entry["references"] = references
        vulnerabilities.append(entry)
    return _skeleton(
        "csaf_security_advisory",
        "CRA Evidence CLI draft advisory",
        vulnerabilities,
        full_product_names,
    )
