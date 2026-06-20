"""Pure, network-free VEX suppression engine for the no-key local pipeline.

Parses VEX documents (OpenVEX and, minimally, CSAF VEX) and applies their
statements to a list of :class:`~cra_evidence_cli.local.models.Finding` objects,
suppressing findings that a VEX statement marks as ``not_affected`` (with a
justification or impact statement) or ``fixed``.

No network, no subprocess, no exit codes, no printing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cra_evidence_cli.local.models import Finding


class VexParseError(ValueError):
    """Raised when a VEX document is unparseable or in an unsupported format."""


# Statuses that, when matched, cause a finding to be suppressed.
_SUPPRESSING_STATUSES = {"not_affected", "fixed"}


@dataclass
class Suppression:
    """A record of a single finding suppressed by a VEX statement."""

    vuln_id: str
    status: str
    justification: str | None
    product: str
    kev_conflict: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "status": self.status,
            "justification": self.justification,
            "product": self.product,
            "kev_conflict": self.kev_conflict,
        }


@dataclass
class _Statement:
    """A normalized internal VEX statement.

    ``vuln_ids`` are uppercased. ``products`` empty means "applies to all
    products" (id-only match).
    """

    vuln_ids: set[str]
    status: str
    justification: str | None
    products: set[str] = field(default_factory=set)


@dataclass
class VexDocument:
    """Normalized internal representation of a parsed VEX document."""

    statements: list[_Statement]
    format: str


def load_vex(path: Path) -> VexDocument:
    """Parse a VEX JSON document into a normalized :class:`VexDocument`.

    Supports OpenVEX and (minimally) CSAF VEX. Raises :class:`VexParseError`
    if the document cannot be parsed or its format is not recognized.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem error passthrough
        msg = f"Cannot read VEX document: {exc}"
        raise VexParseError(msg) from exc

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        msg = f"VEX document is not valid JSON: {exc}"
        raise VexParseError(msg) from exc

    if not isinstance(data, dict):
        msg = "VEX document must be a JSON object"
        raise VexParseError(msg)

    if _looks_like_openvex(data):
        return VexDocument(statements=_parse_openvex(data), format="openvex")
    if _looks_like_csaf(data):
        return VexDocument(statements=_parse_csaf(data), format="csaf")

    msg = "Unrecognized VEX document format (expected OpenVEX or CSAF)"
    raise VexParseError(msg)


# -- format detection --
def _looks_like_openvex(data: dict[str, Any]) -> bool:
    context = data.get("@context")
    if isinstance(context, str) and "openvex" in context.lower():
        return True
    if isinstance(context, list) and any(
        isinstance(item, str) and "openvex" in item.lower() for item in context
    ):
        return True
    statements = data.get("statements")
    if isinstance(statements, list) and any(
        isinstance(item, dict) and "vulnerability" in item and "status" in item
        for item in statements
    ):
        return True
    return False


def _looks_like_csaf(data: dict[str, Any]) -> bool:
    document = data.get("document")
    if isinstance(document, dict) and document.get("csaf_version"):
        return True
    vulnerabilities = data.get("vulnerabilities")
    if isinstance(vulnerabilities, list) and any(
        isinstance(item, dict)
        and ("cve" in item or "ids" in item)
        and "product_status" in item
        for item in vulnerabilities
    ):
        return True
    return False


# -- OpenVEX parsing --
def _parse_openvex(data: dict[str, Any]) -> list[_Statement]:
    statements_raw = data.get("statements")
    if not isinstance(statements_raw, list):
        msg = "OpenVEX document has no 'statements' list"
        raise VexParseError(msg)

    statements: list[_Statement] = []
    for entry in statements_raw:
        if not isinstance(entry, dict):
            continue
        vuln_ids = _openvex_vuln_ids(entry.get("vulnerability"))
        status = entry.get("status")
        if not vuln_ids or not isinstance(status, str):
            continue
        # OpenVEX not_affected requires a justification or impact_statement to be actionable.
        justification = entry.get("justification") or entry.get("impact_statement")
        if not isinstance(justification, str) or not justification.strip():
            justification = None
        products = _openvex_products(entry.get("products"))
        statements.append(
            _Statement(
                vuln_ids=vuln_ids,
                status=status.strip().lower(),
                justification=justification,
                products=products,
            )
        )
    return statements


def _openvex_vuln_ids(vulnerability: Any) -> set[str]:
    ids: set[str] = set()
    if isinstance(vulnerability, str):
        if vulnerability.strip():
            ids.add(vulnerability.strip().upper())
    elif isinstance(vulnerability, dict):
        # OpenVEX 0.2.0 uses an object: {"name": "CVE-...", "aliases": [...]}
        name = vulnerability.get("name") or vulnerability.get("@id") or vulnerability.get("id")
        if isinstance(name, str) and name.strip():
            ids.add(name.strip().upper())
        for alias in vulnerability.get("aliases") or []:
            if isinstance(alias, str) and alias.strip():
                ids.add(alias.strip().upper())
    return ids


def _openvex_products(products: Any) -> set[str]:
    result: set[str] = set()
    if not isinstance(products, list):
        return result
    for product in products:
        if isinstance(product, str) and product.strip():
            result.add(product.strip())
        elif isinstance(product, dict):
            for key in ("@id", "id", "name"):
                value = product.get(key)
                if isinstance(value, str) and value.strip():
                    result.add(value.strip())
            # Subcomponents / purls can live under identifiers.
            identifiers = product.get("identifiers")
            if isinstance(identifiers, dict):
                for value in identifiers.values():
                    if isinstance(value, str) and value.strip():
                        result.add(value.strip())
    return result


# -- CSAF VEX parsing (minimal) --
_CSAF_STATUS_MAP = {
    "known_not_affected": "not_affected",
    "fixed": "fixed",
    "first_fixed": "fixed",
    "known_affected": "affected",
}


def _parse_csaf(data: dict[str, Any]) -> list[_Statement]:
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        msg = "CSAF document has no 'vulnerabilities' list"
        raise VexParseError(msg)

    statements: list[_Statement] = []
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            continue
        vuln_ids = _csaf_vuln_ids(entry)
        product_status = entry.get("product_status")
        if not vuln_ids or not isinstance(product_status, dict):
            continue
        justification = _csaf_justification(entry)
        for csaf_status, products in product_status.items():
            mapped = _CSAF_STATUS_MAP.get(csaf_status)
            if not mapped:
                continue
            product_set = {
                str(item).strip()
                for item in (products or [])
                if isinstance(item, str) and item.strip()
            }
            statements.append(
                _Statement(
                    vuln_ids=set(vuln_ids),
                    status=mapped,
                    justification=justification,
                    products=product_set,
                )
            )
    return statements


def _csaf_vuln_ids(entry: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    cve = entry.get("cve")
    if isinstance(cve, str) and cve.strip():
        ids.add(cve.strip().upper())
    for ident in entry.get("ids") or []:
        if isinstance(ident, dict):
            text = ident.get("text")
            if isinstance(text, str) and text.strip():
                ids.add(text.strip().upper())
        elif isinstance(ident, str) and ident.strip():
            ids.add(ident.strip().upper())
    return ids


def _csaf_justification(entry: dict[str, Any]) -> str | None:
    # CSAF carries rationale in flags[].label and/or threats[].details.
    flags = entry.get("flags")
    if isinstance(flags, list):
        for flag in flags:
            if isinstance(flag, dict):
                label = flag.get("label")
                if isinstance(label, str) and label.strip():
                    return label.strip()
    threats = entry.get("threats")
    if isinstance(threats, list):
        for threat in threats:
            if isinstance(threat, dict):
                details = threat.get("details")
                if isinstance(details, str) and details.strip():
                    return details.strip()
    return None


# -- application --
def apply_vex(
    findings: list[Finding], vex_doc: VexDocument
) -> tuple[list[Finding], list[Suppression]]:
    """Apply VEX statements to findings.

    Returns ``(kept_findings, suppressions)``. A finding is suppressed only when
    a matching statement is ``fixed``, or ``not_affected`` with a non-empty
    justification/impact statement. All other cases keep the finding live.
    """
    statements = vex_doc.statements if isinstance(vex_doc, VexDocument) else []

    kept: list[Finding] = []
    suppressions: list[Suppression] = []

    for finding in findings:
        suppression = _first_suppressing_match(finding, statements)
        if suppression is None:
            kept.append(finding)
        else:
            suppressions.append(suppression)

    return kept, suppressions


def _first_suppressing_match(
    finding: Finding, statements: list[_Statement]
) -> Suppression | None:
    finding_ids = _finding_id_set(finding)
    for statement in statements:
        if not (statement.vuln_ids & finding_ids):
            continue
        product = _matched_product(finding, statement)
        if product is None:
            continue
        if not _is_suppressing(statement):
            continue
        return Suppression(
            vuln_id=finding.id,
            status=statement.status,
            justification=statement.justification,
            product=product,
            kev_conflict=finding.known_exploited is True,
        )
    return None


def _is_suppressing(statement: _Statement) -> bool:
    if statement.status == "fixed":
        return True
    if statement.status == "not_affected":
        return bool(statement.justification)
    return False


def _finding_id_set(finding: Finding) -> set[str]:
    ids = {finding.id.upper()}
    ids.update(alias.upper() for alias in finding.aliases)
    ids.update(finding.cve_aliases)  # already uppercased
    return ids


def _matched_product(finding: Finding, statement: _Statement) -> str | None:
    """Return the matched product string, or ``"*"`` when the statement has no
    product scope. Returns ``None`` when products are scoped but none match.
    """
    if not statement.products:
        return "*"
    purl = finding.purl or ""
    package = finding.package or ""
    for product in statement.products:
        if purl and _purl_matches(product, purl):
            return product
        if package and product == package:
            return product
    return None


def _purl_matches(product: str, purl: str) -> bool:
    """Precise purl scoping for VEX products.

    Matches on exact purl, or a versionless product purl against any version of
    the same package, or a versioned product against the same version. Crucially
    it does NOT use a bare prefix test, which would let ``pkg:pypi/acme`` wrongly
    suppress ``pkg:pypi/acme-evil``.
    """
    if product == purl:
        return True
    product_base, _, product_version = product.partition("@")
    purl_base, _, purl_version = purl.partition("@")
    # Compare package identity without qualifiers (?...) or subpath (#...).
    if _purl_identity(product_base) != _purl_identity(purl_base):
        return False
    if product_version:
        # A versioned product purl only matches the same version.
        return product_version.partition("?")[0] == purl_version.partition("?")[0]
    # A versionless product purl matches any version of the same package.
    return True


def _purl_identity(base: str) -> str:
    return base.split("?", 1)[0].split("#", 1)[0]
