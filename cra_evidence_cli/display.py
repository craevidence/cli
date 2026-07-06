"""User-facing display labels and shared output helpers for CLI text output."""

from __future__ import annotations

import re
import sys

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_]+$")

_ACRONYMS = {
    "api": "API",
    "cd": "CD",
    "ci": "CI",
    "cra": "CRA",
    "csv": "CSV",
    "eu": "EU",
    "hbom": "HBOM",
    "id": "ID",
    "json": "JSON",
    "oidc": "OIDC",
    "pdf": "PDF",
    "sarif": "SARIF",
    "sbom": "SBOM",
    "uii": "UII",
    "url": "URL",
    "vex": "VEX",
    "yaml": "YAML",
}

_KNOWN_LABELS = {
    "architecture_diagram": "Architecture diagram",
    "compliance_yaml": "Compliance YAML",
    "conformity_certificate": "Conformity certificate",
    "coordinated_disclosure_policy": "Coordinated disclosure policy",
    "cyclonedx_json": "CycloneDX JSON",
    "eu_declaration_of_conformity": "EU declaration of conformity",
    "gemara_yaml": "Compliance YAML",
    "harmonised_standards": "Harmonised standards",
    "risk_assessment": "Risk assessment",
    "secure_development_policy": "Secure development policy",
    "supplier_due_diligence": "Supplier due diligence",
    "technical_documentation": "Technical documentation",
    "test_report": "Test report",
    "third_party_audit": "Third-party audit",
    "uii": "UII",
    "update_mechanism_documentation": "Update mechanism documentation",
    "user_manual": "User manual",
    "vulnerability_policy": "Vulnerability policy",
}

_FIELD_PREFIX_LABELS = {
    "annex_i_attestations": "Security attestations",
}

_FIELD_SUFFIX_LABELS = {
    "secure_by_default_confirmed": "Secure by default confirmed",
}


def humanize_identifier(value: object) -> str:
    text = str(value or "")
    if not text:
        return ""
    known = _KNOWN_LABELS.get(text)
    if known:
        return known
    if not _TOKEN_RE.fullmatch(text):
        return text
    words = []
    for part in text.split("_"):
        lowered = part.lower()
        words.append(_ACRONYMS.get(lowered, lowered.capitalize()))
    return " ".join(words)


def warn_unsupported_output_format(
    format_name: str, supported: tuple[str, ...] = ("text", "json", "sarif")
) -> None:
    """Print a notice to stderr when an output format is not supported by a command.

    Callers should then fall back to text rendering. The notice text is:
    'format <x> not supported for this command; using text'

    Only emits output when the requested format is not in the supported tuple.
    """
    if format_name not in supported:
        sys.stderr.write(
            f"format {format_name} not supported for this command; using text\n"
        )
        sys.stderr.flush()


def humanize_field_path(value: object) -> str:
    text = str(value or "")
    parts = text.split(".")
    known = _FIELD_SUFFIX_LABELS.get(parts[-1] if parts else "")
    if known:
        return known
    labels = []
    for index, part in enumerate(parts):
        if index == 0 and part in _FIELD_PREFIX_LABELS:
            labels.append(_FIELD_PREFIX_LABELS[part])
        else:
            labels.append(humanize_identifier(part))
    return ": ".join(label for label in labels if label)
