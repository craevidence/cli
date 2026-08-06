"""Pure builder for the CycloneDX VEX document the no-key draft command emits.

:func:`build_cyclonedx_vex` assembles a CycloneDX 1.6 VEX skeleton from local
scan findings, with every statement marked ``in_triage``. No network, no
subprocess, no printing.

Two details matter for the document to be usable by other tools:

* ``affects[].ref`` must resolve to a ``bom-ref`` that exists in the document.
  A bare package URL that appears nowhere in ``components`` is not resolvable,
  so every referenced package is also emitted as a component whose ``bom-ref``
  is that same package URL.
* Scanners commonly report the same vulnerability once per place a package is
  referenced. Emitting one statement per report inflates the document and makes
  it hard to read, so statements are collapsed per vulnerability, with each
  affected package listed once under ``affects``.

This produces a draft skeleton, not an audit artifact. Every statement says the
finding is still being investigated, which is the honest starting position: the
author has to evaluate each one and set a real status.
"""

from __future__ import annotations

import uuid

from cra_evidence_cli.local.disclaimer import DISCLAIMER_TEXT
from cra_evidence_cli.local.models import Finding, utc_now_iso

SPEC_VERSION = "1.6"

# CycloneDX spells "being investigated" as in_triage.
INITIAL_STATE = "in_triage"


def _package_ref(finding: Finding) -> str | None:
    """Package URL used both as the component bom-ref and the affects ref."""
    if finding.purl:
        return finding.purl
    if finding.package and finding.version:
        return f"{finding.package}@{finding.version}"
    return finding.package or None


def build_cyclonedx_vex(findings: list[Finding]) -> dict:
    """Build a CycloneDX VEX skeleton from local scan findings.

    Statements are collapsed per vulnerability id. Every package affected by
    that vulnerability appears once in its ``affects`` list, and each of those
    packages is emitted as a component so the reference resolves.
    """
    components: list[dict] = []
    seen_components: set[str] = set()

    vulnerabilities: list[dict] = []
    by_id: dict[str, dict] = {}
    refs_by_id: dict[str, set[str]] = {}

    for finding in findings:
        ref = _package_ref(finding)

        if ref and ref not in seen_components:
            seen_components.add(ref)
            component: dict = {"type": "library", "bom-ref": ref}
            if finding.purl:
                component["purl"] = finding.purl
            if finding.package:
                component["name"] = finding.package
            if finding.version:
                component["version"] = finding.version
            components.append(component)

        entry = by_id.get(finding.id)
        if entry is None:
            entry = {
                "bom-ref": f"vuln-{len(vulnerabilities) + 1}",
                "id": finding.id,
                "analysis": {
                    "state": INITIAL_STATE,
                    "detail": DISCLAIMER_TEXT,
                },
                "affects": [],
            }
            if finding.severity and finding.severity != "unknown":
                entry["ratings"] = [{"severity": finding.severity, "method": "other"}]
            if finding.title:
                entry["description"] = finding.title
            if finding.fixed_versions:
                entry["recommendation"] = "Upgrade to one of: " + ", ".join(
                    finding.fixed_versions
                )
            by_id[finding.id] = entry
            refs_by_id[finding.id] = set()
            vulnerabilities.append(entry)

        if ref and ref not in refs_by_id[finding.id]:
            refs_by_id[finding.id].add(ref)
            entry["affects"].append({"ref": ref})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": utc_now_iso(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "CRA Evidence CLI",
                        "author": "CRA Evidence",
                    }
                ]
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
