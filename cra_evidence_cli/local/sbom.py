"""SBOM parsing helpers for local no-key checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cra_evidence_cli.local.models import Component


class SBOMParseError(ValueError):
    """Raised when an SBOM cannot be parsed."""


def load_sbom(path: Path) -> tuple[list[Component], dict[str, Any]]:
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        msg = f"Failed to parse SBOM {path}: {exc}"
        raise SBOMParseError(msg) from exc

    if isinstance(data.get("components"), list):
        return _parse_cyclonedx(data), data
    if isinstance(data.get("packages"), list):
        return _parse_spdx(data), data
    msg = "Unsupported SBOM format: expected CycloneDX components or SPDX packages"
    raise SBOMParseError(msg)


def _parse_cyclonedx(data: dict[str, Any]) -> list[Component]:
    components: list[Component] = []
    for item in data.get("components", []):
        if not isinstance(item, dict):
            continue
        licenses = []
        for license_item in item.get("licenses") or []:
            if isinstance(license_item, dict):
                license_data = license_item.get("license") or {}
                if isinstance(license_data, dict):
                    value = license_data.get("id") or license_data.get("name")
                    if value:
                        licenses.append(str(value))
        supplier = item.get("supplier")
        if isinstance(supplier, dict):
            supplier = supplier.get("name")
        components.append(
            Component(
                name=str(item.get("name") or item.get("bom-ref") or "unknown"),
                version=item.get("version"),
                purl=item.get("purl"),
                supplier=supplier if isinstance(supplier, str) else None,
                licenses=licenses,
            )
        )
    return components


def _parse_spdx(data: dict[str, Any]) -> list[Component]:
    components: list[Component] = []
    for item in data.get("packages", []):
        if not isinstance(item, dict):
            continue
        purl = None
        for ref in item.get("externalRefs") or []:
            if not isinstance(ref, dict):
                continue
            locator = ref.get("referenceLocator")
            if isinstance(locator, str) and locator.startswith("pkg:"):
                purl = locator
                break
        license_value = item.get("licenseConcluded") or item.get("licenseDeclared")
        licenses = [str(license_value)] if license_value and license_value != "NOASSERTION" else []
        components.append(
            Component(
                name=str(item.get("name") or "unknown"),
                version=item.get("versionInfo"),
                purl=purl,
                supplier=item.get("supplier") if isinstance(item.get("supplier"), str) else None,
                licenses=licenses,
            )
        )
    return components
