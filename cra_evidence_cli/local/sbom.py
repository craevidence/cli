"""SBOM parsing helpers for local no-key checks."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
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

    if not isinstance(data, dict):
        msg = "Invalid SBOM format: expected a JSON object at the root"
        raise SBOMParseError(msg)

    if isinstance(data.get("components"), list):
        return _parse_cyclonedx(data), data
    if isinstance(data.get("packages"), list):
        return _parse_spdx(data), data
    msg = "Unsupported SBOM format: expected CycloneDX components or SPDX packages"
    raise SBOMParseError(msg)


def _parse_cyclonedx(data: dict[str, Any]) -> list[Component]:
    components: list[Component] = []

    def visit(items: object) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                msg = "Invalid CycloneDX SBOM: each component must be a JSON object"
                raise SBOMParseError(msg)
            parse(item)
            visit(item.get("components"))

    def parse(item: dict[str, Any]) -> None:
        licenses = []
        for license_item in item.get("licenses") or []:
            if isinstance(license_item, dict):
                license_data = license_item.get("license") or {}
                if isinstance(license_data, dict):
                    value = license_data.get("id") or license_data.get("name")
                else:
                    value = None
                value = value or license_item.get("expression")
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
                cpe=item.get("cpe"),
                supplier=supplier if isinstance(supplier, str) else None,
                licenses=licenses,
            )
        )

    visit(data.get("components"))
    return components


def _parse_spdx(data: dict[str, Any]) -> list[Component]:
    components: list[Component] = []
    for item in data.get("packages", []):
        if not isinstance(item, dict):
            msg = "Invalid SPDX SBOM: each package must be a JSON object"
            raise SBOMParseError(msg)
        purl = None
        # SPDX 2.2 and 2.3 spell the CPE referenceCategory differently
        # (PACKAGE-MANAGER vs PACKAGE_MANAGER etc.), so - like the purl
        # match above - this reads referenceType/referenceLocator directly
        # rather than trusting referenceCategory. A cpe23Type locator is
        # preferred over cpe22Type when a package declares both, since it
        # is the more specific, current format; the first locator seen for
        # whichever type wins is kept, mirroring the purl match's
        # first-one-wins behavior.
        cpe23 = None
        cpe22 = None
        for ref in item.get("externalRefs") or []:
            if not isinstance(ref, dict):
                continue
            locator = ref.get("referenceLocator")
            if not isinstance(locator, str):
                continue
            if purl is None and locator.startswith("pkg:"):
                purl = locator
                continue
            ref_type = ref.get("referenceType")
            if cpe23 is None and ref_type == "cpe23Type":
                cpe23 = locator
            elif cpe22 is None and ref_type == "cpe22Type":
                cpe22 = locator
        cpe = cpe23 or cpe22
        license_value = item.get("licenseConcluded")
        if not license_value or license_value == "NOASSERTION":
            license_value = item.get("licenseDeclared")
        licenses = [str(license_value)] if license_value and license_value != "NOASSERTION" else []
        components.append(
            Component(
                name=str(item.get("name") or "unknown"),
                version=item.get("versionInfo"),
                purl=purl,
                cpe=cpe,
                supplier=item.get("supplier") if isinstance(item.get("supplier"), str) else None,
                licenses=licenses,
            )
        )
    return components


def read_sbom_observations(
    data: dict[str, Any], components: list[Component]
) -> dict[str, Any]:
    """Read the raw document and component projection from one successful load_sbom call."""
    cyclonedx = isinstance(data.get("components"), list)
    collection = "components" if cyclonedx else "packages"
    version_field = "version" if cyclonedx else "versionInfo"
    versions: dict[str, Any] = {
        state: {"count": 0, "locations": [], "omitted": 0}
        for state in ("absent", "null", "blank", "invalid_type")
    }
    versions["nonblank_strings"] = 0
    identifiers: dict[str, Any] = {"count": 0, "locations": [], "omitted": 0}

    def record(group: dict[str, Any], location: str) -> None:
        group["count"] += 1
        if len(group["locations"]) < 5:
            group["locations"].append(location)
        else:
            group["omitted"] += 1

    def walk(
        items: list[dict[str, Any]], prefix: str
    ) -> Iterator[tuple[dict[str, Any], str]]:
        for index, item in enumerate(items):
            location = f"{prefix}/{index}"
            yield item, location
            children = item.get("components")
            if cyclonedx and isinstance(children, list):
                yield from walk(children, f"{location}/components")

    for index, (item, location) in enumerate(walk(data[collection], f"/{collection}")):
        value = item.get(version_field)
        state: str | None
        if version_field not in item:
            state = "absent"
        elif value is None:
            state = "null"
        elif not isinstance(value, str):
            state = "invalid_type"
        elif not value.strip():
            state = "blank"
        else:
            state = None
        if state is None:
            versions["nonblank_strings"] += 1
        else:
            record(versions[state], f"{location}/{version_field}")

        component = components[index]
        if not any(
            isinstance(identifier, str) and bool(identifier.strip())
            for identifier in (component.purl, component.cpe)
        ):
            record(identifiers, location)

    return {
        "status": "reported",
        "scope": "parsed_component_occurrences",
        "component_count": len(components),
        "version_fields": versions,
        "identifier_fields": {"without_nonblank_identifier": identifiers},
        "not_assessed": [
            "schema_validity",
            "identifier_syntax",
            "version_meaning",
            "dependency_reference_integrity",
            "license_accuracy",
            "artifact_binding",
            "inventory_completeness",
        ],
    }


def read_sbom_graph_observations(data: dict[str, Any]) -> dict[str, Any]:
    """Interpret local SPDX identities from the raw document of a successful load_sbom call."""
    result: dict[str, Any] = {
        "status": "reported",
        "scope": "spdx_2_3_local_definitions_and_relationship_endpoints",
        "relationships_state": None,
        "definition_occurrences": None,
        "local_relationship_endpoint_occurrences": None,
        "repeated_local_identifiers": None,
        "unresolved_local_relationship_endpoints": None,
        "limitation": None,
    }

    def limited(status: str, code: str, location: str) -> dict[str, Any]:
        result["status"] = status
        result["limitation"] = {"code": code, "location": location}
        return result

    def string_issue(item: dict[str, Any], field: str) -> str | None:
        if field not in item:
            return "absent"
        value = item[field]
        if value is None:
            return "null"
        if not isinstance(value, str):
            return "invalid_type"
        if not value:
            return "empty"
        if not value.strip():
            return "blank"
        return None

    if isinstance(data.get("components"), list):
        return limited("not_assessed", "selected_component_shape", "/components")
    issue = string_issue(data, "spdxVersion")
    if issue:
        return limited("not_assessed", f"version_{issue}", "/spdxVersion")
    if data["spdxVersion"] != "SPDX-2.3":
        return limited("not_assessed", "unsupported_version", "/spdxVersion")
    for marker in ("bomFormat", "@context", "@graph"):
        if marker in data:
            return limited("not_assessed", "conflicting_format_markers", f"/{marker}")

    seen: set[str] = set()
    definitions = 0
    repeats: dict[str, Any] = {"count": 0, "locations": [], "omitted": 0}
    unresolved: dict[str, Any] = {"count": 0, "locations": [], "omitted": 0}
    local_id = re.compile(r"SPDXRef-[A-Za-z0-9.-]+")
    external_id = re.compile(r"DocumentRef-[A-Za-z0-9.+-]+:SPDXRef-[A-Za-z0-9.-]+")

    def record(group: dict[str, Any], location: str) -> None:
        group["count"] += 1
        if len(group["locations"]) < 5:
            group["locations"].append(location)
        else:
            group["omitted"] += 1

    def define(item: dict[str, Any], location: str) -> str | None:
        nonlocal definitions
        issue = string_issue(item, "SPDXID")
        if issue:
            return issue
        identifier = item["SPDXID"]
        if not local_id.fullmatch(identifier):
            return "invalid_syntax"
        if location == "/SPDXID" and identifier != "SPDXRef-DOCUMENT":
            return "unexpected_document_identifier"
        definitions += 1
        if identifier in seen:
            record(repeats, location)
        else:
            seen.add(identifier)
        return None

    issue = define(data, "/SPDXID")
    if issue:
        return limited("uninterpretable", issue, "/SPDXID")
    for collection in ("packages", "files", "snippets"):
        items = data[collection] if collection == "packages" else data.get(collection, [])
        if collection != "packages" and not isinstance(items, list):
            return limited("uninterpretable", "invalid_type", f"/{collection}")
        for index, item in enumerate(items):
            location = f"/{collection}/{index}"
            if collection != "packages" and not isinstance(item, dict):
                return limited("uninterpretable", "invalid_type", location)
            issue = define(item, f"{location}/SPDXID")
            if issue:
                return limited("uninterpretable", issue, f"{location}/SPDXID")

    relationships = data.get("relationships", [])
    if not isinstance(relationships, list):
        return limited("uninterpretable", "invalid_type", "/relationships")
    local_endpoints = 0
    for index, relationship in enumerate(relationships):
        location = f"/relationships/{index}"
        if not isinstance(relationship, dict):
            return limited("uninterpretable", "invalid_type", location)
        for field in ("spdxElementId", "relatedSpdxElement"):
            pointer = f"{location}/{field}"
            issue = string_issue(relationship, field)
            if issue:
                return limited("uninterpretable", issue, pointer)
            identifier = relationship[field]
            if identifier in {"NONE", "NOASSERTION"}:
                if field == "spdxElementId":
                    return limited("uninterpretable", "special_not_allowed_here", pointer)
            elif local_id.fullmatch(identifier):
                local_endpoints += 1
                if identifier not in seen:
                    record(unresolved, pointer)
            elif not external_id.fullmatch(identifier):
                return limited("uninterpretable", "invalid_syntax", pointer)

    result.update({
        "relationships_state": (
            "present" if relationships else "empty" if "relationships" in data else "absent"
        ),
        "definition_occurrences": definitions,
        "local_relationship_endpoint_occurrences": local_endpoints,
        "repeated_local_identifiers": repeats,
        "unresolved_local_relationship_endpoints": unresolved,
    })
    return result
