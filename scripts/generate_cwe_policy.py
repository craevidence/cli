#!/usr/bin/env python3
"""Generate the pinned rule-pack CWE mapping policy from a MITRE catalog."""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def _catalog(xml_path: Path) -> tuple[str, str, dict[str, dict[str, str]]]:
    # Input is the locally pinned MITRE release catalog, not request data.
    root = ET.parse(xml_path).getroot()  # noqa: S314
    namespace = {"cwe": "http://cwe.mitre.org/cwe-7"}
    version = str(root.attrib.get("Version") or "")
    catalog_date = str(root.attrib.get("Date") or "")
    entries: dict[str, dict[str, str]] = {}
    groups = (
        ("Weaknesses", "Weakness", "weakness"),
        ("Categories", "Category", "category"),
        ("Views", "View", "view"),
    )
    for group, element_name, kind in groups:
        for element in root.findall(
            f"cwe:{group}/cwe:{element_name}", namespace
        ):
            cwe_id = str(element.attrib["ID"])
            usage_node = element.find("cwe:Mapping_Notes/cwe:Usage", namespace)
            usage = (usage_node.text or "").strip() if usage_node is not None else ""
            if not usage:
                message = f"CWE-{cwe_id} has no mapping usage"
                raise ValueError(message)
            if cwe_id in entries:
                message = f"duplicate CWE catalog id: {cwe_id}"
                raise ValueError(message)
            entries[cwe_id] = {
                "kind": kind,
                "name": str(element.attrib.get("Name") or ""),
                "abstraction": str(element.attrib.get("Abstraction") or "").lower(),
                "status": str(element.attrib.get("Status") or "").lower(),
                "usage": usage.lower(),
            }
    if not entries:
        message = "CWE catalog contains no Weakness entries"
        raise ValueError(message)
    return version, catalog_date, dict(sorted(entries.items(), key=lambda item: int(item[0])))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xml", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    previous = json.loads(args.output.read_text(encoding="utf-8"))
    version, catalog_date, entries = _catalog(args.xml)
    disallowed = {
        cwe_id: entry["usage"]
        for cwe_id, entry in entries.items()
        if entry["usage"] in {"discouraged", "prohibited"}
    }
    allowed_with_review = {
        cwe_id: entry["abstraction"]
        for cwe_id, entry in entries.items()
        if entry["usage"] == "allowed-with-review"
    }
    document = {
        "schema_version": 2,
        "source": f"MITRE CWE {version}",
        "source_url": f"https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip",
        "catalog_date": catalog_date,
        "known_mapping_ids": entries,
        "allowed_with_review_mapping_ids": allowed_with_review,
        "reviewed_current_mappings": previous["reviewed_current_mappings"],
        "disallowed_mapping_ids": disallowed,
    }
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
