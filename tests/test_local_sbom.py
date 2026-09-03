"""Unit tests for cra_evidence_cli.local.sbom.

No network calls are made.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cra_evidence_cli.local.models import identifier_coverage
from cra_evidence_cli.local.sbom import load_sbom

# Fixtures / helpers


def _write(path: Path, data: dict[str, Any]) -> Path:
    path.write_text(json.dumps(data))
    return path


def _cyclonedx(components: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
    }


def _spdx(packages: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": packages,
    }


CPE_ONLY = "cpe:2.3:a:vendor:cpe-only-widget:1.0:*:*:*:*:*:*:*"
CPE_BOTH = "cpe:2.3:a:vendor:both-widget:2.0:*:*:*:*:*:*:*"
CPE_22 = "cpe:/a:vendor:legacy-widget:1.0"


# CycloneDX


def test_cyclonedx_cpe_only_is_parsed_with_no_purl(tmp_path):
    """A component with only a CPE (no purl) must have it parsed."""
    sbom = _write(
        tmp_path / "sbom.json",
        _cyclonedx(
            [{"type": "library", "name": "cpe-only-widget", "version": "1.0", "cpe": CPE_ONLY}]
        ),
    )
    components, _ = load_sbom(sbom)
    assert len(components) == 1
    assert components[0].purl is None
    assert components[0].cpe == CPE_ONLY


def test_cyclonedx_cpe_and_purl_both_parsed(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _cyclonedx(
            [
                {
                    "type": "library",
                    "name": "both-widget",
                    "version": "2.0",
                    "purl": "pkg:pypi/both-widget@2.0",
                    "cpe": CPE_BOTH,
                }
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    assert components[0].purl == "pkg:pypi/both-widget@2.0"
    assert components[0].cpe == CPE_BOTH


def test_cyclonedx_component_without_cpe_field_stays_none(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _cyclonedx([{"type": "library", "name": "no-identifier", "version": "1.0"}]),
    )
    components, _ = load_sbom(sbom)
    assert components[0].purl is None
    assert components[0].cpe is None


def test_cyclonedx_empty_string_cpe_does_not_crash_and_is_not_counted(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _cyclonedx([{"type": "library", "name": "empty-cpe", "version": "1.0", "cpe": ""}]),
    )
    components, _ = load_sbom(sbom)
    assert not components[0].purl
    assert not components[0].cpe
    coverage = identifier_coverage(components)
    assert coverage["components_with_identifier_field"] == 0


def test_cyclonedx_nested_components_are_parsed_and_counted(tmp_path):
    sbom = _write(
        tmp_path / "nested-sbom.json",
        _cyclonedx(
            [
                {
                    "type": "application",
                    "name": "parent",
                    "purl": "pkg:generic/parent@1.0",
                    "components": [
                        {
                            "type": "library",
                            "name": "child-without-identifier",
                            "components": [
                                {
                                    "type": "library",
                                    "name": "grandchild-with-cpe",
                                    "cpe": CPE_ONLY,
                                }
                            ],
                        }
                    ],
                }
            ]
        ),
    )

    components, _ = load_sbom(sbom)
    coverage = identifier_coverage(components)

    assert [component.name for component in components] == [
        "parent",
        "child-without-identifier",
        "grandchild-with-cpe",
    ]
    assert coverage["total_components"] == 3
    assert coverage["components_with_identifier_field"] == 2
    assert coverage["all_components_have_identifier_field"] is False


# SPDX


def test_spdx_cpe23_type_is_parsed(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "cpe-only-widget",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "cpe23Type",
                            "referenceLocator": CPE_ONLY,
                        }
                    ],
                }
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    assert len(components) == 1
    assert components[0].purl is None
    assert components[0].cpe == CPE_ONLY


def test_spdx_cpe22_type_is_parsed(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "legacy-widget",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "cpe22Type",
                            "referenceLocator": CPE_22,
                        }
                    ],
                }
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    assert components[0].purl is None
    assert components[0].cpe == CPE_22


def test_spdx_prefers_cpe23_over_cpe22_when_both_declared(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "both-cpes-widget",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "cpe22Type",
                            "referenceLocator": CPE_22,
                        },
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "cpe23Type",
                            "referenceLocator": CPE_BOTH,
                        },
                    ],
                }
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    assert components[0].cpe == CPE_BOTH


def test_spdx_purl_and_cpe23_both_parsed_from_same_package(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "both-widget",
                    "versionInfo": "2.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/both-widget@2.0",
                        },
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "cpe23Type",
                            "referenceLocator": CPE_BOTH,
                        },
                    ],
                }
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    assert components[0].purl == "pkg:pypi/both-widget@2.0"
    assert components[0].cpe == CPE_BOTH


def test_spdx_package_without_identifying_ref_stays_none(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "no-identifier",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "OTHER",
                            "referenceType": "website",
                            "referenceLocator": "https://example.com/no-identifier",
                        }
                    ],
                }
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    assert components[0].purl is None
    assert components[0].cpe is None


def test_spdx_missing_locator_on_cpe_ref_does_not_crash(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "malformed-ref-widget",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {"referenceCategory": "SECURITY", "referenceType": "cpe23Type"}
                    ],
                }
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    assert components[0].cpe is None


def test_spdx_non_string_locator_on_cpe_ref_does_not_crash(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "malformed-ref-widget",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "cpe23Type",
                            "referenceLocator": 12345,
                        }
                    ],
                }
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    assert components[0].cpe is None


def test_spdx_empty_string_cpe_locator_does_not_crash_and_is_not_counted(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "empty-cpe-widget",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "cpe23Type",
                            "referenceLocator": "",
                        }
                    ],
                }
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    assert not components[0].cpe
    coverage = identifier_coverage(components)
    assert coverage["components_with_identifier_field"] == 0


# End-to-end wiring: identifier_coverage reflects a CPE-only SBOM correctly.


def test_identifier_coverage_reflects_parsed_cpe_only_components(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _cyclonedx(
            [
                {"type": "library", "name": "cpe-only-widget", "version": "1.0", "cpe": CPE_ONLY},
                {"type": "library", "name": "no-identifier", "version": "1.0"},
            ]
        ),
    )
    components, _ = load_sbom(sbom)
    coverage = identifier_coverage(components)
    assert coverage["total_components"] == 2
    assert coverage["components_with_identifier_field"] == 1
    assert coverage["all_components_have_identifier_field"] is False
