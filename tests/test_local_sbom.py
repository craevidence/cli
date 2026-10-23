"""Unit tests for cra_evidence_cli.local.sbom.

No network calls are made.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cra_evidence_cli.local.models import identifier_coverage
from cra_evidence_cli.local.sbom import (
    SBOMParseError,
    load_sbom,
    read_sbom_graph_observations,
    read_sbom_observations,
)

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


@pytest.mark.parametrize("root", [None, [], "not-an-object", 7])
def test_non_object_json_root_is_a_controlled_sbom_parse_error(tmp_path, root):
    path = tmp_path / "invalid-root.json"
    path.write_text(json.dumps(root), encoding="utf-8")

    with pytest.raises(SBOMParseError, match="JSON object at the root"):
        load_sbom(path)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (_cyclonedx([None]), "each component must be a JSON object"),
        (_cyclonedx([{"name": "valid"}, "invalid"]), "each component must be a JSON object"),
        (
            _cyclonedx([{"name": "parent", "components": [None]}]),
            "each component must be a JSON object",
        ),
        (_spdx([None]), "each package must be a JSON object"),
        (_spdx([{"name": "valid"}, "invalid"]), "each package must be a JSON object"),
    ],
)
def test_non_object_inventory_members_are_not_silently_dropped(tmp_path, payload, message):
    """Catches partial or zero inventories from silently skipped typed entries."""
    path = tmp_path / "invalid-member.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SBOMParseError, match=message):
        load_sbom(path)


@pytest.mark.parametrize("payload", [_cyclonedx([]), _spdx([])])
def test_explicit_empty_inventory_arrays_remain_valid(tmp_path, payload):
    """Catches treating an explicit empty inventory as unsupported or unmeasured."""
    path = tmp_path / "empty-inventory.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    components, _ = load_sbom(path)

    assert components == []
    observations = read_sbom_observations(payload, components)
    assert observations["status"] == "reported"
    assert observations["component_count"] == 0
    assert observations["version_fields"]["nonblank_strings"] == 0
    for state in ("absent", "null", "blank", "invalid_type"):
        assert observations["version_fields"][state] == {"count": 0, "locations": [], "omitted": 0}
    assert observations["identifier_fields"]["without_nonblank_identifier"] == {
        "count": 0, "locations": [], "omitted": 0
    }


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


@pytest.mark.parametrize(
    "expression",
    ["MIT OR Apache-2.0", "MIT AND BSD-3-Clause", "Apache-2.0 WITH LLVM-exception"],
)
def test_cyclonedx_license_expression_is_preserved_with_id_and_name(tmp_path, expression):
    sbom = _write(
        tmp_path / "sbom.json",
        _cyclonedx(
            [
                {
                    "name": "licensed-widget",
                    "licenses": [
                        {"license": {"id": "MIT"}},
                        {"license": {"name": "Custom License"}},
                        {"expression": expression},
                    ],
                }
            ]
        ),
    )

    components, _ = load_sbom(sbom)

    assert components[0].licenses == ["MIT", "Custom License", expression]


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


def test_spdx_absent_conclusion_uses_declared_license(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx([{"name": "declared-widget", "licenseDeclared": "Apache-2.0"}]),
    )

    components, _ = load_sbom(sbom)

    assert components[0].licenses == ["Apache-2.0"]


def test_spdx_noassertion_conclusion_uses_declared_license(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "declared-widget",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "Apache-2.0",
                }
            ]
        ),
    )

    components, _ = load_sbom(sbom)

    assert components[0].licenses == ["Apache-2.0"]


def test_spdx_none_conclusion_keeps_precedence_over_declared_license(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "none-widget",
                    "licenseConcluded": "NONE",
                    "licenseDeclared": "Apache-2.0",
                }
            ]
        ),
    )

    components, _ = load_sbom(sbom)

    assert components[0].licenses == ["NONE"]


def test_spdx_empty_conclusion_uses_declared_license(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "declared-widget",
                    "licenseConcluded": "",
                    "licenseDeclared": "Apache-2.0",
                }
            ]
        ),
    )

    components, _ = load_sbom(sbom)

    assert components[0].licenses == ["Apache-2.0"]


def test_spdx_meaningful_conclusion_overrides_declared_license(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "concluded-widget",
                    "licenseConcluded": "MIT",
                    "licenseDeclared": "Apache-2.0",
                }
            ]
        ),
    )

    components, _ = load_sbom(sbom)

    assert components[0].licenses == ["MIT"]


def test_spdx_noassertion_conclusion_and_declaration_produce_no_license(tmp_path):
    sbom = _write(
        tmp_path / "sbom.json",
        _spdx(
            [
                {
                    "name": "unknown-license-widget",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                }
            ]
        ),
    )

    components, _ = load_sbom(sbom)

    assert components[0].licenses == []


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


@pytest.mark.parametrize(
    ("collection", "field"), [("components", "version"), ("packages", "versionInfo")]
)
@pytest.mark.parametrize(
    ("present", "value", "state"),
    [
        (False, None, "absent"),
        (True, None, "null"),
        (True, "", "blank"),
        (True, " \t", "blank"),
        (True, 0, "invalid_type"),
        (True, False, "invalid_type"),
        (True, [], "invalid_type"),
        (True, {}, "invalid_type"),
        (True, "NOASSERTION", "nonblank_strings"),
        (True, "1.0", "nonblank_strings"),
    ],
)
def test_observations_distinguish_raw_version_states(
    tmp_path, collection, field, present, value, state
):
    """Catches truthiness defaults, string coercion and treating placeholders as missing fields."""
    item = {"name": "example"}
    if present:
        item[field] = value
    components, raw = load_sbom(_write(tmp_path / "sbom.json", {collection: [item]}))

    observations = read_sbom_observations(raw, components)

    assert observations["component_count"] == 1
    versions = observations["version_fields"]
    assert versions["nonblank_strings"] == int(state == "nonblank_strings")
    for group in ("absent", "null", "blank", "invalid_type"):
        assert versions[group] == {
            "count": int(group == state),
            "locations": [f"/{collection}/0/{field}"] if group == state else [],
            "omitted": 0,
        }


def test_observation_locations_follow_nested_occurrences_and_selected_scope(tmp_path):
    """Catches deduplicating names, skipping nested entries or including another inventory."""
    document = {
        "components": [{"name": "same", "components": [{"name": "same", "version": None}]}],
        "packages": [{"name": "ignored"}],
        "metadata": {"component": {"name": "root"}},
        "services": [{"name": "service"}],
    }
    document["components"][0]["purl"] = "pkg:generic/parent@1"
    components, raw = load_sbom(_write(tmp_path / "sbom.json", document))

    observations = read_sbom_observations(raw, components)

    assert observations["component_count"] == 2
    assert observations["version_fields"]["absent"]["locations"] == ["/components/0/version"]
    assert observations["version_fields"]["null"]["locations"] == [
        "/components/0/components/0/version"
    ]
    assert observations["identifier_fields"]["without_nonblank_identifier"] == {
        "count": 1,
        "locations": ["/components/0/components/0"],
        "omitted": 0,
    }
    assert raw == document


def test_observations_use_existing_spdx_identifier_selection(tmp_path):
    """Catches treating arbitrary external references as selected PURLs or validating syntax."""
    document = _spdx(
        [
            {"name": "generic", "externalRefs": [{"referenceLocator": "pkg:generic/example@1"}]},
            {
                "name": "cpe",
                "externalRefs": [{"referenceType": "cpe23Type", "referenceLocator": "not-a-cpe"}],
            },
            {"name": "other", "externalRefs": [{"referenceLocator": "https://example.invalid"}]},
            {
                "name": "typed",
                "externalRefs": [{"referenceType": "cpe23Type", "referenceLocator": 42}],
            },
        ]
    )
    components, raw = load_sbom(_write(tmp_path / "sbom.json", document))

    observations = read_sbom_observations(raw, components)

    assert identifier_coverage(components)["components_with_identifier_field"] == 2
    assert observations["identifier_fields"]["without_nonblank_identifier"] == {
        "count": 2, "locations": ["/packages/2", "/packages/3"], "omitted": 0
    }


@pytest.mark.parametrize(
    ("collection", "field"), [("components", "version"), ("packages", "versionInfo")]
)
def test_observation_examples_are_bounded_without_truncating_counts(tmp_path, collection, field):
    """Catches unbounded examples, a shared cap across groups or stopping the count at five."""
    items = [
        {"name": "same", **fields}
        for fields in ({}, {field: None}, {field: " "}, {field: {}})
        for _ in range(6)
    ]
    components, raw = load_sbom(_write(tmp_path / "sbom.json", {collection: items}))

    observations = read_sbom_observations(raw, components)

    assert observations["component_count"] == 24
    for index, state in enumerate(("absent", "null", "blank", "invalid_type")):
        assert observations["version_fields"][state] == {
            "count": 6,
            "locations": [
                f"/{collection}/{offset}/{field}" for offset in range(index * 6, index * 6 + 5)
            ],
            "omitted": 1,
        }
    assert observations["identifier_fields"]["without_nonblank_identifier"] == {
        "count": 24,
        "locations": [f"/{collection}/{index}" for index in range(5)],
        "omitted": 19,
    }


def _graph_document():
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [{"SPDXID": "SPDXRef-A", "name": "same"}] * 2,
        "files": [{"SPDXID": "SPDXRef-F"}],
        "snippets": [{"SPDXID": "SPDXRef-S"}],
        "relationships": [
            {"spdxElementId": "SPDXRef-A", "relatedSpdxElement": "SPDXRef-B"},
            {"spdxElementId": "DocumentRef-x:SPDXRef-A", "relatedSpdxElement": "SPDXRef-A"},
            {"spdxElementId": "SPDXRef-F", "relatedSpdxElement": "SPDXRef-S"},
        ],
    }


def test_graph_observations_count_the_complete_local_definition_universe(tmp_path):
    """Catches package-only indexing, distinct-ID totals and external namespace stripping."""
    components, raw = load_sbom(_write(tmp_path / "graph.json", _graph_document()))
    assert len(components) == 2
    assert read_sbom_graph_observations(raw) == {
        "status": "reported",
        "scope": "spdx_2_3_local_definitions_and_relationship_endpoints",
        "relationships_state": "present",
        "definition_occurrences": 5,
        "local_relationship_endpoint_occurrences": 5,
        "repeated_local_identifiers": {
            "count": 1, "locations": ["/packages/1/SPDXID"], "omitted": 0,
        },
        "unresolved_local_relationship_endpoints": {
            "count": 1, "locations": ["/relationships/0/relatedSpdxElement"], "omitted": 0,
        },
        "limitation": None,
    }


def test_graph_repeats_preserve_exact_identity_and_occurrence_semantics():
    """Catches metadata deduplication, document exclusion and treating ambiguity as absence."""
    raw = _graph_document()
    raw["packages"] += [
        {"SPDXID": "SPDXRef-DOCUMENT"},
        {"SPDXID": "SPDXRef-a", "name": "same"},
    ]
    raw["files"] = [{"SPDXID": "SPDXRef-A"}]
    raw["snippets"] = [{"SPDXID": "SPDXRef-A"}]
    raw["relationships"] = [{"spdxElementId": "SPDXRef-A", "relatedSpdxElement": "SPDXRef-a"}]
    observed = read_sbom_graph_observations(raw)
    assert observed["definition_occurrences"] == 7
    assert observed["repeated_local_identifiers"] == {
        "count": 4,
        "locations": [
            "/packages/1/SPDXID", "/packages/2/SPDXID", "/files/0/SPDXID", "/snippets/0/SPDXID"
        ],
        "omitted": 0,
    }
    assert observed["unresolved_local_relationship_endpoints"]["count"] == 0


@pytest.mark.parametrize("side", ["spdxElementId", "relatedSpdxElement"])
def test_graph_external_namespaces_do_not_resolve_against_local_ids(side):
    """Catches local lookup of external suffixes or requiring external declarations."""
    raw = _graph_document()
    raw["relationships"] = []
    for suffix in ("A", "missing"):
        relation = {"spdxElementId": "SPDXRef-A", "relatedSpdxElement": "SPDXRef-A"}
        relation[side] = f"DocumentRef-x+.1:SPDXRef-{suffix}"
        raw["relationships"].append(relation)
    observed = read_sbom_graph_observations(raw)
    assert observed["status"] == "reported"
    assert observed["local_relationship_endpoint_occurrences"] == 2
    assert observed["unresolved_local_relationship_endpoints"]["count"] == 0


@pytest.mark.parametrize("special", ["NONE", "NOASSERTION"])
@pytest.mark.parametrize("side", ["spdxElementId", "relatedSpdxElement"])
def test_graph_special_endpoint_states_are_directional(special, side):
    """Catches treating a right special as unresolved or admitting it on the left."""
    raw = _graph_document()
    relation = {"spdxElementId": "SPDXRef-A", "relatedSpdxElement": "SPDXRef-A"}
    relation[side] = special
    raw["relationships"] = [relation]
    observed = read_sbom_graph_observations(raw)
    if side == "relatedSpdxElement":
        assert observed["status"] == "reported"
        assert observed["local_relationship_endpoint_occurrences"] == 1
        assert observed["unresolved_local_relationship_endpoints"]["count"] == 0
    else:
        assert observed["status"] == "uninterpretable"
        assert observed["limitation"] == {
            "code": "special_not_allowed_here", "location": "/relationships/0/spdxElementId"
        }
        assert observed["definition_occurrences"] is None


@pytest.mark.parametrize("owner", ["document", "packages", "files", "snippets", "left", "right"])
@pytest.mark.parametrize(
    ("provided", "value", "code"),
    [(False, None, "absent"), (True, None, "null"), (True, "", "empty"),
     (True, " \t", "blank"), (True, 1, "invalid_type"),
     (True, "SPDXRef-A\n", "invalid_syntax"), (True, " SPDXRef-A", "invalid_syntax"),
     (True, "SPDXRef-A+B", "invalid_syntax"), (True, "SPDXRef-A_B", "invalid_syntax"),
     (True, "SPDXRef-", "invalid_syntax")],
)
def test_graph_invalid_identity_states_withhold_all_totals(owner, provided, value, code):
    """Catches coercion, normalization, ignored malformed entries and partial totals."""
    raw = _graph_document()
    if owner == "document":
        item, field, pointer = raw, "SPDXID", "/SPDXID"
    elif owner in {"packages", "files", "snippets"}:
        item, field, pointer = raw[owner][0], "SPDXID", f"/{owner}/0/SPDXID"
    else:
        field = "spdxElementId" if owner == "left" else "relatedSpdxElement"
        item, pointer = raw["relationships"][0], f"/relationships/0/{field}"
    if provided:
        item[field] = value
    else:
        item.pop(field)
    observed = read_sbom_graph_observations(raw)
    assert observed == {
        "status": "uninterpretable",
        "scope": "spdx_2_3_local_definitions_and_relationship_endpoints",
        "relationships_state": None,
        "definition_occurrences": None,
        "local_relationship_endpoint_occurrences": None,
        "repeated_local_identifiers": None,
        "unresolved_local_relationship_endpoints": None,
        "limitation": {"code": code, "location": pointer},
    }


@pytest.mark.parametrize(
    "value",
    ["DocumentRef-:SPDXRef-A", "DocumentRef-x:SPDXRef-", "#SPDXRef-A", "urn:SPDXRef-A"],
)
def test_graph_malformed_external_endpoints_are_not_classified_as_local(value):
    """Catches prefix-only namespace handling or guessing locality for unknown syntax."""
    raw = _graph_document()
    raw["relationships"][0]["relatedSpdxElement"] = value
    observed = read_sbom_graph_observations(raw)
    assert observed["limitation"] == {
        "code": "invalid_syntax", "location": "/relationships/0/relatedSpdxElement"
    }
    assert observed["unresolved_local_relationship_endpoints"] is None


def test_graph_document_identifier_is_reserved_and_error_order_is_deterministic():
    """Catches treating any local ID as the document or preferring a later error."""
    raw = _graph_document()
    raw["SPDXID"] = "SPDXRef-Other"
    raw["files"] = None
    assert read_sbom_graph_observations(raw)["limitation"] == {
        "code": "unexpected_document_identifier", "location": "/SPDXID"
    }
    raw["SPDXID"] = "SPDXRef-DOCUMENT"
    raw["packages"][0]["SPDXID"] = None
    assert read_sbom_graph_observations(raw)["limitation"] == {
        "code": "null", "location": "/packages/0/SPDXID"
    }


@pytest.mark.parametrize("collection", ["files", "snippets", "relationships"])
@pytest.mark.parametrize("value", [None, {}, "", 5, [None]])
def test_graph_invalid_optional_containers_are_visible_limits(collection, value):
    """Catches silently treating malformed optional scope as an empty collection."""
    raw = _graph_document()
    raw[collection] = value
    observed = read_sbom_graph_observations(raw)
    pointer = f"/{collection}/0" if isinstance(value, list) else f"/{collection}"
    assert observed["status"] == "uninterpretable"
    assert observed["limitation"] == {"code": "invalid_type", "location": pointer}
    assert observed["repeated_local_identifiers"] is None
    assert observed["unresolved_local_relationship_endpoints"] is None


def test_graph_late_endpoint_failure_discards_both_prefix_counts():
    """Catches exposing earlier duplicate and unresolved observations as complete totals."""
    raw = _graph_document()
    raw["relationships"].append({"spdxElementId": "SPDXRef-B", "relatedSpdxElement": None})
    observed = read_sbom_graph_observations(raw)
    assert observed["limitation"] == {
        "code": "null",
        "location": "/relationships/3/relatedSpdxElement",
    }
    for field in (
        "definition_occurrences",
        "local_relationship_endpoint_occurrences",
        "repeated_local_identifiers",
        "unresolved_local_relationship_endpoints",
        "relationships_state",
    ):
        assert observed[field] is None


@pytest.mark.parametrize("state", ["absent", "empty", "present"])
@pytest.mark.parametrize("with_nodes", [False, True])
def test_graph_empty_software_inventory_keeps_graph_scope_and_relationship_state(
    tmp_path, state, with_nodes
):
    """Catches equating software count with definitions or omission with an explicit empty list."""
    raw = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": []}
    if with_nodes:
        raw.update(files=[{"SPDXID": "SPDXRef-F"}], snippets=[{"SPDXID": "SPDXRef-S"}])
    if state != "absent":
        raw["relationships"] = [] if state == "empty" else [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-DOCUMENT"}
        ]
    components, loaded = load_sbom(_write(tmp_path / "empty-graph.json", raw))
    assert components == []
    observed = read_sbom_graph_observations(loaded)
    assert observed["definition_occurrences"] == (3 if with_nodes else 1)
    assert observed["relationships_state"] == state
    assert observed["local_relationship_endpoint_occurrences"] == (2 if state == "present" else 0)
    assert observed["unresolved_local_relationship_endpoints"]["count"] == 0


def test_graph_scope_does_not_expand_to_relationship_types_or_other_reference_fields():
    """Catches schema/type validation or recursive traversal of explicitly excluded references."""
    raw = _graph_document()
    raw["documentDescribes"] = ["SPDXRef-missing"]
    raw["packages"][0]["hasFiles"] = ["SPDXRef-missing"]
    raw["snippets"][0]["snippetFromFile"] = "SPDXRef-missing"
    raw["relationships"] = [
        {"spdxElementId": "SPDXRef-A", "relatedSpdxElement": "SPDXRef-F", "relationshipType": value}
        for value in (None, "UNKNOWN", "DEPENDENCY_OF")
    ]
    observed = read_sbom_graph_observations(raw)
    assert observed["status"] == "reported"
    assert observed["local_relationship_endpoint_occurrences"] == 6
    assert observed["unresolved_local_relationship_endpoints"]["count"] == 0


def test_graph_counts_continue_after_pointer_sample_cap_without_retaining_ids():
    """Catches early truncation, distinct-ID counts and raw identity retention."""
    secret = "SPDXRef-Private" + "x" * 1000
    raw = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
           "packages": [{"SPDXID": secret}] * 7,
           "relationships": [
               {"spdxElementId": secret + "missing", "relatedSpdxElement": "NONE"}
           ] * 6}
    observed = read_sbom_graph_observations(raw)
    assert observed["repeated_local_identifiers"] == {
        "count": 6, "locations": [f"/packages/{i}/SPDXID" for i in range(1, 6)], "omitted": 1,
    }
    assert observed["unresolved_local_relationship_endpoints"] == {
        "count": 6,
        "locations": [f"/relationships/{i}/spdxElementId" for i in range(5)],
        "omitted": 1,
    }
    assert observed["local_relationship_endpoint_occurrences"] == 6
    assert secret not in json.dumps(observed)


@pytest.mark.parametrize(
    ("fields", "code", "pointer"),
    [({}, "version_absent", "/spdxVersion"),
     ({"spdxVersion": None}, "version_null", "/spdxVersion"),
     ({"spdxVersion": ""}, "version_empty", "/spdxVersion"),
     ({"spdxVersion": " "}, "version_blank", "/spdxVersion"),
     ({"spdxVersion": 2.3}, "version_invalid_type", "/spdxVersion"),
     ({"spdxVersion": "SPDX-2.2"}, "unsupported_version", "/spdxVersion"),
     ({"spdxVersion": "SPDX-2.3", "components": []}, "selected_component_shape", "/components"),
     *[({"spdxVersion": "SPDX-2.3", marker: None}, "conflicting_format_markers", f"/{marker}")
       for marker in ("bomFormat", "@context", "@graph")]],
)
def test_graph_profile_does_not_guess_format_from_package_projection(
    tmp_path, fields, code, pointer
):
    """Catches guessed format/version support, hybrid inspection and absent/null conflation."""
    raw = {"SPDXID": "SPDXRef-DOCUMENT", "packages": [], **fields}
    _, loaded = load_sbom(_write(tmp_path / "profile.json", raw))
    observed = read_sbom_graph_observations(loaded)
    assert observed["status"] == "not_assessed"
    assert observed["limitation"] == {"code": code, "location": pointer}
    for field in (
        "definition_occurrences",
        "local_relationship_endpoint_occurrences",
        "repeated_local_identifiers",
        "unresolved_local_relationship_endpoints",
        "relationships_state",
    ):
        assert observed[field] is None


@pytest.mark.parametrize("raw", [{"@graph": []}, {"spdxVersion": "SPDX-2.3", "files": []}])
def test_graph_observations_do_not_expand_loader_admission(tmp_path, raw):
    """Catches introducing SPDX3 or files-only parsing as a side effect of graph feedback."""
    with pytest.raises(SBOMParseError, match="Unsupported SBOM format"):
        load_sbom(_write(tmp_path / "unsupported.json", raw))


def test_graph_unresolved_counts_endpoint_occurrences_on_both_sides():
    """Catches counting relationships or distinct missing IDs instead of endpoint occurrences."""
    raw = _graph_document()
    raw["relationships"] = [
        {"spdxElementId": "SPDXRef-B", "relatedSpdxElement": "SPDXRef-C"},
        {"spdxElementId": "SPDXRef-B", "relatedSpdxElement": "SPDXRef-A"},
    ]
    observed = read_sbom_graph_observations(raw)
    assert observed["local_relationship_endpoint_occurrences"] == 4
    assert observed["unresolved_local_relationship_endpoints"] == {
        "count": 3,
        "locations": ["/relationships/0/spdxElementId", "/relationships/0/relatedSpdxElement",
                      "/relationships/1/spdxElementId"],
        "omitted": 0,
    }
