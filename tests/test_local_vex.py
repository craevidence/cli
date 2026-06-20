"""Tests for the pure, network-free VEX suppression engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cra_evidence_cli.local.models import Finding
from cra_evidence_cli.local.vex import (
    Suppression,
    VexParseError,
    apply_vex,
    load_vex,
)


# Helpers
def _write(tmp_path: Path, payload: dict) -> Path:
    target = tmp_path / "vex.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def _openvex(statements: list[dict]) -> dict:
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/vex/test",
        "author": "test",
        "statements": statements,
    }


def _finding(
    vid: str = "CVE-2024-0001",
    package: str = "openssl",
    purl: str | None = "pkg:deb/debian/openssl@3.0.0-1",
    aliases: set[str] | None = None,
    known_exploited: bool | None = None,
) -> Finding:
    return Finding(
        id=vid,
        package=package,
        version="3.0.0",
        severity="high",
        aliases=aliases or set(),
        purl=purl,
        known_exploited=known_exploited,
    )


# OpenVEX: not_affected
def test_not_affected_with_justification_suppresses(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [
                {
                    "vulnerability": {"name": "CVE-2024-0001"},
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_in_execute_path",
                }
            ]
        ),
    )
    doc = load_vex(path)
    kept, suppressions = apply_vex([_finding()], doc)

    assert kept == []
    assert len(suppressions) == 1
    supp = suppressions[0]
    assert isinstance(supp, Suppression)
    assert supp.vuln_id == "CVE-2024-0001"
    assert supp.status == "not_affected"
    assert supp.justification == "vulnerable_code_not_in_execute_path"
    assert supp.product == "*"
    assert supp.kev_conflict is False
    assert supp.to_dict()["status"] == "not_affected"


def test_not_affected_with_impact_statement_suppresses(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [
                {
                    "vulnerability": {"name": "CVE-2024-0001"},
                    "status": "not_affected",
                    "impact_statement": "Not reachable in our configuration.",
                }
            ]
        ),
    )
    doc = load_vex(path)
    kept, suppressions = apply_vex([_finding()], doc)

    assert kept == []
    assert len(suppressions) == 1
    assert suppressions[0].justification == "Not reachable in our configuration."


def test_not_affected_without_justification_or_impact_keeps(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [
                {
                    "vulnerability": {"name": "CVE-2024-0001"},
                    "status": "not_affected",
                }
            ]
        ),
    )
    doc = load_vex(path)
    finding = _finding()
    kept, suppressions = apply_vex([finding], doc)

    assert kept == [finding]
    assert suppressions == []


# OpenVEX: fixed / affected / under_investigation
def test_fixed_suppresses(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [{"vulnerability": {"name": "CVE-2024-0001"}, "status": "fixed"}]
        ),
    )
    doc = load_vex(path)
    kept, suppressions = apply_vex([_finding()], doc)

    assert kept == []
    assert len(suppressions) == 1
    assert suppressions[0].status == "fixed"
    # fixed needs no justification
    assert suppressions[0].justification is None


def test_affected_does_not_suppress(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [{"vulnerability": {"name": "CVE-2024-0001"}, "status": "affected"}]
        ),
    )
    doc = load_vex(path)
    finding = _finding()
    kept, suppressions = apply_vex([finding], doc)

    assert kept == [finding]
    assert suppressions == []


def test_under_investigation_does_not_suppress(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [
                {
                    "vulnerability": {"name": "CVE-2024-0001"},
                    "status": "under_investigation",
                }
            ]
        ),
    )
    doc = load_vex(path)
    finding = _finding()
    kept, suppressions = apply_vex([finding], doc)

    assert kept == [finding]
    assert suppressions == []


# Product scoping
def test_product_scoped_only_suppresses_matching_purl(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [
                {
                    "vulnerability": {"name": "CVE-2024-0001"},
                    "status": "fixed",
                    "products": ["pkg:deb/debian/openssl@3.0.0-1"],
                }
            ]
        ),
    )
    doc = load_vex(path)
    matching = _finding(purl="pkg:deb/debian/openssl@3.0.0-1")
    other = _finding(purl="pkg:deb/debian/zlib@1.2.0", package="zlib")
    kept, suppressions = apply_vex([matching, other], doc)

    assert kept == [other]
    assert len(suppressions) == 1
    assert suppressions[0].product == "pkg:deb/debian/openssl@3.0.0-1"


def test_product_prefix_match_on_purl(tmp_path):
    # Statement carries a purl without version qualifiers; finding purl extends it.
    path = _write(
        tmp_path,
        _openvex(
            [
                {
                    "vulnerability": {"name": "CVE-2024-0001"},
                    "status": "fixed",
                    "products": ["pkg:deb/debian/openssl"],
                }
            ]
        ),
    )
    doc = load_vex(path)
    finding = _finding(purl="pkg:deb/debian/openssl@3.0.0-1")
    kept, suppressions = apply_vex([finding], doc)

    assert kept == []
    assert suppressions[0].product == "pkg:deb/debian/openssl"


def test_product_match_on_package_name(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [
                {
                    "vulnerability": {"name": "CVE-2024-0001"},
                    "status": "fixed",
                    "products": ["openssl"],
                }
            ]
        ),
    )
    doc = load_vex(path)
    finding = _finding(package="openssl", purl="pkg:deb/debian/openssl@3.0.0-1")
    kept, suppressions = apply_vex([finding], doc)

    assert kept == []
    assert suppressions[0].product == "openssl"


def test_no_product_scope_suppresses_by_id_alone(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [{"vulnerability": {"name": "CVE-2024-0001"}, "status": "fixed"}]
        ),
    )
    doc = load_vex(path)
    finding = _finding(purl="pkg:any/thing@9")
    kept, suppressions = apply_vex([finding], doc)

    assert kept == []
    assert suppressions[0].product == "*"


# Alias matching
def test_alias_matching_ghsa_finding_cve_vex(tmp_path):
    # Finding.id is a GHSA; the CVE lives in aliases. VEX references the CVE.
    path = _write(
        tmp_path,
        _openvex(
            [
                {
                    "vulnerability": {"name": "cve-2024-9999"},
                    "status": "not_affected",
                    "justification": "component_not_present",
                }
            ]
        ),
    )
    doc = load_vex(path)
    finding = _finding(
        vid="GHSA-aaaa-bbbb-cccc",
        aliases={"CVE-2024-9999"},
    )
    kept, suppressions = apply_vex([finding], doc)

    assert kept == []
    assert len(suppressions) == 1
    # vuln_id on the suppression reflects the finding's own id
    assert suppressions[0].vuln_id == "GHSA-aaaa-bbbb-cccc"


# KEV conflict
def test_kev_conflict_true_when_known_exploited(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [{"vulnerability": {"name": "CVE-2024-0001"}, "status": "fixed"}]
        ),
    )
    doc = load_vex(path)
    finding = _finding(known_exploited=True)
    kept, suppressions = apply_vex([finding], doc)

    assert kept == []
    assert suppressions[0].kev_conflict is True


def test_kev_conflict_false_when_not_exploited(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [{"vulnerability": {"name": "CVE-2024-0001"}, "status": "fixed"}]
        ),
    )
    doc = load_vex(path)
    finding = _finding(known_exploited=None)
    kept, suppressions = apply_vex([finding], doc)

    assert suppressions[0].kev_conflict is False


# OpenVEX detection via statements list (no @context openvex marker)
def test_openvex_detected_without_context_marker(tmp_path):
    path = _write(
        tmp_path,
        {
            "@context": "https://example.com/not-a-known-marker",
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2024-0001"},
                    "status": "fixed",
                }
            ],
        },
    )
    doc = load_vex(path)
    assert doc.format == "openvex"
    kept, suppressions = apply_vex([_finding()], doc)
    assert kept == []
    assert len(suppressions) == 1


# CSAF VEX
def test_csaf_known_not_affected_with_flag_suppresses(tmp_path):
    path = _write(
        tmp_path,
        {
            "document": {
                "csaf_version": "2.0",
                "category": "csaf_vex",
                "title": "Test CSAF VEX",
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-0001",
                    "product_status": {
                        "known_not_affected": ["openssl"],
                    },
                    "flags": [
                        {
                            "label": "vulnerable_code_not_present",
                            "product_ids": ["openssl"],
                        }
                    ],
                }
            ],
        },
    )
    doc = load_vex(path)
    assert doc.format == "csaf"
    finding = _finding(package="openssl")
    kept, suppressions = apply_vex([finding], doc)

    assert kept == []
    assert len(suppressions) == 1
    assert suppressions[0].status == "not_affected"
    assert suppressions[0].justification == "vulnerable_code_not_present"


def test_csaf_known_not_affected_without_flag_keeps(tmp_path):
    path = _write(
        tmp_path,
        {
            "document": {"csaf_version": "2.0", "category": "csaf_vex"},
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-0001",
                    "product_status": {"known_not_affected": ["openssl"]},
                }
            ],
        },
    )
    doc = load_vex(path)
    finding = _finding(package="openssl")
    kept, suppressions = apply_vex([finding], doc)

    assert kept == [finding]
    assert suppressions == []


def test_csaf_fixed_suppresses(tmp_path):
    path = _write(
        tmp_path,
        {
            "document": {"csaf_version": "2.0", "category": "csaf_vex"},
            "vulnerabilities": [
                {
                    "ids": [{"system_name": "cve", "text": "CVE-2024-0001"}],
                    "product_status": {"fixed": ["openssl"]},
                }
            ],
        },
    )
    doc = load_vex(path)
    finding = _finding(package="openssl")
    kept, suppressions = apply_vex([finding], doc)

    assert kept == []
    assert suppressions[0].status == "fixed"


def test_csaf_known_affected_does_not_suppress(tmp_path):
    path = _write(
        tmp_path,
        {
            "document": {"csaf_version": "2.0", "category": "csaf_vex"},
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-0001",
                    "product_status": {"known_affected": ["openssl"]},
                }
            ],
        },
    )
    doc = load_vex(path)
    finding = _finding(package="openssl")
    kept, suppressions = apply_vex([finding], doc)

    assert kept == [finding]
    assert suppressions == []


# Errors
def test_malformed_json_raises(tmp_path):
    target = tmp_path / "vex.json"
    target.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(VexParseError):
        load_vex(target)


def test_unsupported_format_raises(tmp_path):
    path = _write(tmp_path, {"foo": "bar", "something": [1, 2, 3]})
    with pytest.raises(VexParseError):
        load_vex(path)


def test_non_object_json_raises(tmp_path):
    target = tmp_path / "vex.json"
    target.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(VexParseError):
        load_vex(target)


# Multiple findings, mixed outcomes
def test_mixed_findings_partial_suppression(tmp_path):
    path = _write(
        tmp_path,
        _openvex(
            [
                {"vulnerability": {"name": "CVE-2024-0001"}, "status": "fixed"},
                {
                    "vulnerability": {"name": "CVE-2024-0002"},
                    "status": "not_affected",
                },  # no justification -> keep
                {
                    "vulnerability": {"name": "CVE-2024-0003"},
                    "status": "affected",
                },  # keep
            ]
        ),
    )
    doc = load_vex(path)
    f1 = _finding(vid="CVE-2024-0001")
    f2 = _finding(vid="CVE-2024-0002")
    f3 = _finding(vid="CVE-2024-0003")
    f4 = _finding(vid="CVE-2024-0004")  # not referenced -> keep
    kept, suppressions = apply_vex([f1, f2, f3, f4], doc)

    assert f1 not in kept
    assert kept == [f2, f3, f4]
    assert len(suppressions) == 1
    assert suppressions[0].vuln_id == "CVE-2024-0001"
