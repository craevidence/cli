"""Tests for the pure PR/MR annotation formatters."""

from __future__ import annotations

import hashlib

from cra_evidence_cli.ci_detect import CIMetadata
from cra_evidence_cli.local import annotations
from cra_evidence_cli.local.models import Finding, LocalCheckResult


def _result(*, findings=None, provenance=None):
    return LocalCheckResult(
        target="x",
        target_type="sbom",
        sbom_path=None,
        components=[],
        findings=findings or [],
        dimensions=[],
        coverage=[],
        provenance=provenance or {},
        attributions=[],
        sources_consulted=[],
        baseline=None,
    )


def _critical_kev():
    return Finding(
        id="CVE-2024-0001",
        package="libfoo",
        version="1.0",
        severity="critical",
        title="Heap overflow",
        known_exploited=True,
    )


def _medium():
    return Finding(
        id="CVE-2024-0002",
        package="libbar",
        version="2.3",
        severity="medium",
        title="Info leak",
        known_exploited=False,
    )


# github_annotations


def test_github_annotations_levels_and_title():
    result = _result(findings=[_critical_kev(), _medium()])
    lines = annotations.github_annotations(result).split("\n")

    assert len(lines) == 2
    # critical -> ::error, medium -> ::warning
    assert lines[0].startswith("::error ")
    assert lines[1].startswith("::warning ")
    # title= property carries the id
    assert "title=CVE-2024-0001" in lines[0]
    assert "title=CVE-2024-0002" in lines[1]
    # message body includes package/version/title
    assert "libfoo 1.0: Heap overflow" in lines[0]
    # never emit file= (no source location available)
    assert "file=" not in lines[0]
    assert "file=" not in lines[1]


def test_github_annotations_escaping():
    finding = Finding(
        id="CVE-x,y:z",
        package="pkg",
        version="1.0",
        severity="high",
        title="100% broken\nsecond line",
    )
    line = annotations.github_annotations(_result(findings=[finding]))

    # high -> error
    assert line.startswith("::error ")
    # message body: % -> %25, \n -> %0A
    assert "100%25 broken%0Asecond line" in line
    # property value: , -> %2C and : -> %3A
    assert "title=CVE-x%2Cy%3Az" in line
    # raw separators must not survive in the message body
    assert "\n" not in line


def test_github_annotations_empty():
    assert annotations.github_annotations(_result(findings=[])) == ""


# github_step_summary


def test_github_step_summary_table():
    result = _result(findings=[_critical_kev(), _medium()])
    summary = annotations.github_step_summary(result)

    assert "| Package | Version | ID | Severity | KEV |" in summary
    # one row per finding
    assert "| libfoo | 1.0 | CVE-2024-0001 | critical | yes |" in summary
    assert "| libbar | 2.3 | CVE-2024-0002 | medium |  |" in summary
    # title mentions the count
    assert "2 findings" in summary
    # must never claim compliance
    assert "CRA compliant" not in summary


def test_github_step_summary_empty():
    summary = annotations.github_step_summary(_result(findings=[]))
    assert "no blocking findings" in summary.lower()
    assert "CRA compliant" not in summary


# gitlab_codequality


def test_gitlab_codequality_severity_and_location():
    result = _result(
        findings=[_critical_kev(), _medium()],
        provenance={"sbom_path": "build/sbom.json"},
    )
    entries = annotations.gitlab_codequality(result)

    assert len(entries) == 2
    assert entries[0]["severity"] == "blocker"  # critical
    assert entries[1]["severity"] == "minor"  # medium
    # description format
    assert entries[0]["description"] == "CVE-2024-0001: libfoo 1.0 - Heap overflow"
    # location.path from provenance
    assert entries[0]["location"]["path"] == "build/sbom.json"
    assert entries[0]["location"]["lines"]["begin"] == 1


def test_gitlab_codequality_fingerprint_deterministic():
    finding = _critical_kev()
    a = annotations.gitlab_codequality(_result(findings=[finding]))
    b = annotations.gitlab_codequality(_result(findings=[finding]))

    expected = hashlib.sha256(b"CVE-2024-0001|libfoo|1.0").hexdigest()
    assert a[0]["fingerprint"] == expected
    assert a[0]["fingerprint"] == b[0]["fingerprint"]


def test_gitlab_codequality_severity_map_low_unknown():
    low = Finding(id="L", package="p", version="1", severity="low")
    unknown = Finding(id="U", package="p", version="1", severity="unknown")
    entries = annotations.gitlab_codequality(_result(findings=[low, unknown]))
    assert entries[0]["severity"] == "info"
    assert entries[1]["severity"] == "info"


def test_gitlab_codequality_default_path():
    entries = annotations.gitlab_codequality(_result(findings=[_critical_kev()]))
    assert entries[0]["location"]["path"] == "sbom.json"


def test_gitlab_codequality_empty():
    assert annotations.gitlab_codequality(_result(findings=[])) == []


# resolve_mode


def test_resolve_mode_passthrough():
    assert annotations.resolve_mode("github") == "github"
    assert annotations.resolve_mode("gitlab") == "gitlab"
    assert annotations.resolve_mode("none") == "none"


def test_resolve_mode_auto_detects_provider():
    def detect():
        return CIMetadata(ci_provider="gitlab")
    assert annotations.resolve_mode("auto", detect=detect) == "gitlab"


def test_resolve_mode_auto_no_provider():
    def detect():
        return CIMetadata(ci_provider=None)
    assert annotations.resolve_mode("auto", detect=detect) == "none"
