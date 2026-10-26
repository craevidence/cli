"""Local check: candidates whose component version is not confirmed.

The engine returns match-all candidates for a component without a version and
candidates whose version evidence conflicts. These tests drive engine-shaped JSON
through the parser, the ``check`` command and every report format.
"""

import io
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner
from rich.console import Console

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import check as check_module
from cra_evidence_cli.engine import EngineIdentity, EngineInspection
from cra_evidence_cli.exceptions import ScanEngineUnavailable
from cra_evidence_cli.local import annotations
from cra_evidence_cli.local import scanner as scanner_module
from cra_evidence_cli.local.models import (
    CoverageSource,
    Finding,
    LocalCheckResult,
    UnassessedPackage,
)
from cra_evidence_cli.local.report import print_text_report, render
from cra_evidence_cli.local.scanner import parse_grype_output
from cra_evidence_cli.local.version_applicability import InvalidPurlEpoch

TODAY = datetime.now(UTC).date().isoformat()
WILDCARD_CPE = "cpe:2.3:a:widget:widget:*:*:*:*:*:*:*:*"
VERSIONLESS_PURL = "pkg:pypi/widget"


def _direct(version, name="widget"):
    return {
        "type": "exact-direct-match",
        "matcher": "python-matcher",
        "searchedBy": {
            "language": "python",
            "namespace": "github:language:python",
            "package": {"name": name, "version": version},
        },
        "found": {"versionConstraint": "<2.0.0 (python)", "vulnerabilityID": "GHSA-x"},
    }


def _cpe(*cpes):
    return {
        "type": "cpe-match",
        "matcher": "stock-matcher",
        "searchedBy": {"namespace": "nvd:cpe", "cpes": list(cpes)},
        "found": {"versionConstraint": "< 2.0.0 (unknown)", "vulnerabilityID": "CVE-x"},
    }


def _match(
    vuln_id,
    details,
    *,
    name="widget",
    version="",
    purl=VERSIONLESS_PURL,
    severity="High",
    cpes=(WILDCARD_CPE,),
    related=(),
    exploited=False,
):
    return {
        "vulnerability": {
            "id": vuln_id,
            "severity": severity,
            "description": f"{vuln_id} description",
            "knownExploited": [{"cve": "x"}] if exploited else [],
            "fix": {"state": "fixed", "versions": ["2.0.0"]},
        },
        "relatedVulnerabilities": [{"id": item} for item in related],
        "artifact": {"name": name, "version": version, "purl": purl, "cpes": list(cpes)},
        "matchDetails": details,
    }


def _confirmed_match(vuln_id="CVE-2026-1111", *, exploited=False, severity="High"):
    return _match(
        vuln_id,
        [_direct("3.1.3", "jinja2")],
        name="jinja2",
        version="3.1.3",
        purl="pkg:pypi/jinja2@3.1.3",
        cpes=(),
        exploited=exploited,
        severity=severity,
    )


def _versionless_matches():
    return [
        _match("GHSA-aaaa-aaaa-aaaa", [_direct("")], related=("CVE-2026-0001",), exploited=True),
        _match("CVE-2026-0002", [_cpe(WILDCARD_CPE)], severity="Critical"),
    ]


def _sbom(path):
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "widget", "purl": VERSIONLESS_PURL}],
            }
        )
    )
    return path


def _engine_scanner(monkeypatch, stdout, returncode=0):
    monkeypatch.setattr(
        scanner_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=returncode, stdout=stdout, stderr=""),
    )
    scanner = scanner_module.GrypeLocalScanner()
    scanner._inspection = EngineInspection(
        EngineIdentity(path="/opt/bin/grype", version="test-engine", syft_version="1.50.0"),
        "",
    )
    return scanner


def _run(monkeypatch, tmp_path, matches, args=(), *, kev=(), assessment=None, osv=None):
    """Run ``check`` on an SBOM with a fake engine that returns ``matches``."""
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    document = {"matches": matches}
    returncode = 0
    if assessment is not None:
        document["assessment"] = assessment
        returncode = 1
    scanner = _engine_scanner(monkeypatch, json.dumps(document), returncode)
    monkeypatch.setattr(check_module, "GrypeLocalScanner", lambda **_kwargs: scanner)
    monkeypatch.setattr(check_module, "get_embedded_syft_version", lambda: None)
    epss_queries = []

    def fake_epss(cves):
        epss_queries.append(set(cves))
        return {}, CoverageSource("first-epss", "present", as_of=TODAY)

    monkeypatch.setattr(
        check_module,
        "fetch_kev_catalog",
        lambda: (set(kev), CoverageSource("cisa-kev", "present", as_of=TODAY)),
    )
    monkeypatch.setattr(check_module, "fetch_epss_scores", fake_epss)
    if osv is not None:
        monkeypatch.setattr(check_module, "OSVClient", osv)
    sbom = _sbom(tmp_path / "sbom.json")
    result = CliRunner().invoke(cli, ["check", "--sbom", str(sbom), *args])
    result.epss_queries = epss_queries
    return result


def _snapshot_dimension(report):
    dimensions = report["cra_readiness_signal"]["dimensions"]
    return next(d for d in dimensions if "snapshot" in d["title"])


def _json_run(monkeypatch, tmp_path, matches, args=(), **kwargs):
    result = _run(monkeypatch, tmp_path, matches, ["--output", "json", *args], **kwargs)
    return result, json.loads(result.stdout)


# --- parser keeps the evidence the classifier needs -------------------------


def test_parser_marks_versionless_component_matches_indicative():
    """Fails if match-all candidates for an empty version stay confirmed findings."""
    findings = parse_grype_output(json.dumps({"matches": _versionless_matches()}))

    assert [f.indicative_reason for f in findings] == ["unversioned", "unversioned"]
    assert all(f.is_indicative for f in findings)


def test_parser_keeps_confirmed_finding_shape_with_nullable_epss_provenance():
    """Fails if a confirmed finding loses fields or omits unknown EPSS provenance."""
    (finding,) = parse_grype_output(json.dumps({"matches": [_confirmed_match(exploited=True)]}))

    assert not finding.is_indicative
    assert finding.known_exploited is True
    assert set(finding.to_dict()) == {
        "id",
        "package",
        "version",
        "severity",
        "aliases",
        "cve_aliases",
        "fixed_versions",
        "purl",
        "title",
        "references",
        "epss_probability",
        "epss_cve",
        "epss_date",
        "epss_source",
        "known_exploited",
        "source",
        "ignored_by_policy",
        "vex_conflict",
    }


def test_parser_passes_searched_cpe_and_declared_cpe_to_the_classifier():
    """Fails if the parser drops matchDetails or artifact.cpes, hiding a version conflict."""
    matches = [
        _match(
            "CVE-2026-0003",
            [_cpe("cpe:2.3:o:hp:ilo:1.10:*:*:*:*:*:*:*")],
            name="ilo",
            version="1.20",
            purl=None,
            cpes=("cpe:2.3:o:hp:ilo:1.30:*:*:*:*:*:*:*",),
        )
    ]
    (finding,) = parse_grype_output(json.dumps({"matches": matches}))

    assert finding.indicative_reason == "version_conflict"
    evidence = finding.applicability_evidence
    assert evidence["searched_cpes"] == ["cpe:2.3:o:hp:ilo:1.10:*:*:*:*:*:*:*"]
    assert evidence["declared_cpes"] == ["cpe:2.3:o:hp:ilo:1.30:*:*:*:*:*:*:*"]
    assert evidence["concrete_versions"] == ["1.10", "1.20", "1.30"]


def test_parser_classifies_duplicate_occurrence_from_merged_evidence():
    """Fails if two matches of one occurrence are classified apart, splitting its status."""
    version = {"version": "2.0.0", "purl": "pkg:pypi/widget@2.0.0", "cpes": ()}
    matches = [
        _match("CVE-2026-0004", [_cpe("cpe:2.3:a:widget:widget:*:*:*:*:*:*:*:*")], **version),
        _match("CVE-2026-0004", [_direct("2.0.0")], **version),
    ]
    findings = parse_grype_output(json.dumps({"matches": matches}))

    assert [f.is_indicative for f in findings] == [False, False]


def test_parser_keeps_duplicate_indicative_matches_as_separate_candidates():
    """Fails if duplicate package copies are dropped or merged for indicative candidates."""
    match = _match("CVE-2026-0005", [_direct("")])
    findings = parse_grype_output(json.dumps({"matches": [match, match]}))

    assert [f.indicative_reason for f in findings] == ["unversioned", "unversioned"]


# --- malformed match evidence -----------------------------------------------


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:rpm/widget@1.0?epoch=bad",
        "pkg:rpm/widget@1.0?epoch=1&epoch=2",
        "pkg:rpm/widget@2:1.0?epoch=1",
    ],
    ids=["invalid", "duplicate", "contradictory"],
)
@pytest.mark.parametrize(
    ("args", "exit_code"), [((), 0), (("--fail-on", "high"), 11), (("--strict",), 15)]
)
def test_invalid_rpm_epoch_retains_other_findings_and_reports_one_gap(
    monkeypatch, tmp_path, purl, args, exit_code
):
    """Catches whole-scan fallback, accepting a bad epoch, or one gap per vulnerability."""

    class NoFallback:
        def __init__(self):
            pytest.fail("a package epoch must not discard the Grype scan")

    matches = [
        _confirmed_match(),
        *[
            _match(vuln_id, [_direct("1.0")], version="1.0", purl=purl, cpes=())
            for vuln_id in ("CVE-2026-0007", "CVE-2026-0008")
        ],
    ]
    result, report = _json_run(monkeypatch, tmp_path, matches, args, osv=NoFallback)

    assert result.exit_code == exit_code, result.output
    assert report["provenance"]["engine"] == "grype-local"
    assert (
        "Warning: the vulnerability assessment is incomplete; valid findings are retained."
        in result.stderr
    )
    assert [finding["id"] for finding in report["findings"]] == ["CVE-2026-1111"]
    gaps = report["unassessed_packages"]
    assert gaps["total_packages"] == 1
    assert gaps["not_checked"]["by_reason"] == {"invalid-rpm-purl-epoch": 1}
    assert len(gaps["entries"]) == 1
    gap = gaps["entries"][0]
    assert (gap["name"], gap["version"], gap["purl"]) == ("widget", "1.0", purl)
    assert gap["matcher"] == "cli-version-applicability"
    assert "epoch" in gap["remedy"]
    assert "Repair" in gap["remedy"]
    assert (
        next(source for source in report["coverage"] if source["source"] == "grype-db")["status"]
        == "partial"
    )


def test_invalid_rpm_epoch_preserves_native_unassessed_packages(monkeypatch, tmp_path):
    """Catches local gap handling overwriting the native incomplete assessment."""
    match = _match(
        "CVE-2026-0007", [_direct("1.0")], version="1.0", purl="pkg:rpm/widget@1.0?epoch=bad"
    )
    scanner = _engine_scanner(
        monkeypatch,
        json.dumps(
            {
                "matches": [match],
                "assessment": _incomplete(_unassessable("broken", "2.0", BROKEN_PURL)),
            }
        ),
        1,
    )
    findings, coverage = scanner.scan_sbom(tmp_path / "sbom.json")

    assert findings == []
    assert coverage.status == "partial"
    assert {(p.name, p.reason) for p in coverage.unassessed_packages} == {
        ("broken", "version-comparison-error"),
        ("widget", "invalid-rpm-purl-epoch"),
    }


def test_invalid_rpm_epoch_does_not_mask_malformed_match_details(monkeypatch, tmp_path):
    """Catches catching all malformed evidence as a recoverable package epoch problem."""
    match = _match("CVE-2026-0007", [], version="1.0", purl="pkg:rpm/widget@1.0?epoch=bad")
    scanner = _engine_scanner(monkeypatch, json.dumps({"matches": [match]}))
    with pytest.raises(ScanEngineUnavailable, match="malformed match data"):
        scanner.scan_sbom(tmp_path / "sbom.json")


def test_findings_only_parser_does_not_silently_drop_invalid_rpm_epoch():
    """Catches dropping the gap when the helper cannot return assessment context."""
    match = _match(
        "CVE-2026-0007", [_direct("1.0")], version="1.0", purl="pkg:rpm/widget@1.0?epoch=bad"
    )
    with pytest.raises(InvalidPurlEpoch):
        parse_grype_output(json.dumps({"matches": [_confirmed_match(), match]}))


@pytest.mark.parametrize(
    "details",
    [
        [{"type": "future-unknown-match", "searchedBy": {"package": {"version": "1.0"}}}],
        [{"searchedBy": {"package": {"version": "1.0"}}}],
        [],
        None,
        [{"type": "cpe-match", "searchedBy": {"cpes": ["not-a-cpe"]}}],
        [{"type": "cpe-match", "searchedBy": {}}],
        ["not-an-object"],
    ],
    ids=[
        "unknown-type",
        "missing-type",
        "empty-details",
        "absent-details",
        "cpe-match-without-valid-cpe",
        "cpe-match-without-cpes",
        "detail-not-object",
    ],
)
def test_malformed_match_evidence_is_malformed_engine_output(monkeypatch, tmp_path, details):
    """Fails if a malformed match is confirmed, dropped or reported with a different error."""
    match = _match("CVE-2026-0006", details, version="1.0", purl="pkg:pypi/widget@1.0")
    if details is None:
        del match["matchDetails"]
    scanner = _engine_scanner(monkeypatch, json.dumps({"matches": [match]}))

    with pytest.raises(ScanEngineUnavailable) as exc_info:
        scanner.scan_sbom(tmp_path / "sbom.json")

    assert str(exc_info.value) == "scanner returned malformed match data"
    assert isinstance(exc_info.value.__cause__, ValueError)


@pytest.mark.parametrize(("strict", "expected_exit"), [(False, 0), (True, 15)])
def test_malformed_match_evidence_takes_the_existing_fallback_path(
    monkeypatch, tmp_path, strict, expected_exit
):
    """Fails if malformed evidence skips the OSV fallback notice or the strict failure."""

    class NoFindingsOSV:
        def query_components(self, components):
            return [], CoverageSource("osv.dev", "present", as_of=TODAY)

    matches = [_match("CVE-2026-0007", [{"type": "future-unknown-match"}])]
    args = ["--output", "json", *(["--strict"] if strict else [])]
    result = _run(monkeypatch, tmp_path, matches, args, osv=NoFindingsOSV)
    report = json.loads(result.stdout)

    assert result.exit_code == expected_exit, result.output
    assert "Warning: local matcher failed (scanner returned malformed match data)" in result.stderr
    assert report["provenance"]["engine"] == "osv-online"
    assert report["provenance"]["grype-db"]["status"] == "unavailable"
    assert report["findings"] == []
    assert report["indicative_findings"] == []


# --- gates, totals and enrichment -------------------------------------------


@pytest.mark.parametrize("fail_on", ["critical", "high", "medium", "known-exploited"])
def test_indicative_candidates_never_trip_a_fail_on_gate(monkeypatch, tmp_path, fail_on):
    """Fails if an unversioned critical or KEV-listed candidate blocks the build."""
    result, report = _json_run(
        monkeypatch,
        tmp_path,
        _versionless_matches(),
        ["--fail-on", fail_on],
        kev={"CVE-2026-0001"},
    )

    assert result.exit_code == 0, result.output
    assert report["summary"]["total"] == 0
    assert report["summary"]["critical"] == 0
    assert report["summary"]["high"] == 0
    assert report["summary"]["known_exploited"] == 0
    assert [f["id"] for f in report["indicative_findings"]] == [
        "GHSA-aaaa-aaaa-aaaa",
        "CVE-2026-0002",
    ]
    assert report["indicative_summary"] == {"total": 2, "unversioned": 2, "version_conflict": 0}


def test_confirmed_high_finding_still_fails_with_the_documented_exit(monkeypatch, tmp_path):
    """Fails if setting indicative candidates aside also disables the confirmed gate."""
    result, report = _json_run(
        monkeypatch,
        tmp_path,
        [*_versionless_matches(), _confirmed_match()],
        ["--fail-on", "high"],
    )

    assert result.exit_code == 11, result.output
    assert report["summary"]["total"] == 1
    assert report["summary"]["high"] == 1
    assert [f["id"] for f in report["findings"]] == ["CVE-2026-1111"]
    assert len(report["indicative_findings"]) == 2


def test_known_exploited_gate_counts_only_the_confirmed_hit(monkeypatch, tmp_path):
    """Fails if a KEV flag on an indicative candidate adds to the KEV count or gate."""
    result, report = _json_run(
        monkeypatch,
        tmp_path,
        [*_versionless_matches(), _confirmed_match(exploited=True)],
        ["--fail-on", "known-exploited"],
        kev={"CVE-2026-0001", "CVE-2026-1111"},
    )

    assert result.exit_code == 17, result.output
    assert report["summary"]["known_exploited"] == 1


def test_indicative_candidates_are_not_enriched_or_flagged(monkeypatch, tmp_path):
    """Fails if EPSS is queried for, or exploitation is reported on, an indicative candidate."""
    result, report = _json_run(monkeypatch, tmp_path, _versionless_matches(), kev={"CVE-2026-0001"})

    assert result.epss_queries == [set()]
    for entry in report["indicative_findings"]:
        assert "known_exploited" not in entry
        assert "epss_probability" not in entry


def test_version_conflict_candidate_is_indicative_and_not_gated(monkeypatch, tmp_path):
    """Fails if a component whose CPE says 1.10 while it ships 1.20 is confirmed."""
    matches = [
        _match(
            "CVE-2026-0008",
            [_cpe("cpe:2.3:o:hp:ilo:1.10:*:*:*:*:*:*:*")],
            name="ilo",
            version="1.20",
            purl=None,
            cpes=(),
            severity="Critical",
        )
    ]
    result, report = _json_run(monkeypatch, tmp_path, matches, ["--fail-on", "critical"])

    assert result.exit_code == 0, result.output
    assert report["findings"] == []
    (entry,) = report["indicative_findings"]
    assert entry["quality_reason"] == "version_conflict"
    assert entry["applicability_evidence"]["concrete_versions"] == ["1.10", "1.20"]
    assert report["indicative_summary"]["version_conflict"] == 1


@pytest.mark.parametrize(("strict", "expected_exit"), [(False, 0), (True, 15)])
def test_partial_assessment_and_strict_behaviour_are_unchanged(
    monkeypatch, tmp_path, strict, expected_exit
):
    """Fails if indicative candidates change partial coverage or the strict failure."""
    assessment = {
        "status": "incomplete",
        "unassessablePackages": [
            {
                "package": {"name": "broken", "version": "2.0", "purl": "pkg:pypi/broken@2.0"},
                "matcher": "python",
                "reasonCode": "version-comparison-error",
            }
        ],
    }
    args = ["--output", "json", *(["--strict"] if strict else [])]
    result = _run(monkeypatch, tmp_path, _versionless_matches(), args, assessment=assessment)
    report = json.loads(result.stdout)

    assert result.exit_code == expected_exit, result.output
    assert report["coverage"][0]["status"] == "partial"
    assert len(report["indicative_findings"]) == 2
    assert ("strict_failure" in report["provenance"]) is strict


_STRICT_INCOMPLETE_LINE = (
    "Exit 15: strict mode failed because the vulnerability assessment is incomplete, "
    "not because a blocking threshold was exceeded."
)
_THRESHOLD_LINE = "configured blocking threshold exceeded in this local snapshot."


@pytest.mark.parametrize("output", ["text", "markdown"])
def test_strict_closing_line_names_the_incomplete_assessment(monkeypatch, tmp_path, output):
    """Fails if a strict failure caused by an incomplete scan blames a blocking threshold."""
    assessment = _incomplete(_unassessable("broken", "2.0", BROKEN_PURL))

    result = _run(
        monkeypatch, tmp_path, [], ["--output", output, "--strict"], assessment=assessment
    )

    assert result.exit_code == 15, result.output
    assert result.stdout.rstrip().endswith(_STRICT_INCOMPLETE_LINE)
    assert _THRESHOLD_LINE not in result.stdout


def test_strict_incomplete_json_exit_note_is_unchanged(monkeypatch, tmp_path):
    """Fails if the fix to the human-readable line also rewrites the JSON exit_note."""
    assessment = _incomplete(_unassessable("broken", "2.0", BROKEN_PURL))

    _, report = _json_run(monkeypatch, tmp_path, [], ["--strict"], assessment=assessment)

    assert report["exit_note"] == f"Exit 15: {_THRESHOLD_LINE}"


def test_terminal_closing_line_names_the_incomplete_assessment():
    """Fails if the interactive terminal report keeps the threshold wording."""
    result = _result_with()
    result.provenance = {"strict_failure": "incomplete vulnerability assessment"}
    buffer = io.StringIO()

    print_text_report(Console(file=buffer, width=400, color_system=None), result, exit_code=15)

    assert _STRICT_INCOMPLETE_LINE in buffer.getvalue()


def test_closing_line_for_other_exits_is_unchanged():
    """Fails if the new line is used for an exit that the incomplete scan did not cause."""
    result = _result_with()
    result.provenance = {"strict_failure": "incomplete vulnerability assessment"}

    assert render(result, "text", exit_code=10).endswith(f"Exit 10: {_THRESHOLD_LINE}")
    assert render(result, "text", exit_code=0).endswith(
        "Exit 0 means no configured blocking findings in this local snapshot."
    )


# --- report formats ---------------------------------------------------------


def test_json_report_shape_for_indicative_candidates(monkeypatch, tmp_path):
    """Fails if the JSON mixes the lists, drops the policy or omits the reason and evidence."""
    matches = _versionless_matches()
    matches[0]["vulnerability"]["epss"] = [
        {"epss": 0.9, "cve": "CVE-2026-0001", "date": "2026-10-14"},
    ]
    run, report = _json_run(monkeypatch, tmp_path, [*matches, _confirmed_match()])

    assert report["provenance"]["version_applicability_policy"] == "concrete-v1"
    assert [f["id"] for f in report["findings"]] == ["CVE-2026-1111"]
    assert report["summary"]["total"] == 1
    assert run.epss_queries == [{"CVE-2026-1111"}]
    first = report["indicative_findings"][0]
    assert set(first) == {
        "id",
        "package",
        "version",
        "severity",
        "aliases",
        "cve_aliases",
        "fixed_versions",
        "purl",
        "title",
        "references",
        "source",
        "quality_reason",
        "applicability_evidence",
    }
    assert first["quality_reason"] == "unversioned"
    assert first["cve_aliases"] == ["CVE-2026-0001"]
    assert first["applicability_evidence"]["declared_cpes"] == [WILDCARD_CPE]
    dimension = _snapshot_dimension(report)
    assert "2 indicative candidate(s)" in dimension["message"]


def test_json_report_without_candidates_has_empty_indicative_section(monkeypatch, tmp_path):
    """Fails if the section is missing when nothing is indicative, breaking consumers."""
    _, report = _json_run(monkeypatch, tmp_path, [_confirmed_match()])

    assert report["indicative_findings"] == []
    assert report["indicative_summary"] == {"total": 0, "unversioned": 0, "version_conflict": 0}
    dimension = _snapshot_dimension(report)
    assert "indicative" not in dimension["message"]


def test_sarif_keeps_indicative_candidates_out_of_results(monkeypatch, tmp_path):
    """Fails if an indicative candidate becomes a SARIF result that code scanning alerts on."""
    result = _run(
        monkeypatch, tmp_path, [*_versionless_matches(), _confirmed_match()], ["--output", "sarif"]
    )
    sarif = json.loads(result.stdout)
    run = sarif["runs"][0]

    assert [item["ruleId"] for item in run["results"]] == ["CVE-2026-1111"]
    candidates = run["tool"]["driver"]["properties"]["indicativeCandidates"]
    assert [item["id"] for item in candidates] == ["GHSA-aaaa-aaaa-aaaa", "CVE-2026-0002"]


@pytest.mark.parametrize("output", ["text", "markdown"])
def test_human_reports_list_indicative_candidates_apart_from_the_count(
    monkeypatch, tmp_path, output
):
    """Fails if candidates are hidden, or are counted in the vulnerability total."""
    result = _run(monkeypatch, tmp_path, _versionless_matches(), ["--output", output])

    assert result.exit_code == 0, result.output
    assert "Vulnerabilities: 0 (critical=0, high=0, medium=0)" in result.stdout
    assert "Indicative, not counted: 2" in result.stdout
    heading = "Indicative candidates, version not confirmed (not counted, not gated): 2"
    assert heading in result.stdout
    assert "- widget (no version): GHSA-aaaa-aaaa-aaaa, version missing" in result.stdout
    assert "- widget (no version): CVE-2026-0002, version missing" in result.stdout
    assert "Exit 0 means no configured blocking findings" in result.stdout


def test_human_report_caps_a_long_candidate_list(monkeypatch, tmp_path):
    """Fails if a match-all dump floods the human report."""
    matches = [_match(f"CVE-2026-{n:04d}", [_direct("")]) for n in range(1, 16)]
    result = _run(monkeypatch, tmp_path, matches, ["--output", "text"])

    assert "(not counted, not gated): 15" in result.stdout
    assert "CVE-2026-0010" in result.stdout
    assert "CVE-2026-0011" not in result.stdout
    assert "... and 5 more; see --output json" in result.stdout


def _result_with(findings=(), indicative=()):
    return LocalCheckResult(
        target="x",
        target_type="sbom",
        sbom_path=None,
        components=[],
        findings=list(findings),
        dimensions=[],
        coverage=[],
        provenance={},
        attributions=[],
        sources_consulted=[],
        indicative_findings=list(indicative),
    )


def _indicative_finding():
    return Finding(
        id="GHSA-aaaa-aaaa-aaaa",
        package="widget",
        version="",
        severity="critical",
        indicative_reason="unversioned",
        applicability_evidence={},
    )


def test_annotation_outputs_never_carry_indicative_candidates():
    """Fails if a PR annotation or code-quality entry is raised for an unconfirmed candidate."""
    result = _result_with(indicative=[_indicative_finding()])

    assert annotations.github_annotations(result) == ""
    assert annotations.gitlab_codequality(result) == []


def test_github_step_summary_lists_indicative_candidates_in_their_own_section():
    """Fails if the summary counts candidates as findings or omits them."""
    confirmed = Finding(id="CVE-2026-1111", package="jinja2", version="3.1.3", severity="high")
    only_indicative = annotations.github_step_summary(
        _result_with(indicative=[_indicative_finding()])
    )
    both = annotations.github_step_summary(
        _result_with(findings=[confirmed], indicative=[_indicative_finding()])
    )

    assert "No blocking findings were found in this local snapshot." in only_indicative
    assert "Indicative candidates, version not confirmed (not counted): 1" in only_indicative
    assert "| widget |  | GHSA-aaaa-aaaa-aaaa | unversioned |" in only_indicative
    assert "### Local SBOM Check - 1 findings" in both
    assert both.index("jinja2") < both.index("Indicative candidates")


def test_step_summary_without_candidates_is_unchanged():
    """Fails if the summary text changes when nothing is indicative."""
    assert annotations.github_step_summary(_result_with()) == (
        "### Local SBOM Check\n\nNo blocking findings were found in this local snapshot."
    )


# --- baselines --------------------------------------------------------------


def _write_baseline(path, findings):
    path.write_text(json.dumps({"findings": findings}))
    return path


def test_baseline_vulnerability_now_indicative_is_reclassified_not_removed(monkeypatch, tmp_path):
    """Fails if a vulnerability the baseline confirmed is reported as removed or fixed."""
    baseline = _write_baseline(
        tmp_path / "baseline.json",
        [
            {
                "id": "GHSA-aaaa-aaaa-aaaa",
                "aliases": ["CVE-2026-0001"],
                "package": "widget",
                "version": "",
                "purl": VERSIONLESS_PURL,
            },
            {"id": "CVE-2020-9999", "package": "gone", "version": "1.0"},
        ],
    )
    result, report = _json_run(
        monkeypatch,
        tmp_path,
        _versionless_matches(),
        ["--baseline", str(baseline), "--fail-on-new", "any"],
    )

    assert result.exit_code == 0, result.output
    assert report["baseline"]["reclassified_vulnerabilities"] == ["GHSA-aaaa-aaaa-aaaa"]
    assert report["baseline"]["removed_vulnerabilities"] == ["CVE-2020-9999"]
    assert report["baseline"]["new_vulnerabilities"] == []


def test_baseline_text_report_states_the_reclassification(monkeypatch, tmp_path):
    """Fails if the human report calls a reclassified vulnerability fixed or says nothing."""
    baseline = _write_baseline(
        tmp_path / "baseline.json",
        [{"id": "CVE-2026-0002", "package": "widget", "version": "", "purl": VERSIONLESS_PURL}],
    )
    args = ["--output", "text", "--baseline", str(baseline)]
    result = _run(monkeypatch, tmp_path, _versionless_matches(), args)

    assert "- Baseline findings absent now: 0" in result.stdout
    assert "- Reclassified: version could not be confirmed: 1 (CVE-2026-0002)" in result.stdout


def test_baseline_without_policy_fields_keeps_working(monkeypatch, tmp_path):
    """Fails if an older baseline, written before the section existed, is rejected."""
    baseline = _write_baseline(
        tmp_path / "baseline.json",
        [{"id": "CVE-2026-1111", "package": "jinja2", "version": "3.1.3"}],
    )
    result, report = _json_run(
        monkeypatch, tmp_path, [_confirmed_match()], ["--baseline", str(baseline)]
    )

    assert result.exit_code == 0, result.output
    assert report["baseline"]["new_vulnerabilities"] == []
    assert report["baseline"]["removed_vulnerabilities"] == []
    assert report["baseline"]["reclassified_vulnerabilities"] == []


def test_baseline_report_written_with_indicative_candidates_is_a_valid_baseline(
    monkeypatch, tmp_path
):
    """Fails if a report with an indicative section is rejected as a baseline or misread."""
    _, first = _json_run(monkeypatch, tmp_path, [*_versionless_matches(), _confirmed_match()])
    baseline = tmp_path / "previous.json"
    baseline.write_text(json.dumps(first))

    result, report = _json_run(
        monkeypatch,
        tmp_path,
        [*_versionless_matches(), _confirmed_match()],
        ["--baseline", str(baseline), "--fail-on-new", "any"],
    )

    assert result.exit_code == 0, result.output
    assert report["baseline"]["new_vulnerabilities"] == []
    assert report["baseline"]["reclassified_vulnerabilities"] == []


def test_baseline_delta_matches_indicative_by_the_baseline_identity_rules(tmp_path):
    """Fails if reclassification ignores package and version, hiding a real removal."""
    path = _write_baseline(
        tmp_path / "baseline.json",
        [{"id": "GHSA-aaaa-aaaa-aaaa", "package": "widget", "version": "1.0"}],
    )
    other_version = Finding(
        id="GHSA-aaaa-aaaa-aaaa",
        package="widget",
        version="",
        indicative_reason="unversioned",
    )

    delta = check_module._baseline_delta(path, [], [other_version])

    assert delta["removed_vulnerabilities"] == ["GHSA-aaaa-aaaa-aaaa"]
    assert delta["reclassified_vulnerabilities"] == []


def test_baseline_click_errors_are_unchanged_for_invalid_baseline(tmp_path):
    """Fails if the new baseline parameter changes validation of a malformed baseline."""
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"findings": [{"id": ""}]}))

    with pytest.raises(click.ClickException, match="nonempty string id"):
        check_module._baseline_delta(path, [], [])


# --- baselines on a partial assessment --------------------------------------


def _unassessable(name, version, purl, reason="version-comparison-error", matcher="python"):
    package = {"name": name}
    if version is not None:
        package["version"] = version
    if purl is not None:
        package["purl"] = purl
    return {"package": package, "matcher": matcher, "reasonCode": reason}


def _incomplete(*entries):
    return {"status": "incomplete", "unassessablePackages": list(entries)}


BROKEN_PURL = "pkg:pypi/broken@2.0"


def _broken_baseline_row(vuln_id="CVE-2026-3333", **overrides):
    row = {"id": vuln_id, "package": "broken", "version": "2.0", "purl": BROKEN_PURL}
    return {**row, **overrides}


def test_baseline_vulnerability_on_unassessed_package_is_not_reassessed_not_removed(
    monkeypatch, tmp_path
):
    """Fails if a vulnerability on a package the engine could not assess is reported as fixed."""
    baseline = _write_baseline(
        tmp_path / "baseline.json",
        [
            _broken_baseline_row(),
            {"id": "CVE-2026-1111", "package": "jinja2", "version": "3.1.3"},
        ],
    )
    assessment = _incomplete(_unassessable("broken", "2.0", BROKEN_PURL))

    result, report = _json_run(
        monkeypatch,
        tmp_path,
        [_confirmed_match()],
        ["--baseline", str(baseline), "--fail-on-new", "any"],
        assessment=assessment,
    )

    assert result.exit_code == 0, result.output
    assert report["baseline"]["not_reassessed_vulnerabilities"] == ["CVE-2026-3333"]
    assert report["baseline"]["not_reassessed_reasons"] == {
        "CVE-2026-3333": ["version-comparison-error"]
    }
    assert report["baseline"]["removed_vulnerabilities"] == []
    assert report["baseline"]["reclassified_vulnerabilities"] == []


def test_baseline_vulnerability_on_assessed_package_that_disappeared_is_still_removed(
    monkeypatch, tmp_path
):
    """Fails if a partial scan stops reporting genuine removals on packages it did assess."""
    baseline = _write_baseline(
        tmp_path / "baseline.json",
        [
            _broken_baseline_row(),
            {"id": "CVE-2020-9999", "package": "gone", "version": "1.0"},
        ],
    )
    assessment = _incomplete(_unassessable("broken", "2.0", BROKEN_PURL))

    _, report = _json_run(
        monkeypatch,
        tmp_path,
        [_confirmed_match()],
        ["--baseline", str(baseline)],
        assessment=assessment,
    )

    assert report["baseline"]["removed_vulnerabilities"] == ["CVE-2020-9999"]
    assert report["baseline"]["not_reassessed_vulnerabilities"] == ["CVE-2026-3333"]


@pytest.mark.parametrize(
    "row",
    [
        _broken_baseline_row(version="1.0"),
        _broken_baseline_row(purl="pkg:pypi/broken@3.0"),
        _broken_baseline_row(package="other"),
        {"id": "CVE-2026-3333"},
    ],
    ids=["other-version", "conflicting-purl", "other-package", "legacy-id-only-row"],
)
def test_baseline_row_that_is_not_the_unassessed_package_is_removed(monkeypatch, tmp_path, row):
    """Fails if unassessed packages are matched more loosely than baseline findings are."""
    baseline = _write_baseline(tmp_path / "baseline.json", [row])
    assessment = _incomplete(_unassessable("broken", "2.0", BROKEN_PURL))

    _, report = _json_run(
        monkeypatch,
        tmp_path,
        [_confirmed_match()],
        ["--baseline", str(baseline)],
        assessment=assessment,
    )

    assert report["baseline"]["removed_vulnerabilities"] == ["CVE-2026-3333"]
    assert report["baseline"]["not_reassessed_vulnerabilities"] == []


@pytest.mark.parametrize("output", ["text", "markdown"])
def test_baseline_absence_with_changed_identity_does_not_claim_remediation(
    monkeypatch, tmp_path, output
):
    """Catches calling an absent finding fixed when the new package could not be checked."""
    baseline = _write_baseline(
        tmp_path / "baseline.json", [_broken_baseline_row(version="1.0")]
    )
    assessment = _incomplete(_unassessable("broken", "2.0", BROKEN_PURL))
    result = _run(
        monkeypatch,
        tmp_path,
        [],
        ["--baseline", str(baseline), "--output", output],
        assessment=assessment,
    )

    assert result.exit_code == 0, result.output
    text = " ".join(result.stdout.split())
    assert "Baseline findings absent now: 1" in text
    assert "Absence alone does not prove remediation" in text
    assert "package identity or scan coverage may have changed" in text
    assert "Removed vulnerabilities" not in text


def test_terminal_baseline_absence_does_not_claim_remediation():
    """Catches the interactive renderer retaining the old claim or omitting its caveat."""
    result = _result_with()
    result.baseline = {"removed_vulnerabilities": ["CVE-2026-3333"]}
    buffer = io.StringIO()

    print_text_report(Console(file=buffer, width=400, color_system=None), result, exit_code=0)

    text = buffer.getvalue()
    assert "Baseline findings absent now: 1" in text
    assert "Absence alone does not prove remediation" in text
    assert "Removed vulnerabilities" not in text


def test_baseline_row_without_purl_matches_unassessed_package_by_name_and_version(
    monkeypatch, tmp_path
):
    """Fails if a missing PURL on either side blocks a name and version match."""
    row = {"id": "CVE-2026-3333", "package": "broken", "version": "2.0"}
    baseline = _write_baseline(tmp_path / "baseline.json", [row])
    assessment = _incomplete(_unassessable("broken", "2.0", None))

    _, report = _json_run(
        monkeypatch,
        tmp_path,
        [_confirmed_match()],
        ["--baseline", str(baseline)],
        assessment=assessment,
    )

    assert report["baseline"]["not_reassessed_vulnerabilities"] == ["CVE-2026-3333"]
    assert report["baseline"]["removed_vulnerabilities"] == []


def test_not_reassessed_reasons_combine_every_entry_for_the_package(monkeypatch, tmp_path):
    """Fails if only the first reason code of a package listed twice is kept."""
    baseline = _write_baseline(tmp_path / "baseline.json", [_broken_baseline_row()])
    assessment = _incomplete(
        _unassessable("broken", "2.0", BROKEN_PURL, reason="version-comparison-error"),
        _unassessable("broken", "2.0", BROKEN_PURL, reason="matcher-error", matcher="stock"),
    )

    _, report = _json_run(
        monkeypatch,
        tmp_path,
        [_confirmed_match()],
        ["--baseline", str(baseline)],
        assessment=assessment,
    )

    assert report["baseline"]["not_reassessed_reasons"] == {
        "CVE-2026-3333": ["matcher-error", "version-comparison-error"]
    }


def test_indicative_reclassification_wins_over_not_reassessed(monkeypatch, tmp_path):
    """Fails if a baseline vulnerability that is now indicative loses its reclassification."""
    baseline = _write_baseline(
        tmp_path / "baseline.json",
        [
            {"id": "CVE-2026-0002", "package": "widget", "version": "", "purl": VERSIONLESS_PURL},
            _broken_baseline_row(),
        ],
    )
    assessment = _incomplete(
        _unassessable("widget", "", VERSIONLESS_PURL),
        _unassessable("broken", "2.0", BROKEN_PURL),
    )

    _, report = _json_run(
        monkeypatch,
        tmp_path,
        _versionless_matches(),
        ["--baseline", str(baseline)],
        assessment=assessment,
    )

    assert report["baseline"]["reclassified_vulnerabilities"] == ["CVE-2026-0002"]
    assert report["baseline"]["not_reassessed_vulnerabilities"] == ["CVE-2026-3333"]
    assert report["baseline"]["removed_vulnerabilities"] == []


def _two_package_baseline(tmp_path):
    return _write_baseline(
        tmp_path / "baseline.json",
        [
            {"id": "CVE-2026-4444", "package": "a", "version": "1.0"},
            {"id": "CVE-2026-4444", "package": "b", "version": "1.0"},
        ],
    )


def test_id_on_two_packages_with_one_unassessed_is_not_also_removed(tmp_path):
    """Fails if an ID with an unresolved occurrence is also listed as removed."""
    path = _two_package_baseline(tmp_path)
    unassessed = [UnassessedPackage("b", "1.0", None, "matcher-error")]

    delta = check_module._baseline_delta(path, [], None, unassessed)

    assert delta["not_reassessed_vulnerabilities"] == ["CVE-2026-4444"]
    assert delta["not_reassessed_reasons"] == {"CVE-2026-4444": ["matcher-error"]}
    assert delta["removed_vulnerabilities"] == []


def test_id_on_two_packages_with_one_indicative_is_not_also_removed(tmp_path):
    """Fails if an ID that is now only indicative on one package is also listed as removed."""
    path = _two_package_baseline(tmp_path)
    indicative = [Finding(id="CVE-2026-4444", package="a", version="1.0")]

    delta = check_module._baseline_delta(path, [], indicative)

    assert delta["reclassified_vulnerabilities"] == ["CVE-2026-4444"]
    assert delta["removed_vulnerabilities"] == []


def test_id_removed_on_every_package_is_still_removed(tmp_path):
    """Fails if the ID-level precedence drops a removal where every occurrence was reassessed."""
    path = _two_package_baseline(tmp_path)
    unassessed = [UnassessedPackage("c", "1.0", None, "matcher-error")]

    delta = check_module._baseline_delta(path, [], None, unassessed)

    assert delta["removed_vulnerabilities"] == ["CVE-2026-4444"]
    assert delta["not_reassessed_vulnerabilities"] == []


def test_complete_scan_reports_a_vanished_vulnerability_as_removed(monkeypatch, tmp_path):
    """Fails if a complete scan stops reporting removals or the text report gains a line."""
    baseline = _write_baseline(tmp_path / "baseline.json", [_broken_baseline_row()])
    args = ["--baseline", str(baseline)]

    _, report = _json_run(monkeypatch, tmp_path, [_confirmed_match()], args)
    text = _run(monkeypatch, tmp_path, [_confirmed_match()], ["--output", "text", *args])

    assert report["baseline"]["removed_vulnerabilities"] == ["CVE-2026-3333"]
    assert report["baseline"]["not_reassessed_vulnerabilities"] == []
    assert report["baseline"]["not_reassessed_reasons"] == {}
    assert "- Baseline findings absent now: 1" in text.stdout
    assert "Not reassessed" not in text.stdout


def test_not_reassessed_does_not_hide_a_new_vulnerability_from_fail_on_new(monkeypatch, tmp_path):
    """Fails if --fail-on-new stops gating once the scan is partial or counts not-reassessed."""
    baseline = _write_baseline(tmp_path / "baseline.json", [_broken_baseline_row()])
    assessment = _incomplete(_unassessable("broken", "2.0", BROKEN_PURL))

    result, report = _json_run(
        monkeypatch,
        tmp_path,
        [_confirmed_match()],
        ["--baseline", str(baseline), "--fail-on-new", "high"],
        assessment=assessment,
    )

    assert result.exit_code == 11, result.output
    assert report["baseline"]["new_vulnerabilities"] == ["CVE-2026-1111"]
    assert report["baseline"]["not_reassessed_vulnerabilities"] == ["CVE-2026-3333"]


def test_text_report_states_which_vulnerabilities_were_not_reassessed(monkeypatch, tmp_path):
    """Fails if the human report calls an unassessed vulnerability removed or says nothing."""
    baseline = _write_baseline(tmp_path / "baseline.json", [_broken_baseline_row()])
    assessment = _incomplete(_unassessable("broken", "2.0", BROKEN_PURL))

    result = _run(
        monkeypatch,
        tmp_path,
        [_confirmed_match()],
        ["--output", "text", "--baseline", str(baseline)],
        assessment=assessment,
    )

    assert "- Baseline findings absent now: 0" in result.stdout
    assert (
        "- Not reassessed: package could not be assessed in this scan: 1 (CVE-2026-3333)"
        in result.stdout
    )


def test_baseline_json_shape_lists_not_reassessed_beside_the_other_buckets(monkeypatch, tmp_path):
    """Fails if the new fields are missing or the existing baseline fields change shape."""
    baseline = _write_baseline(tmp_path / "baseline.json", [_broken_baseline_row()])
    assessment = _incomplete(_unassessable("broken", "2.0", BROKEN_PURL))

    _, report = _json_run(
        monkeypatch,
        tmp_path,
        [_confirmed_match()],
        ["--baseline", str(baseline)],
        assessment=assessment,
    )

    assert report["baseline"] == {
        "new_vulnerabilities": ["CVE-2026-1111"],
        "removed_vulnerabilities": [],
        "reclassified_vulnerabilities": [],
        "not_reassessed_vulnerabilities": ["CVE-2026-3333"],
        "not_reassessed_reasons": {"CVE-2026-3333": ["version-comparison-error"]},
        "new_occurrences": [
            {
                "id": "CVE-2026-1111",
                "package": "jinja2",
                "version": "3.1.3",
                "purl": "pkg:pypi/jinja2@3.1.3",
            }
        ],
    }
    assert report["coverage"][0]["status"] == "partial"
    assert "unassessed_packages" not in report["coverage"][0]
