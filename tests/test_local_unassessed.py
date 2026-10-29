"""Local check: packages the scan engine could not check.

The engine reports each package it could not assess with a reason code. Some
codes mean the SBOM or the vulnerability database lacked what the search needs
(not checked); every other code, including an unknown one, means the assessment
failed. These tests drive engine-shaped JSON through ``check`` and every report.
"""

import io
import json

import pytest
from rich.console import Console

from cra_evidence_cli.local import annotations
from cra_evidence_cli.local.models import CoverageSource, UnassessedPackage
from cra_evidence_cli.local.report import print_text_report
from tests.test_local_applicability import (
    _confirmed_match,
    _incomplete,
    _json_run,
    _result_with,
    _run,
    _unassessable,
)

VERSION_REMEDY = (
    "Add the resolved version (for example, generate the SBOM from the lock file or build "
    "output) and scan again."
)
ECOSYSTEM_REMEDY = "Give the package a typed purl (pkg:type/name@version) or a CPE and scan again."
DISTRO_REMEDY = (
    "Add the package's actual operating-system distribution and release to the SBOM, "
    "then scan again."
)
FAILED_REMEDY = "The scanner could not check these packages. Scan again; if it persists, report it."
WARNING = (
    "Warning: the vulnerability assessment is incomplete; valid findings are retained."
)
MALFORMED_WARNING = (
    "Warning: the scan engine returned malformed details for packages it could not check; "
    "those details are not shown."
)
DEBIAN_14 = {"name": "debian", "version": "14", "label": "", "channel": "", "exact": False}


def _left_pad(**extra):
    entry = _unassessable(
        "left-pad", None, "pkg:npm/left-pad", "unknown-package-version", "javascript-matcher"
    )
    return {**entry, **extra}


def _mystery():
    return _unassessable("mystery-lib", "1.0", None, "no-package-ecosystem", "stock-matcher")


def _libc6(scopes=(DEBIAN_14,)):
    entry = _unassessable(
        "libc6",
        "2.41-1",
        "pkg:deb/debian/libc6@2.41-1?distro=debian-14",
        "distro-release-not-in-db",
        "dpkg-matcher",
    )
    return {**entry, "searchedDistros": list(scopes)}


def _missing_distro():
    return _unassessable(
        "libc6", "2.41-1", "pkg:deb/debian/libc6@2.41-1", "missing-distro", "dpkg-matcher"
    )


def _broken(reason="matcher-error"):
    return _unassessable("broken", "2.0", "pkg:pypi/broken@2.0", reason, "python-matcher")


def _gap_only():
    return _incomplete(_left_pad(), _mystery(), _libc6())


def _mixed():
    return _incomplete(_left_pad(), _broken())


def _section(text, heading):
    """The lines of one report section, from its heading to the next blank line."""
    start = text.index(heading)
    end = text.find("\n\n", start)
    return text[start:] if end == -1 else text[start:end]


def test_gap_only_text_report_lists_each_reason_with_its_remedy(monkeypatch, tmp_path):
    """Fails if the section is missing, reasons are not grouped or a remedy is missing."""
    result = _run(monkeypatch, tmp_path, [], ["--output", "text"], assessment=_gap_only())

    assert result.exit_code == 0, result.output
    section = _section(result.stdout, "Not checked for vulnerabilities: 3 packages")
    assert section.splitlines() == [
        "Not checked for vulnerabilities: 3 packages",
        "The vulnerability counts above do not cover these packages.",
        (
            "- Operating-system release not in the vulnerability database "
            "(distro-release-not-in-db): 1 package"
        ),
        (
            "  The vulnerability database has no entry for the requested operating-system scope "
            "debian 14. Either the advisory data does not cover that release, or the "
            "operating-system identity in the SBOM is not the intended one."
        ),
        "  - libc6 2.41-1 (matcher: dpkg-matcher)",
        "- Package ecosystem unknown (no-package-ecosystem): 1 package",
        f"  {ECOSYSTEM_REMEDY}",
        "  - mystery-lib 1.0 (matcher: stock-matcher)",
        "- Package version unknown (unknown-package-version): 1 package",
        f"  {VERSION_REMEDY}",
        "  - left-pad (no version) (matcher: javascript-matcher)",
    ]
    assert "Assessment failed" not in result.stdout
    lowered = section.lower()
    for claim in ("safe", "clean", "no known vulnerabilities"):
        assert claim not in lowered


def test_mixed_scan_separates_gaps_from_assessment_failures(monkeypatch, tmp_path):
    """Fails if packages are classified by coverage status instead of by reason code."""
    result = _run(monkeypatch, tmp_path, [], ["--output", "text"], assessment=_mixed())

    not_checked = _section(result.stdout, "Not checked for vulnerabilities: 1 package")
    failed = _section(result.stdout, "Assessment failed: 1 package")
    assert "left-pad" in not_checked
    assert "broken" not in not_checked
    assert failed.splitlines() == [
        "Assessment failed: 1 package",
        "The vulnerability counts above do not cover these packages.",
        FAILED_REMEDY,
        "- Matcher error (matcher-error): 1 package",
        "  - broken 2.0 (matcher: python-matcher)",
    ]


def test_unknown_reason_code_is_an_assessment_failure(monkeypatch, tmp_path):
    """Fails if a reason code the CLI does not know is treated as a harmless gap."""
    assessment = _incomplete(_broken("future-thing"))

    _, report = _json_run(monkeypatch, tmp_path, [], assessment=assessment)
    text = _run(monkeypatch, tmp_path, [], ["--output", "text"], assessment=assessment).stdout

    assert report["unassessed_packages"]["entries"][0]["category"] == "assessment_failed"
    assert report["unassessed_packages"]["assessment_failed"]["by_reason"] == {"future-thing": 1}
    assert report["unassessed_packages"]["not_checked"]["total_packages"] == 0
    assert "- Unrecognised reason (future-thing): 1 package" in text
    assert "Not checked for vulnerabilities" not in text


def test_missing_distro_is_actionable_not_checked_input_gap(monkeypatch, tmp_path):
    """Catches a missing distro being reported as a matcher failure or DB gap."""
    assessment = _incomplete(_missing_distro())

    result, report = _json_run(monkeypatch, tmp_path, [], assessment=assessment)
    text = _run(monkeypatch, tmp_path, [], ["--output", "text"], assessment=assessment).stdout

    entry = report["unassessed_packages"]["entries"][0]
    assert entry["reason"] == "missing-distro"
    assert entry["category"] == "not_checked"
    assert entry["remedy"] == DISTRO_REMEDY
    assert entry["searched_distros"] == []
    assert report["unassessed_packages"]["not_checked"]["by_reason"] == {
        "missing-distro": 1
    }
    assert report["unassessed_packages"]["assessment_failed"]["total_packages"] == 0
    assert result.exit_code == 0
    assert "Operating-system distribution context missing (missing-distro): 1 package" in text
    assert DISTRO_REMEDY in text
    assert "distro-release-not-in-db" not in text


@pytest.mark.parametrize("assessment", [_gap_only, _mixed, lambda: _incomplete(_broken())])
@pytest.mark.parametrize(
    ("strict", "fail_on", "expected_exit"),
    [(False, None, 0), (True, None, 15), (False, "critical", 10), (True, "critical", 15)],
)
def test_exit_codes_and_stderr_are_unchanged(
    monkeypatch, tmp_path, assessment, strict, fail_on, expected_exit
):
    """Fails if a default exit code changes or package names move to stderr."""
    args = ["--output", "json"]
    if strict:
        args.append("--strict")
    if fail_on:
        args.extend(["--fail-on", fail_on])
    matches = [_confirmed_match(severity="Critical")]

    result = _run(monkeypatch, tmp_path, matches, args, assessment=assessment())

    assert result.exit_code == expected_exit, result.output
    assert result.stderr.count(WARNING) == 1
    for name in ("left-pad", "broken", "mystery-lib", "libc6"):
        assert name not in result.stderr


def test_json_is_null_when_no_engine_assessment_was_made(monkeypatch, tmp_path):
    """Fails if "not measured" on the OSV.dev path is reported as "nothing unchecked"."""

    class OSV:
        def query_components(self, components):
            return [], CoverageSource("osv.dev", "present", as_of="2026-01-01")

    # A malformed assessment is a scan failure, which takes the OSV.dev fallback.
    result, report = _json_run(
        monkeypatch, tmp_path, [], osv=OSV, assessment={"status": "malformed"}
    )

    assert report["provenance"]["engine"] == "osv-online"
    assert report["unassessed_packages"] is None


def test_json_is_empty_after_a_complete_engine_run(monkeypatch, tmp_path):
    """Fails if a complete engine run is reported as unmeasured (null)."""
    _, report = _json_run(monkeypatch, tmp_path, [_confirmed_match()])

    assert report["unassessed_packages"] == {
        "total_packages": 0,
        "not_checked": {"total_packages": 0, "by_reason": {}},
        "assessment_failed": {"total_packages": 0, "by_reason": {}},
        "entries": [],
    }


def test_json_entries_carry_category_remedy_and_engine_details(monkeypatch, tmp_path):
    """Fails if an entry drops the matcher, the searched scopes or the remedy."""
    _, report = _json_run(monkeypatch, tmp_path, [], assessment=_gap_only())

    unassessed = report["unassessed_packages"]
    assert unassessed["total_packages"] == 3
    assert unassessed["not_checked"] == {
        "total_packages": 3,
        "by_reason": {
            "distro-release-not-in-db": 1,
            "no-package-ecosystem": 1,
            "unknown-package-version": 1,
        },
    }
    assert unassessed["entries"][-1] == {
        "name": "left-pad",
        "version": None,
        "purl": "pkg:npm/left-pad",
        "matcher": "javascript-matcher",
        "reason": "unknown-package-version",
        "category": "not_checked",
        "remedy": VERSION_REMEDY,
        "searched_distros": [],
        "candidate_vulnerability_count": None,
        "candidate_vulnerability_ids": None,
    }
    assert unassessed["entries"][0]["searched_distros"] == [DEBIAN_14]


def test_existing_json_fields_are_unchanged_by_the_new_object(monkeypatch, tmp_path):
    """Fails if the additive change edits a field that existed before it."""
    _, report = _json_run(monkeypatch, tmp_path, [], ["--strict"], assessment=_mixed())

    assert set(report) == {
        "advisory",
        "attributions",
        "baseline",
        "components",
        "coverage",
        "cra_readiness_signal",
        "exit_note",
        "findings",
        "identifier_coverage",
        "indicative_findings",
        "indicative_summary",
        "inventory_coverage",
        "provenance",
        "schema_version",
        "sbom_observations",
        "sbom_graph_observations",
        "sources_consulted",
        "summary",
        "suppressions",
        "target",
        "unassessed_packages",
    }
    assert report["schema_version"] == "craevidence.local_check.v1"
    assert report["coverage"][0]["detail"] == (
        "Incomplete vulnerability assessment: pkg:npm/left-pad (javascript-matcher: "
        "unknown-package-version); pkg:pypi/broken@2.0 (python-matcher: matcher-error)"
    )
    assert report["exit_note"] == (
        "Exit 15: configured blocking threshold exceeded in this local snapshot."
    )
    assert report["provenance"]["strict_failure"] == "incomplete vulnerability assessment"


def test_candidate_count_and_ids_reach_json_only(monkeypatch, tmp_path):
    """Fails if candidates are dropped, shown in the text yet, or an absent count reads as 0."""
    computed = _left_pad(
        candidateVulnerabilityCount=3, candidateVulnerabilityIds=["CVE-2026-1", "CVE-2026-2"]
    )
    zero = _unassessable("zero", None, "pkg:npm/zero", "unknown-package-version", "javascript")
    zero.update(candidateVulnerabilityCount=0, candidateVulnerabilityIds=[])
    assessment = _incomplete(computed, zero, _mystery())

    result, report = _json_run(monkeypatch, tmp_path, [], assessment=assessment)
    text = _run(monkeypatch, tmp_path, [], ["--output", "text"], assessment=assessment).stdout

    entries = {entry["name"]: entry for entry in report["unassessed_packages"]["entries"]}
    assert entries["left-pad"]["candidate_vulnerability_count"] == 3
    assert entries["left-pad"]["candidate_vulnerability_ids"] == ["CVE-2026-1", "CVE-2026-2"]
    assert entries["zero"]["candidate_vulnerability_count"] == 0
    assert entries["zero"]["candidate_vulnerability_ids"] == []
    assert entries["mystery-lib"]["candidate_vulnerability_count"] is None
    assert entries["mystery-lib"]["candidate_vulnerability_ids"] is None
    assert "CVE-2026-1" not in text
    assert "candidate" not in text.lower()
    assert MALFORMED_WARNING not in result.stderr


@pytest.mark.parametrize(
    "extra",
    [
        {"candidateVulnerabilityCount": True, "candidateVulnerabilityIds": []},
        {"candidateVulnerabilityCount": -1, "candidateVulnerabilityIds": []},
        {
            "candidateVulnerabilityCount": 30,
            "candidateVulnerabilityIds": [f"CVE-{i}" for i in range(21)],
        },
        {"candidateVulnerabilityIds": ["CVE-2026-1"]},
        {"candidateVulnerabilityCount": 1},
        {"candidateVulnerabilityCount": 1, "candidateVulnerabilityIds": ["CVE-1", "CVE-2"]},
        {"candidateVulnerabilityCount": 1, "candidateVulnerabilityIds": [""]},
        {"candidateVulnerabilityCount": 1, "candidateVulnerabilityIds": "CVE-1"},
    ],
)
def test_malformed_candidates_are_not_computed_and_warned_once(monkeypatch, tmp_path, extra):
    """Fails if malformed candidate data is trusted or escalated to an engine failure."""
    assessment = _incomplete(_left_pad(**extra), _left_pad(**extra) | {"matcher": "other"})

    result, report = _json_run(monkeypatch, tmp_path, [], assessment=assessment)

    assert result.exit_code == 0, result.output
    assert report["provenance"]["engine"] == "grype-local"
    entries = report["unassessed_packages"]["entries"]
    assert len(entries) == 2
    assert all(entry["candidate_vulnerability_count"] is None for entry in entries)
    assert all(entry["candidate_vulnerability_ids"] is None for entry in entries)
    assert result.stderr.count(MALFORMED_WARNING) == 1


def test_candidates_on_a_failure_entry_are_malformed(monkeypatch, tmp_path):
    """Fails if candidate data is accepted on a reason the engine never writes it for."""
    broken = {**_broken(), "candidateVulnerabilityCount": 1, "candidateVulnerabilityIds": ["X"]}

    result, report = _json_run(monkeypatch, tmp_path, [], assessment=_incomplete(broken))

    assert report["unassessed_packages"]["entries"][0]["candidate_vulnerability_count"] is None
    assert result.stderr.count(MALFORMED_WARNING) == 1


def test_text_caps_each_reason_at_five_packages_and_json_keeps_all(monkeypatch, tmp_path):
    """Fails if the JSON list is truncated or the text list is unbounded."""
    packages = [
        _unassessable(f"pkg{i}", None, f"pkg:npm/pkg{i}", "unknown-package-version", "js")
        for i in range(7)
    ]
    assessment = _incomplete(*packages)

    _, report = _json_run(monkeypatch, tmp_path, [], assessment=assessment)
    text = _run(monkeypatch, tmp_path, [], ["--output", "text"], assessment=assessment).stdout

    assert len(report["unassessed_packages"]["entries"]) == 7
    section = _section(text, "Not checked for vulnerabilities: 7 packages")
    assert [line for line in section.splitlines() if line.startswith("  - pkg")] == [
        f"  - pkg{i} (no version) (matcher: js)" for i in range(5)
    ]
    assert "  - ... and 2 more; see --output json" in section


def test_counts_are_distinct_packages_not_engine_entries(monkeypatch, tmp_path):
    """Fails if a package reported by two matchers, or in two categories, is counted twice."""
    assessment = _incomplete(
        _left_pad(),
        _left_pad() | {"matcher": "stock-matcher"},
        _unassessable("left-pad", None, "pkg:npm/left-pad", "matcher-error", "other-matcher"),
    )

    _, report = _json_run(monkeypatch, tmp_path, [], assessment=assessment)
    text = _run(monkeypatch, tmp_path, [], ["--output", "text"], assessment=assessment).stdout

    unassessed = report["unassessed_packages"]
    assert unassessed["total_packages"] == 1
    assert unassessed["not_checked"]["by_reason"] == {"unknown-package-version": 1}
    assert unassessed["assessment_failed"]["by_reason"] == {"matcher-error": 1}
    assert len(unassessed["entries"]) == 3
    assert "  - left-pad (no version) (matcher: javascript-matcher, stock-matcher)" in text


def test_distro_remedy_names_every_searched_scope(monkeypatch, tmp_path):
    """Fails if the engine's searched operating-system scopes are dropped."""
    scopes = (
        DEBIAN_14,
        {"name": "rhel", "version": "", "label": "9", "channel": "eus", "exact": True},
    )
    assessment = _incomplete(_libc6(scopes))

    _, report = _json_run(monkeypatch, tmp_path, [], assessment=assessment)

    assert report["unassessed_packages"]["entries"][0]["remedy"].startswith(
        "The vulnerability database has no entry for the requested operating-system scopes "
        "debian 14, rhel 9 (eus channel). Either"
    )


def test_malformed_searched_scopes_are_dropped_and_warned(monkeypatch, tmp_path):
    """Fails if a malformed scope list rejects the scan or is shown as engine data."""
    entry = _libc6() | {"searchedDistros": [{"name": "debian"}]}

    result, report = _json_run(monkeypatch, tmp_path, [], assessment=_incomplete(entry))

    assert result.exit_code == 0, result.output
    only = report["unassessed_packages"]["entries"][0]
    assert only["searched_distros"] == []
    assert "operating-system scope. Either" in only["remedy"]
    assert result.stderr.count(MALFORMED_WARNING) == 1


def _sarif_run(monkeypatch, tmp_path, matches, args=(), **kwargs):
    result = _run(monkeypatch, tmp_path, matches, ["--output", "sarif", *args], **kwargs)
    return result, json.loads(result.stdout)["runs"][0]


def test_sarif_reports_gaps_as_warning_notifications_not_results(monkeypatch, tmp_path):
    """Fails if gaps become results (new alerts) or are marked as a failed run."""
    _, run = _sarif_run(monkeypatch, tmp_path, [_confirmed_match()], assessment=_gap_only())

    assert [result["ruleId"] for result in run["results"]] == ["CVE-2026-1111"]
    (invocation,) = run["invocations"]
    assert invocation["executionSuccessful"] is True
    notifications = invocation["toolExecutionNotifications"]
    assert [(n["descriptor"]["id"], n["level"]) for n in notifications] == [
        ("craevidence/not-checked/distro-release-not-in-db", "warning"),
        ("craevidence/not-checked/no-package-ecosystem", "warning"),
        ("craevidence/not-checked/unknown-package-version", "warning"),
    ]
    version_note = notifications[2]
    assert version_note["message"]["text"] == (
        "Not checked for vulnerabilities, Package version unknown (unknown-package-version): "
        f"1 package. {VERSION_REMEDY}"
    )
    assert version_note["properties"]["packages"][0]["name"] == "left-pad"
    assert version_note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_reports_assessment_failures_as_errors(monkeypatch, tmp_path):
    """Fails if a real failure is downgraded to a warning or the run is called successful."""
    _, run = _sarif_run(monkeypatch, tmp_path, [], assessment=_mixed())

    (invocation,) = run["invocations"]
    assert invocation["executionSuccessful"] is False
    notifications = invocation["toolExecutionNotifications"]
    assert [(n["descriptor"]["id"], n["level"]) for n in notifications] == [
        ("craevidence/not-checked/unknown-package-version", "warning"),
        ("craevidence/assessment-failed/matcher-error", "error"),
    ]
    assert run["results"] == []


def test_sarif_of_a_complete_run_has_no_invocations(monkeypatch, tmp_path):
    """Fails if the SARIF structure changes for a run with nothing unchecked."""
    _, run = _sarif_run(monkeypatch, tmp_path, [_confirmed_match()])

    assert set(run) == {"tool", "results"}


def test_markdown_report_carries_the_sections(monkeypatch, tmp_path):
    """Fails if the Markdown report drifts from the text report."""
    result = _run(monkeypatch, tmp_path, [], ["--output", "markdown"], assessment=_mixed())

    assert "## Not checked for vulnerabilities: 1 package" in result.stdout
    assert "## Assessment failed: 1 package" in result.stdout
    assert f"  {VERSION_REMEDY}" in result.stdout


def _unassessed_result(packages, provenance=None):
    result = _result_with()
    result.unassessed_packages = packages
    result.provenance = provenance or {}
    return result


def test_terminal_report_prints_the_sections():
    """Fails if the interactive terminal report omits what the plain text report shows."""
    packages = [
        UnassessedPackage("left-pad", None, "pkg:npm/left-pad", "unknown-package-version", "js"),
        UnassessedPackage("broken", "2.0", None, "matcher-panic", "python-matcher"),
    ]
    buffer = io.StringIO()
    console = Console(file=buffer, width=400, color_system=None)

    print_text_report(console, _unassessed_result(packages))

    output = buffer.getvalue()
    assert "Not checked for vulnerabilities: 1 package" in output
    assert "  - left-pad (no version) (matcher: js)" in output
    assert "- Matcher stopped unexpectedly (matcher-panic): 1 package" in output
    assert FAILED_REMEDY in output






def test_step_summary_lists_both_sections():
    """Fails if the GitHub step summary omits unchecked packages or their remedy."""
    packages = [
        UnassessedPackage("left-pad", None, "pkg:npm/left-pad", "unknown-package-version", "js"),
        UnassessedPackage("broken", "2.0", None, "matcher-error", "python-matcher"),
    ]

    summary = annotations.github_step_summary(_unassessed_result(packages))

    assert "No blocking findings were found in this local snapshot." in summary
    assert "#### Not checked for vulnerabilities: 1 package" in summary
    assert f"| unknown-package-version | 1 | left-pad (no version) | {VERSION_REMEDY} |" in summary
    assert "#### Assessment failed: 1 package" in summary
    assert f"| matcher-error | 1 | broken 2.0 | {FAILED_REMEDY} |" in summary


def test_alert_channels_are_unchanged_by_unchecked_packages():
    """Fails if unchecked packages leak into PR annotations or GitLab Code Quality."""
    packages = [UnassessedPackage("broken", "2.0", None, "matcher-error", "python-matcher")]

    assert annotations.github_annotations(_unassessed_result(packages)) == ""
    assert annotations.gitlab_codequality(_unassessed_result(packages)) == []
    assert annotations.github_step_summary(_unassessed_result([])) == (
        "### Local SBOM Check\n\nNo blocking findings were found in this local snapshot."
    )


def test_counts_use_singular_and_plural_package_forms(monkeypatch, tmp_path):
    """Fails if a count is written as "package(s)" or with the wrong number form."""
    single = _run(monkeypatch, tmp_path, [], ["--output", "text"], assessment=_mixed()).stdout
    several = _run(monkeypatch, tmp_path, [], ["--output", "text"], assessment=_gap_only()).stdout
    summary = annotations.github_step_summary(
        _unassessed_result(
            [UnassessedPackage("broken", "2.0", None, "matcher-error", "python-matcher")]
        )
    )

    assert "Not checked for vulnerabilities: 1 package\n" in single
    assert "- Package version unknown (unknown-package-version): 1 package\n" in single
    assert "Not checked for vulnerabilities: 3 packages\n" in several
    assert "#### Assessment failed: 1 package\n" in summary
    for output in (single, several, summary):
        assert "package(s)" not in output
