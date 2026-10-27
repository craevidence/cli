"""The inventory coverage statement read from engine SBOMs and shown by `check`.

The generated-*.json fixtures are CRA Evidence engine `sbom` output for a tree
with a lock-less package.json, a locked package.json and a setup.py with an
unpinned requirement. Only the scanned directory path and the engine version
string were normalised. Each test names the wrong implementation it catches.
"""

import copy
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import check as check_module
from cra_evidence_cli.local.inventory_coverage import (
    CODE_DEPENDENCY_GRAPH_UNRESOLVED,
    STATUS_ABSENT,
    STATUS_REPORTED,
    STATUS_UNINTERPRETABLE,
    read_inventory_coverage,
)
from cra_evidence_cli.local.models import CoverageSource, Finding
from cra_evidence_cli.sbom_generator import SBOMGenerationResult

FIXTURES = Path(__file__).parent / "fixtures" / "inventory_coverage"
EXPECTED_ENTRIES = [
    ("/py/setup.py", "declared_unresolved", "requirements-not-fully-read"),
    ("/service/package.json", "declared_unresolved", "manifest-without-lock"),
]


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _with_statement(document: dict, statement: object) -> dict:
    document = copy.deepcopy(document)
    value = statement if isinstance(statement, str) else json.dumps(statement)
    for item in document["metadata"]["properties"]:
        if item["name"] == "craev:inventory-coverage":
            item["value"] = value
    return document


@pytest.mark.parametrize("name", ["generated-cyclonedx.json", "generated-spdx.json"])
def test_generated_statement_is_read_from_both_formats(name):
    # Catches a reader that knows one carrier only (CycloneDX property or SPDX annotation).
    coverage = read_inventory_coverage(_fixture(name))
    assert coverage.status == STATUS_REPORTED
    assert coverage.state == "incomplete"
    assert coverage.counts == {"declared_unresolved": 2}
    assert [(e.path, e.code, e.by) for e in coverage.entries] == EXPECTED_ENTRIES


def test_absent_statement_is_no_information():
    # Catches reading a document without a statement as complete or as a gap.
    document = {"bomFormat": "CycloneDX", "components": [], "metadata": {}}
    coverage = read_inventory_coverage(document)
    assert coverage.status == STATUS_ABSENT
    assert coverage.to_dict()["state"] is None


@pytest.mark.parametrize(
    "statement",
    [
        "not json",
        [],
        {"v": 2, "state": "unknown", "counts": {}, "listed": 0, "omitted": 0, "entries": []},
        {"v": 1, "state": "complete", "counts": {}, "listed": 0, "omitted": 0, "entries": []},
        {"v": 1, "state": {}, "counts": {}, "listed": 0, "omitted": 0, "entries": []},
        {"v": 1, "state": [], "counts": {}, "listed": 0, "omitted": 0, "entries": []},
        {
            "v": 1,
            "state": "unknown",
            "counts": {"unparsed": 1},
            "listed": 0,
            "omitted": 1,
            "entries": [],
        },
        {
            "v": 1,
            "state": "incomplete",
            "counts": {"unparsed": 2},
            "listed": 2,
            "omitted": 0,
            "entries": [{"p": "/a", "c": "unparsed", "by": "x"}],
        },
        {
            "v": 1,
            "state": "incomplete",
            "counts": {"unparsed": 1},
            "listed": 1,
            "omitted": 0,
            "entries": [{"p": "/a", "c": "limit_refused", "by": "x"}],
        },
        {
            "v": 1,
            "state": "incomplete",
            "counts": {"unparsed": -1},
            "listed": 0,
            "omitted": 0,
            "entries": [],
        },
        {
            "v": 1,
            "state": "incomplete",
            "counts": {"unparsed": 1},
            "listed": 1,
            "omitted": 0,
            "entries": [{"p": "/a", "c": "unparsed"}],
        },
    ],
)
def test_malformed_or_contradictory_statement_is_uninterpretable(statement):
    # Catches a broad default that turns an unreadable statement into an empty, clean-looking list.
    coverage = read_inventory_coverage(
        _with_statement(_fixture("generated-cyclonedx.json"), statement)
    )
    assert coverage.status == STATUS_UNINTERPRETABLE
    assert coverage.detail
    assert coverage.entries == []


def test_two_statements_are_uninterpretable():
    # Catches picking one of two conflicting statements.
    document = _fixture("generated-cyclonedx.json")
    document["metadata"]["properties"].append(copy.deepcopy(document["metadata"]["properties"][-1]))
    assert read_inventory_coverage(document).status == STATUS_UNINTERPRETABLE


def test_unknown_reason_code_is_kept_and_named():
    # Catches dropping a reason this CLI does not know yet.
    statement = {
        "v": 1,
        "state": "incomplete",
        "counts": {"future_reason": 1},
        "listed": 1,
        "omitted": 0,
        "entries": [{"p": "/x.lock", "c": "future_reason", "by": "x"}],
    }
    coverage = read_inventory_coverage(
        _with_statement(_fixture("generated-cyclonedx.json"), statement)
    )
    assert coverage.status == STATUS_REPORTED
    assert "reason code future_reason" in coverage.to_dict()["entries"][0]["reason"]


def test_dependency_graph_gap_preserves_packages_without_claiming_they_are_missing():
    # Catches treating unresolved graph targets as missing package entries.
    statement = {
        "v": 1,
        "state": "incomplete",
        "counts": {CODE_DEPENDENCY_GRAPH_UNRESOLVED: 1},
        "listed": 1,
        "omitted": 0,
        "entries": [
            {"p": "/Gemfile.lock", "c": CODE_DEPENDENCY_GRAPH_UNRESOLVED, "by": "bundler"}
        ],
    }
    coverage = read_inventory_coverage(
        _with_statement(_fixture("generated-cyclonedx.json"), statement)
    )
    output = coverage.to_dict()
    assert coverage.status == STATUS_REPORTED
    assert output["counts"] == {CODE_DEPENDENCY_GRAPH_UNRESOLVED: 1}
    assert output["entries"][0]["code"] == CODE_DEPENDENCY_GRAPH_UNRESOLVED
    assert "ambiguous or missing" in output["entries"][0]["reason"]
    assert "Package entries are retained" in output["entries"][0]["reason"]
    assert "no dependency edges were guessed" in output["entries"][0]["reason"]
    assert "no dependency edges were guessed" in output["note"]
    assert "packages may be missing" not in output["note"]


class _Scanner:
    findings: list = []

    def __init__(self, *args, **kwargs):
        pass

    def is_available(self):
        return True

    def scan_sbom(self, sbom_path):
        return list(type(self).findings), CoverageSource("grype-db", "present", as_of="2026-06-10")


@pytest.fixture
def offline_check(monkeypatch):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    monkeypatch.setattr(check_module, "GrypeLocalScanner", _Scanner)
    monkeypatch.setattr(check_module, "get_embedded_syft_version", lambda: None)
    monkeypatch.setattr(
        check_module,
        "fetch_kev_catalog",
        lambda: (set(), CoverageSource("cisa-kev", "present", as_of="2026-06-10")),
    )
    monkeypatch.setattr(
        check_module,
        "fetch_epss_scores",
        lambda cves: ({}, CoverageSource("first-epss", "present", as_of="2026-06-10")),
    )
    _Scanner.findings = []
    return _Scanner


def _critical():
    return Finding(
        id="CVE-2025-1",
        package="click",
        version="8.1.7",
        severity="critical",
        purl="pkg:pypi/click@8.1.7",
    )


def _without_statement(tmp_path: Path) -> Path:
    document = _fixture("generated-cyclonedx.json")
    document["metadata"]["properties"] = [
        p for p in document["metadata"]["properties"] if p["name"] != "craev:inventory-coverage"
    ]
    path = tmp_path / "plain.json"
    path.write_text(json.dumps(document))
    return path


def _run(*args):
    return CliRunner().invoke(cli, ["check", *args])


def test_check_json_report_carries_the_statement(offline_check):
    # Catches a statement read but never reported, and a warning that corrupts JSON stdout.
    result = _run("--sbom", str(FIXTURES / "generated-cyclonedx.json"), "--output", "json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    inventory = payload["inventory_coverage"]
    assert inventory["status"] == "reported"
    assert inventory["counts"] == {"declared_unresolved": 2}
    assert [(e["path"], e["code"], e["by"]) for e in inventory["entries"]] == EXPECTED_ENTRIES
    assert all(e["reason"] for e in inventory["entries"])
    assert "may be missing from the SBOM" in result.stderr
    assert all(source["source"] != "inventory" for source in payload["coverage"])


@pytest.mark.parametrize("name", ["generated-cyclonedx.json", "generated-spdx.json"])
def test_check_text_report_names_each_file_and_reason(offline_check, name):
    # Catches a progress-only message that imported SBOMs never show, and a section
    # without the files.
    result = _run("--sbom", str(FIXTURES / name), "--output", "text")
    assert result.exit_code == 0, result.output
    assert (
        "Inventory coverage: incomplete, 2 coverage-gap entries reported by the SBOM generator"
        in result.stdout
    )
    assert "/service/package.json: declares dependencies and no lock file" in result.stdout
    assert (
        "/py/setup.py: install_requires has a requirement without an exact == pin" in result.stdout
    )


def test_dependency_graph_gap_is_reported_without_changing_findings_or_exit_code(
    offline_check, tmp_path
):
    # Catches classifying an unresolved relationship as an unassessed package or finding.
    statement = {
        "v": 1,
        "state": "incomplete",
        "counts": {CODE_DEPENDENCY_GRAPH_UNRESOLVED: 1},
        "listed": 1,
        "omitted": 0,
        "entries": [
            {"p": "/Gemfile.lock", "c": CODE_DEPENDENCY_GRAPH_UNRESOLVED, "by": "bundler"}
        ],
    }
    path = tmp_path / "graph-gap.json"
    path.write_text(json.dumps(_with_statement(_fixture("generated-cyclonedx.json"), statement)))
    offline_check.findings = [_critical()]
    result = _run("--sbom", str(path), "--output", "json", "--fail-on", "critical")
    assert result.exit_code == 10
    payload = json.loads(result.stdout)
    assert [item["id"] for item in payload["findings"]] == ["CVE-2025-1"]
    assert payload["inventory_coverage"]["counts"] == {CODE_DEPENDENCY_GRAPH_UNRESOLVED: 1}
    assert payload["inventory_coverage"]["entries"][0]["path"] == "/Gemfile.lock"
    assert "packages may be missing" not in payload["inventory_coverage"]["note"]

    text = _run("--sbom", str(path), "--output", "text")
    assert text.exit_code == 0
    assert "Dependency relationships with unresolved targets" in text.stdout
    assert "/Gemfile.lock: declares dependency relationships" in text.stdout


def test_check_without_statement_prints_no_section(offline_check, tmp_path):
    # Catches an alarm on SBOMs from other generators, which carry no statement.
    result = _run("--sbom", str(_without_statement(tmp_path)), "--output", "text")
    assert result.exit_code == 0, result.output
    assert "Inventory coverage" not in result.stdout
    assert (
        json.loads(_run("--sbom", str(_without_statement(tmp_path)), "--output", "json").stdout)[
            "inventory_coverage"
        ]["status"]
        == "absent"
    )


@pytest.mark.parametrize(
    "extra",
    [[], ["--strict"], ["--fail-on", "critical"], ["--strict", "--fail-on", "critical"]],
)
@pytest.mark.parametrize("with_finding", [False, True])
def test_statement_never_changes_the_exit_code(offline_check, tmp_path, extra, with_finding):
    # Catches the disclosure feeding the strict source gate or a severity gate.
    offline_check.findings = [_critical()] if with_finding else []
    reported = _run(
        "--sbom", str(FIXTURES / "generated-cyclonedx.json"), "--output", "json", *extra
    )
    plain = _run("--sbom", str(_without_statement(tmp_path)), "--output", "json", *extra)
    assert reported.exit_code == plain.exit_code
    first, second = json.loads(reported.stdout), json.loads(plain.stdout)
    assert first["findings"] == second["findings"]
    assert first["summary"] == second["summary"]
    assert first["coverage"] == second["coverage"]


@pytest.mark.parametrize("state", [{}, [], {"incomplete": True}, ["incomplete"]])
@pytest.mark.parametrize("extra", [[], ["--strict", "--fail-on", "critical"]])
@pytest.mark.parametrize("with_finding", [False, True])
def test_unhashable_state_never_changes_findings_or_exit_code(
    offline_check, tmp_path, state, extra, with_finding
):
    # Catches a set-membership test on an object or array state, which raised TypeError before
    # the scan ran and so changed the exit code and lost the findings.
    offline_check.findings = [_critical()] if with_finding else []
    statement = {"v": 1, "state": state, "counts": {}, "listed": 0, "omitted": 0, "entries": []}
    path = tmp_path / "state.json"
    path.write_text(json.dumps(_with_statement(_fixture("generated-cyclonedx.json"), statement)))
    malformed = _run("--sbom", str(path), "--output", "json", *extra)
    plain = _run("--sbom", str(_without_statement(tmp_path)), "--output", "json", *extra)
    assert malformed.exception is None or isinstance(malformed.exception, SystemExit)
    assert malformed.exit_code == plain.exit_code
    first, second = json.loads(malformed.stdout), json.loads(plain.stdout)
    assert first["findings"] == second["findings"]
    assert first["summary"] == second["summary"]
    assert first["coverage"] == second["coverage"]
    assert first["inventory_coverage"]["status"] == "uninterpretable"
    assert "could not be interpreted" in malformed.stderr


def test_totals_are_entries_not_distinct_files(offline_check, tmp_path):
    # Catches an aggregate labelled as files when one file has two reasons: two catalogers that
    # could not read the same lock are two entries for one file.
    statement = {
        "v": 1,
        "state": "incomplete",
        "counts": {"unparsed": 2, "declared_unresolved": 1},
        "listed": 3,
        "omitted": 0,
        "entries": [
            {"p": "/package.json", "c": "declared_unresolved", "by": "declared-not-in-lock"},
            {"p": "/yarn.lock", "c": "unparsed", "by": "javascript-lock-cataloger"},
            {"p": "/yarn.lock", "c": "unparsed", "by": "another-cataloger"},
        ],
    }
    path = tmp_path / "two.json"
    path.write_text(json.dumps(_with_statement(_fixture("generated-cyclonedx.json"), statement)))
    sarif = tmp_path / "out.sarif"
    result = _run("--sbom", str(path), "--output", "text", "--sarif-output", str(sarif))
    assert result.exit_code == 0, result.output
    assert "3 coverage-gap entries reported by the SBOM generator" in result.stdout
    assert "file(s)" not in result.stdout
    assert "3 coverage-gap entries for files whose packages may be missing" in result.stderr
    assert "/package.json: declares a dependency that is not among the packages" in result.stdout
    notifications = json.loads(sarif.read_text())["runs"][0]["invocations"][0][
        "toolExecutionNotifications"
    ]
    texts = {n["descriptor"]["id"].rsplit("/", 1)[1]: n["message"]["text"] for n in notifications}
    assert "2 coverage-gap entries reported" in texts["unparsed"]
    assert "1 dependency manifest(s) reported" in texts["declared_unresolved"]
    unparsed = next(n for n in notifications if n["descriptor"]["id"].endswith("/unparsed"))
    assert [e["path"] for e in unparsed["properties"]["entries"]] == ["/yarn.lock", "/yarn.lock"]


def test_sarif_reports_the_statement_as_notifications_not_results(offline_check, tmp_path):
    # Catches the disclosure presented as a vulnerability result.
    sarif = tmp_path / "out.sarif"
    result = _run(
        "--sbom", str(FIXTURES / "generated-cyclonedx.json"), "--sarif-output", str(sarif)
    )
    assert result.exit_code == 0, result.output
    run = json.loads(sarif.read_text())["runs"][0]
    assert run["results"] == []
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    ids = [n["descriptor"]["id"] for n in notifications]
    assert ids == ["craevidence/inventory-coverage/declared_unresolved"]
    assert notifications[0]["level"] == "warning"
    assert notifications[0]["properties"]["count"] == 2
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["tool"]["driver"]["properties"]["inventoryCoverage"]["status"] == "reported"


def test_markdown_report_has_the_section(offline_check):
    # Catches a format that drops the disclosure.
    result = _run("--sbom", str(FIXTURES / "generated-cyclonedx.json"), "--output", "markdown")
    assert result.exit_code == 0, result.output
    assert "## Inventory coverage: incomplete" in result.stdout


def test_uninterpretable_statement_is_shown_and_does_not_change_the_exit(offline_check, tmp_path):
    # Catches a silent fallback that hides a statement this CLI cannot read.
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(_with_statement(_fixture("generated-cyclonedx.json"), "{")))
    result = _run("--sbom", str(path), "--output", "text")
    assert result.exit_code == 0, result.output
    assert "Inventory coverage: could not be interpreted" in result.stdout
    assert "could not be interpreted" in result.stderr


def test_directory_with_only_unresolved_manifests_names_them(offline_check, monkeypatch, tmp_path):
    # Catches the old "No dependency manifests" message when the generator found manifests it could
    # not resolve. The exit code stays 1.
    gen_dir = tmp_path / "sbom_gen"
    gen_dir.mkdir()
    document = _fixture("generated-cyclonedx.json")
    document["components"] = []
    statement = {
        "v": 1,
        "state": "incomplete",
        "counts": {"declared_unresolved": 1},
        "listed": 1,
        "omitted": 0,
        "entries": [
            {"p": "/package.json", "c": "declared_unresolved", "by": "manifest-without-lock"}
        ],
    }
    generated = gen_dir / "sbom.json"
    generated.write_text(json.dumps(_with_statement(document, statement)))
    monkeypatch.setattr(
        check_module,
        "generate_sbom_from_directory",
        lambda *a, **k: SBOMGenerationResult(generated, 0, "cyclonedx", "craevidence-grype"),
    )
    src = tmp_path / "src"
    src.mkdir()
    result = CliRunner().invoke(cli, ["check", str(src)])
    assert result.exit_code == 1
    assert "No packages were resolved under" in result.stderr
    assert (
        "/package.json declares dependencies and no lock file the generator reads covers it"
        in result.stderr
    )
    assert "No dependency manifests or SBOM found" not in result.stderr
    assert not gen_dir.exists()
