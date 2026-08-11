"""CLI tests for the code-check command. No network, no API key, no opengrep binary."""

from __future__ import annotations

import json
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands.code_check import (
    _BUNDLED_RULES,
    _SAST_DEGRADED_EXIT_CODE,
    _SAST_EXIT_CODE,
    _UPLOAD_SIZE_LIMIT,
    _sanitized_sarif,
    code_check,
)
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.exceptions import CRAEvidenceError
from cra_evidence_cli.local.rules_pack import inspect_rule_pack
from cra_evidence_cli.local.sast_scanner import (
    OPENGREP_INSTALL_HINT,
    SASTFinding,
    SASTReport,
)

_BINARY = "/usr/bin/opengrep"
_OPENGREP_PATCH = "cra_evidence_cli.commands.code_check.opengrep_path"
_RUN_SCAN_PATCH = "cra_evidence_cli.commands.code_check.run_scan"


@pytest.fixture
def runner():
    return CliRunner()


def _make_obj(output_format: str = "text") -> dict:
    return {
        "config": CRAEvidenceConfig(
            url="https://api.craevidence.com",
            output_format=output_format,
        ),
        "verbose": False,
    }


def _clean_report() -> SASTReport:
    return SASTReport(
        engine_version="1.25.0",
        rules_path="/rules",
        rule_count=8,
        findings=[],
        scan_failed=False,
        failure_reason=None,
        sarif_raw={"version": "2.1.0", "runs": []},
    )


def _report_with_findings(level: str = "warning") -> SASTReport:
    finding = SASTFinding(
        rule_id="cra-python-sql-injection",
        severity=level,
        file="app/db.py",
        line=42,
        message="String formatting in SQL execute() call.",
        cwe_list=[
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
        ],
        fingerprint="abc123",
    )
    return SASTReport(
        engine_version="1.25.0",
        rules_path="/rules",
        rule_count=8,
        findings=[finding],
        scan_failed=False,
        failure_reason=None,
        sarif_raw=None,
    )


def _failed_report() -> SASTReport:
    return SASTReport(
        engine_version="1.25.0",
        rules_path="/rules",
        rule_count=0,
        findings=[],
        scan_failed=True,
        failure_reason="engine exited 2: fatal error",
        sarif_raw=None,
    )


def _degraded_report() -> SASTReport:
    report = _report_with_findings("error")
    report.files_scanned = 2
    report.engine_errors = [
        {"level": "warn", "type": ["PartialParsing", []], "path": "broken.py"}
    ]
    return report


# --- binary-missing path ---


def test_binary_missing_prints_hint_and_exits_nonzero(runner, tmp_path):
    with patch(_OPENGREP_PATCH, return_value=None):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 1, result.output
    combined = result.output + (result.stderr or "")
    assert OPENGREP_INSTALL_HINT in combined
    assert "Scan failed" in combined


def test_binary_missing_is_not_reported_as_clean(runner, tmp_path):
    with patch(_OPENGREP_PATCH, return_value=None):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 1
    assert "Scan failed" in result.output
    assert "No findings matched" not in result.output


def test_binary_missing_with_fail_on_does_not_pass_gate(runner, tmp_path):
    # A gated run must not silently succeed when the engine is absent.
    with patch(_OPENGREP_PATCH, return_value=None):
        result = runner.invoke(
            code_check, [str(tmp_path), "--fail-on", "error"], obj=_make_obj("text")
        )
    assert result.exit_code != 0
    assert "Scan failed" in (result.output + (result.stderr or ""))


def test_binary_missing_sarif_is_valid_failed_invocation(runner, tmp_path):
    with patch(_OPENGREP_PATCH, return_value=None):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("sarif"))

    document = json.loads(result.output)
    invocation = document["runs"][0]["invocations"][0]
    assert result.exit_code == 1
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["level"] == "error"


# --- engine nonzero exit renders scan-failed, not clean ---


def test_scan_failed_shows_failure_reason(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_failed_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 1, result.output
    assert "Scan failed" in result.output
    assert "engine exited 2" in result.output
    assert "No findings matched" not in result.output


def test_scan_failure_preserves_findings_from_completed_analysis(runner, tmp_path):
    report = _report_with_findings("error")
    report.scan_failed = True
    report.failure_reason = "Opengrep reported 1 non-recoverable scan error(s)"
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=report),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))

    assert result.exit_code == 1
    assert "Scan failed" in result.output
    assert "Findings from completed analysis" in result.output
    assert "cra-python-sql-injection" in result.output


def test_scan_failed_json_sets_scan_failed_true(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_failed_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("json"))
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["scan_failed"] is True
    assert data["findings"] == []


def test_degraded_scan_renders_findings_and_exits_with_distinct_gate_code(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_degraded_report()),
    ):
        advisory = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))

    assert advisory.exit_code == 0, advisory.output
    assert "Coverage degraded" in advisory.output
    assert "cra-python-sql-injection" in advisory.output
    assert "No findings rendered" not in advisory.output

    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_degraded_report()),
    ):
        gated = runner.invoke(
            code_check,
            [str(tmp_path), "--fail-on", "error"],
            obj=_make_obj("text"),
        )
    assert gated.exit_code == _SAST_DEGRADED_EXIT_CODE


def test_degraded_scan_without_findings_cannot_pass_explicit_gate(runner, tmp_path):
    report = _clean_report()
    report.files_scanned = 1
    report.engine_errors = [
        {"type": "PythonSyntaxError", "path": "legacy.py", "line": 1}
    ]
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=report),
    ):
        gated = runner.invoke(
            code_check,
            [str(tmp_path), "--fail-on", "error"],
            obj=_make_obj("text"),
        )

    assert gated.exit_code == _SAST_DEGRADED_EXIT_CODE
    assert "Coverage degraded" in gated.output


def test_degraded_json_and_sarif_report_success_with_warning(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_degraded_report()),
    ):
        json_result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("json"))
    payload = json.loads(json_result.output)
    assert json_result.exit_code == 0
    assert payload["scan_failed"] is False
    assert payload["coverage_degraded"] is True
    assert payload["finding_count"] == 1

    sarif_report = _degraded_report()
    sarif_report.sarif_raw = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Opengrep"}},
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {"text": "Coverage degraded"},
                            }
                        ],
                    }
                ],
            }
        ],
    }
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=sarif_report),
    ):
        sarif_result = runner.invoke(
            code_check, [str(tmp_path)], obj=_make_obj("sarif")
        )
    document = json.loads(sarif_result.output)
    assert sarif_result.exit_code == 0
    assert document["runs"][0]["invocations"][0]["executionSuccessful"] is True
    assert (
        document["runs"][0]["tool"]["driver"]["properties"]
        ["craEvidenceCoverageDegraded"]
        is True
    )


# --- advisory exit 0 with findings ---


def test_advisory_exit_zero_with_findings(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_report_with_findings("warning")),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0, result.output
    assert "cra-python-sql-injection" in result.output


def test_bundled_experimental_rules_are_opt_in(runner, tmp_path):
    (tmp_path / "Example.java").write_text("class Example {}\n", encoding="utf-8")
    default_report = _clean_report()
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=default_report) as run_scan_mock,
    ):
        default_result = runner.invoke(
            code_check, [str(tmp_path)], obj=_make_obj("json")
        )
    default_payload = json.loads(default_result.output)
    excluded = run_scan_mock.call_args.kwargs["exclude_rules"]
    assert run_scan_mock.call_args.kwargs["zero_files_reason"] == (
        "Opengrep scanned zero files"
    )
    assert len(excluded) == 41
    assert default_payload["rule_count"] == 54
    assert default_payload["rule_tiers"] == {
        "default_enabled": 54,
        "experimental_enabled": 0,
        "experimental_available": 41,
    }
    assert default_payload["rule_language_counts"] == {
        "csharp": 7,
        "go": 2,
        "java": 3,
        "python": 42,
    }

    experimental_report = _clean_report()
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=experimental_report) as run_scan_mock,
    ):
        experimental_result = runner.invoke(
            code_check,
            [str(tmp_path), "--include-experimental"],
            obj=_make_obj("json"),
        )
    experimental_payload = json.loads(experimental_result.output)
    assert run_scan_mock.call_args.kwargs["exclude_rules"] == ()
    assert run_scan_mock.call_args.kwargs["zero_files_reason"] == (
        "Opengrep scanned zero files"
    )
    assert experimental_payload["rule_count"] == 95
    assert experimental_payload["rule_tiers"]["experimental_enabled"] == 41


def test_zero_file_message_does_not_suggest_experimental_for_unrelated_files(
    runner, tmp_path
):
    (tmp_path / "README.txt").write_text("documentation only\n", encoding="utf-8")
    failed = _failed_report()
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=failed) as run_scan_mock,
    ):
        runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))

    assert run_scan_mock.call_args.kwargs["zero_files_reason"] == (
        "Opengrep scanned zero files"
    )


def test_zero_file_message_suggests_experimental_for_an_opt_in_language(
    runner, tmp_path
):
    """Rust has no default rule, so a Rust file must prompt for the opt-in flag.

    The language named here has to be one the pack still covers with
    experimental rules only. Java used to serve that purpose and no longer can.
    """
    (tmp_path / "example.rs").write_text("fn main() {}\n", encoding="utf-8")
    failed = _failed_report()
    failed.failure_reason = "Opengrep scanned zero files"
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=failed),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))

    assert "Experimental rules for" in result.output
    assert "Rust" in result.output
    assert "--include-experimental" in result.output


def test_zero_file_message_never_names_a_language_with_a_default_rule(
    runner, tmp_path
):
    """A promoted language must disappear from the opt-in message by itself."""
    (tmp_path / "example.rs").write_text("fn main() {}\n", encoding="utf-8")
    failed = _failed_report()
    failed.failure_reason = "Opengrep scanned zero files"
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=failed),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))

    inventory = inspect_rule_pack(_BUNDLED_RULES)
    opt_in = set(inventory.experimental_only_languages)
    assert "python" not in opt_in
    for language, display in (("java", "Java"), ("go", "Go"), ("csharp", "C#")):
        if language not in opt_in:
            # A word boundary, because "Java" is a substring of "JavaScript"
            # and "Go" of "Golang": a plain containment check reads as a
            # failure whenever another listed language merely starts the same.
            pattern = rf"\b{re.escape(display)}\b"
            assert re.search(pattern, result.output) is None


def test_polyglot_default_gate_fails_when_an_opt_in_language_is_not_analysed(
    runner, tmp_path
):
    """The file left unanalysed must belong to a language with no default rule."""
    python_file = tmp_path / "app.py"
    rust_file = tmp_path / "vuln.rs"
    python_file.write_text("print('clean')\n", encoding="utf-8")
    rust_file.write_text("fn main() {}\n", encoding="utf-8")
    report = _clean_report()
    report.files_scanned = 1
    report.scanned_paths = (str(python_file),)
    report.language_counts = {"Python": 1}

    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=report),
    ):
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--fail-on", "error"],
            obj=_make_obj("json"),
        )

    payload = json.loads(result.output)
    assert result.exit_code == _SAST_DEGRADED_EXIT_CODE
    assert payload["coverage_degraded"] is True
    assert payload["unanalysed_file_count"] == 1
    assert payload["unanalysed_language_counts"] == {"Rust": 1}
    assert payload["unanalysed_files"] == [
        {
            "path": "vuln.rs",
            "language": "Rust",
            "reason": "no_enabled_rules",
        }
    ]


def test_experimental_gate_reports_mts_and_cts_engine_omissions(runner, tmp_path):
    selected = tmp_path / "selected.ts"
    missed_mts = tmp_path / "missed.mts"
    missed_cts = tmp_path / "missed.cts"
    for source in (selected, missed_mts, missed_cts):
        source.write_text("eval(input);\n", encoding="utf-8")
    report = _clean_report()
    report.files_scanned = 1
    report.scanned_paths = (str(selected),)
    report.language_counts = {"TypeScript": 1}

    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=report),
    ):
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--include-experimental", "--fail-on", "error"],
            obj=_make_obj("json"),
        )

    payload = json.loads(result.output)
    assert result.exit_code == _SAST_DEGRADED_EXIT_CODE
    assert payload["unanalysed_language_counts"] == {"TypeScript": 2}
    assert {item["reason"] for item in payload["unanalysed_files"]} == {
        "engine_not_selected"
    }
    assert {item["path"] for item in payload["unanalysed_files"]} == {
        "missed.mts",
        "missed.cts",
    }


def test_explicit_exclude_is_not_reported_as_degraded_coverage(runner, tmp_path):
    python_file = tmp_path / "app.py"
    java_file = tmp_path / "ignored.java"
    python_file.write_text("print('clean')\n", encoding="utf-8")
    java_file.write_text("class Ignored {}\n", encoding="utf-8")
    report = _clean_report()
    report.files_scanned = 1
    report.scanned_paths = (str(python_file),)

    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=report),
    ):
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--exclude", "*.java", "--fail-on", "error"],
            obj=_make_obj("json"),
        )

    payload = json.loads(result.output)
    assert result.exit_code == 0
    assert payload["coverage_degraded"] is False
    assert payload["unanalysed_file_count"] == 0


# --- exit 27 with --fail-on matching a finding severity ---


def test_fail_on_exits_27_when_threshold_matched(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_report_with_findings("warning")),
    ):
        result = runner.invoke(
            code_check, [str(tmp_path), "--fail-on", "warning"], obj=_make_obj("text")
        )
    assert result.exit_code == _SAST_EXIT_CODE


def test_fail_on_exits_zero_when_below_threshold(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_report_with_findings("note")),
    ):
        result = runner.invoke(
            code_check, [str(tmp_path), "--fail-on", "error"], obj=_make_obj("text")
        )
    assert result.exit_code == 0


def test_fail_on_exits_nonzero_when_scan_failed(runner, tmp_path):
    # A failed scan must not pass a gated run.
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_failed_report()),
    ):
        result = runner.invoke(
            code_check, [str(tmp_path), "--fail-on", "note"], obj=_make_obj("text")
        )
    assert result.exit_code == 1
    assert "Scan failed" in (result.output + (result.stderr or ""))


def test_no_fail_on_still_fails_when_scan_failed(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_failed_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 1
    assert "Scan failed" in result.output


# --- CWE parsed from tags ---


def test_cwe_appears_in_text_output(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_report_with_findings("error")),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0
    assert "CWE-89" in result.output


def test_cwe_in_json_output(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_report_with_findings("error")),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("json"))
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["findings"][0]["cwe_list"] == [
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
    ]


# --- --upload refusal on failed scan ---


def test_upload_refused_when_scan_failed(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_failed_report()),
        patch("cra_evidence_cli.client.CRAEvidenceClient") as client_cls,
    ):
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--upload", "--product", "p", "--version", "1.0"],
            obj=_make_obj("text"),
        )
    # A failed scan with --upload must fail loudly, not exit 0, and must not
    # attempt to build the client or contact the API.
    assert result.exit_code != 0
    combined = result.output + (result.stderr or "")
    assert "cannot upload" in combined
    client_cls.assert_not_called()


# --- 10 MiB preflight refusal ---


def test_upload_refused_when_sarif_over_10mb(runner, tmp_path):
    padding = "x" * (11 * 1024 * 1024)
    big_sarif = {"version": "2.1.0", "runs": [], "padding": padding}
    big_report = SASTReport(
        engine_version="1.25.0",
        rules_path="/rules",
        rule_count=8,
        findings=[],
        scan_failed=False,
        failure_reason=None,
        sarif_raw=big_sarif,
    )
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=big_report),
        patch("cra_evidence_cli.commands.code_check.validate_config"),
        patch(
            "cra_evidence_cli.commands.code_check.resolve_identity",
            return_value=("prod", "1.0", None),
        ),
        patch("cra_evidence_cli.client.CRAEvidenceClient") as client_cls,
    ):
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--upload", "--product", "prod", "--version", "1.0"],
            obj=_make_obj("text"),
        )
    # Oversized SARIF must fail loudly and never reach the client.
    assert result.exit_code != 0
    combined = result.output + (result.stderr or "")
    assert "10 MiB" in combined or "exceeds" in combined
    client_cls.assert_not_called()


# --- sast alias ---


def test_sast_alias_is_registered(runner, tmp_path):
    with patch(_OPENGREP_PATCH, return_value=None):
        result = runner.invoke(cli, ["sast", str(tmp_path)])
    assert result.exit_code == 1
    assert OPENGREP_INSTALL_HINT in (result.output + (result.stderr or ""))


def test_sast_alias_is_same_command_as_code_check(runner, tmp_path):
    with patch(_OPENGREP_PATCH, return_value=None):
        r1 = runner.invoke(cli, ["code-check", str(tmp_path)])
        r2 = runner.invoke(cli, ["sast", str(tmp_path)])
    assert r1.exit_code == r2.exit_code == 1


# --- no-key list includes both names ---


def test_no_key_list_includes_code_check(monkeypatch):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    r = CliRunner()
    with (
        r.isolated_filesystem(),
        patch(_OPENGREP_PATCH, return_value=None),
    ):
        result = r.invoke(cli, ["code-check", "."])
    assert result.exit_code == 1
    assert "API key is required" not in (result.output + (result.stderr or ""))


def test_no_key_list_includes_sast(monkeypatch):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    r = CliRunner()
    with (
        r.isolated_filesystem(),
        patch(_OPENGREP_PATCH, return_value=None),
    ):
        result = r.invoke(cli, ["sast", "."])
    assert result.exit_code == 1
    assert "API key is required" not in (result.output + (result.stderr or ""))


# --- SARIF parsing against the real Opengrep output shape ---

# Opengrep 1.25.0 omits "level" on results; the level lives on the rule's
# defaultConfiguration. Results carry fingerprints["matchBasedId/v1"] and the
# CWE only as a rule tag string.
_REAL_SHAPE_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "invocations": [
                {"executionSuccessful": True, "toolExecutionNotifications": []}
            ],
            "tool": {
                "driver": {
                    "name": "Opengrep OSS",
                    "semanticVersion": "1.25.0",
                    "rules": [
                        {
                            "id": "cra-python-sql-injection",
                            "defaultConfiguration": {"level": "error"},
                            "properties": {
                                "precision": "very-high",
                                "tags": [
                                    (
                                        "CWE-89: Improper Neutralization of Special"
                                        " Elements used in an SQL Command"
                                    ),
                                    "HIGH CONFIDENCE",
                                    "security",
                                ],
                            },
                        },
                        {
                            "id": "cra-go-weak-hash",
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {
                                "tags": ["CWE-328: Use of Weak Hash", "security"]
                            },
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "cra-python-sql-injection",
                    "message": {"text": "String formatting in SQL execute() call."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app.py"},
                                "region": {"startLine": 6},
                            }
                        }
                    ],
                    "fingerprints": {"matchBasedId/v1": "aaa_0"},
                    "properties": {},
                },
                {
                    "ruleId": "cra-go-weak-hash",
                    "message": {"text": "MD5 is a broken hash."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "main.go"},
                                "region": {"startLine": 9},
                            }
                        }
                    ],
                    "fingerprints": {"matchBasedId/v1": "bbb_0"},
                    "properties": {},
                },
            ],
        }
    ],
}


def test_parse_sarif_takes_level_from_rule_default_configuration():
    from cra_evidence_cli.local.sast_scanner import _parse_sarif

    findings = _parse_sarif(_REAL_SHAPE_SARIF)
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["cra-python-sql-injection"].severity == "error"
    assert by_rule["cra-go-weak-hash"].severity == "warning"


def test_parse_sarif_real_shape_fingerprint_and_cwe():
    from cra_evidence_cli.local.sast_scanner import _parse_sarif

    findings = _parse_sarif(_REAL_SHAPE_SARIF)
    assert [f.fingerprint for f in findings] == ["aaa_0", "bbb_0"]
    assert findings[0].cwe_list == [
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
    ]
    assert findings[0].line == 6


def test_parse_sarif_explicit_result_level_wins_over_rule_default():
    import copy

    from cra_evidence_cli.local.sast_scanner import _parse_sarif

    doc = copy.deepcopy(_REAL_SHAPE_SARIF)
    doc["runs"][0]["results"][1]["level"] = "note"
    findings = _parse_sarif(doc)
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["cra-go-weak-hash"].severity == "note"


def test_fail_on_error_gates_real_shape_findings(runner, tmp_path):
    from cra_evidence_cli.local.sast_scanner import _parse_sarif

    findings = _parse_sarif(_REAL_SHAPE_SARIF)
    report = SASTReport(
        engine_version="1.25.0",
        rules_path="/rules",
        rule_count=2,
        findings=findings,
        scan_failed=False,
        failure_reason=None,
        sarif_raw=_REAL_SHAPE_SARIF,
    )
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=report),
    ):
        result = runner.invoke(
            cli, ["code-check", str(tmp_path), "--fail-on", "error"], obj=_make_obj()
        )
    assert result.exit_code == _SAST_EXIT_CODE


# ---------------------------------------------------------------------------
# --- PATH argument that does not exist -> Click rejects it (exists=True) ---
# ---------------------------------------------------------------------------


def test_nonexistent_path_argument_fails(runner):
    result = runner.invoke(
        code_check,
        ["/nonexistent/path/that/cannot/exist"],
        obj=_make_obj("text"),
    )
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "") + str(result.exception or "")
    assert (
        "nonexistent" in combined.lower()
        or "invalid" in combined.lower()
        or "does not exist" in combined.lower()
    )


# ---------------------------------------------------------------------------
# --- --fail-on case sensitivity and invalid choices ---
# ---------------------------------------------------------------------------


def test_fail_on_case_insensitive_upper(runner, tmp_path):
    """Click Choice is case_sensitive=False; ERROR is accepted."""
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_report_with_findings("error")),
    ):
        result = runner.invoke(
            code_check, [str(tmp_path), "--fail-on", "ERROR"], obj=_make_obj("text")
        )
    assert result.exit_code == _SAST_EXIT_CODE


def test_fail_on_invalid_choice_rejected(runner, tmp_path):
    result = runner.invoke(
        code_check, [str(tmp_path), "--fail-on", "critical"], obj=_make_obj("text")
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# --- --output json shape; --output sarif emits raw SARIF ---
# ---------------------------------------------------------------------------


def test_output_json_shape_and_valid_parse(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("json"))
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "scan_failed" in data
    assert "findings" in data
    assert "engine" in data
    assert "rule_count" in data
    assert isinstance(data["findings"], list)


def test_output_sarif_is_valid_json(runner, tmp_path):
    report = _clean_report()
    report.language_counts = {"Python": 2}
    report.sarif_raw = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Opengrep"}}, "results": []}],
    }
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=report),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("sarif"))
    assert result.exit_code == 0
    doc = json.loads(result.output)
    assert "version" in doc or "runs" in doc
    properties = doc["runs"][0]["tool"]["driver"]["properties"]
    assert properties["craEvidenceLanguageCounts"] == {"Python": 2}
    assert "not an audit" in properties["advisory"]["code_check"]


# ---------------------------------------------------------------------------
# --- -o writes to file; message on stderr; file content matches stdout ---
# ---------------------------------------------------------------------------


def test_output_file_writes_content_and_prints_message(runner, tmp_path):
    out_file = tmp_path / "report.txt"
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
    ):
        result = runner.invoke(
            code_check,
            [str(tmp_path), "-o", str(out_file)],
            obj=_make_obj("text"),
        )
    assert result.exit_code == 0
    assert out_file.exists()
    file_content = out_file.read_text(encoding="utf-8")
    assert "Source code security check" in file_content
    # The "written to" notification must appear in the combined output.
    assert "report written" in result.output.lower()


# ---------------------------------------------------------------------------
# --- --upload without --product or --version -> clear error, no upload ---
# ---------------------------------------------------------------------------


def test_upload_without_product_and_version_errors(runner, tmp_path):
    """resolve_identity raises when product/version absent; upload must not proceed."""
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
        patch(
            "cra_evidence_cli.commands.code_check.resolve_identity",
            side_effect=CRAEvidenceError("product and version are required", exit_code=2),
        ),
        patch("cra_evidence_cli.client.CRAEvidenceClient") as mock_client,
    ):
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--upload"],
            obj=_make_obj("text"),
        )
    mock_client.assert_not_called()
    assert result.exit_code != 0 or "required" in (
        result.output + (result.stderr or "")
    ).lower()


# ---------------------------------------------------------------------------
# --- --upload when client raises -> nonzero exit, no traceback ---
# ---------------------------------------------------------------------------


def test_upload_client_error_gives_nonzero_exit_no_traceback(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
        patch("cra_evidence_cli.commands.code_check.validate_config"),
        patch(
            "cra_evidence_cli.commands.code_check.resolve_identity",
            return_value=("prod", "1.0", None),
        ),
        patch("cra_evidence_cli.client.CRAEvidenceClient") as mock_client_cls,
    ):
        mock_instance = MagicMock()
        mock_instance.upload_sarif = AsyncMock(
            side_effect=CRAEvidenceError("auth failed", exit_code=2)
        )
        mock_client_cls.return_value = mock_instance
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--upload", "--product", "prod", "--version", "1.0"],
            obj=_make_obj("text"),
        )
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "Traceback" not in combined


# ---------------------------------------------------------------------------
# --- Upload preflight at exact 10 MiB boundary (operator is >, not >=) ---
# ---------------------------------------------------------------------------


def test_upload_size_limit_constant_is_exactly_10mib():
    assert _UPLOAD_SIZE_LIMIT == 10 * 1024 * 1024


def test_upload_sarif_removes_source_and_environment_but_keeps_taint_flow(tmp_path):
    source = tmp_path / "src" / "app.py"
    report = _clean_report()
    report.scan_root = str(tmp_path / "src")
    report.sarif_raw = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "test-rule",
                                "fullDescription": {"text": "Static rule guidance"},
                            }
                        ]
                    }
                },
                "originalUriBaseIds": {"ROOT": {"uri": f"file://{tmp_path}/src/"}},
                "invocations": [
                    {
                        "commandLine": f"opengrep {tmp_path}/src",
                        "environmentVariables": {"TOKEN": "secret"},
                    }
                ],
                "results": [
                    {
                        "ruleId": "test-rule",
                        "message": {"text": "expanded SECRET_SOURCE expression"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": str(source)},
                                    "region": {"snippet": {"text": "secret source"}},
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "message": {"text": "SECRET_FLOW expression"},
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": str(source)
                                                        },
                                                        "region": {
                                                            "snippet": {
                                                                "text": "nested source"
                                                            }
                                                        },
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "relatedLocations": [
                            {
                                "message": {"text": "RELATED_SECRET"},
                                "physicalLocation": {
                                    "artifactLocation": {"uri": str(source)},
                                    "region": {"snippet": {"text": "related secret"}},
                                },
                            }
                        ],
                        "fixes": [
                            {
                                "description": {"text": "FIX_SECRET"},
                                "artifactChanges": [
                                    {
                                        "artifactLocation": {"uri": str(source)},
                                        "replacements": [
                                            {
                                                "insertedContent": {
                                                    "text": "replacement secret"
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ],
    }

    sanitized = _sanitized_sarif(report)
    serialized = json.dumps(sanitized)

    assert sanitized["runs"][0]["results"][0]["codeFlows"]
    assert "app.py" in serialized
    assert str(tmp_path) not in serialized
    assert "secret source" not in serialized
    assert "nested source" not in serialized
    assert "SECRET_SOURCE" not in serialized
    assert "SECRET_FLOW" not in serialized
    assert "RELATED_SECRET" not in serialized
    assert "FIX_SECRET" not in serialized
    assert "replacement secret" not in serialized
    assert "relatedLocations" not in serialized
    assert "fixes" not in serialized
    assert "Static rule guidance" in serialized
    assert "TOKEN" not in serialized


def test_upload_sarif_preserves_sanitized_degraded_coverage_status():
    report = _degraded_report()
    report.pack_version = "2.0.1"
    report.default_rule_count = 51
    report.experimental_rule_count = 0
    report.available_experimental_rule_count = 12
    report.rule_language_counts = {"python": 43}
    report.sarif_raw = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": "/secret/path"}}
                        ],
                    }
                ],
            }
        ],
    }

    sanitized = _sanitized_sarif(report)
    run = sanitized["runs"][0]
    notification = run["invocations"][0]["toolExecutionNotifications"][0]
    properties = run["tool"]["driver"]["properties"]
    assert notification["message"]["text"] == (
        "Coverage degraded: 1 file parse error(s)"
    )
    assert properties["craEvidenceCoverageDegraded"] is True
    assert properties["craEvidencePackVersion"] == "2.0.1"
    assert "/secret/path" not in json.dumps(sanitized)


def test_upload_exactly_at_limit_is_allowed(runner, tmp_path):
    """A SARIF payload of exactly 10 MiB must not be refused (operator is >)."""
    overhead = len(json.dumps({"payload": ""}, indent=2).encode("utf-8"))
    exact_doc = {"payload": "x" * (_UPLOAD_SIZE_LIMIT - overhead)}

    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
        patch("cra_evidence_cli.commands.code_check.validate_config"),
        patch(
            "cra_evidence_cli.commands.code_check.resolve_identity",
            return_value=("prod", "1.0", None),
        ),
        patch(
            "cra_evidence_cli.commands.code_check._sanitized_sarif",
            return_value=exact_doc,
        ),
        patch("cra_evidence_cli.client.CRAEvidenceClient") as mock_client_cls,
    ):
        mock_instance = MagicMock()
        mock_instance.upload_sarif = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_instance
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--upload", "--product", "prod", "--version", "1.0"],
            obj=_make_obj("text"),
        )
    combined = (result.output or "") + (result.stderr or "")
    assert result.exit_code == 0, combined
    assert "exceeds" not in combined
    assert "10 MiB" not in combined
    # The upload must actually happen at exactly the limit.
    mock_client_cls.assert_called_once()
    mock_instance.upload_sarif.assert_awaited_once()


def test_upload_one_byte_over_limit_is_refused(runner, tmp_path):
    overhead = len(json.dumps({"payload": ""}, indent=2).encode("utf-8"))
    over_doc = {"payload": "x" * (_UPLOAD_SIZE_LIMIT - overhead + 1)}

    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
        patch("cra_evidence_cli.commands.code_check.validate_config"),
        patch(
            "cra_evidence_cli.commands.code_check.resolve_identity",
            return_value=("prod", "1.0", None),
        ),
        patch(
            "cra_evidence_cli.commands.code_check._sanitized_sarif",
            return_value=over_doc,
        ),
        patch("cra_evidence_cli.client.CRAEvidenceClient") as mock_client_cls,
    ):
        mock_client_cls.return_value = MagicMock()
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--upload", "--product", "prod", "--version", "1.0"],
            obj=_make_obj("text"),
        )
    combined = (result.output or "") + (result.stderr or "")
    assert "exceeds" in combined or "10 MiB" in combined
    mock_client_cls.return_value.upload_sarif.assert_not_called()


# ---------------------------------------------------------------------------
# --- verbose flag includes honest notes ---
# ---------------------------------------------------------------------------


def test_verbose_flag_includes_honest_note(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
    ):
        result = runner.invoke(
            code_check, [str(tmp_path), "--verbose"], obj=_make_obj("text")
        )
    assert result.exit_code == 0
    assert "not an audit" in result.output


def test_default_text_includes_honest_note(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0
    assert "not an audit" in result.output


# ---------------------------------------------------------------------------
# --- sast alias with --fail-on gives identical exit to code-check ---
# ---------------------------------------------------------------------------


def test_sast_alias_fail_on_exit_matches_code_check(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_report_with_findings("error")),
    ):
        r_cc = runner.invoke(
            cli, ["code-check", str(tmp_path), "--fail-on", "error"], obj=_make_obj()
        )
        r_sast = runner.invoke(
            cli, ["sast", str(tmp_path), "--fail-on", "error"], obj=_make_obj()
        )
    assert r_cc.exit_code == r_sast.exit_code == _SAST_EXIT_CODE


# --- pack version display + --exclude-rule passthrough ---


def test_bundled_scan_shows_pack_version(runner, tmp_path):
    from cra_evidence_cli.local.rules_pack import PACK_VERSION

    report = _clean_report()
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=report) as run_scan_mock,
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0
    # Bundled rules used (no --rules) -> pack version stamped and shown.
    assert report.pack_version == PACK_VERSION
    assert f"pack {PACK_VERSION}" in result.output
    run_scan_mock.assert_called_once()


def test_custom_rules_omit_pack_version(runner, tmp_path):
    rules_dir = tmp_path / "myrules"
    rules_dir.mkdir()
    report = _clean_report()
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=report),
    ):
        result = runner.invoke(
            code_check, [str(tmp_path), "--rules", str(rules_dir)], obj=_make_obj("text")
        )
    assert result.exit_code == 0
    assert report.pack_version is None
    assert "pack " not in result.output


def test_exclude_rule_passed_through(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()) as run_scan_mock,
    ):
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--exclude-rule", "cra-go-weak-hash"],
            obj=_make_obj("text"),
    )
    assert result.exit_code == 0
    passed = run_scan_mock.call_args.kwargs["exclude_rules"]
    assert passed[0] == "cra-go-weak-hash"
    assert len(passed[1:]) == 41


# --- upload must not silently succeed when the engine is absent ---


def test_binary_missing_with_upload_fails_loudly(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=None),
        patch("cra_evidence_cli.client.CRAEvidenceClient") as client_cls,
    ):
        result = runner.invoke(
            code_check,
            [str(tmp_path), "--upload", "--product", "p", "--version", "1.0"],
            obj=_make_obj("text"),
        )
    assert result.exit_code != 0
    assert "cannot upload" in (result.output + (result.stderr or ""))
    client_cls.assert_not_called()


# --- custom rules omit pack_version from JSON ---


def test_custom_rules_json_omits_pack_version(runner, tmp_path):
    rules_dir = tmp_path / "myrules"
    rules_dir.mkdir()
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
    ):
        result = runner.invoke(
            code_check, [str(tmp_path), "--rules", str(rules_dir)], obj=_make_obj("json")
        )
    data = json.loads(result.output)
    assert "pack_version" not in data


def test_bundled_rules_json_includes_pack_version(runner, tmp_path):
    from cra_evidence_cli.local.rules_pack import PACK_VERSION

    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("json"))
    data = json.loads(result.output)
    assert data["pack_version"] == PACK_VERSION
