"""CLI tests for the code-check command. No network, no API key, no opengrep binary."""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands.code_check import _SAST_EXIT_CODE, _UPLOAD_SIZE_LIMIT, code_check
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.exceptions import CRAEvidenceError
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


# --- binary-missing path ---


def test_binary_missing_prints_hint_and_exits_zero(runner, tmp_path):
    with patch(_OPENGREP_PATCH, return_value=None):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0, result.output
    combined = result.output + (result.stderr or "")
    assert OPENGREP_INSTALL_HINT in combined
    assert "opengrep not found" in combined


def test_binary_missing_no_scan_failure_text(runner, tmp_path):
    with patch(_OPENGREP_PATCH, return_value=None):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0
    assert "Scan failed" not in result.output


def test_binary_missing_with_fail_on_does_not_pass_gate(runner, tmp_path):
    # A gated run must not silently succeed when the engine is absent.
    with patch(_OPENGREP_PATCH, return_value=None):
        result = runner.invoke(
            code_check, [str(tmp_path), "--fail-on", "error"], obj=_make_obj("text")
        )
    assert result.exit_code != 0
    assert "cannot evaluate the --fail-on gate" in (result.output + (result.stderr or ""))


# --- engine nonzero exit renders scan-failed, not clean ---


def test_scan_failed_shows_failure_reason(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_failed_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0, result.output
    assert "Scan failed" in result.output
    assert "engine exited 2" in result.output
    assert "No findings matched" not in result.output


def test_scan_failed_json_sets_scan_failed_true(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_failed_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("json"))
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["scan_failed"] is True
    assert data["findings"] == []


# --- advisory exit 0 with findings ---


def test_advisory_exit_zero_with_findings(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_report_with_findings("warning")),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0, result.output
    assert "cra-python-sql-injection" in result.output


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
    assert "refusing to pass" in (result.output + (result.stderr or ""))


def test_no_fail_on_stays_advisory_when_scan_failed(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_failed_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0
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
    assert result.exit_code == 0
    assert "opengrep not found" in (result.output + (result.stderr or ""))


def test_sast_alias_is_same_command_as_code_check(runner, tmp_path):
    with patch(_OPENGREP_PATCH, return_value=None):
        r1 = runner.invoke(cli, ["code-check", str(tmp_path)])
        r2 = runner.invoke(cli, ["sast", str(tmp_path)])
    assert r1.exit_code == r2.exit_code == 0


# --- no-key list includes both names ---


def test_no_key_list_includes_code_check(monkeypatch):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    r = CliRunner()
    with (
        r.isolated_filesystem(),
        patch(_OPENGREP_PATCH, return_value=None),
    ):
        result = r.invoke(cli, ["code-check", "."])
    assert result.exit_code == 0
    assert "API key is required" not in (result.output + (result.stderr or ""))


def test_no_key_list_includes_sast(monkeypatch):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    r = CliRunner()
    with (
        r.isolated_filesystem(),
        patch(_OPENGREP_PATCH, return_value=None),
    ):
        result = r.invoke(cli, ["sast", "."])
    assert result.exit_code == 0
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
                                    "CWE-89: Improper Neutralization of Special"
                                    " Elements used in an SQL Command",
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
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("sarif"))
    assert result.exit_code == 0
    doc = json.loads(result.output)
    assert "version" in doc or "runs" in doc


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


def test_upload_exactly_at_limit_is_allowed(runner, tmp_path):
    """A SARIF payload of exactly 10 MiB must not be refused (operator is >)."""
    exact_bytes = b"x" * _UPLOAD_SIZE_LIMIT

    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
        patch("cra_evidence_cli.commands.code_check.validate_config"),
        patch(
            "cra_evidence_cli.commands.code_check.resolve_identity",
            return_value=("prod", "1.0", None),
        ),
        patch(
            "cra_evidence_cli.commands.code_check._render_sarif",
            return_value=exact_bytes.decode("latin-1"),
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
    assert "exceeds" not in combined
    assert "10 MiB" not in combined


def test_upload_one_byte_over_limit_is_refused(runner, tmp_path):
    over_bytes = b"x" * (_UPLOAD_SIZE_LIMIT + 1)

    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
        patch("cra_evidence_cli.commands.code_check.validate_config"),
        patch(
            "cra_evidence_cli.commands.code_check.resolve_identity",
            return_value=("prod", "1.0", None),
        ),
        patch(
            "cra_evidence_cli.commands.code_check._render_sarif",
            return_value=over_bytes.decode("latin-1"),
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


def test_no_verbose_flag_omits_honest_note(runner, tmp_path):
    with (
        patch(_OPENGREP_PATCH, return_value=_BINARY),
        patch(_RUN_SCAN_PATCH, return_value=_clean_report()),
    ):
        result = runner.invoke(code_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0
    assert "not an audit" not in result.output


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


# ---------------------------------------------------------------------------
# C. Rules pack schema sanity
# ---------------------------------------------------------------------------

_RULES_DIR = Path(__file__).parent.parent / "cra_evidence_cli" / "local" / "rules"
_VALID_SEVERITIES = {"ERROR", "WARNING", "INFO"}
_CWE_PATTERN = re.compile(r"^CWE-\d+")


def _iter_rules():
    """Yield (file_path, rule_dict) for every rule in every YAML in the rules dir."""
    for yaml_file in sorted(_RULES_DIR.glob("*.yaml")):
        with yaml_file.open(encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict) or "rules" not in doc:
            continue
        for rule in doc["rules"]:
            yield yaml_file.name, rule


@pytest.mark.parametrize(("filename", "rule"), list(_iter_rules()))
def test_rule_id_starts_with_cra(filename, rule):
    assert str(rule.get("id", "")).startswith("cra-"), (
        f"{filename}: rule id {rule.get('id')!r} does not start with 'cra-'"
    )


@pytest.mark.parametrize(("filename", "rule"), list(_iter_rules()))
def test_rule_has_message(filename, rule):
    assert rule.get("message"), f"{filename}: rule {rule.get('id')!r} missing message"


@pytest.mark.parametrize(("filename", "rule"), list(_iter_rules()))
def test_rule_severity_in_allowed_set(filename, rule):
    sev = rule.get("severity")
    assert sev in _VALID_SEVERITIES, (
        f"{filename}: rule {rule.get('id')!r} severity {sev!r} not in {_VALID_SEVERITIES}"
    )


@pytest.mark.parametrize(("filename", "rule"), list(_iter_rules()))
def test_rule_languages_non_empty(filename, rule):
    langs = rule.get("languages")
    assert langs is not None, f"{rule.get('id')!r} missing languages"
    assert len(langs) > 0, f"{rule.get('id')!r} has empty languages"


@pytest.mark.parametrize(("filename", "rule"), list(_iter_rules()))
def test_rule_metadata_cwe_non_empty_and_valid_format(filename, rule):
    meta = rule.get("metadata") or {}
    cwe_list = meta.get("cwe")
    assert cwe_list is not None, f"{rule.get('id')!r} missing metadata.cwe"
    assert len(cwe_list) > 0, f"{rule.get('id')!r} metadata.cwe is empty"
    for entry in cwe_list:
        assert _CWE_PATTERN.match(str(entry)), (
            f"{filename}: rule {rule.get('id')!r} cwe entry {entry!r} does not match CWE-<digits>"
        )


@pytest.mark.parametrize(("filename", "rule"), list(_iter_rules()))
def test_rule_metadata_license_is_mit(filename, rule):
    meta = rule.get("metadata") or {}
    lic = meta.get("license")
    assert lic == "MIT", (
        f"{filename}: rule {rule.get('id')!r} metadata.license is {lic!r}, expected MIT"
    )


_VALID_MODES = {"taint"}


@pytest.mark.parametrize(("filename", "rule"), list(_iter_rules()))
def test_taint_rule_has_sources_and_sinks(filename, rule):
    """Rules with mode: taint must declare pattern-sources and pattern-sinks."""
    if rule.get("mode") not in _VALID_MODES:
        return
    rule_id = rule.get("id", "?")
    assert rule.get("pattern-sources"), (
        f"{filename}: taint rule {rule_id!r} missing pattern-sources"
    )
    assert rule.get("pattern-sinks"), (
        f"{filename}: taint rule {rule_id!r} missing pattern-sinks"
    )


# The Go rules adapted from dgryski/semgrep-go (MIT). Each MUST carry provenance.
_DGRYSKI_DERIVED_RULE_IDS = {
    "cra-go-hmac-timing",
    "cra-go-hmac-reused-hash",
    "cra-go-parseint-downcast",
    "cra-go-wrong-lock-unlock",
}


def test_dgryski_derived_rules_carry_origin_metadata():
    """Every dgryski-derived rule must declare its MIT origin (release gate)."""
    by_id = {rule.get("id"): rule for _, rule in _iter_rules()}
    missing = _DGRYSKI_DERIVED_RULE_IDS - set(by_id)
    assert not missing, f"expected dgryski-derived rules not found in the pack: {missing}"
    for rule_id in _DGRYSKI_DERIVED_RULE_IDS:
        origin = (by_id[rule_id].get("metadata") or {}).get("origin", "")
        assert "dgryski/semgrep-go" in origin, (
            f"rule {rule_id!r} origin {origin!r} must reference dgryski/semgrep-go"
        )
        assert "MIT" in origin, (
            f"rule {rule_id!r} origin {origin!r} must declare MIT"
        )


def _taint_rule_errors(rule: dict) -> list[str]:
    """Return schema errors for a taint rule (shared by the pack test and the guard)."""
    errors = []
    if rule.get("mode") == "taint":
        if not rule.get("pattern-sources"):
            errors.append("missing pattern-sources")
        if not rule.get("pattern-sinks"):
            errors.append("missing pattern-sinks")
    return errors


def test_malformed_taint_rule_missing_sinks_caught():
    """The taint-rule validator must reject a taint rule with no pattern-sinks."""
    bad_rule = {
        "id": "cra-test-bad-taint",
        "mode": "taint",
        "message": "test",
        "severity": "ERROR",
        "languages": ["python"],
        "metadata": {"cwe": ["CWE-89: test"], "license": "MIT"},
        "pattern-sources": [{"pattern": "input(...)"}],
        # pattern-sinks intentionally absent
    }
    assert "missing pattern-sinks" in _taint_rule_errors(bad_rule)
    # And a well-formed taint rule from the shipped pack produces no errors.
    good = next(
        rule for _, rule in _iter_rules() if rule.get("mode") == "taint"
    )
    assert _taint_rule_errors(good) == []
    # The guard from test_taint_rule_has_sources_and_sinks would catch this.
    assert bad_rule.get("mode") == "taint"
    assert bad_rule.get("pattern-sinks") is None
