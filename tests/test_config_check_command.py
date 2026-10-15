"""CLI tests for the config-check command. No network, no API key."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands.config_check import config_check
from cra_evidence_cli.config import CRAEvidenceConfig


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


def _bad_dockerfile(tmp_path: Path) -> Path:
    (tmp_path / "Dockerfile").write_text("FROM alpine\nUSER root\n", encoding="utf-8")
    return tmp_path


def test_no_findings_text(runner, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\nUSER app\n", encoding="utf-8")
    result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0, result.output
    assert "No curated misconfiguration patterns matched" in result.output
    assert "not a full IaC scanner" not in result.output

    verbose = runner.invoke(config_check, [str(tmp_path), "-v"], obj=_make_obj("text"))
    assert verbose.exit_code == 0, verbose.output
    assert "not a full IaC scanner" in verbose.output


def test_findings_listed_with_cra_point(runner, tmp_path):
    _bad_dockerfile(tmp_path)
    result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0, result.output
    assert "container-user-root" in result.output
    assert "(2)(b)" not in result.output


def test_json_output_schema_and_fields(runner, tmp_path):
    _bad_dockerfile(tmp_path)
    result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("json"))
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["schema_version"] == "craevidence.config_audit.v1"
    assert data["report"]["finding_count"] >= 1
    rules = {f["rule"] for f in data["report"]["findings"]}
    assert "container-user-root" in rules


def test_unreadable_config_is_reported_as_partial_in_text_and_json(
    runner, tmp_path, monkeypatch
):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine\nUSER root\n", encoding="utf-8")
    monkeypatch.setattr("cra_evidence_cli.local.config_audit._read_text", lambda _path: None)

    text_result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("text"))
    assert text_result.exit_code == 0, text_result.output
    assert "Files scanned: 0 | Skipped: 1" in text_result.output
    assert "results are partial" in text_result.output

    json_result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("json"))
    assert json_result.exit_code == 0, json_result.output
    report = json.loads(json_result.output)["report"]
    assert report["files_scanned"] == 0
    assert report["files_skipped"] == 1
    assert report["partial"] is True

    sarif_result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("sarif"))
    assert sarif_result.exit_code == 0, sarif_result.output
    run_properties = json.loads(sarif_result.output)["runs"][0]["properties"]
    assert run_properties == {"filesScanned": 0, "filesSkipped": 1, "partial": True}


def test_sarif_output_structure(runner, tmp_path):
    _bad_dockerfile(tmp_path)
    result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("sarif"))
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    rule_ids = {r["ruleId"] for r in data["runs"][0]["results"]}
    assert "CONFIG-container-user-root" in rule_ids


def test_sarif_file_location_encodes_filesystem_path_characters(runner, tmp_path):
    config_file = tmp_path / "config #50%.yaml"
    config_file.write_text("privileged: true\n", encoding="utf-8")

    result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("sarif"))

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "config%20%2350%25.yaml"


def test_advisory_default_exits_zero_with_findings(runner, tmp_path):
    _bad_dockerfile(tmp_path)
    result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("text"))
    assert result.exit_code == 0, result.output


def test_fail_on_match_exits_19(runner, tmp_path):
    _bad_dockerfile(tmp_path)
    result = runner.invoke(
        config_check, [str(tmp_path), "--fail-on-match"], obj=_make_obj("text")
    )
    assert result.exit_code == 19, result.output


def test_fail_on_match_clean_exits_zero(runner, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\nUSER app\n", encoding="utf-8")
    result = runner.invoke(
        config_check, [str(tmp_path), "--fail-on-match"], obj=_make_obj("text")
    )
    assert result.exit_code == 0, result.output


def test_output_file_written(runner, tmp_path):
    _bad_dockerfile(tmp_path)
    out = tmp_path / "report" / "config.txt"
    result = runner.invoke(
        config_check, [str(tmp_path), "-o", str(out)], obj=_make_obj("text")
    )
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_command_runs_without_api_key(runner, tmp_path, monkeypatch):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    (tmp_path / "Dockerfile").write_text("FROM alpine\nUSER app\n", encoding="utf-8")
    result = runner.invoke(cli, ["config-check", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "API key is required" not in result.output
    assert "Secure-by-default configuration audit" in result.output


def test_unsupported_format_emits_notice(runner, tmp_path):
    """An unsupported output format triggers a stderr notice and falls back to text."""
    (tmp_path / "Dockerfile").write_text("FROM alpine\nUSER app\n", encoding="utf-8")
    result = runner.invoke(config_check, [str(tmp_path)], obj=_make_obj("markdown"))
    assert result.exit_code == 0, result.output
    combined = result.output
    assert "markdown" in combined
    assert "not supported" in combined
    assert "Secure-by-default configuration audit" in combined
