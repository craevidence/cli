"""CLI tests for the secrets-check command.

All tests use --no-git-history so they need no git binary. One test invokes the
full CLI group with no API key to confirm the command is available.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands.secrets import secrets_check
from cra_evidence_cli.config import CRAEvidenceConfig

AWS = "AKIAIOSFODNN7EXAMPLE"
ENT = "x7Kp2mQ9vL4nR8sT1wZ3"


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


def _project(tmp_path: Path, body: str) -> Path:
    (tmp_path / "app.py").write_text(body, encoding="utf-8")
    return tmp_path


def test_no_findings_text(runner, tmp_path):
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    result = runner.invoke(
        secrets_check, [str(tmp_path), "--no-git-history"], obj=_make_obj("text")
    )
    assert result.exit_code == 0, result.output
    assert "No candidate secrets matched" in result.output
    # The weakness-class mapping is verbose-only; the default stays concise.
    assert "helps review vulnerability exposure" not in result.output

    verbose = runner.invoke(
        secrets_check, [str(tmp_path), "--no-git-history", "-v"], obj=_make_obj("text")
    )
    assert "helps review vulnerability exposure" in verbose.output


def test_finding_listed_and_redacted(runner, tmp_path):
    _project(tmp_path, f'KEY = "{AWS}"\n')
    result = runner.invoke(
        secrets_check, [str(tmp_path), "--no-git-history"], obj=_make_obj("text")
    )
    assert result.exit_code == 0, result.output
    assert "aws-access-key-id" in result.output
    assert "working-tree" in result.output
    assert AWS not in result.output


def test_no_raw_secret_in_any_output(runner, tmp_path):
    _project(tmp_path, f'KEY = "{AWS}"\nx = "{ENT}"\n')
    for fmt in ("text", "json", "sarif"):
        result = runner.invoke(
            secrets_check, [str(tmp_path), "--no-git-history"], obj=_make_obj(fmt)
        )
        assert result.exit_code == 0, result.output
        assert AWS not in result.output, fmt
        assert ENT not in result.output, fmt


def test_json_output_schema_and_fields(runner, tmp_path):
    _project(tmp_path, f'KEY = "{AWS}"\n')
    result = runner.invoke(
        secrets_check, [str(tmp_path), "--no-git-history"], obj=_make_obj("json")
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["schema_version"] == "craevidence.secrets.v1"
    assert data["report"]["working_tree_hits"] == 1
    assert data["report"]["hits"][0]["detector"] == "aws-access-key-id"
    assert data["advisory"]["disclaimer"] == "Review before use."


def test_sarif_output_structure(runner, tmp_path):
    _project(tmp_path, f'KEY = "{AWS}"\n')
    result = runner.invoke(
        secrets_check, [str(tmp_path), "--no-git-history"], obj=_make_obj("sarif")
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    res0 = data["runs"][0]["results"][0]
    assert res0["ruleId"] == "SECRET-aws-access-key-id"
    assert res0["level"] == "warning"


def test_advisory_default_exits_zero_with_findings(runner, tmp_path):
    _project(tmp_path, f'KEY = "{AWS}"\n')
    result = runner.invoke(
        secrets_check, [str(tmp_path), "--no-git-history"], obj=_make_obj("text")
    )
    assert result.exit_code == 0, result.output


def test_fail_on_match_exits_18(runner, tmp_path):
    _project(tmp_path, f'KEY = "{AWS}"\n')
    result = runner.invoke(
        secrets_check,
        [str(tmp_path), "--no-git-history", "--fail-on-match"],
        obj=_make_obj("text"),
    )
    assert result.exit_code == 18, result.output


def test_fail_on_match_clean_exits_zero(runner, tmp_path):
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    result = runner.invoke(
        secrets_check,
        [str(tmp_path), "--no-git-history", "--fail-on-match"],
        obj=_make_obj("text"),
    )
    assert result.exit_code == 0, result.output


def test_output_file_written(runner, tmp_path):
    _project(tmp_path, f'KEY = "{AWS}"\n')
    out = tmp_path / "report" / "secrets.txt"
    result = runner.invoke(
        secrets_check,
        [str(tmp_path), "--no-git-history", "-o", str(out)],
        obj=_make_obj("text"),
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert AWS not in out.read_text(encoding="utf-8")


def test_command_runs_without_api_key(runner, tmp_path, monkeypatch):
    """Invoked through the full CLI group with no API key, secrets-check runs."""
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _project(tmp_path, "x = 1\n")
    result = runner.invoke(cli, ["secrets-check", str(tmp_path), "--no-git-history"])
    assert result.exit_code == 0, result.output
    assert "API key is required" not in result.output
    assert "Secret scan" in result.output


def test_unsupported_format_emits_notice(runner, tmp_path):
    """An unsupported output format triggers a stderr notice and falls back to text."""
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    result = runner.invoke(
        secrets_check,
        [str(tmp_path), "--no-git-history"],
        obj=_make_obj("markdown"),
    )
    assert result.exit_code == 0, result.output
    # The stderr notice must mention the unsupported format.
    combined = result.output
    assert "markdown" in combined
    assert "not supported" in combined
    # Falls back to text: the normal text header must appear.
    assert "Secret scan" in combined
