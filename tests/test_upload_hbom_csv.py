"""CLI tests for `upload-hbom` --file / --csv inputs."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

BASE_ENV = {
    "CRA_EVIDENCE_API_KEY": "test_key_123",
    "CRA_EVIDENCE_URL": "http://localhost:8000",
}


def _invoke(args, files=None):
    from cra_evidence_cli.cli import cli

    runner = CliRunner()
    with patch(
        "cra_evidence_cli.commands.upload.CRAEvidenceClient"
    ) as mock_client_cls, patch(
        "cra_evidence_cli.commands.upload.asyncio.run"
    ) as mock_run:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_run.return_value = {
            "artifact_id": "hbom-123",
            "artifact_type": "hbom",
            "product": {"name": "test", "created": False},
            "version": {"number": "1.0", "created": False},
            "component_count": 2,
        }
        with runner.isolated_filesystem():
            for name, content in (files or {}).items():
                Path(name).write_text(content, encoding="utf-8")
            result = runner.invoke(
                cli, ["upload-hbom", *args, "--no-ci-detect"], env=BASE_ENV
            )
        return result, mock_client


def test_file_and_csv_are_mutually_exclusive():
    result, _ = _invoke(
        ["--product", "p", "--version", "1.0", "--file", "h.json", "--csv", "p.csv"],
        files={"h.json": "{}", "p.csv": "name\nX\n"},
    )
    assert result.exit_code != 0
    assert "exactly one" in result.output.lower()


def test_neither_file_nor_csv_is_rejected():
    result, _ = _invoke(["--product", "p", "--version", "1.0"])
    assert result.exit_code != 0
    assert "exactly one" in result.output.lower()


def test_csv_path_is_passed_to_client():
    result, mock_client = _invoke(
        ["--product", "p", "--version", "1.0", "--csv", "parts.csv"],
        files={"parts.csv": "name,component_type\nESP32,processor\n"},
    )
    assert result.exit_code == 0, result.output
    mock_client.upload_hbom.assert_called_once()
    kwargs = mock_client.upload_hbom.call_args.kwargs
    assert Path(kwargs["file_path"]).name == "parts.csv"


def test_file_path_is_passed_to_client():
    result, mock_client = _invoke(
        ["--product", "p", "--version", "1.0", "--file", "hbom.json"],
        files={"hbom.json": "{}"},
    )
    assert result.exit_code == 0, result.output
    mock_client.upload_hbom.assert_called_once()
    kwargs = mock_client.upload_hbom.call_args.kwargs
    assert Path(kwargs["file_path"]).name == "hbom.json"


def test_csv_help_points_to_real_schema_sources():
    from click.testing import CliRunner

    from cra_evidence_cli.cli import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["upload-hbom", "--help"])

    assert result.exit_code == 0
    # The help must not advertise a template invocation that does not exist
    assert "--csv template" not in result.output
    # It points at real sources for the column schema instead
    assert "name column is required" in result.output
    assert "docs/account-commands.md" in result.output
