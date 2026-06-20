"""Tests for upload-sarif: command registration, upload contract, and Click validation."""
import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def base_env():
    return {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }


@pytest.fixture
def sarif_file(tmp_path):
    """Minimal valid SARIF 2.1.0 JSON file."""
    p = tmp_path / "results.sarif"
    p.write_text(json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "TestTool"}}, "results": []}],
    }))
    return p


class TestUploadSarifCommand:

    def test_command_registered(self, runner, base_env):
        """upload-sarif command appears in CLI help."""
        result = runner.invoke(cli, ["--help"], env=base_env)
        assert "upload-sarif" in result.output

    @patch("cra_evidence_cli.commands.upload.asyncio.run")
    @patch("cra_evidence_cli.commands.upload.CRAEvidenceClient")
    def test_upload_sarif_success(
        self, mock_client_class, mock_asyncio_run, runner, base_env, sarif_file
    ):
        """Successful SARIF upload with JSON output."""
        mock_asyncio_run.return_value = {
            "artifact_id": "abc-123",
            "artifact_type": "sarif",
            "product": {"name": "test", "slug": "test"},
            "version": {"number": "1.0.0"},
        }

        result = runner.invoke(
            cli,
            [
                "--output", "json", "upload-sarif",
                "--product", "test", "--version", "1.0.0", "--file", str(sarif_file),
            ],
            env=base_env,
        )
        assert result.exit_code == 0
        # asyncio.run should have been called with the upload coroutine
        mock_asyncio_run.assert_called_once()

    @patch("cra_evidence_cli.commands.upload.asyncio.run")
    @patch("cra_evidence_cli.commands.upload.CRAEvidenceClient")
    def test_upload_sarif_with_sarif_extension(
        self, mock_client_class, mock_asyncio_run, runner, base_env, tmp_path
    ):
        """Accepts .sarif file extension."""
        sarif = tmp_path / "scan.sarif"
        sarif.write_text("{}")
        mock_asyncio_run.return_value = {
            "artifact_id": "abc-123",
            "artifact_type": "sarif",
        }
        result = runner.invoke(
            cli,
            [
                "--output", "json", "upload-sarif",
                "--product", "test", "--version", "1.0.0", "--file", str(sarif),
            ],
            env=base_env,
        )
        assert result.exit_code == 0

    def test_upload_sarif_missing_product(self, runner, base_env, sarif_file):
        """Omitting --product causes a non-zero exit and mentions 'product' in output."""
        result = runner.invoke(
            cli,
            ["upload-sarif", "--version", "1.0.0", "--file", str(sarif_file)],
            env=base_env,
        )
        assert result.exit_code != 0
        assert "product" in result.output.lower() or "Missing" in result.output

    def test_upload_sarif_file_not_found(self, runner, base_env):
        """Non-existent file shows error.

        click.Path(exists=True) rejects paths that don't exist before
        the command handler runs, so this tests Click's built-in validation.
        """
        result = runner.invoke(
            cli,
            [
                "upload-sarif", "--product", "test", "--version", "1.0.0",
                "--file", "/nonexistent/scan.sarif",
            ],
            env=base_env,
        )
        assert result.exit_code != 0
