"""
Tests for CLI UX improvements: smart defaults and --source flag.

Tests:
- --create-product defaults to True
- --no-create-product sets it to False
- --source + --image mutual exclusivity
- No source provided raises UsageError
- generate_sbom_from_directory happy path + Syft not installed
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.sbom_generator import (
    SBOMGenerationError,
    generate_sbom_from_directory,
)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def base_env():
    return {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }


class TestCreateProductDefaultTrue:
    """Test that --create-product and --create-version default to True."""

    def test_create_product_defaults_true(self, runner, base_env):
        """Without the --no-create-* flags, upload_sbom is called with
        create_product/create_version True."""
        stub = {
            "artifact_id": "test", "artifact_type": "sbom",
            "product": {"name": "test", "created": True},
            "version": {"number": "1.0", "created": True},
        }
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.upload_sbom = MagicMock(return_value=stub)
            mock_client_cls.return_value = mock_client

            with patch("cra_evidence_cli.commands.upload.asyncio.run", return_value=stub):
                with runner.isolated_filesystem():
                    Path("sbom.json").write_text('{"components": []}')
                    runner.invoke(
                        cli,
                        [
                            "upload-sbom", "--product", "test",
                            "--version", "1.0", "--file", "sbom.json",
                        ],
                        env=base_env,
                    )

            mock_client.upload_sbom.assert_called_once()
            kwargs = mock_client.upload_sbom.call_args.kwargs
            assert kwargs["create_product"] is True
            assert kwargs["create_version"] is True

    def test_no_create_product_sets_false(self, runner, base_env):
        """With --no-create-product/--no-create-version, upload_sbom is called with both False."""
        stub = {
            "artifact_id": "test", "artifact_type": "sbom",
            "product": {"name": "test", "created": False},
            "version": {"number": "1.0", "created": False},
        }
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.upload_sbom = MagicMock(return_value=stub)
            mock_client_cls.return_value = mock_client

            with patch("cra_evidence_cli.commands.upload.asyncio.run", return_value=stub):
                with runner.isolated_filesystem():
                    Path("sbom.json").write_text('{"components": []}')
                    runner.invoke(
                        cli,
                        [
                            "upload-sbom", "--product", "test", "--version", "1.0",
                            "--file", "sbom.json", "--no-create-product", "--no-create-version",
                        ],
                        env=base_env,
                    )

            mock_client.upload_sbom.assert_called_once()
            kwargs = mock_client.upload_sbom.call_args.kwargs
            assert kwargs["create_product"] is False
            assert kwargs["create_version"] is False


class TestSourceMutualExclusivity:
    """Test that --file, --image, and --source are mutually exclusive."""

    def test_source_and_image_rejected(self, runner, base_env, tmp_path):
        """--source + --image should fail."""
        result = runner.invoke(
            cli,
            [
                "upload-sbom", "--product", "test", "--version", "1.0",
                "--source", str(tmp_path), "--image", "nginx:latest",
            ],
            env=base_env,
        )
        assert result.exit_code != 0
        assert "Only one of" in result.output

    def test_source_and_file_rejected(self, runner, base_env, tmp_path):
        """--source + --file should fail."""
        with runner.isolated_filesystem():
            Path("sbom.json").write_text('{"components": []}')
            result = runner.invoke(
                cli,
                [
                    "upload-sbom", "--product", "test", "--version", "1.0",
                    "--source", str(tmp_path), "--file", "sbom.json",
                ],
                env=base_env,
            )
        assert result.exit_code != 0
        assert "Only one of" in result.output

    def test_no_source_provided(self, runner, base_env):
        """No --file, --image, or --source should fail."""
        result = runner.invoke(
            cli,
            ["upload-sbom", "--product", "test", "--version", "1.0"],
            env=base_env,
        )
        assert result.exit_code != 0
        assert "One of --file, --image, or --source is required" in result.output


class TestGenerateSbomFromDirectory:
    """Test generate_sbom_from_directory function."""

    def test_directory_not_found(self):
        """Non-existent directory should raise SBOMGenerationError."""
        with pytest.raises(SBOMGenerationError, match="does not exist"):
            generate_sbom_from_directory("/nonexistent/path")

    def test_unsupported_format(self, tmp_path):
        """Unsupported format should raise SBOMGenerationError."""
        with pytest.raises(SBOMGenerationError, match="Unsupported format"):
            generate_sbom_from_directory(str(tmp_path), output_format="xml")

    def test_syft_not_installed(self, tmp_path):
        """Missing Syft should raise SBOMGenerationError with install instructions."""
        with patch("cra_evidence_cli.sbom_generator.check_syft_installed", return_value=False):
            with pytest.raises(SBOMGenerationError, match="Syft is not installed"):
                generate_sbom_from_directory(str(tmp_path))

    def test_happy_path(self, tmp_path):
        """Successful directory scan should return SBOMGenerationResult."""
        sbom_data = {"components": [{"name": "pkg-a"}, {"name": "pkg-b"}]}

        with patch("cra_evidence_cli.sbom_generator.check_syft_installed", return_value=True):
            with patch(
                "cra_evidence_cli.sbom_generator._generate_sbom_with_local_syft"
            ) as mock_syft:
                def write_sbom(image, fmt, output_path, verbose=False, offline=False):
                    output_path.write_text(json.dumps(sbom_data))

                mock_syft.side_effect = write_sbom

                result = generate_sbom_from_directory(str(tmp_path))

        assert result.component_count == 2
        assert result.format_type == "cyclonedx"
        assert result.generation_method == "syft"
        assert result.file_path.exists()

        # Verify dir: prefix was passed to syft
        mock_syft.assert_called_once()
        call_args = mock_syft.call_args
        assert call_args[0][0] == f"dir:{tmp_path}"

        # Cleanup
        result.file_path.unlink(missing_ok=True)
