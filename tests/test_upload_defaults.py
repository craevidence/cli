"""
Tests for CLI UX improvements: smart defaults and --source flag.

Tests:
- --create-product defaults to False (opt-in); --create-version defaults to True
- --create-product sets it to True
- Missing-product errors point at --create-product
- Rejected product creation points at --target-markets
- --source + --image mutual exclusivity
- No source provided raises UsageError
- generate_sbom_from_directory happy path + Syft not installed
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cra_evidence_cli import sbom_generator
from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands.upload import (
    clarify_product_not_found_error,
    clarify_target_markets_error,
    clarify_upload_error,
)
from cra_evidence_cli.exceptions import APIError
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


class TestCreateProductDefaultFalse:
    """--create-product defaults to False (opt-in); --create-version stays True."""

    def test_create_product_defaults_false(self, runner, base_env):
        """Without any --create-product flag, upload_sbom is called with
        create_product False and create_version True."""
        stub = {
            "artifact_id": "test", "artifact_type": "sbom",
            "product": {"name": "test", "created": False},
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
            assert kwargs["create_product"] is False
            assert kwargs["create_version"] is True

    def test_create_product_flag_sets_true(self, runner, base_env):
        """With --create-product --target-markets, upload_sbom is called with
        create_product True."""
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
                            "upload-sbom", "--product", "test", "--version", "1.0",
                            "--file", "sbom.json", "--create-product",
                            "--target-markets", "DE,FR,ES",
                        ],
                        env=base_env,
                    )

            mock_client.upload_sbom.assert_called_once()
            kwargs = mock_client.upload_sbom.call_args.kwargs
            assert kwargs["create_product"] is True
            assert kwargs["target_markets"] == "DE,FR,ES"

    def test_no_create_product_sets_false(self, runner, base_env):
        """--no-create-product/--no-create-version still work explicitly."""
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


class TestMissingProductErrorMentionsCreateProductFlag:
    """A missing-product error must point at --create-product, not the raw
    API form field name."""

    def test_clarify_product_not_found_error_rewrites_api_hint(self):
        api_message = (
            "Product 'ghost-product' not found. Set create_product=true to auto-create."
        )
        clarified = clarify_product_not_found_error(api_message)

        assert "--create-product" in clarified
        assert "--target-markets" in clarified
        assert "create_product=true" not in clarified

    def test_clarify_product_not_found_error_leaves_other_messages_untouched(self):
        message = "release_notes exceeds maximum length of 5000 characters."
        assert clarify_product_not_found_error(message) == message

    def test_upload_sbom_missing_product_without_flag_surfaces_create_product_hint(
        self, runner, base_env
    ):
        """upload-sbom against a missing product, without --create-product,
        surfaces an error that names the CLI flag that would fix it."""
        api_error = APIError(
            message=(
                "Product 'ghost-product' not found. "
                "Set create_product=true to auto-create."
            ),
            status_code=400,
        )
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            with patch(
                "cra_evidence_cli.commands.upload.asyncio.run", side_effect=api_error
            ):
                with runner.isolated_filesystem():
                    Path("sbom.json").write_text('{"components": []}')
                    result = runner.invoke(
                        cli,
                        [
                            "upload-sbom", "--product", "ghost-product",
                            "--version", "1.0", "--file", "sbom.json",
                        ],
                        env=base_env,
                    )

        assert result.exit_code == api_error.exit_code
        assert "--create-product" in result.output
        assert "create_product=true" not in result.output


TARGET_MARKETS_API_MESSAGE = (
    "target_markets is required to auto-create product 'ghost-product'. "
    "Provide comma-separated EU country codes (e.g. 'DE,FR,ES'). "
    "Alternatively, create the product manually in the UI and re-run without "
    "create_product, or use its slug or UUID."
)


class TestMissingTargetMarketsErrorMentionsCliFlags:
    """A rejected product creation must point at --target-markets, not the raw
    API form field names."""

    def test_clarify_target_markets_error_rewrites_field_names(self):
        clarified = clarify_target_markets_error(TARGET_MARKETS_API_MESSAGE)

        assert "--target-markets is required to create product" in clarified
        assert "re-run without --create-product" in clarified
        assert "target_markets" not in clarified
        assert "create_product" not in clarified
        # The country codes and product identifier survive the rewrite.
        assert "'DE,FR,ES'" in clarified
        assert "'ghost-product'" in clarified

    def test_clarify_target_markets_error_leaves_other_messages_untouched(self):
        message = "external_url exceeds maximum length of 512 characters."
        assert clarify_target_markets_error(message) == message

    def test_clarify_upload_error_covers_both_rewrites(self):
        not_found = (
            "Product 'ghost-product' not found. Set create_product=true to auto-create."
        )

        assert "--create-product" in clarify_upload_error(not_found)
        assert "--target-markets is required" in clarify_upload_error(
            TARGET_MARKETS_API_MESSAGE
        )

    def test_upload_sbom_surfaces_target_markets_flag_on_rejected_creation(
        self, runner, base_env
    ):
        """upload-sbom --create-product without target markets surfaces an
        error that names the CLI flag that would fix it."""
        api_error = APIError(message=TARGET_MARKETS_API_MESSAGE, status_code=400)
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            with patch(
                "cra_evidence_cli.commands.upload.asyncio.run", side_effect=api_error
            ):
                with runner.isolated_filesystem():
                    Path("sbom.json").write_text('{"components": []}')
                    result = runner.invoke(
                        cli,
                        [
                            "upload-sbom", "--product", "ghost-product",
                            "--version", "1.0", "--file", "sbom.json",
                            "--create-product",
                        ],
                        env=base_env,
                    )

        assert result.exit_code == api_error.exit_code
        assert "--target-markets" in result.output
        assert "target_markets is required" not in result.output


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


def test_docker_syft_fallback_uses_an_immutable_image_digest(tmp_path):
    output_path = tmp_path / "sbom.json"
    completed = MagicMock(
        returncode=0,
        stdout='{"bomFormat":"CycloneDX","components":[]}',
        stderr="",
    )

    with patch(
        "cra_evidence_cli.sbom_generator.subprocess.run",
        return_value=completed,
    ) as run:
        sbom_generator._generate_sbom_with_docker(
            "example/image:1.0",
            "cyclonedx",
            output_path,
        )

    command = run.call_args.args[0]
    syft_image = command[command.index("/var/run/docker.sock:/var/run/docker.sock") + 1]
    assert syft_image.startswith("anchore/syft:v1.50.0@sha256:")
    assert syft_image.endswith(
        "1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026"
    )
    assert output_path.read_text() == completed.stdout
