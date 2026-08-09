"""
Tests for CLI UX improvements: smart defaults and --source flag.

Tests:
- --create-product defaults to False (opt-in); --create-version defaults to True
- --create-product sets it to True
- Missing-product errors point at --create-product
- Rejected product creation points at --target-markets
- --source + --image mutual exclusivity
- No source provided raises UsageError
- generate_sbom_from_directory happy path + incompatible engine
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
from cra_evidence_cli.engine import EngineIdentity, EngineInspection
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

    def test_compatible_engine_not_installed(self, tmp_path):
        with patch(
            "cra_evidence_cli.sbom_generator.inspect_engine",
            return_value=EngineInspection(None, "the CRA Evidence engine is not installed"),
        ):
            with pytest.raises(SBOMGenerationError, match="compatible CRA Evidence engine"):
                generate_sbom_from_directory(str(tmp_path))

    def test_happy_path(self, tmp_path):
        """Successful directory scan should return SBOMGenerationResult."""
        sbom_data = {"components": [{"name": "pkg-a"}, {"name": "pkg-b"}]}

        with patch(
            "cra_evidence_cli.sbom_generator._generate_sbom_with_engine"
        ) as mock_engine:
            def write_sbom(source, fmt, output_path, verbose=False, offline=False):
                output_path.write_text(json.dumps(sbom_data))

            mock_engine.side_effect = write_sbom
            result = generate_sbom_from_directory(str(tmp_path))

        assert result.component_count == 2
        assert result.format_type == "cyclonedx"
        assert result.generation_method == "craevidence-grype"
        assert result.file_path.exists()

        mock_engine.assert_called_once()
        call_args = mock_engine.call_args
        assert call_args[0][0] == f"dir:{tmp_path}"

        # Cleanup
        result.file_path.unlink(missing_ok=True)


def test_engine_generation_uses_fork_sbom_command(tmp_path):
    output_path = tmp_path / "sbom.json"
    completed = type("Completed", (), {
        "returncode": 0,
        "stdout": "",
        "stderr": "",
    })()
    identity = EngineIdentity(
        path="/opt/bin/grype",
        version="craevidence-v0.116.1-p3",
        syft_version="1.50.0",
    )

    with patch(
        "cra_evidence_cli.sbom_generator.inspect_engine",
        return_value=EngineInspection(identity, ""),
    ), patch(
        "cra_evidence_cli.sbom_generator.subprocess.run",
        return_value=completed,
    ) as run:
        sbom_generator._generate_sbom_with_engine(
            "dir:/workspace",
            "cyclonedx",
            output_path,
            offline=True,
        )

    assert run.call_args.args[0] == [
        "/opt/bin/grype",
        "sbom",
        "dir:/workspace",
        "--output",
        "cyclonedx-json",
        "--file",
        str(output_path),
        "--offline",
    ]
    assert run.call_args.kwargs["env"]["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"


def test_stock_grype_is_not_used_for_generation(tmp_path):
    output_path = tmp_path / "sbom.json"
    with patch(
        "cra_evidence_cli.sbom_generator.inspect_engine",
        return_value=EngineInspection(
            None,
            "stock or unstamped Grype is not a supported engine",
        ),
    ), patch("cra_evidence_cli.sbom_generator.subprocess.run") as run:
        with pytest.raises(SBOMGenerationError, match="stock or unstamped Grype"):
            sbom_generator._generate_sbom_with_engine(
                "example/image:1.0",
                "cyclonedx",
                output_path,
            )

    run.assert_not_called()
