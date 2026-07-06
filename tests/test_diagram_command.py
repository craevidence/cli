"""
Tests for `craevidence upload-diagram`.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

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


def _mock_response():
    return {
        "artifact_id": "doc-abc",
        "artifact_type": "document",
        "product": {"name": "test", "created": False},
        "version": {"number": "1.0", "created": False},
    }


class TestUploadDiagram:
    def test_renders_via_mmdc_when_available(self, runner, base_env, tmp_path):
        with patch("cra_evidence_cli.commands.diagram.shutil.which") as which, \
             patch("cra_evidence_cli.commands.diagram._render_mermaid_to_png") as render, \
             patch("cra_evidence_cli.commands.diagram.CRAEvidenceClient") as client_cls, \
             patch("cra_evidence_cli.commands.diagram.asyncio.run") as run:
            which.return_value = "/usr/bin/mmdc"
            rendered_png = tmp_path / "out.png"
            rendered_png.write_bytes(b"\x89PNG")
            render.return_value = rendered_png
            mock_client = MagicMock()
            client_cls.return_value = mock_client
            run.return_value = _mock_response()

            with runner.isolated_filesystem():
                Path("architecture.mmd").write_text("graph TD; A-->B")
                result = runner.invoke(
                    cli,
                    [
                        "upload-diagram",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "architecture.mmd",
                        "--no-ci-detect",
                    ],
                    env=base_env,
                )

        assert result.exit_code == 0, result.output
        render.assert_called_once()
        mock_client.upload_document.assert_called_once()
        kwargs = mock_client.upload_document.call_args.kwargs
        assert kwargs["document_type"] == "architecture_diagram"
        assert kwargs["file_path"] == rendered_png

    def test_falls_back_to_raw_when_mmdc_missing(self, runner, base_env, tmp_path):
        with patch("cra_evidence_cli.commands.diagram.shutil.which") as which, \
             patch("cra_evidence_cli.commands.diagram._render_mermaid_to_png") as render, \
             patch("cra_evidence_cli.commands.diagram.CRAEvidenceClient") as client_cls, \
             patch("cra_evidence_cli.commands.diagram.asyncio.run") as run:
            which.return_value = None
            mock_client = MagicMock()
            client_cls.return_value = mock_client
            run.return_value = _mock_response()

            with runner.isolated_filesystem():
                src = Path("architecture.mmd")
                src.write_text("graph TD; A-->B")
                result = runner.invoke(
                    cli,
                    [
                        "upload-diagram",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "architecture.mmd",
                        "--no-ci-detect",
                    ],
                    env=base_env,
                )

        assert result.exit_code == 0, result.output
        assert "mmdc not found" in result.output
        render.assert_not_called()
        mock_client.upload_document.assert_called_once()
        kwargs = mock_client.upload_document.call_args.kwargs
        assert kwargs["document_type"] == "architecture_diagram"
        # File path should be the raw .mmd, not a rendered PNG.
        assert kwargs["file_path"].name == "architecture.mmd"

    def test_no_render_uploads_raw_even_when_mmdc_present(
        self, runner, base_env, tmp_path
    ):
        with patch("cra_evidence_cli.commands.diagram.shutil.which") as which, \
             patch("cra_evidence_cli.commands.diagram._render_mermaid_to_png") as render, \
             patch("cra_evidence_cli.commands.diagram.CRAEvidenceClient") as client_cls, \
             patch("cra_evidence_cli.commands.diagram.asyncio.run") as run:
            which.return_value = "/usr/bin/mmdc"
            mock_client = MagicMock()
            client_cls.return_value = mock_client
            run.return_value = _mock_response()

            with runner.isolated_filesystem():
                Path("architecture.mmd").write_text("graph TD; A-->B")
                result = runner.invoke(
                    cli,
                    [
                        "upload-diagram",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "architecture.mmd",
                        "--no-render",
                        "--no-ci-detect",
                    ],
                    env=base_env,
                )

        assert result.exit_code == 0, result.output
        render.assert_not_called()
        kwargs = mock_client.upload_document.call_args.kwargs
        assert kwargs["file_path"].name == "architecture.mmd"

    def test_non_mmd_extension_warns_but_proceeds(
        self, runner, base_env
    ):
        with patch("cra_evidence_cli.commands.diagram.shutil.which") as which, \
             patch("cra_evidence_cli.commands.diagram.CRAEvidenceClient") as client_cls, \
             patch("cra_evidence_cli.commands.diagram.asyncio.run") as run:
            which.return_value = None
            mock_client = MagicMock()
            client_cls.return_value = mock_client
            run.return_value = _mock_response()

            with runner.isolated_filesystem():
                Path("diagram.txt").write_text("graph TD; A-->B")
                result = runner.invoke(
                    cli,
                    [
                        "upload-diagram",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "diagram.txt",
                        "--no-ci-detect",
                    ],
                    env=base_env,
                )

        assert result.exit_code == 0, result.output
        assert "expected a .mmd file" in result.output

    def test_resolves_product_and_version_from_env(self, runner, base_env, tmp_path):
        """upload-diagram resolves --product and --version from CRA_EVIDENCE_PRODUCT/VERSION."""
        env = dict(base_env)
        env["CRA_EVIDENCE_PRODUCT"] = "env-product"
        env["CRA_EVIDENCE_VERSION"] = "3.0"

        with patch("cra_evidence_cli.commands.diagram.shutil.which") as which, \
             patch("cra_evidence_cli.commands.diagram.CRAEvidenceClient") as client_cls, \
             patch("cra_evidence_cli.commands.diagram.asyncio.run") as run:
            which.return_value = None
            mock_client = MagicMock()
            client_cls.return_value = mock_client
            run.return_value = _mock_response()

            with runner.isolated_filesystem():
                Path("architecture.mmd").write_text("graph TD; A-->B")
                result = runner.invoke(
                    cli,
                    [
                        "upload-diagram",
                        "--file", "architecture.mmd",
                        "--no-ci-detect",
                    ],
                    env=env,
                )

        assert result.exit_code == 0, result.output
        kwargs = mock_client.upload_document.call_args.kwargs
        assert kwargs["product"] == "env-product"
        assert kwargs["version"] == "3.0"

    def test_fails_without_product_or_env(self, runner, base_env):
        """upload-diagram fails with a clear error when product cannot be resolved."""
        env = dict(base_env)
        env.pop("CRA_EVIDENCE_PRODUCT", None)

        with runner.isolated_filesystem():
            Path("architecture.mmd").write_text("graph TD; A-->B")
            result = runner.invoke(
                cli,
                [
                    "upload-diagram",
                    "--file", "architecture.mmd",
                    "--no-ci-detect",
                ],
                env=env,
            )

        assert result.exit_code != 0
        assert "Product is required" in result.output or "Error" in result.output

    def test_module_docstring_cites_annex_vii(self):
        """Module docstring must cite Annex VII (not Annex II) for architecture requirement."""
        import cra_evidence_cli.commands.diagram as diagram_mod

        assert "Annex VII" in (diagram_mod.__doc__ or "")
        assert "Annex II" not in (diagram_mod.__doc__ or "")
