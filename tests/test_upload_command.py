(
    "Tests for upload command: threshold logic, output rendering, "
    "and structured evidence guardrails."
)

from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

from cra_evidence_cli.commands import upload as upload_module
from cra_evidence_cli.commands.upload import (
    check_vulnerability_threshold,
    enforce_structured_mapping,
    format_output,
)
from cra_evidence_cli.exceptions import (
    StructuredEvidenceMappingRequired,
    VulnerabilityThresholdExceeded,
)

# Fixtures - mock upload responses matching CIUploadResponse schema


@pytest.fixture
def upload_response():
    """A successful upload response with scan results."""
    return {
        "artifact_id": "abc123",
        "artifact_type": "sbom",
        "product": {
            "id": "prod-123",
            "name": "My Product",
            "slug": "my-product",
            "created": False,
        },
        "version": {
            "id": "ver-456",
            "number": "1.2.3",
            "created": True,
            "cra_status": "incomplete",
            "release_state": "draft",
            "environment": "production",
        },
        "quality_score": 85,
        "component_count": 142,
        "vulnerability_count": None,
        "scan_results": {
            "status": "completed",
            "vulnerabilities": {
                "critical": 0,
                "high": 2,
                "medium": 5,
                "low": 12,
            },
        },
        "warnings": ["Created new version: 1.2.3"],
        "message": "SBOM uploaded successfully",
    }


@pytest.fixture
def upload_response_no_scan():
    """Upload response without scan results."""
    return {
        "artifact_id": "abc123",
        "artifact_type": "sbom",
        "product": {
            "id": "prod-123",
            "name": "My Product",
            "slug": "my-product",
            "created": True,
        },
        "version": {
            "id": "ver-456",
            "number": "1.0.0",
            "created": True,
            "cra_status": "incomplete",
            "release_state": "draft",
            "environment": "production",
        },
        "quality_score": 72,
        "component_count": 50,
        "vulnerability_count": None,
        "scan_results": None,
        "warnings": [],
        "message": "SBOM uploaded successfully",
    }


def _extract_vulns(response: dict) -> dict:
    """Extract vulnerability summary from a full upload response."""
    scan_results = response.get("scan_results") or {}
    return scan_results.get("vulnerabilities") or {}


# check_vulnerability_threshold tests


class TestCheckVulnerabilityThreshold:
    """Tests for upload-time vulnerability threshold checking."""

    def test_no_fail_on(self, upload_response):
        """No --fail-on → never raises."""
        check_vulnerability_threshold(_extract_vulns(upload_response), "none")

    def test_no_scan_results(self, upload_response_no_scan):
        """No scan results → threshold check is skipped."""
        check_vulnerability_threshold(_extract_vulns(upload_response_no_scan), "critical")

    def test_critical_threshold_passes(self, upload_response):
        """--fail-on critical passes when no critical vulns."""
        check_vulnerability_threshold(_extract_vulns(upload_response), "critical")

    def test_high_threshold_fails(self, upload_response):
        """--fail-on high fails when high vulns > 0."""
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_vulnerability_threshold(_extract_vulns(upload_response), "high")
        assert exc_info.value.severity == "high"
        assert exc_info.value.exit_code == 11

    def test_medium_threshold_fails(self, upload_response):
        """--fail-on medium fails when high vulns > 0 (cascade)."""
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_vulnerability_threshold(_extract_vulns(upload_response), "medium")
        # Should fail on high first (higher severity takes priority)
        assert exc_info.value.severity == "high"

    def test_critical_threshold_with_critical_vulns(self):
        """--fail-on critical fails when critical vulns > 0."""
        vulns = {
            "critical": 3,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_vulnerability_threshold(vulns, "critical")
        assert exc_info.value.exit_code == 10
        assert exc_info.value.count == 3


# format_output tests (basic rendering)


class TestFormatOutput:
    """Tests for format_output rendering."""

    def test_json_output(self, upload_response):
        """JSON format renders without raising."""
        format_output(upload_response, "json")

    def test_text_output(self, upload_response):
        """Text format renders without raising."""
        format_output(upload_response, "text")

    def test_text_output_renders_package_and_component_attribution_rows(
        self, upload_response, monkeypatch
    ):
        """Text output must expose component attribution and package count."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=120, color_system=None),
        )
        upload_response.update(
            {
                "component_slug": "firmware",
                "component_auto_created": True,
                "_component_repository": "https://github.com/acme/firmware",
            }
        )

        format_output(upload_response, "text")

        rendered = out.getvalue()
        assert "Packages" in rendered
        assert "142" in rendered
        assert "Attributed to component" in rendered
        assert "firmware (auto-created)" in rendered
        assert "Component repository" in rendered
        assert "https://github.com/acme/firmware" in rendered

    def test_text_output_no_scan(self, upload_response_no_scan):
        """Text format renders without raising when scan_results is None."""
        format_output(upload_response_no_scan, "text")

    def test_text_output_minimal(self):
        """Minimal dict with only artifact_type is handled without raising."""
        format_output({"artifact_type": "sbom"}, "text")

    def test_text_output_renders_structured_evidence_summary(
        self, upload_response, monkeypatch
    ):
        """Structured evidence reporting is visible in text output."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )
        upload_response.update(
            {
                "artifact_type": "document",
                "doc_type": "test_report",
                "gemara_source_download_url": (
                    "/api/v1/documents/abc123/gemara-source/download"
                ),
                "evidence_summary": {
                    "source": "gemara_export",
                    "format": "gemara_yaml",
                    "schema_type": "EvaluationLog",
                    "document_type": "test_report",
                    "parser_outcome": "accepted_and_mapped",
                    "mapped_fields": [
                        "annex_i_attestations.secure_by_default_confirmed"
                    ],
                    "manual_followups": [
                        "Review CRA status for legal, risk, supplier, and release items."
                    ],
                },
            }
        )

        format_output(upload_response, "text")

        rendered = out.getvalue()
        assert "Structured Evidence" in rendered
        assert "Compliance YAML (EvaluationLog)" in rendered
        assert "Mapped fields confirmed" in rendered
        assert "Secure by default confirmed" in rendered
        assert "Manual / review remaining" in rendered
        assert "Retained source" in rendered
        assert (
            "craevidence compliance-as-code download-source "
            "--document-id abc123 --output <output.yaml>"
        ) in rendered
        assert "/api/v1/documents/abc123/gemara-source/download" in rendered
        assert "does not reprocess YAML or update readiness state" in rendered

    def test_text_output_renders_document_only_structured_evidence_summary(
        self, upload_response, monkeypatch
    ):
        """Structured evidence output handles document-only results."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )
        upload_response.update(
            {
                "artifact_type": "document",
                "doc_type": "risk_assessment",
                "evidence_summary": {
                    "source": "gemara_export",
                    "format": "gemara_yaml",
                    "schema_type": "RiskCatalog",
                    "document_type": "risk_assessment",
                    "parser_outcome": "accepted_document_only",
                    "mapped_fields": [],
                    "manual_followups": [
                        "Stored as document evidence; no structured compliance "
                        "fields were auto-populated from this schema type."
                    ],
                },
            }
        )

        format_output(upload_response, "text")

        rendered = out.getvalue()
        assert "Document stored; no mapped fields confirmed" in rendered
        assert "Mapped fields" in rendered
        assert "none" in rendered
        assert "Stored as document evidence" in rendered

    def test_text_output_does_not_render_source_download_for_non_gemara_summary(
        self, upload_response, monkeypatch
    ):
        """Source download hint is limited to retained source YAML provenance."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )
        upload_response.update(
            {
                "artifact_type": "document",
                "doc_type": "test_report",
                "gemara_source_download_url": (
                    "/api/v1/documents/abc123/gemara-source/download"
                ),
                "evidence_summary": {
                    "source": "sarif_upload",
                    "format": "sarif_json",
                    "schema_type": "SARIF",
                    "document_type": "test_report",
                    "parser_outcome": "accepted_document_only",
                    "mapped_fields": [],
                    "manual_followups": [],
                },
            }
        )

        format_output(upload_response, "text")

        rendered = out.getvalue()
        assert "Structured Evidence" in rendered
        assert "Retained source" not in rendered
        assert "download-source" not in rendered

    @pytest.mark.parametrize(
        ("summary_source", "summary_format"),
        [
            ("sarif_upload", "gemara_yaml"),
            ("gemara_export", "sarif_json"),
        ],
    )
    def test_text_output_requires_both_gemara_source_and_format_for_download_hint(
        self, upload_response, monkeypatch, summary_source, summary_format
    ):
        """Both structured provenance markers are required before printing the hint."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )
        upload_response.update(
            {
                "artifact_type": "document",
                "doc_type": "test_report",
                "gemara_source_download_url": (
                    "/api/v1/documents/abc123/gemara-source/download"
                ),
                "evidence_summary": {
                    "source": summary_source,
                    "format": summary_format,
                    "schema_type": "EvaluationLog",
                    "document_type": "test_report",
                    "parser_outcome": "accepted_document_only",
                    "mapped_fields": [],
                    "manual_followups": [],
                },
            }
        )

        format_output(upload_response, "text")

        rendered = out.getvalue()
        assert "Structured Evidence" in rendered
        assert "Retained source" not in rendered
        assert "download-source" not in rendered

    def test_text_output_requires_document_id_for_gemara_source_download_hint(
        self, monkeypatch
    ):
        """Do not print a command unless the upload response contains a document ID."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )

        format_output(
            {
                "artifact_type": "document",
                "doc_type": "test_report",
                "gemara_source_download_url": (
                    "/api/v1/documents/abc123/gemara-source/download"
                ),
                "evidence_summary": {
                    "source": "gemara_export",
                    "format": "gemara_yaml",
                    "schema_type": "EvaluationLog",
                    "document_type": "test_report",
                    "parser_outcome": "accepted_document_only",
                    "mapped_fields": [],
                    "manual_followups": [],
                },
            },
            "text",
        )

        rendered = out.getvalue()
        assert "Structured Evidence" in rendered
        assert "Retained source" not in rendered
        assert "download-source" not in rendered

    def test_text_output_requires_source_url_for_gemara_download_hint(
        self, upload_response, monkeypatch
    ):
        """Do not infer retained source availability from structured summary alone."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )
        upload_response.update(
            {
                "artifact_type": "document",
                "doc_type": "test_report",
                "evidence_summary": {
                    "source": "gemara_export",
                    "format": "gemara_yaml",
                    "schema_type": "EvaluationLog",
                    "document_type": "test_report",
                    "parser_outcome": "accepted_document_only",
                    "mapped_fields": [],
                    "manual_followups": [],
                },
            }
        )

        format_output(upload_response, "text")

        rendered = out.getvalue()
        assert "Structured Evidence" in rendered
        assert "Retained source" not in rendered
        assert "download-source" not in rendered

    def test_text_output_escapes_structured_evidence_markup(
        self, upload_response, monkeypatch
    ):
        """Server-supplied summary strings are rendered as text, not markup."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )
        upload_response.update(
            {
                "artifact_type": "document",
                "evidence_summary": {
                    "source": "gemara_export",
                    "format": "gemara_yaml",
                    "schema_type": "RiskCatalog",
                    "document_type": "risk_assessment",
                    "parser_outcome": "accepted_document_only",
                    "mapped_fields": ["annex_i_attestations.[red]x[/red]"],
                    "manual_followups": ["Review [red]manually[/red]."],
                },
            }
        )

        format_output(upload_response, "text")

        rendered = out.getvalue()
        assert "[red]x[/red]" in rendered
        assert "Review [red]manually[/red]." in rendered

    def test_text_output_renders_supplier_review_guardrail(
        self, upload_response, monkeypatch
    ):
        """SBOM supplier candidates are shown as review aids, not due diligence."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )
        upload_response.update(
            {
                "supplier_review": {
                    "source": "sbom_component_supplier_fields",
                    "parser_outcome": "review_candidates_found",
                    "total_components": 3,
                    "components_with_supplier": 2,
                    "candidate_count": 1,
                    "candidates": [
                        {"name": "Acme Components", "component_count": 2}
                    ],
                    "truncated": False,
                    "manual_followups": [
                        "Supplier names from SBOM component metadata are review "
                        "candidates only; they do not satisfy supplier due diligence."
                    ],
                },
            }
        )

        format_output(upload_response, "text")

        rendered = out.getvalue()
        assert "Supplier Review" in rendered
        assert "SBOM supplier names are review candidates only" in rendered
        assert "2/3" in rendered
        assert "Acme Components (2 component(s))" in rendered
        assert "do not satisfy supplier due diligence" in rendered

    def test_text_output_renders_supplier_review_without_candidates(
        self, upload_response, monkeypatch
    ):
        """No supplier strings still leaves due diligence manual."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )
        upload_response.update(
            {
                "supplier_review": {
                    "source": "sbom_component_supplier_fields",
                    "parser_outcome": "no_supplier_candidates_found",
                    "total_components": 1,
                    "components_with_supplier": 0,
                    "candidate_count": 0,
                    "candidates": [],
                    "truncated": False,
                    "manual_followups": [
                        "Supplier due diligence remains manual and must be "
                        "supported by supplier_due_diligence evidence."
                    ],
                },
            }
        )

        format_output(upload_response, "text")

        rendered = out.getvalue()
        assert "Candidates:" in rendered
        assert "none found" in rendered
        assert "Supplier due diligence remains manual" in rendered


class TestStructuredEvidenceMappingEnforcement:
    """Tests for the opt-in structured mapping CI guardrail."""

    def test_flag_off_allows_document_only(self):
        enforce_structured_mapping(
            {"evidence_summary": {"parser_outcome": "accepted_document_only"}},
            require_structured_mapping=False,
        )

    def test_flag_on_allows_accepted_and_mapped(self):
        enforce_structured_mapping(
            {"evidence_summary": {"parser_outcome": "accepted_and_mapped"}},
            require_structured_mapping=True,
        )

    @pytest.mark.parametrize(
        "parser_outcome",
        [
            "accepted_document_only",
            "accepted_needs_review",
            "missing_evidence_summary",
        ],
    )
    def test_flag_on_fails_without_mapping(self, parser_outcome):
        data = {}
        if parser_outcome != "missing_evidence_summary":
            data = {"evidence_summary": {"parser_outcome": parser_outcome}}

        with pytest.raises(StructuredEvidenceMappingRequired) as exc_info:
            enforce_structured_mapping(data, require_structured_mapping=True)

        assert exc_info.value.exit_code == 21
        assert exc_info.value.parser_outcome == parser_outcome


class TestUploadDocumentStructuredMappingFlag:
    """Verify upload-document can require confirmed field mapping."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    def _invoke(self, parser_outcome: str, extra_args: list[str] | None = None):
        from unittest.mock import MagicMock, patch

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
                "artifact_id": "doc-123",
                "artifact_type": "document",
                "doc_type": "risk_assessment",
                "product": {"name": "test", "created": False},
                "version": {"number": "1.0", "created": False},
                "evidence_summary": {
                    "source": "gemara_export",
                    "format": "gemara_yaml",
                    "schema_type": "RiskCatalog",
                    "document_type": "risk_assessment",
                    "parser_outcome": parser_outcome,
                    "mapped_fields": [],
                    "manual_followups": ["Manual review required."],
                },
            }

            with runner.isolated_filesystem():
                Path("risk.yaml").write_text(
                    "metadata:\n  type: RiskCatalog\n", encoding="utf-8"
                )
                result = runner.invoke(
                    cli,
                    [
                        "upload-document",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "risk.yaml",
                        "--type", "risk_assessment",
                        "--no-ci-detect",
                        *(extra_args or []),
                    ],
                    env=self.BASE_ENV,
                )

        return result, mock_client

    def test_default_upload_stays_permissive_for_document_only(self):
        result, mock_client = self._invoke("accepted_document_only")

        assert result.exit_code == 0, result.output
        assert "Document stored; no mapped fields confirmed" in result.output
        mock_client.upload_document.assert_called_once()

    def test_require_structured_mapping_fails_after_document_only_upload(self):
        result, mock_client = self._invoke(
            "accepted_document_only",
            ["--require-structured-mapping"],
        )

        assert result.exit_code == 21, result.output
        assert "mapped fields were not" in result.output
        assert "confirmed" in result.output
        assert "Structured evidence mapping was required" in result.output
        mock_client.upload_document.assert_called_once()

    def test_require_structured_mapping_passes_when_fields_are_mapped(self):
        result, mock_client = self._invoke(
            "accepted_and_mapped",
            ["--require-structured-mapping"],
        )

        assert result.exit_code == 0, result.output
        mock_client.upload_document.assert_called_once()


class TestGemaraUploadStructuredMappingFlag:
    """Verify compliance-as-code upload shares the same optional guardrail."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    def _invoke(self, parser_outcome: str, extra_args: list[str] | None = None):
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.gemara.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.gemara.asyncio.run"
        ) as mock_run:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.return_value = {
                "artifact_id": "doc-123",
                "artifact_type": "document",
                "doc_type": "risk_assessment",
                "product": {"name": "test", "created": False},
                "version": {"number": "1.0", "created": False},
                "evidence_summary": {
                    "source": "gemara_export",
                    "format": "gemara_yaml",
                    "schema_type": "RiskCatalog",
                    "document_type": "risk_assessment",
                    "parser_outcome": parser_outcome,
                    "mapped_fields": [],
                    "manual_followups": ["Manual review required."],
                },
            }

            with runner.isolated_filesystem():
                Path("risk.yaml").write_text(
                    "metadata:\n  type: RiskCatalog\n", encoding="utf-8"
                )
                result = runner.invoke(
                    cli,
                    [
                        "compliance-as-code",
                        "upload",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "risk.yaml",
                        *(extra_args or []),
                    ],
                    env=self.BASE_ENV,
                )

        return result, mock_client

    def test_default_upload_stays_permissive_for_document_only(self):
        result, mock_client = self._invoke("accepted_document_only")

        assert result.exit_code == 0, result.output
        assert "Document stored; no mapped fields confirmed" in result.output
        mock_client.upload_document.assert_called_once()

    def test_require_structured_mapping_fails_after_document_only_upload(self):
        result, mock_client = self._invoke(
            "accepted_document_only",
            ["--require-structured-mapping"],
        )

        assert result.exit_code == 21, result.output
        assert "Document stored; no mapped fields confirmed" in result.output
        assert "Structured evidence mapping was required" in result.output
        mock_client.upload_document.assert_called_once()


class TestGemaraUploadNoGuessingRouting:
    """Pin compliance-as-code upload routing boundaries."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    def test_upload_requires_declared_file_even_when_cra_directory_exists(self):
        """Do not auto-discover compliance files from a repository directory."""
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.gemara.CRAEvidenceClient"
        ) as mock_client_cls, runner.isolated_filesystem():
            Path(".cra").mkdir()
            Path(".cra/evaluation-log.yaml").write_text(
                "metadata:\n  type: EvaluationLog\n",
                encoding="utf-8",
            )

            result = runner.invoke(
                cli,
                [
                    "compliance-as-code",
                    "upload",
                    "--product", "test",
                    "--version", "1.0",
                ],
                env=self.BASE_ENV,
            )

        assert result.exit_code != 0
        assert "Missing option" in result.output
        assert "--file" in result.output
        mock_client_cls.assert_not_called()

    def _invoke(
        self,
        gemara_type: str,
        extra_args: list[str] | None = None,
        response: dict | None = None,
    ):
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.gemara.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.gemara.asyncio.run"
        ) as mock_run:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            default_doc_type = {
                "Policy": "vulnerability_policy",
                "ControlCatalog": "secure_development_policy",
                "RiskCatalog": "risk_assessment",
            }.get(gemara_type, "other")
            mock_run.return_value = response or {
                "artifact_id": "doc-123",
                "artifact_type": "document",
                "doc_type": default_doc_type,
                "product": {"name": "test", "created": False},
            }

            with runner.isolated_filesystem():
                Path("gemara.yaml").write_text(
                    f"metadata:\n  type: {gemara_type}\n", encoding="utf-8"
                )
                result = runner.invoke(
                    cli,
                    [
                        "compliance-as-code",
                        "upload",
                        "--product", "test",
                        "--file", "gemara.yaml",
                        *(extra_args or []),
                    ],
                    env=self.BASE_ENV,
                )

        return result, mock_client_cls, mock_client

    def test_policy_requires_explicit_document_type(self):
        result, mock_client_cls, _mock_client = self._invoke("Policy")

        assert result.exit_code != 0
        assert "Policy files require --document-type" in result.output
        mock_client_cls.assert_not_called()

    def test_policy_with_document_type_routes_product_level(self):
        result, _mock_client_cls, mock_client = self._invoke(
            "Policy",
            ["--document-type", "vulnerability_policy"],
        )

        assert result.exit_code == 0, result.output
        mock_client.upload_product_document_gemara.assert_called_once()
        assert mock_client.upload_product_document_gemara.call_args.kwargs == {
            "product": "test",
            "document_type": "vulnerability_policy",
            "file_path": Path("gemara.yaml"),
        }
        mock_client.upload_document.assert_not_called()

    def test_control_catalog_without_version_routes_product_level(self):
        result, _mock_client_cls, mock_client = self._invoke("ControlCatalog")

        assert result.exit_code == 0, result.output
        mock_client.upload_product_document_gemara.assert_called_once()
        assert mock_client.upload_product_document_gemara.call_args.kwargs[
            "document_type"
        ] == "secure_development_policy"
        mock_client.upload_document.assert_not_called()

    def test_control_catalog_with_version_routes_version_upload_explicitly(self):
        result, _mock_client_cls, mock_client = self._invoke(
            "ControlCatalog",
            ["--version", "1.0"],
            response={
                "artifact_id": "doc-123",
                "artifact_type": "document",
                "doc_type": "secure_development_policy",
                "product": {"name": "test", "created": False},
                "version": {"number": "1.0", "created": False},
            },
        )

        assert result.exit_code == 0, result.output
        mock_client.upload_document.assert_called_once()
        assert mock_client.upload_document.call_args.kwargs == {
            "product": "test",
            "version": "1.0",
            "file_path": Path("gemara.yaml"),
            "document_type": "secure_development_policy",
            "create_product": True,
            "create_version": True,
        }
        mock_client.upload_product_document_gemara.assert_not_called()

    def test_version_specific_type_requires_version(self):
        result, mock_client_cls, _mock_client = self._invoke("RiskCatalog")

        assert result.exit_code != 0
        assert "--version is required for version-specific type 'RiskCatalog'" in result.output
        mock_client_cls.assert_not_called()


class TestGemaraDownloadSourceCommand:
    """Pin explicit retained-source download behavior."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    def test_download_source_help_does_not_claim_status_returns_document_ids(self):
        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["compliance-as-code", "download-source", "--help"],
        )

        assert result.exit_code == 0
        assert "rendered compliance document" in result.output
        assert "upload or API workflows" in result.output
        assert "status/API workflows" not in result.output

    def test_download_source_requires_explicit_document_id_and_output(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.gemara.CRAEvidenceClient") as mock_client_cls:
            result = runner.invoke(
                cli,
                ["compliance-as-code", "download-source"],
                env=self.BASE_ENV,
            )

        assert result.exit_code != 0
        assert "Missing option" in result.output
        assert "--document-id" in result.output
        mock_client_cls.assert_not_called()

    def test_download_source_writes_to_explicit_output(self):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.gemara.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.gemara.asyncio.run"
        ) as mock_run:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.return_value = {
                "status": "success",
                "document_id": "doc-123",
                "file_path": "source.yaml",
                "size_bytes": 30,
                "provenance_only": True,
            }

            with runner.isolated_filesystem():
                result = runner.invoke(
                    cli,
                    [
                        "compliance-as-code",
                        "download-source",
                        "--document-id", "doc-123",
                        "--output", "source.yaml",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code == 0, result.output
        assert "Downloaded" in result.output
        assert "Provenance only" in result.output
        mock_client.download_gemara_source.assert_called_once()
        assert mock_client.download_gemara_source.call_args.kwargs == {
            "document_id": "doc-123",
            "output_path": Path("source.yaml"),
        }

    def test_download_source_refuses_overwrite_without_force(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.gemara.CRAEvidenceClient") as mock_client_cls:
            with runner.isolated_filesystem():
                Path("source.yaml").write_text("existing\n", encoding="utf-8")
                result = runner.invoke(
                    cli,
                    [
                        "compliance-as-code",
                        "download-source",
                        "--document-id", "doc-123",
                        "--output", "source.yaml",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code != 0
        assert "already exists" in result.output
        mock_client_cls.assert_not_called()

    def test_download_source_force_allows_overwrite(self):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.gemara.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.gemara.asyncio.run"
        ) as mock_run:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.return_value = {
                "status": "success",
                "document_id": "doc-123",
                "file_path": "source.yaml",
                "size_bytes": 30,
                "provenance_only": True,
            }

            with runner.isolated_filesystem():
                Path("source.yaml").write_text("existing\n", encoding="utf-8")
                result = runner.invoke(
                    cli,
                    [
                        "compliance-as-code",
                        "download-source",
                        "--document-id", "doc-123",
                        "--output", "source.yaml",
                        "--force",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code == 0, result.output
        mock_client.download_gemara_source.assert_called_once()

    def test_download_source_surfaces_api_error(self):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli
        from cra_evidence_cli.exceptions import APIError

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.gemara.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.gemara.asyncio.run",
            side_effect=APIError("Gemara source not found", status_code=404),
        ):
            mock_client_cls.return_value = MagicMock()

            with runner.isolated_filesystem():
                result = runner.invoke(
                    cli,
                    [
                        "compliance-as-code",
                        "download-source",
                        "--document-id", "doc-404",
                        "--output", "source.yaml",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code == 3
        assert "Gemara source not found" in result.output

    def test_download_source_json_output_is_parseable(self):
        import json as _json
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.gemara.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.gemara.asyncio.run"
        ) as mock_run:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.return_value = {
                "status": "success",
                "document_id": "doc-123",
                "file_path": "source.yaml",
                "size_bytes": 30,
                "provenance_only": True,
            }

            with runner.isolated_filesystem():
                result = runner.invoke(
                    cli,
                    [
                        "--output", "json",
                        "compliance-as-code",
                        "download-source",
                        "--document-id", "doc-123",
                        "--output", "source.yaml",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code == 0, result.output
        parsed = _json.loads(result.output)
        assert parsed["document_id"] == "doc-123"
        assert parsed["provenance_only"] is True


class TestAttestationOutput:
    """Tests for attestation-specific output."""

    def test_text_output_warns_when_not_verified(self, monkeypatch):
        """Pending attestations must not be presented as verified provenance."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )

        upload_module.format_attestation_output(
            {
                "id": "att-123",
                "version_id": "ver-456",
                "format": "dsse_intoto",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "signature_count": 1,
                "verification_status": "pending",
                "builder_id": "https://github.com/actions",
                "source_commit": "abc123",
            },
            "text",
        )

        rendered = out.getvalue()
        assert "Attestation uploaded" in rendered
        assert "pending" in rendered
        assert "not verified provenance unless verification_status is valid" in rendered

    def test_text_output_omits_warning_when_verified(self, monkeypatch):
        """Valid verification can be shown without the pending warning."""
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=140, color_system=None),
        )

        upload_module.format_attestation_output(
            {
                "id": "att-123",
                "version_id": "ver-456",
                "format": "dsse_intoto",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "signature_count": 1,
                "verification_status": "valid",
            },
            "text",
        )

        rendered = out.getvalue()
        assert "valid" in rendered
        assert "not verified provenance" not in rendered


class TestUploadAttestationCommand:
    """Verify upload-attestation forwards the explicit API contract."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    def test_upload_attestation_calls_client_with_existing_version(self):
        from pathlib import Path
        from unittest.mock import MagicMock, patch

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
                "id": "att-123",
                "version_id": "ver-456",
                "format": "dsse_intoto",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "signature_count": 1,
                "verification_status": "pending",
            }

            with runner.isolated_filesystem():
                Path("provenance.json").write_text('{"payload": "abc"}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-attestation",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "provenance.json",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code == 0, result.output
        mock_client.upload_attestation.assert_called_once()
        assert mock_client.upload_attestation.call_args.kwargs == {
            "product": "test",
            "version": "1.0",
            "file_path": Path("provenance.json"),
        }
        assert "not verified provenance" in result.output
        assert "verification_status is valid" in result.output


# --component flag passthrough


class TestUploadSbomComponentFlag:
    """Verify --component <slug> forwards to client.upload_sbom(component=...)."""

    def _run_upload(self, runner_kwargs, extra_args):
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from click.testing import CliRunner

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            with patch(
                "cra_evidence_cli.commands.upload.asyncio.run"
            ) as mock_run:
                mock_run.return_value = {
                    "artifact_id": "abc",
                    "artifact_type": "sbom",
                    "product": {"name": "test", "created": False},
                    "version": {"number": "1.0", "created": False},
                }
                with runner.isolated_filesystem():
                    Path("sbom.json").write_text('{"components": []}')
                    result = runner.invoke(
                        cli,
                        [
                            "upload-sbom",
                            "--product", "test",
                            "--version", "1.0",
                            "--file", "sbom.json",
                            "--no-ci-detect",
                            *extra_args,
                        ],
                        env={
                            "CRA_EVIDENCE_API_KEY": "test_key_123",
                            "CRA_EVIDENCE_URL": "http://localhost:8000",
                        },
                    )
                return result, mock_client.upload_sbom.call_args

    def test_component_flag_forwarded_to_client(self):
        result, call_args = self._run_upload(
            {}, ["--component", "firmware"],
        )
        assert result.exit_code == 0, result.output
        assert call_args is not None
        assert call_args.kwargs.get("component") == "firmware"

    def test_component_version_flag_forwarded_to_client(self):
        result, call_args = self._run_upload(
            {}, ["--component-version", "2.4.0"],
        )
        assert result.exit_code == 0, result.output
        assert call_args is not None
        assert call_args.kwargs.get("component_version") == "2.4.0"

    def test_component_flag_absent_passes_none(self):
        result, call_args = self._run_upload({}, [])
        assert result.exit_code == 0, result.output
        assert call_args is not None
        assert call_args.kwargs.get("component") is None
        assert call_args.kwargs.get("component_version") is None

    def test_target_markets_flag_forwarded_to_client(self):
        result, call_args = self._run_upload(
            {}, ["--target-markets", "DE,ES"],
        )
        assert result.exit_code == 0, result.output
        assert call_args is not None
        assert call_args.kwargs.get("target_markets") == "DE,ES"


class TestUploadSbomSignatureVerification:
    """Verify upload-sbom can upload then verify a Sigstore SBOM bundle."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    def _invoke(self, signature_response: dict, extra_args: list[str] | None = None):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.upload.asyncio.run"
        ) as mock_run:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.side_effect = [
                {
                    "artifact_id": "sbom-123",
                    "artifact_type": "sbom",
                    "product": {"name": "test", "created": False},
                    "version": {"number": "1.0", "created": False},
                },
                signature_response,
            ]

            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                Path("sbom.sigstore.json").write_text('{"bundle": "json"}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--signature-bundle", "sbom.sigstore.json",
                        "--signature-identity", "https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main",
                        "--signature-issuer", "https://token.actions.githubusercontent.com",
                        "--no-ci-detect",
                        *(extra_args or []),
                    ],
                    env=self.BASE_ENV,
                )

        return result, mock_client

    def test_upload_then_verify_signature_bundle(self):
        result, mock_client = self._invoke(
            {
                "sbom_id": "sbom-123",
                "verification": {
                    "status": "valid",
                    "policy_enforced": True,
                    "signer_identity": "https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main",
                    "signer_issuer": "https://token.actions.githubusercontent.com",
                    "expected_identity": "https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main",
                    "expected_issuer": "https://token.actions.githubusercontent.com",
                    "transparency_log_entry": {"log_index": 123, "log_id": "abc"},
                },
            }
        )

        assert result.exit_code == 0, result.output
        assert "Release Integrity" in result.output
        assert "Trusted" in result.output
        mock_client.upload_sbom.assert_called_once()
        mock_client.verify_sbom_signature.assert_called_once()
        assert mock_client.verify_sbom_signature.call_args.kwargs == {
            "sbom_id": "sbom-123",
            "bundle_path": Path("sbom.sigstore.json"),
            "expected_identity": "https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main",
            "expected_issuer": "https://token.actions.githubusercontent.com",
        }

    def test_fail_untrusted_exits_nonzero_after_showing_result(self):
        result, mock_client = self._invoke(
            {
                "sbom_id": "sbom-123",
                "verification": {
                    "status": "valid",
                    "policy_enforced": False,
                },
            },
            ["--fail-untrusted"],
        )

        assert result.exit_code == 22, result.output
        assert "Valid Untrusted" in result.output
        assert "SBOM upload completed" in result.output
        assert "signature verification was required to be" in result.output
        assert "trusted" in result.output
        mock_client.upload_sbom.assert_called_once()
        mock_client.verify_sbom_signature.assert_called_once()

    def test_signature_on_uses_default_bundle_and_env_policy(self):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.upload.asyncio.run"
        ) as mock_run:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.side_effect = [
                {
                    "artifact_id": "sbom-123",
                    "artifact_type": "sbom",
                    "product": {"name": "test", "created": False},
                    "version": {"number": "1.0", "created": False},
                },
                {
                    "sbom_id": "sbom-123",
                    "verification": {
                        "status": "valid",
                        "policy_enforced": True,
                    },
                },
            ]

            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                Path("sbom.json.sigstore.json").write_text('{"bundle": "json"}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--signature-on",
                        "--no-ci-detect",
                    ],
                    env={
                        **self.BASE_ENV,
                        "CRA_EVIDENCE_SIGNATURE_IDENTITY": "https://gitlab.com/acme/device//.gitlab-ci.yml@refs/heads/main",
                        "CRA_EVIDENCE_SIGNATURE_ISSUER": "https://gitlab.com",
                    },
                )

        assert result.exit_code == 0, result.output
        mock_client.upload_sbom.assert_called_once()
        mock_client.verify_sbom_signature.assert_called_once()
        assert mock_client.verify_sbom_signature.call_args.kwargs == {
            "sbom_id": "sbom-123",
            "bundle_path": Path("sbom.json.sigstore.json"),
            "expected_identity": "https://gitlab.com/acme/device//.gitlab-ci.yml@refs/heads/main",
            "expected_issuer": "https://gitlab.com",
        }

    def test_signature_on_fails_when_default_bundle_is_missing(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--signature-on",
                    ],
                    env={
                        **self.BASE_ENV,
                        "CRA_EVIDENCE_SIGNATURE_IDENTITY": "https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main",
                        "CRA_EVIDENCE_SIGNATURE_ISSUER": "https://token.actions.githubusercontent.com",
                    },
                )

        assert result.exit_code != 0
        assert "expected Sigstore bundle" in result.output
        assert "sbom.json.sigstore.json" in result.output
        mock_client_cls.assert_not_called()

    def test_signature_on_fails_when_policy_is_missing(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                Path("sbom.json.sigstore.json").write_text('{"bundle": "json"}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--signature-on",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code != 0
        assert "CRA_EVIDENCE_SIGNATURE_IDENTITY" in result.output
        assert "CRA_EVIDENCE_SIGNATURE_ISSUER" in result.output
        mock_client_cls.assert_not_called()

    def test_signature_on_requires_file_not_image(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            result = runner.invoke(
                cli,
                [
                    "upload-sbom",
                    "--product", "test",
                    "--version", "1.0",
                    "--image", "example.com/acme/device:1.0",
                    "--signature-on",
                ],
                env={
                    **self.BASE_ENV,
                    "CRA_EVIDENCE_SIGNATURE_IDENTITY": "https://gitlab.com/acme/device//.gitlab-ci.yml@refs/heads/main",
                    "CRA_EVIDENCE_SIGNATURE_ISSUER": "https://gitlab.com",
                },
            )

        assert result.exit_code != 0
        assert "--signature-on is supported only with --file" in result.output
        mock_client_cls.assert_not_called()

    def test_signature_on_explicit_policy_overrides_env(self):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.upload.asyncio.run"
        ) as mock_run:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.side_effect = [
                {
                    "artifact_id": "sbom-123",
                    "artifact_type": "sbom",
                    "product": {"name": "test", "created": False},
                    "version": {"number": "1.0", "created": False},
                },
                {
                    "sbom_id": "sbom-123",
                    "verification": {"status": "valid", "policy_enforced": True},
                },
            ]

            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                Path("custom.sigstore.json").write_text('{"bundle": "json"}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--signature-on",
                        "--signature-bundle", "custom.sigstore.json",
                        "--signature-identity", "explicit-identity",
                        "--signature-issuer", "https://issuer.example",
                        "--no-ci-detect",
                    ],
                    env={
                        **self.BASE_ENV,
                        "CRA_EVIDENCE_SIGNATURE_IDENTITY": "env-identity",
                        "CRA_EVIDENCE_SIGNATURE_ISSUER": "https://env-issuer.example",
                    },
                )

        assert result.exit_code == 0, result.output
        assert mock_client.verify_sbom_signature.call_args.kwargs == {
            "sbom_id": "sbom-123",
            "bundle_path": Path("custom.sigstore.json"),
            "expected_identity": "explicit-identity",
            "expected_issuer": "https://issuer.example",
        }

    def test_sign_creates_bundle_then_verifies_with_current_signer_policy(self):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli
        from cra_evidence_cli.sbom_signer import SBOMSigningResult

        runner = CliRunner()

        def fake_sign_sbom(*, sbom_path, bundle_path):
            bundle_path.write_text('{"mediaType": "application/vnd.dev.sigstore.bundle+json"}')
            return SBOMSigningResult(
                bundle_path=bundle_path,
                signer_identity="https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main",
                signer_issuer="https://token.actions.githubusercontent.com",
                transparency_log_index=123,
            )

        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.upload.asyncio.run"
        ) as mock_run, patch(
            "cra_evidence_cli.commands.upload.sign_sbom_with_sigstore",
            side_effect=fake_sign_sbom,
        ) as mock_sign:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.side_effect = [
                {
                    "artifact_id": "sbom-123",
                    "artifact_type": "sbom",
                    "product": {"name": "test", "created": False},
                    "version": {"number": "1.0", "created": False},
                },
                {
                    "sbom_id": "sbom-123",
                    "verification": {"status": "valid", "policy_enforced": True},
                },
            ]

            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--sign",
                        "--no-ci-detect",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code == 0, result.output
        assert "Signed SBOM bundle" in result.output
        mock_sign.assert_called_once()
        assert mock_sign.call_args.kwargs == {
            "sbom_path": Path("sbom.json"),
            "bundle_path": Path("sbom.json.sigstore.json"),
        }
        assert mock_client.verify_sbom_signature.call_args.kwargs == {
            "sbom_id": "sbom-123",
            "bundle_path": Path("sbom.json.sigstore.json"),
            "expected_identity": "https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main",
            "expected_issuer": "https://token.actions.githubusercontent.com",
        }

    def test_sign_uses_explicit_policy_over_current_signer(self):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli
        from cra_evidence_cli.sbom_signer import SBOMSigningResult

        runner = CliRunner()

        def fake_sign_sbom(*, sbom_path, bundle_path):
            bundle_path.write_text('{"mediaType": "application/vnd.dev.sigstore.bundle+json"}')
            return SBOMSigningResult(
                bundle_path=bundle_path,
                signer_identity="actual-identity",
                signer_issuer="https://actual-issuer.example",
            )

        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.upload.asyncio.run"
        ) as mock_run, patch(
            "cra_evidence_cli.commands.upload.sign_sbom_with_sigstore",
            side_effect=fake_sign_sbom,
        ):
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.side_effect = [
                {
                    "artifact_id": "sbom-123",
                    "artifact_type": "sbom",
                    "product": {"name": "test", "created": False},
                    "version": {"number": "1.0", "created": False},
                },
                {
                    "sbom_id": "sbom-123",
                    "verification": {"status": "valid", "policy_enforced": True},
                },
            ]

            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--sign",
                        "--fail-untrusted",
                        "--signature-identity", "expected-identity",
                        "--signature-issuer", "https://expected-issuer.example",
                        "--no-ci-detect",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code == 0, result.output
        assert mock_client.verify_sbom_signature.call_args.kwargs == {
            "sbom_id": "sbom-123",
            "bundle_path": Path("sbom.json.sigstore.json"),
            "expected_identity": "expected-identity",
            "expected_issuer": "https://expected-issuer.example",
        }

    def test_sign_fail_untrusted_requires_pinned_policy(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--sign",
                        "--fail-untrusted",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code != 0
        assert "--fail-untrusted with --sign requires a pinned signer policy" in result.output
        mock_client_cls.assert_not_called()

    def test_sign_and_signature_on_are_mutually_exclusive(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--sign",
                        "--signature-on",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code != 0
        assert "Use --sign to create a bundle or --signature-on" in result.output
        mock_client_cls.assert_not_called()

    def test_signature_bundle_can_use_env_policy_without_signature_on(self):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.upload.asyncio.run"
        ) as mock_run:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.side_effect = [
                {
                    "artifact_id": "sbom-123",
                    "artifact_type": "sbom",
                    "product": {"name": "test", "created": False},
                    "version": {"number": "1.0", "created": False},
                },
                {
                    "sbom_id": "sbom-123",
                    "verification": {"status": "valid", "policy_enforced": True},
                },
            ]

            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                Path("custom.sigstore.json").write_text('{"bundle": "json"}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--signature-bundle", "custom.sigstore.json",
                        "--no-ci-detect",
                    ],
                    env={
                        **self.BASE_ENV,
                        "CRA_EVIDENCE_SIGNATURE_IDENTITY": "env-identity",
                        "CRA_EVIDENCE_SIGNATURE_ISSUER": "https://env-issuer.example",
                    },
                )

        assert result.exit_code == 0, result.output
        assert mock_client.verify_sbom_signature.call_args.kwargs == {
            "sbom_id": "sbom-123",
            "bundle_path": Path("custom.sigstore.json"),
            "expected_identity": "env-identity",
            "expected_issuer": "https://env-issuer.example",
        }

    def test_orphan_signature_policy_flags_fail_before_upload(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--signature-identity", "orphan-identity",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code != 0
        assert "require --sign, --signature-on, or --signature-bundle" in result.output
        mock_client_cls.assert_not_called()

    def test_fail_untrusted_requires_signature_verification(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--fail-untrusted",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code != 0
        assert (
            "--fail-untrusted requires --sign, --signature-on, or --signature-bundle"
            in result.output
        )
        mock_client_cls.assert_not_called()

    def test_signature_bundle_requires_identity_and_issuer(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as mock_client_cls:
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                Path("sbom.sigstore.json").write_text('{"bundle": "json"}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--signature-bundle", "sbom.sigstore.json",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code != 0
        assert "--signature-identity" in result.output
        assert "--signature-issuer" in result.output
        mock_client_cls.assert_not_called()


# --sbomqs-check / --fail-on-score


class TestSbomqsCheck:
    """Verify the opt-in BSI TR-03183-2 v2 pre-upload check.

    The helper itself (subprocess invocation, JSON parsing, missing-binary
    handling) is unit-tested in `tests/test_sbomqs_check.py`. These CLI-level
    tests verify the wiring: that the flag triggers the helper, that score
    output reaches the user, and that the failure threshold short-circuits
    the network upload.
    """

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    @staticmethod
    def _result(score: float):
        from cra_evidence_cli.sbomqs_check import FeatureScore, SbomqsResult
        return SbomqsResult(
            file_name="sbom.json",
            num_components=107,
            score_out_of_100=score,
            worst_features=[
                FeatureScore("comp_with_supplier", 0, 10),
                FeatureScore("comp_with_source_code_uri", 0, 10),
                FeatureScore("sbom_with_signature", 0, 10),
            ],
        )

    def _invoke(self, extra_args, run_sbomqs_side_effect=None, cli_prefix=None):
        """Invoke upload-sbom with the helper patched.

        run_sbomqs_side_effect: either a SbomqsResult (returned by the mock),
        an Exception (raised by the mock), or None (helper not patched,
        which only matters when the flag is off).
        cli_prefix: extra args before the subcommand (e.g., ["--output", "json"]).
        """
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from click.testing import CliRunner

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.upload.asyncio.run"
        ) as mock_run, patch(
            "cra_evidence_cli.commands.upload.run_sbomqs"
        ) as mock_run_sbomqs:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_run.return_value = {
                "artifact_id": "abc",
                "artifact_type": "sbom",
                "product": {"name": "test", "created": False},
                "version": {"number": "1.0", "created": False},
            }
            if isinstance(run_sbomqs_side_effect, Exception):
                mock_run_sbomqs.side_effect = run_sbomqs_side_effect
            elif run_sbomqs_side_effect is not None:
                mock_run_sbomqs.return_value = run_sbomqs_side_effect

            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        *(cli_prefix or []),
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--no-ci-detect",
                        *extra_args,
                    ],
                    env=self.BASE_ENV,
                )
            return result, mock_client, mock_run_sbomqs

    def test_flag_off_does_not_invoke_sbomqs(self):
        result, mock_client, mock_run_sbomqs = self._invoke([])
        assert result.exit_code == 0, result.output
        mock_run_sbomqs.assert_not_called()
        mock_client.upload_sbom.assert_called_once()

    def test_flag_on_passing_score_uploads(self):
        result, mock_client, mock_run_sbomqs = self._invoke(
            ["--sbomqs-check"],
            run_sbomqs_side_effect=self._result(85.0),
        )
        assert result.exit_code == 0, result.output
        assert "sbomqs bsi-v2.0: 85.0/100" in result.output
        assert "comp_with_supplier 0/10" in result.output
        mock_run_sbomqs.assert_called_once()
        mock_client.upload_sbom.assert_called_once()

    def test_fail_on_score_below_threshold_blocks_upload(self):
        result, mock_client, mock_run_sbomqs = self._invoke(
            ["--sbomqs-check", "--fail-on-score", "60"],
            run_sbomqs_side_effect=self._result(47.9),
        )
        assert result.exit_code == 14, result.output
        assert "sbomqs bsi-v2.0: 47.9/100" in result.output
        mock_client.upload_sbom.assert_not_called()

    def test_fail_on_score_above_threshold_passes(self):
        result, mock_client, mock_run_sbomqs = self._invoke(
            ["--sbomqs-check", "--fail-on-score", "30"],
            run_sbomqs_side_effect=self._result(47.9),
        )
        assert result.exit_code == 0, result.output
        assert "sbomqs bsi-v2.0: 47.9/100" in result.output
        mock_client.upload_sbom.assert_called_once()

    def test_sbomqs_binary_missing_errors_with_install_hint(self):
        from cra_evidence_cli.exceptions import CRAEvidenceError
        result, mock_client, mock_run_sbomqs = self._invoke(
            ["--sbomqs-check"],
            run_sbomqs_side_effect=CRAEvidenceError(
                "sbomqs binary not found on PATH. Install sbomqs to use "
                "--sbomqs-check: `go install github.com/interlynk-io/sbomqs@latest`",
                exit_code=2,
            ),
        )
        assert result.exit_code == 2, result.output
        assert "sbomqs binary not found" in result.output
        assert "go install github.com/interlynk-io/sbomqs" in result.output
        mock_client.upload_sbom.assert_not_called()

    def test_fail_on_score_without_check_is_usage_error(self):
        result, mock_client, mock_run_sbomqs = self._invoke(
            ["--fail-on-score", "60"],
        )
        assert result.exit_code != 0
        assert "--fail-on-score requires --sbomqs-check" in result.output
        mock_run_sbomqs.assert_not_called()
        mock_client.upload_sbom.assert_not_called()

    def test_json_output_mode_keeps_stdout_parseable(self):
        """With --output json, the sbomqs summary goes to stderr so the
        stdout JSON payload stays valid for `| jq` pipelines."""
        import json as _json
        result, mock_client, mock_run_sbomqs = self._invoke(
            ["--sbomqs-check"],
            cli_prefix=["--output", "json"],
            run_sbomqs_side_effect=self._result(85.0),
        )
        assert result.exit_code == 0, result.output

        # stdout must be valid JSON (no human summary mixed in)
        parsed = _json.loads(result.stdout)
        assert parsed["artifact_id"] == "abc"
        assert "sbomqs bsi-v2.0" not in result.stdout

        # human summary must still be visible - on stderr
        assert "sbomqs bsi-v2.0: 85.0/100" in result.stderr


class TestUploadSbomFailOnGate:
    """upload-sbom --scan --fail-on waits for the asynchronous scan and
    gates on the completed counts; --fail-on without --scan is rejected."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    UPLOAD_RESPONSE_PENDING_SCAN = {
        "artifact_id": "sbom-123",
        "artifact_type": "sbom",
        "product": {"name": "test", "created": False},
        "version": {"number": "1.0", "created": False},
        "scan_results": {"status": "pending", "vulnerabilities": None},
    }

    def _invoke(self, upload_response, status_responses, args, monotonic_values=None):
        from itertools import count
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        # upload.py and scan.py share the asyncio module, so one patch
        # covers the upload call and the status polls: the first response
        # answers the upload, the rest answer the polls.
        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.upload.asyncio.run",
            side_effect=[upload_response, *status_responses],
        ) as mock_run, patch(
            "cra_evidence_cli.commands.scan.time.sleep"
        ), patch(
            "cra_evidence_cli.commands.scan.time.monotonic",
            side_effect=monotonic_values or count(0.0, 1.0),
        ):
            mock_client_cls.return_value = MagicMock()
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--no-ci-detect",
                        *args,
                    ],
                    env=self.BASE_ENV,
                )
        return result, mock_run

    def test_fail_on_without_scan_is_usage_error(self):
        from unittest.mock import patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls:
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "sbom.json",
                        "--fail-on", "critical",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code != 0
        assert "--fail-on requires --scan" in result.output
        mock_client_cls.assert_not_called()

    @pytest.mark.parametrize(
        ("fail_on", "summary", "expected_exit"),
        [
            ("critical", {"critical": 1, "high": 0, "medium": 0, "low": 0}, 10),
            ("high", {"critical": 0, "high": 2, "medium": 0, "low": 0}, 11),
            ("medium", {"critical": 0, "high": 0, "medium": 5, "low": 0}, 12),
        ],
    )
    def test_pending_scan_is_polled_then_gated(self, fail_on, summary, expected_exit):
        status_responses = [
            {"scan_state": "running", "vulnerability_summary": {}},
            {"scan_state": "completed", "vulnerability_summary": summary},
        ]

        result, mock_run = self._invoke(
            self.UPLOAD_RESPONSE_PENDING_SCAN,
            status_responses,
            ["--scan", "--fail-on", fail_on],
        )

        assert result.exit_code == expected_exit, result.output
        # 1 upload call + 2 status polls prove the command waited
        assert mock_run.call_count == 3

    def test_pending_scan_completing_clean_exits_zero(self):
        status_responses = [
            {
                "scan_state": "completed",
                "vulnerability_summary": {
                    "critical": 0, "high": 0, "medium": 0, "low": 3,
                },
            },
        ]

        result, mock_run = self._invoke(
            self.UPLOAD_RESPONSE_PENDING_SCAN,
            status_responses,
            ["--scan", "--fail-on", "medium"],
        )

        assert result.exit_code == 0, result.output
        assert mock_run.call_count == 2

    def test_scan_timeout_exits_3_with_clear_message(self):
        status_responses = [
            {"scan_state": "pending", "vulnerability_summary": {}},
        ]

        result, mock_run = self._invoke(
            self.UPLOAD_RESPONSE_PENDING_SCAN,
            status_responses,
            ["--scan", "--fail-on", "high", "--scan-timeout", "120"],
            monotonic_values=[0.0, 121.0],
        )

        assert result.exit_code == 3, result.output
        assert "did not complete within 120 seconds" in result.output
        assert mock_run.call_count == 2

    def test_completed_scan_in_upload_response_gates_without_polling(self):
        upload_response = {
            "artifact_id": "sbom-123",
            "artifact_type": "sbom",
            "product": {"name": "test", "created": False},
            "version": {"number": "1.0", "created": False},
            "scan_results": {
                "status": "completed",
                "vulnerabilities": {
                    "critical": 1, "high": 0, "medium": 0, "low": 0,
                },
            },
        }

        result, mock_run = self._invoke(
            upload_response,
            [],
            ["--scan", "--fail-on", "critical"],
        )

        assert result.exit_code == 10, result.output
        # only the upload call happened; no status polling was needed
        assert mock_run.call_count == 1

    def test_failed_scan_in_upload_response_exits_3(self):
        upload_response = {
            "artifact_id": "sbom-123",
            "artifact_type": "sbom",
            "product": {"name": "test", "created": False},
            "version": {"number": "1.0", "created": False},
            "scan_results": {"status": "failed", "vulnerabilities": None},
        }

        result, mock_run = self._invoke(
            upload_response,
            [],
            ["--scan", "--fail-on", "critical"],
        )

        assert result.exit_code == 3, result.output
        assert "scan failed" in result.output.lower()
        assert mock_run.call_count == 1


class TestUploadVexOutput:
    """upload-vex renders the CI upload response shape, including the
    VEX vulnerability count."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    def test_format_output_renders_vulnerability_count(self, monkeypatch):
        out = StringIO()
        monkeypatch.setattr(
            upload_module,
            "console",
            Console(file=out, force_terminal=False, width=120, color_system=None),
        )

        format_output(
            {
                "artifact_id": "vex-123",
                "artifact_type": "vex",
                "product": {"name": "My Product", "created": False},
                "version": {"number": "1.0", "created": False},
                "vulnerability_count": 4,
            },
            "text",
        )

        rendered = out.getvalue()
        assert "VEX" in rendered
        assert "Vulnerabilities" in rendered
        assert "4" in rendered

    def test_upload_vex_forwards_options_to_client(self):
        from unittest.mock import MagicMock, patch

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
                "artifact_id": "vex-123",
                "artifact_type": "vex",
                "product": {"name": "test", "created": False},
                "version": {"number": "1.0", "created": False},
                "vulnerability_count": 2,
            }

            with runner.isolated_filesystem():
                Path("vex.json").write_text('{"vulnerabilities": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-vex",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "vex.json",
                        "--cra-role", "manufacturer",
                        "--subcategory", "vpn",
                        "--product-group", "iot",
                        "--environment", "production",
                        "--tags", "ci,nightly",
                        "--commit", "abc123",
                        "--no-inherit",
                        "--no-ci-detect",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code == 0, result.output
        mock_client.upload_vex.assert_called_once()
        kwargs = mock_client.upload_vex.call_args.kwargs
        assert kwargs["product"] == "test"
        assert kwargs["version"] == "1.0"
        assert kwargs["cra_role"] == "manufacturer"
        assert kwargs["subcategory"] == "vpn"
        assert kwargs["category"] == "important_class_i"
        assert kwargs["product_group"] == "iot"
        assert kwargs["environment"] == "production"
        assert kwargs["tags"] == "ci,nightly"
        assert kwargs["commit_sha"] == "abc123"
        assert kwargs["no_inherit"] is True


class TestUploadDocumentTypeRow:
    """upload-document shows the submitted document type in text output."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    def test_document_type_row_uses_submitted_type(self):
        from unittest.mock import MagicMock, patch

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.upload.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.upload.asyncio.run"
        ) as mock_run:
            mock_client_cls.return_value = MagicMock()
            # Response shaped like CIUploadResponse: no doc_type key
            mock_run.return_value = {
                "artifact_id": "doc-123",
                "artifact_type": "document",
                "product": {"name": "test", "created": False},
                "version": {"number": "1.0", "created": False},
            }

            with runner.isolated_filesystem():
                Path("report.pdf").write_text("pdf-bytes")
                result = runner.invoke(
                    cli,
                    [
                        "upload-document",
                        "--product", "test",
                        "--version", "1.0",
                        "--file", "report.pdf",
                        "--type", "test_report",
                        "--no-ci-detect",
                    ],
                    env=self.BASE_ENV,
                )

        assert result.exit_code == 0, result.output
        assert "Document Type" in result.output
        assert "Test report" in result.output
