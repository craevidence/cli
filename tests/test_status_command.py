"""Tests for status command: fail-on threshold logic, exit codes, and text output rendering."""

import json
from io import StringIO
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import status as status_module
from cra_evidence_cli.commands.status import check_fail_on, format_status_output
from cra_evidence_cli.exceptions import (
    CRANonCompliantError,
    ReleasePolicyNotMetError,
    VulnerabilityThresholdExceeded,
)

BASE_ENV = {
    "CRA_EVIDENCE_API_KEY": "test_key_123",
    "CRA_EVIDENCE_URL": "http://localhost:8000",
}

# Fixtures - mock responses matching CIStatusResponse schema


@pytest.fixture
def status_response_clean():
    """A clean version: CRA ready, no vulnerabilities."""
    return {
        "product": {"id": "prod-123", "name": "My Product", "slug": "my-product"},
        "version": {
            "id": "ver-456",
            "number": "1.2.3",
            "cra_status": "ready",
            "release_state": "released",
            "environment": "production",
        },
        "cra_status": "ready",
        "release_state": "released",
        "scan_state": "completed",
        "sbom": {"format": "cyclonedx", "component_count": 142, "quality_score": 85},
        "vulnerability_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0,
        },
        "documents": {
            "risk_assessment": True,
            "eu_declaration_of_conformity": True,
            "user_manual": True,
            "vulnerability_policy": True,
        },
        "document_artifacts": [],
        "artifact_inventory": {},
    }


@pytest.fixture
def status_response_vulnerable():
    """A version with vulnerabilities."""
    return {
        "product": {"id": "prod-123", "name": "My Product", "slug": "my-product"},
        "version": {
            "id": "ver-456",
            "number": "2.0.0",
            "cra_status": "incomplete",
            "release_state": "draft",
            "environment": "staging",
        },
        "cra_status": "incomplete",
        "release_state": "draft",
        "scan_state": "completed",
        "sbom": {"format": "spdx", "component_count": 200, "quality_score": 60},
        "vulnerability_summary": {
            "critical": 2,
            "high": 5,
            "medium": 10,
            "low": 20,
            "total": 37,
        },
        "documents": {
            "risk_assessment": False,
            "eu_declaration_of_conformity": True,
            "user_manual": False,
            "vulnerability_policy": True,
        },
        "document_artifacts": [],
        "artifact_inventory": {},
    }


@pytest.fixture
def status_response_incomplete():
    """A version that is not CRA ready."""
    return {
        "product": {"id": "prod-123", "name": "My Product", "slug": "my-product"},
        "version": {
            "id": "ver-456",
            "number": "0.1.0",
            "cra_status": "incomplete",
            "release_state": "draft",
            "environment": "development",
        },
        "cra_status": "incomplete",
        "release_state": "draft",
        "scan_state": "none",
        "sbom": None,
        "vulnerability_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0,
        },
        "documents": {},
        "document_artifacts": [],
        "artifact_inventory": {},
    }


# check_fail_on tests


class TestCheckFailOn:
    """Tests for fail-on threshold checking.

    check_fail_on(fail_on, vulnerability_summary, cra_status) is only invoked
    by the command when fail_on != "none". Tests reflect that contract directly.
    """

    def test_no_fail_on_never_called(self):
        """check_fail_on with a ready status and no vulns does not raise."""
        check_fail_on("critical", {}, "ready")  # Should not raise

    def test_non_compliant_fails_on_incomplete(self, status_response_incomplete):
        """Any fail_on value (e.g. critical) fails when CRA status is incomplete."""
        with pytest.raises(CRANonCompliantError) as exc_info:
            check_fail_on(
                "critical",
                status_response_incomplete.get("vulnerability_summary", {}),
                status_response_incomplete.get("cra_status", ""),
            )
        assert exc_info.value.exit_code == 20

    def test_non_compliant_fails_on_incomplete_vulnerable(self, status_response_vulnerable):
        """Any fail_on value (e.g. critical) fails when CRA status is incomplete (vulns fixture)."""
        with pytest.raises(CRANonCompliantError):
            check_fail_on(
                "critical",
                # status_response_vulnerable has 2 critical vulns, so strip them
                # to isolate the CRA status check.
                {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
                status_response_vulnerable.get("cra_status", ""),
            )

    def test_non_compliant_passes_on_ready(self, status_response_clean):
        """Any fail_on value passes when CRA status is ready and no vulns."""
        check_fail_on(
            "critical",
            status_response_clean.get("vulnerability_summary", {}),
            status_response_clean.get("cra_status", ""),
        )  # Should not raise

    # ---- Floor (exit 20) vs release policy (exit 24) split ----

    def test_floor_failure_exits_20(self):
        """A legal-floor failure raises CRANonCompliantError (exit 20)."""
        with pytest.raises(CRANonCompliantError) as exc_info:
            check_fail_on(
                "critical",
                {},
                "incomplete",
                cra_floor_status="incomplete",
                release_policy_status="incomplete",
            )
        assert exc_info.value.exit_code == 20

    def test_release_policy_failure_exits_24(self):
        """Floor met but release policy not met raises ReleasePolicyNotMetError (exit 24)."""
        with pytest.raises(ReleasePolicyNotMetError) as exc_info:
            check_fail_on(
                "critical",
                {},
                "incomplete",
                cra_floor_status="ready",
                release_policy_status="incomplete",
            )
        assert exc_info.value.exit_code == 24

    def test_floor_and_policy_both_ready_passes(self):
        """Floor and release policy both ready -> no failure."""
        check_fail_on(
            "critical",
            {},
            "ready",
            cra_floor_status="ready",
            release_policy_status="ready",
        )  # Should not raise

    def test_backcompat_single_status_uses_exit_20(self):
        """Older API responses without floor/policy fields fall back to the status gate."""
        with pytest.raises(CRANonCompliantError) as exc_info:
            check_fail_on("critical", {}, "incomplete")
        assert exc_info.value.exit_code == 20

    def test_critical_fails_on_critical_vulns(self, status_response_vulnerable):
        """--fail-on critical fails when critical vulns > 0."""
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_fail_on(
                "critical",
                status_response_vulnerable.get("vulnerability_summary", {}),
                status_response_vulnerable.get("cra_status", ""),
            )
        assert exc_info.value.exit_code == 10
        assert exc_info.value.severity == "critical"

    def test_critical_passes_when_no_critical(self, status_response_clean):
        """--fail-on critical passes when no critical vulns."""
        check_fail_on(
            "critical",
            status_response_clean.get("vulnerability_summary", {}),
            status_response_clean.get("cra_status", ""),
        )

    def test_high_fails_on_critical_vulns(self, status_response_vulnerable):
        """--fail-on high fails on critical vulns (most severe first)."""
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_fail_on(
                "high",
                status_response_vulnerable.get("vulnerability_summary", {}),
                status_response_vulnerable.get("cra_status", ""),
            )
        assert exc_info.value.exit_code == 10  # critical exit code

    def test_high_fails_on_high_vulns(self):
        """--fail-on high fails on high vulns when no critical."""
        vuln_summary = {
            "critical": 0,
            "high": 3,
            "medium": 0,
            "low": 0,
            "total": 3,
        }
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_fail_on("high", vuln_summary, "ready")
        assert exc_info.value.exit_code == 11
        assert exc_info.value.severity == "high"

    def test_medium_fails_on_medium_vulns(self):
        """--fail-on medium fails on medium vulns."""
        vuln_summary = {
            "critical": 0,
            "high": 0,
            "medium": 5,
            "low": 0,
            "total": 5,
        }
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_fail_on("medium", vuln_summary, "ready")
        assert exc_info.value.exit_code == 12

    def test_medium_passes_when_only_low(self):
        """--fail-on medium passes when only low vulns."""
        vuln_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 10,
            "total": 10,
        }
        check_fail_on("medium", vuln_summary, "ready")  # Should not raise

    def test_low_fails_on_low_vulns(self):
        """--fail-on low fails on low vulns."""
        vuln_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 1,
            "total": 1,
        }
        with pytest.raises(VulnerabilityThresholdExceeded):
            check_fail_on("low", vuln_summary, "ready")

    def test_empty_vuln_summary_passes(self):
        """Empty vulnerability summary passes all threshold checks when CRA is ready."""
        check_fail_on("critical", {}, "ready")
        check_fail_on("high", {}, "ready")
        check_fail_on("medium", {}, "ready")
        check_fail_on("low", {}, "ready")

    def test_missing_vuln_summary_passes(self):
        """Empty vulnerability summary (no keys) passes all checks when CRA is ready."""
        check_fail_on("critical", {}, "ready")
        check_fail_on("high", {}, "ready")

    def test_vulnerability_error_raised_before_cra_check(self):
        """Vulnerability threshold error is raised before the status check.

        Even when CRA status is incomplete, if vulns exceed the threshold the
        VulnerabilityThresholdExceeded error takes priority (it is checked first
        in check_fail_on).
        """
        vuln_summary = {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1}
        with pytest.raises(VulnerabilityThresholdExceeded):
            check_fail_on("critical", vuln_summary, "incomplete")


# format_status_output tests (basic rendering - no assertion on Rich markup)


class TestFormatStatusOutput:
    """Tests for format_status_output rendering."""

    def test_json_output(self, status_response_clean, capsys):
        """JSON format renders without raising."""
        format_status_output(status_response_clean, "json")

    def test_text_output_clean(self, status_response_clean):
        """Text format renders a clean (ready, no vulns) version without raising."""
        format_status_output(status_response_clean, "text")

    def test_text_output_renders_package_and_component_attribution_rows(
        self, status_response_clean, monkeypatch
    ):
        """Text status output must expose component attribution and package count."""
        out = StringIO()
        monkeypatch.setattr(
            status_module,
            "console",
            Console(file=out, force_terminal=False, width=120, color_system=None),
        )
        status_response_clean["sbom"].update(
            {
                "component_slug": "edge",
                "component_repository": "https://github.com/acme/edge",
            }
        )

        format_status_output(status_response_clean, "text")

        rendered = out.getvalue()
        assert "Packages" in rendered
        assert "142" in rendered
        assert "Attributed to component" in rendered
        assert "edge" in rendered
        assert "Component repository" in rendered
        assert "https://github.com/acme/edge" in rendered

    def test_text_output_vulnerable(self, status_response_vulnerable):
        """Text format renders a vulnerable version without raising."""
        format_status_output(status_response_vulnerable, "text")

    def test_text_output_incomplete(self, status_response_incomplete):
        """Text format renders an incomplete version without raising."""
        format_status_output(status_response_incomplete, "text")

    def test_text_output_renders_retained_gemara_sources(self, status_response_clean, monkeypatch):
        """Status text uses explicit source URLs for download hints."""
        out = StringIO()
        monkeypatch.setattr(
            status_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        status_response_clean["document_artifacts"] = [
            {
                "id": "doc-123",
                "doc_type": "risk_assessment",
                "filename": "risk-catalog.pdf",
                "review_status": "pending_review",
                "gemara_source_download_url": ("/api/v1/documents/doc-123/gemara-source/download"),
            }
        ]

        format_status_output(status_response_clean, "text")

        rendered = out.getvalue()
        assert "Retained Source YAML" in rendered
        assert "Risk assessment (risk-catalog.pdf)" in rendered
        assert (
            "craevidence compliance-as-code download-source "
            "--document-id doc-123 --output <output.yaml>"
        ) in rendered
        assert "/api/v1/documents/doc-123/gemara-source/download" in rendered

    def test_text_output_does_not_truncate_retained_source_command(
        self, status_response_clean, monkeypatch
    ):
        """Long retained-source commands must remain copyable in narrow output."""
        out = StringIO()
        monkeypatch.setattr(
            status_module,
            "console",
            Console(file=out, force_terminal=False, width=72, color_system=None),
        )
        document_id = "b2f1f39b-4094-4fe7-aad9-3a916264b940"
        status_response_clean["document_artifacts"] = [
            {
                "id": document_id,
                "doc_type": "risk_assessment",
                "filename": "risk-catalog.pdf",
                "review_status": "pending_review",
                "gemara_source_download_url": (
                    f"/api/v1/documents/{document_id}/gemara-source/download"
                ),
            }
        ]

        format_status_output(status_response_clean, "text")

        rendered = out.getvalue()
        assert "craevidence compliance-as-code download-source" in rendered
        assert f"--document-id {document_id}" in rendered
        assert "--output <output.yaml>" in rendered
        assert "…" not in rendered

    def test_text_output_does_not_infer_retained_source_without_url(
        self, status_response_clean, monkeypatch
    ):
        """A document artifact without explicit source URL does not print a hint."""
        out = StringIO()
        monkeypatch.setattr(
            status_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        status_response_clean["document_artifacts"] = [
            {
                "id": "doc-123",
                "doc_type": "risk_assessment",
                "filename": "risk-catalog.pdf",
                "review_status": "pending_review",
                "gemara_source_download_url": None,
            }
        ]

        format_status_output(status_response_clean, "text")

        rendered = out.getvalue()
        assert "CRA Documents" in rendered
        assert "Retained Source YAML" not in rendered
        assert "download-source" not in rendered

    def test_text_output_renders_scope_aware_artifact_inventory(
        self, status_response_clean, monkeypatch
    ):
        """Evidence inventory reports included families and scoped omissions."""
        out = StringIO()
        monkeypatch.setattr(
            status_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        status_response_clean["artifact_inventory"] = {
            "sbom": {
                "included": True,
                "count": 1,
                "latest_id": "sbom-1",
                "latest_filename": "sbom.json",
                "latest_status": None,
                "required_scope": "sbom:read",
                "reason": None,
            },
            "static_analysis": {
                "included": False,
                "count": None,
                "latest_id": None,
                "latest_filename": None,
                "latest_status": None,
                "required_scope": "vuln:read",
                "reason": "missing_scope",
            },
            "attestations": {
                "included": True,
                "count": 1,
                "latest_id": "att-1",
                "latest_filename": "provenance.json",
                "latest_status": None,
                "required_scope": "sbom:read",
                "reason": None,
            },
        }

        format_status_output(status_response_clean, "text")

        rendered = out.getvalue()
        assert "Evidence Inventory" in rendered
        assert "SBOM" in rendered
        assert "1 (sbom.json)" in rendered
        assert "Static Analysis" in rendered
        assert "requires vuln:read" in rendered
        assert "Attestations" in rendered
        assert "1 (provenance.json)" in rendered

    def test_text_output_minimal_data(self):
        """Empty dict is handled without raising."""
        format_status_output({}, "text")

    def test_text_output_null_sbom(self):
        """Null SBOM field is handled without raising."""
        data = {
            "product": {"name": "Test"},
            "version": {"number": "1.0"},
            "cra_status": "incomplete",
            "sbom": None,
        }
        format_status_output(data, "text")


class TestIdentifierCoverage:
    """Tests for version_matching_identifier_coverage rendering.

    The API reports validated declared matching-identifier coverage alongside the
    vulnerability result. A zero-finding result must never read as an
    unqualified clean or pass verdict when coverage is not complete: this
    directly encodes the risk that an SBOM can list only generic identifiers
    and return no findings.
    """

    def _render(self, data, monkeypatch, width=160):
        out = StringIO()
        monkeypatch.setattr(
            status_module,
            "console",
            Console(file=out, force_terminal=False, width=width, color_system=None),
        )
        format_status_output(data, "text")
        # Collapse whitespace/line wraps so phrase assertions do not depend on
        # exactly where the terminal table wraps long caveat text.
        return " ".join(out.getvalue().split())

    def _render_json(self, data, monkeypatch):
        """Render through the real production formatter, not a bare Console.

        Asserting against a locally constructed Console.print_json would test
        rich, not this CLI: the json branch of format_status_output could be
        deleted and such a test would still pass.
        """
        out = StringIO()
        monkeypatch.setattr(
            status_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        format_status_output(data, "json")
        return out.getvalue()

    def test_complete_coverage_renders_no_extra_rows(self, status_response_clean, monkeypatch):
        """A complete-coverage result adds nothing beyond the existing vuln output.

        Complete coverage proves supported identifiers were declared. It does not prove the
        vulnerability database was fresh, that matching actually ran, or that the
        scanner did not error, so a zero-finding total still renders as the
        neutral "0 found" and never as a "clean" claim, even here.
        """
        status_response_clean["version_matching_identifier_coverage"] = {
            "total_components": 142,
            "ecosystem_purl": 140,
            "declared_cpe": 2,
            "generic_or_unsupported_purl_only": 0,
            "no_supported_purl_or_cpe": 0,
            "projection_unknown": 0,
            "state": "complete",
            "reason_code": "all_components_declare_matching_identifier",
        }

        rendered = self._render(status_response_clean, monkeypatch)

        assert "Matching Identifier Coverage" not in rendered
        assert "0 found" in rendered
        assert "0 (clean)" not in rendered

    def test_incomplete_coverage_qualifies_zero_finding_result(
        self, status_response_clean, monkeypatch
    ):
        """A zero-finding result with incomplete coverage never claims 'clean'.

        The two components declare only generic PURLs. Incomplete coverage means
        they have no validated declared matching identifier, so zero findings
        cannot be presented as a clean result.
        """
        status_response_clean["vulnerability_summary"] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0,
        }
        status_response_clean["version_matching_identifier_coverage"] = {
            "total_components": 2,
            "ecosystem_purl": 0,
            "declared_cpe": 0,
            "generic_or_unsupported_purl_only": 2,
            "no_supported_purl_or_cpe": 0,
            "projection_unknown": 0,
            "state": "incomplete",
            "reason_code": "components_without_matching_identifier",
        }

        rendered = self._render(status_response_clean, monkeypatch)

        assert "0 (clean)" not in rendered
        assert "0 found" in rendered
        assert "Matching Identifier Coverage" in rendered
        assert "0/2 components declare a supported ecosystem PURL or validated CPE" in rendered
        # The caveat explaining that this is not a clean claim still prints.
        assert "does not mean those components are clean" in rendered
        assert "an attempted query is not a successful match" in rendered
        assert "are still matched" not in rendered
        assert "reason_code: components_without_matching_identifier" in rendered

    def test_incomplete_coverage_shown_alongside_nonzero_findings(
        self, status_response_vulnerable, monkeypatch
    ):
        """Incomplete coverage is surfaced even when findings are non-zero.

        Findings exist, but some components lack a validated declared matching
        identifier, so the caveat applies regardless of vulnerability count.
        """
        status_response_vulnerable["version_matching_identifier_coverage"] = {
            "total_components": 200,
            "ecosystem_purl": 150,
            "declared_cpe": 10,
            "generic_or_unsupported_purl_only": 30,
            "no_supported_purl_or_cpe": 10,
            "projection_unknown": 0,
            "state": "incomplete",
            "reason_code": "components_without_matching_identifier",
        }

        rendered = self._render(status_response_vulnerable, monkeypatch)

        assert "Matching Identifier Coverage" in rendered
        assert "160/200 components declare a supported ecosystem PURL or validated CPE" in rendered
        # A non-zero finding count is unaffected by the coverage-aware wording:
        # the severity breakdown still renders and no zero-finding text appears.
        assert "0 (clean)" not in rendered
        assert "0 found" not in rendered
        assert "Critical" in rendered

    def test_incomplete_coverage_qualifies_a_legacy_subset(
        self, status_response_clean, monkeypatch
    ):
        status_response_clean["version_matching_identifier_coverage"] = {
            "total_components": 2,
            "ecosystem_purl": 0,
            "declared_cpe": 0,
            "generic_or_unsupported_purl_only": 1,
            "no_supported_purl_or_cpe": 1,
            "projection_unknown": 1,
            "state": "incomplete",
            "reason_code": "components_without_matching_identifier",
        }

        rendered = self._render(status_response_clean, monkeypatch)

        assert (
            "0/2 stored component projections contain a supported ecosystem PURL "
            "or validated CPE" in rendered
        )
        assert "At least one component with a current projection" in rendered
        assert "legacy projection that predates CPE tracking" in rendered
        assert "Their declared-CPE coverage cannot be verified" in rendered
        assert "Components outside this count declare only" not in rendered
        assert "0 (clean)" not in rendered

    def test_unknown_coverage_is_neutral_and_not_blaming(self, status_response_clean, monkeypatch):
        """Legacy projection state gets neutral wording, with no fault implied."""
        status_response_clean["version_matching_identifier_coverage"] = {
            "total_components": None,
            "ecosystem_purl": None,
            "declared_cpe": None,
            "generic_or_unsupported_purl_only": None,
            "no_supported_purl_or_cpe": None,
            "projection_unknown": None,
            "state": "unknown",
            "reason_code": "legacy_projection_unknown",
        }

        rendered = self._render(status_response_clean, monkeypatch)

        assert "Matching Identifier Coverage" in rendered
        assert "not verifiable" in rendered
        assert "predate CPE tracking" in rendered
        assert "Re-upload the current SBOM" in rendered
        # Unmeasured coverage never claims cleanliness, even neutrally worded.
        assert "0 (clean)" not in rendered
        assert "0 found" in rendered
        # No blame or fault language directed at the customer.
        assert "you did" not in rendered.lower()
        assert "your fault" not in rendered.lower()
        assert "error" not in rendered.lower()

    def test_unknown_state_with_unrecognised_reason_does_not_invent_legacy_history(
        self, status_response_clean, monkeypatch
    ):
        status_response_clean["version_matching_identifier_coverage"] = {
            "total_components": None,
            "ecosystem_purl": None,
            "declared_cpe": None,
            "generic_or_unsupported_purl_only": None,
            "no_supported_purl_or_cpe": None,
            "projection_unknown": None,
            "state": "unknown",
            "reason_code": "future_unknown_reason",
        }

        rendered = self._render(status_response_clean, monkeypatch)

        assert "Matching Identifier Coverage" in rendered
        assert "unrecognised" in rendered
        assert "does not recognise the coverage state" in rendered
        assert "predate CPE tracking" not in rendered
        assert "Re-upload the current SBOM" not in rendered

    def test_inconsistent_complete_pair_fails_closed(self, status_response_clean, monkeypatch):
        status_response_clean["version_matching_identifier_coverage"] = {
            "total_components": 2,
            "ecosystem_purl": 2,
            "declared_cpe": 0,
            "generic_or_unsupported_purl_only": 0,
            "no_supported_purl_or_cpe": 0,
            "projection_unknown": 0,
            "state": "complete",
            "reason_code": "future_complete_reason",
        }

        rendered = self._render(status_response_clean, monkeypatch)

        assert "Matching Identifier Coverage" in rendered
        assert "unrecognised" in rendered
        assert "0 found" in rendered
        assert "0 (clean)" not in rendered

    def test_no_components_is_not_described_as_unidentified_components(
        self, status_response_clean, monkeypatch
    ):
        status_response_clean["version_matching_identifier_coverage"] = {
            "total_components": 0,
            "ecosystem_purl": 0,
            "declared_cpe": 0,
            "generic_or_unsupported_purl_only": 0,
            "no_supported_purl_or_cpe": 0,
            "projection_unknown": 0,
            "state": "incomplete",
            "reason_code": "no_components",
        }

        rendered = self._render(status_response_clean, monkeypatch)

        assert "no components to measure" in rendered
        assert "coverage cannot be measured" in rendered
        assert "Components outside this count" not in rendered
        assert "does not mean the product is clean" in rendered

    def test_no_components_explanation_is_selected_by_reason_code(
        self, status_response_clean, monkeypatch
    ):
        status_response_clean["version_matching_identifier_coverage"] = {
            "total_components": 7,
            "ecosystem_purl": 0,
            "declared_cpe": 0,
            "generic_or_unsupported_purl_only": 0,
            "no_supported_purl_or_cpe": 0,
            "projection_unknown": 0,
            "state": "incomplete",
            "reason_code": "no_components",
        }

        rendered = self._render(status_response_clean, monkeypatch)

        assert "no components to measure" in rendered
        assert "Components outside this count" not in rendered

    def test_unrecognized_state_fails_closed_without_inventing_a_cause(
        self, status_response_clean, monkeypatch
    ):
        """An unrecognised state fails closed but is never given a cause we have not established.

        Telling the user the result "predates coverage tracking" would assert a
        history that a newer server state is no evidence of.
        """
        status_response_clean["version_matching_identifier_coverage"] = {
            "total_components": 5,
            "ecosystem_purl": 5,
            "declared_cpe": 0,
            "generic_or_unsupported_purl_only": 0,
            "no_supported_purl_or_cpe": 0,
            "projection_unknown": 0,
            "state": "some_future_state",
            "reason_code": "future_reason",
        }

        rendered = self._render(status_response_clean, monkeypatch)

        assert "Matching Identifier Coverage" in rendered
        assert "does not recognise the coverage state" in rendered
        # The invented history must not be offered for a state we cannot read.
        assert "predates coverage tracking" not in rendered
        assert "Re-upload the current SBOM" not in rendered
        # An unrecognised state is never treated as complete for the clean claim.
        assert "0 (clean)" not in rendered
        assert "0 found" in rendered

    def test_absent_coverage_field_says_nothing_extra(self, status_response_clean, monkeypatch):
        """When the field is absent (e.g. an older server), no coverage rows render.

        Absence must never be read as coverage being complete: fail closed and
        never print the unqualified clean claim.
        """
        assert "version_matching_identifier_coverage" not in status_response_clean

        rendered = self._render(status_response_clean, monkeypatch)

        assert "Matching Identifier Coverage" not in rendered
        assert "0 (clean)" not in rendered
        assert "0 found" in rendered

    def test_null_coverage_field_says_nothing_extra(self, status_response_clean, monkeypatch):
        """An explicit null coverage value is handled the same as an absent field."""
        status_response_clean["version_matching_identifier_coverage"] = None

        rendered = self._render(status_response_clean, monkeypatch)

        assert "Matching Identifier Coverage" not in rendered
        assert "0 (clean)" not in rendered
        assert "0 found" in rendered

    def test_json_output_passes_coverage_through_verbatim(self, status_response_clean, monkeypatch):
        """JSON output is additive: the coverage object round-trips unchanged."""
        coverage = {
            "total_components": 2,
            "ecosystem_purl": 0,
            "declared_cpe": 0,
            "generic_or_unsupported_purl_only": 0,
            "no_supported_purl_or_cpe": 2,
            "projection_unknown": 0,
            "state": "incomplete",
            "reason_code": "components_without_matching_identifier",
        }
        status_response_clean["version_matching_identifier_coverage"] = coverage

        rendered = self._render_json(status_response_clean, monkeypatch)

        assert '"version_matching_identifier_coverage"' in rendered
        # Parse it back: the coverage object must survive the real json branch
        # unchanged, which a substring check alone would not establish.
        assert json.loads(rendered)["version_matching_identifier_coverage"] == coverage

    @pytest.mark.parametrize(
        "coverage_state",
        ["complete", "incomplete", "unknown", "some_future_state", None],
    )
    def test_clean_claim_never_appears_in_any_output_path(
        self, status_response_clean, status_response_vulnerable, monkeypatch, coverage_state
    ):
        """The literal phrase "(clean)" must never appear, regardless of coverage state.

        A zero-finding total proves only that nothing was found in what could be
        checked; it does not prove the vulnerability database was fresh, that
        matching actually ran, or that the scanner did not error. This guards
        against the claim resurfacing for any coverage state, including states
        this CLI version does not recognize.
        """
        for data in (status_response_clean, status_response_vulnerable):
            if coverage_state is None:
                data.pop("version_matching_identifier_coverage", None)
            else:
                data["version_matching_identifier_coverage"] = {
                    "total_components": 1,
                    "ecosystem_purl": 1,
                    "declared_cpe": 0,
                    "generic_or_unsupported_purl_only": 0,
                    "no_supported_purl_or_cpe": 0,
                    "projection_unknown": 0,
                    "state": coverage_state,
                    "reason_code": "all_components_declare_matching_identifier",
                }

            rendered = self._render(data, monkeypatch)
            assert "(clean)" not in rendered

            assert "(clean)" not in self._render_json(data, monkeypatch)


class TestWaitReadyGateLabel:
    """Tests that wait-ready labels its success message by the gated field.

    Invokes the real `wait-ready` command end to end, mocking only the HTTP
    client. A test that reimplements the label ternary locally and asserts
    against its own copy cannot fail when the command itself regresses; this
    exercises the production code path instead.
    """

    def _invoke(self, response: dict):
        with patch.object(status_module, "CRAEvidenceClient") as client_class:
            client = client_class.return_value
            client.get_version_status = AsyncMock(return_value=response)
            return CliRunner().invoke(
                cli,
                ["wait-ready", "--product", "test-product", "--version", "1.0.0"],
                env=BASE_ENV,
            )

    def test_gate_field_identified_by_release_policy_status(self):
        """When release_policy_status is set, the gate label is 'Policy Status'."""
        result = self._invoke({"cra_status": "ready", "release_policy_status": "ready"})

        assert result.exit_code == 0, result.output
        assert "Policy Status: READY" in result.output
        assert "CRA Status: READY" not in result.output

    def test_gate_label_falls_back_to_cra_status(self):
        """When release_policy_status is absent, the gate label is 'CRA Status'."""
        result = self._invoke({"cra_status": "ready"})

        assert result.exit_code == 0, result.output
        assert "CRA Status: READY" in result.output
