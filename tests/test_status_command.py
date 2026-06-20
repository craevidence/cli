"""Tests for status command: fail-on threshold logic, exit codes, and text output rendering."""

from io import StringIO

import pytest
from rich.console import Console

from cra_evidence_cli.commands import status as status_module
from cra_evidence_cli.commands.status import check_fail_on, format_status_output
from cra_evidence_cli.exceptions import (
    CRANonCompliantError,
    ReleasePolicyNotMetError,
    VulnerabilityThresholdExceeded,
)

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
        (
            "Any fail_on value (e.g. critical) fails when CRA status is "
            "incomplete (with vulns fixture)."
        )
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
                "critical", {},
                "incomplete",
                cra_floor_status="incomplete",
                release_policy_status="incomplete",
            )
        assert exc_info.value.exit_code == 20

    def test_release_policy_failure_exits_24(self):
        """Floor met but release policy not met raises ReleasePolicyNotMetError (exit 24)."""
        with pytest.raises(ReleasePolicyNotMetError) as exc_info:
            check_fail_on(
                "critical", {},
                "incomplete",
                cra_floor_status="ready",
                release_policy_status="incomplete",
            )
        assert exc_info.value.exit_code == 24

    def test_floor_and_policy_both_ready_passes(self):
        """Floor and release policy both ready -> no failure."""
        check_fail_on(
            "critical", {},
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

    def test_text_output_renders_retained_gemara_sources(
        self, status_response_clean, monkeypatch
    ):
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
                "gemara_source_download_url": (
                    "/api/v1/documents/doc-123/gemara-source/download"
                ),
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
