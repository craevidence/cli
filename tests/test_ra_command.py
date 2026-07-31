"""
Tests for `craevidence ra status`.

Follows the CliRunner + patched CRAEvidenceClient/asyncio.run pattern used by
test_scan_command.py, plus renderer tests via a captured StringIO console
(test_status_command.py's pattern).
"""

from __future__ import annotations

import json
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import ra as ra_module
from cra_evidence_cli.commands.ra import format_risk_assessment_output
from cra_evidence_cli.exceptions import APIError

BASE_ENV = {
    "CRA_EVIDENCE_API_KEY": "test_key_123",
    "CRA_EVIDENCE_URL": "http://localhost:8000",
}


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def ra_payload_needs_review():
    """A completed assessment that still needs review, no sign-off yet."""
    return {
        "assessment_status": "completed",
        "review_status": "needs_review",
        "completion_pct": 85,
        "inherited_from": None,
        "signed_off": None,
        "counts": {"assets": 12, "threats": 30, "risks": 18},
        "part_ii_coverage": {
            "applicable": True,
            "pct": 40,
            "resolved_count": 4,
            "expected_count": 10,
            "missing": [
                "Update mechanism",
                "Coordinated disclosure process",
                "SBOM management",
                "Patch delivery",
                "Security testing",
                "Vulnerability monitoring",
            ],
        },
    }


@pytest.fixture
def ra_payload_signed():
    """A signed-off assessment carried over from an earlier version."""
    return {
        "assessment_status": "signed_off",
        "review_status": "reviewed",
        "completion_pct": 100,
        "inherited_from": {
            "source_version": "1.0.0",
            "signed_at": "2026-01-10T09:00:00Z",
        },
        "signed_off": {
            "signed_by": "alice@acme.com",
            "signed_at": "2026-01-15T12:00:00Z",
        },
        "counts": {"assets": 12, "threats": 30, "risks": 18},
        "part_ii_coverage": {
            "applicable": True,
            "pct": 90,
            "resolved_count": 9,
            "expected_count": 10,
            "missing": ["Security testing"],
        },
    }


def _invoke(payload_or_exc, args, output_format=None):
    runner = CliRunner()
    cli_args = list(args)
    root_args = []
    if output_format:
        root_args = ["--output", output_format]

    with patch(
        "cra_evidence_cli.commands.ra.CRAEvidenceClient"
    ) as mock_client_cls, patch(
        "cra_evidence_cli.commands.ra.asyncio.run",
    ) as mock_run:
        mock_client_cls.return_value = MagicMock()
        if isinstance(payload_or_exc, Exception):
            mock_run.side_effect = payload_or_exc
        else:
            mock_run.return_value = payload_or_exc
        result = runner.invoke(cli, [*root_args, "ra", "status", *cli_args], env=BASE_ENV)
    return result


class TestRaStatusExitCodes:
    def test_default_exit_0_on_needs_review(self, ra_payload_needs_review):
        result = _invoke(
            ra_payload_needs_review,
            ["--product", "my-product", "--version", "1.2.3"],
        )
        assert result.exit_code == 0, result.output

    def test_fail_on_unreviewed_exits_28_on_needs_review(self, ra_payload_needs_review):
        result = _invoke(
            ra_payload_needs_review,
            [
                "--product", "my-product", "--version", "1.2.3",
                "--fail-on", "unreviewed",
            ],
        )
        assert result.exit_code == 28, result.output

    def test_fail_on_unreviewed_passes_when_reviewed(self, ra_payload_signed):
        result = _invoke(
            ra_payload_signed,
            [
                "--product", "my-product", "--version", "2.0.0",
                "--fail-on", "unreviewed",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_missing_ra_404_exits_0_with_note(self):
        """The read endpoint's 404 for "no risk assessment yet" carries
        details.resource_type == "Risk assessment" plus
        product_level_assessment_exists; that shape is swallowed into a
        note, not a failure."""
        result = _invoke(
            APIError(
                "No structured risk assessment exists for this version.",
                status_code=404,
                error_details={
                    "resource_type": "Risk assessment",
                    "product_level_assessment_exists": False,
                },
            ),
            ["--product", "my-product", "--version", "9.9.9"],
        )
        assert result.exit_code == 0, result.output
        assert "No risk assessment recorded yet" in result.output

    def test_missing_ra_404_exits_0_even_with_fail_on_unreviewed(self):
        result = _invoke(
            APIError(
                "No structured risk assessment exists for this version.",
                status_code=404,
                error_details={
                    "resource_type": "Risk assessment",
                    "product_level_assessment_exists": False,
                },
            ),
            [
                "--product", "my-product", "--version", "9.9.9",
                "--fail-on", "unreviewed",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_unknown_version_404_propagates(self):
        """A 404 for an unknown product or version (details.resource_type ==
        "Version"/"Product") is a real error, not "no risk assessment yet":
        a typo must fail loudly instead of being reported as exit 0."""
        result = _invoke(
            APIError(
                "Version '9.9.9' not found for product 'my-product'.",
                status_code=404,
                error_details={"resource_type": "Version"},
            ),
            ["--product", "my-product", "--version", "9.9.9"],
        )
        assert result.exit_code == 3, result.output

    def test_unknown_product_404_propagates(self):
        result = _invoke(
            APIError(
                "Product 'my-product' not found.",
                status_code=404,
                error_details={"resource_type": "Product"},
            ),
            ["--product", "my-product", "--version", "9.9.9"],
        )
        assert result.exit_code == 3, result.output

    def test_bare_404_without_details_propagates(self):
        """A 404 with no parsed details (non-JSON body, or a body without
        the RFC 7807 details envelope) cannot be told apart from a real
        error, so it must not be swallowed into exit 0."""
        result = _invoke(
            APIError("Not found", status_code=404),
            ["--product", "my-product", "--version", "9.9.9"],
        )
        assert result.exit_code == 3, result.output

    def test_missing_identity_exits_with_resolve_identity_code(self, monkeypatch):
        # No --product/--version, no env, no .cra/evidence.yaml: resolve_identity
        # raises CRAEvidenceError before the client is ever constructed.
        monkeypatch.delenv("CRA_EVIDENCE_PRODUCT", raising=False)
        monkeypatch.delenv("CRA_EVIDENCE_VERSION", raising=False)
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["ra", "status"], env=BASE_ENV)
        assert result.exit_code != 0
        assert "Product is required" in result.output or "Error" in result.output

    def test_non_404_api_error_propagates(self):
        result = _invoke(
            APIError("Server error", status_code=500),
            ["--product", "my-product", "--version", "1.2.3"],
        )
        assert result.exit_code == 3, result.output


class TestRaStatusJsonOutput:
    def test_json_includes_advisory_disclaimer(self, ra_payload_needs_review):
        result = _invoke(
            ra_payload_needs_review,
            ["--product", "my-product", "--version", "1.2.3"],
            output_format="json",
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["risk_assessment"]["review_status"] == "needs_review"
        assert parsed["advisory"]["disclaimer"]

    def test_json_with_fail_on_keeps_stdout_pure_json(self, ra_payload_needs_review):
        # The gate notice must go to stderr so machine consumers can always
        # parse stdout, even when the command exits 28.
        result = _invoke(
            ra_payload_needs_review,
            ["--product", "my-product", "--version", "1.2.3", "--fail-on", "unreviewed"],
            output_format="json",
        )
        assert result.exit_code == 28
        parsed = json.loads(result.stdout)
        assert parsed["risk_assessment"]["review_status"] == "needs_review"


class TestRaStatusJsonErrorPurity:
    """`ra status` error paths in --output json mode: stdout stays empty,
    diagnostics go to stderr, and the exit code is preserved."""

    def test_json_mode_api_error_keeps_stdout_empty(self):
        result = _invoke(
            APIError(
                "Version '9.9.9' not found for product 'my-product'.",
                status_code=404,
                error_details={"resource_type": "Version"},
            ),
            ["--product", "my-product", "--version", "9.9.9"],
            output_format="json",
        )
        assert result.exit_code == 3, result.output
        assert result.stdout.strip() == ""
        assert "Version '9.9.9' not found" in result.stderr

    def test_json_mode_missing_identity_keeps_stdout_empty(self, monkeypatch):
        monkeypatch.delenv("CRA_EVIDENCE_PRODUCT", raising=False)
        monkeypatch.delenv("CRA_EVIDENCE_VERSION", raising=False)
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli, ["--output", "json", "ra", "status"], env=BASE_ENV
            )
        assert result.exit_code != 0
        assert result.stdout.strip() == ""
        assert result.stderr.strip() != ""

    def test_text_mode_api_error_prints_to_stdout(self):
        result = _invoke(
            APIError(
                "Version '9.9.9' not found for product 'my-product'.",
                status_code=404,
                error_details={"resource_type": "Version"},
            ),
            ["--product", "my-product", "--version", "9.9.9"],
        )
        assert result.exit_code == 3, result.output
        assert "Version '9.9.9' not found" in result.stdout


class TestFormatRiskAssessmentOutput:
    """Renderer tests via a captured StringIO console (status.py test pattern)."""

    def _render(self, monkeypatch, data):
        out = StringIO()
        monkeypatch.setattr(
            ra_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        format_risk_assessment_output(data, "text")
        return out.getvalue()

    def test_json_output_no_raise(self, ra_payload_needs_review, capsys):
        format_risk_assessment_output(ra_payload_needs_review, "json")

    def test_text_output_needs_review(self, ra_payload_needs_review, monkeypatch):
        rendered = self._render(monkeypatch, ra_payload_needs_review)
        assert "Assessment Status" in rendered
        assert "Review Status" in rendered
        assert "needs_review" in rendered
        assert "not signed" in rendered
        assert "Part II Coverage" in rendered
        assert "Update mechanism" in rendered
        assert "+1 more" in rendered
        assert "guidance only, review state is not a compliance verdict" in rendered

    def test_text_output_signed(self, ra_payload_signed, monkeypatch):
        rendered = self._render(monkeypatch, ra_payload_signed)
        assert "Inherited From" in rendered
        assert "1.0.0" in rendered
        assert "Sign-off" in rendered
        assert "alice@acme.com" in rendered
        assert "guidance only, review state is not a compliance verdict" in rendered

    def test_text_output_minimal_data(self):
        """Empty dict is handled without raising."""
        format_risk_assessment_output({}, "text")


def test_risk_assessment_alias_registers_the_same_group():
    # `risk-assessment` is a discoverability alias for `ra`; both must expose
    # the same subcommands.
    from cra_evidence_cli.cli import cli as root

    assert root.commands["risk-assessment"] is root.commands["ra"]
