"""Tests for actionable SBOM validation command output."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cra_evidence_cli.cli import cli

BASE_ENV = {
    "CRA_EVIDENCE_API_KEY": "test_key_123",
    "CRA_EVIDENCE_URL": "http://localhost:8000",
}


def test_invalid_sbom_output_shows_detected_identity_and_next_step(tmp_path):
    sbom = tmp_path / "bom.xml"
    sbom.write_text("<bom/>")
    payload = {
        "valid": False,
        "format": None,
        "serialization": None,
        "spec_version": None,
        "component_count": 0,
        "purl_coverage_pct": 0.0,
        "versionless_count": 0,
        "warnings": [],
        "errors": ["CycloneDX XML schema validation failed"],
        "detected": {
            "family": "cyclonedx",
            "serialization": "xml",
            "version": "1.6",
        },
        "accepted_versions": ["1.6", "1.7"],
        "action": "Correct the reported fields and retry.",
    }

    with (
        patch("cra_evidence_cli.commands.validate.CRAEvidenceClient") as client_class,
        patch(
            "cra_evidence_cli.commands.validate.asyncio.run",
            return_value=payload,
        ),
    ):
        client_class.return_value = MagicMock()
        result = CliRunner().invoke(
            cli,
            ["validate", "--sbom", str(sbom)],
            env=BASE_ENV,
        )

    assert result.exit_code == 1
    assert "Detected: cyclonedx 1.6 xml" in result.output
    assert "Accepted versions: 1.6, 1.7" in result.output
    assert "Next step: Correct the reported fields and retry." in result.output
