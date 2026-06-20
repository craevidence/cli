"""Tests for the local check report renderers."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

from cra_evidence_cli.local.models import Finding, LocalCheckResult
from cra_evidence_cli.local.report import print_text_report, render


def _result() -> LocalCheckResult:
    return LocalCheckResult(
        target="x",
        target_type="sbom",
        sbom_path=None,
        components=[],
        findings=[],
        dimensions=[
            {
                "entry_id": "cra:annex-i-part-ii-1",
                "result": "Needs Review",
                "title": "SBOM exists and is machine-readable",
                "message": "Parsed components.",
                "citation_ids": ["annex_I.part-ii-item-1", "annex_VII.item-2-b"],
            }
        ],
        coverage=[],
        provenance={"engine": "grype-local", "grype-db": "2026-06-13"},
        attributions=["Grype and Syft are Apache-2.0 projects from Anchore."],
        sources_consulted=["grype"],
    )


def test_default_text_is_concise() -> None:
    text = render(_result(), "text")
    # Concise default: summary + the scope note, but not the reviewed
    # dimensions or the "cannot tell you" block (those move behind -v).
    assert "Summary" in text
    # The dimension rows and the cannot-tell-you block are not rendered (the
    # -v hint may mention them by name, but the content itself is absent).
    assert "SBOM exists and is machine-readable" not in text
    assert "What this local snapshot cannot tell you" not in text
    assert "Exit 0 means no configured blocking findings" in text
    # And a pointer tells the user where the detail is.
    assert "-v" in text
    assert "--output json" in text


def test_verbose_text_shows_dimensions_but_not_raw_slugs() -> None:
    text = render(_result(), "text", verbose=True)
    assert "Reviewed dimensions" in text
    assert "SBOM exists and is machine-readable" in text
    assert "What this local snapshot cannot tell you" in text
    # Even verbose text keeps the raw citation slugs, provenance, and attribution
    # out of the human output (they live in JSON/SARIF).
    assert "annex_I.part-ii-item-1" not in text
    assert "annex_VII.item-2-b" not in text
    assert "grype-local" not in text
    assert "Apache-2.0" not in text


def test_json_output_retains_citations_provenance_and_attribution() -> None:
    data = json.loads(render(_result(), "json"))
    dim = data["cra_readiness_signal"]["dimensions"][0]
    assert dim["citation_ids"] == ["annex_I.part-ii-item-1", "annex_VII.item-2-b"]
    assert data["provenance"]["engine"] == "grype-local"
    assert data["attributions"] == ["Grype and Syft are Apache-2.0 projects from Anchore."]


def test_rich_text_report_uses_restrained_terminal_color() -> None:
    result = _result()
    result.findings = [
        Finding(
            id="CVE-2026-0001",
            package="demo",
            version="1.0.0",
            severity="critical",
            fixed_versions=["1.0.1"],
            known_exploited=True,
            epss_probability=0.91,
        )
    ]
    out = StringIO()
    console = Console(file=out, force_terminal=True, color_system="standard", width=120)

    print_text_report(console, result)

    rendered = out.getvalue()
    assert "\x1b[" in rendered
    assert "Local SBOM Check" in rendered
    assert "known-exploited" in rendered
    assert "Upload successful" not in rendered
    assert "╭" not in rendered


def test_plain_text_render_has_no_terminal_control_sequences() -> None:
    text = render(_result(), "text")
    assert "\x1b[" not in text
