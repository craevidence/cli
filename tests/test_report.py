"""Tests for the local check report renderers."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

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


def test_exit_note_reflects_exit_code() -> None:
    """A non-zero exit code produces a factual exit note, not the exit-0 wording."""
    passing = render(_result(), "text", exit_code=0)
    failing = render(_result(), "text", exit_code=10)

    assert "Exit 0 means no configured blocking findings" in passing
    assert "Exit 0 means no configured blocking findings" not in failing
    assert "Exit 10:" in failing
    assert "threshold exceeded" in failing


def test_exit_note_in_json_reflects_exit_code() -> None:
    """JSON output carries the correct exit_note for failing runs."""
    data = json.loads(render(_result(), "json", exit_code=10))
    assert "Exit 0 means" not in data["exit_note"]
    assert "Exit 10:" in data["exit_note"]

    data_pass = json.loads(render(_result(), "json", exit_code=0))
    assert "Exit 0 means no configured blocking findings" in data_pass["exit_note"]


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


# Fix 1: SARIF locations


def test_sarif_results_have_locations() -> None:
    """Every SARIF result must include a locations entry."""
    result = _result()
    result.findings = [
        Finding(id="CVE-2026-0001", package="demo", version="1.0.0", severity="high")
    ]
    doc = json.loads(render(result, "sarif"))
    for res in doc["runs"][0]["results"]:
        assert "locations" in res, "SARIF result missing locations"
        loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert loc, "SARIF location URI is empty"


def test_sarif_location_uses_sbom_path_not_tmp() -> None:
    """SARIF URI uses the user-supplied sbom_path, never an absolute /tmp path."""
    result = _result()
    result.sbom_path = Path("build/sbom.json")
    result.findings = [
        Finding(id="CVE-2026-0002", package="pkg", version="1.0.0", severity="medium")
    ]
    doc = json.loads(render(result, "sarif"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "build/sbom.json"
    assert not uri.startswith("/tmp")  # noqa: S108


def test_sarif_location_falls_back_when_sbom_path_is_tmp() -> None:
    """When sbom_path is a /tmp absolute path, the URI falls back to 'sbom.json'."""
    result = _result()
    result.sbom_path = Path("/tmp/syft-12345/sbom.json")  # noqa: S108
    result.findings = [
        Finding(id="CVE-2026-0003", package="pkg", version="1.0.0", severity="low")
    ]
    doc = json.loads(render(result, "sarif"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "sbom.json"
    assert not uri.startswith("/tmp")  # noqa: S108


def test_sarif_location_uses_sbom_output_from_provenance() -> None:
    """When sbom_path is absent but provenance has sbom_output, use that."""
    result = _result()
    result.sbom_path = None
    result.provenance = {"engine": "grype-local", "sbom_output": "out/generated.json"}
    result.findings = [
        Finding(id="CVE-2026-0004", package="pkg", version="1.0.0", severity="low")
    ]
    doc = json.loads(render(result, "sarif"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "out/generated.json"


# Fix 2: top-actions ranking


def test_top_actions_kev_without_fix_ranks_above_low_with_fix() -> None:
    """A KEV finding with no fix must rank above a low finding that has a fix."""
    result = _result()
    result.findings = [
        Finding(
            id="CVE-LOW-FIXED",
            package="low-pkg",
            version="1.0",
            severity="low",
            fixed_versions=["1.1"],
            known_exploited=False,
        ),
        Finding(
            id="CVE-KEV-UNFIXED",
            package="kev-pkg",
            version="2.0",
            severity="critical",
            fixed_versions=[],
            known_exploited=True,
        ),
    ]
    text = render(result, "text")
    kev_pos = text.find("kev-pkg")
    low_pos = text.find("low-pkg")
    assert kev_pos != -1, "KEV finding not in output"
    assert low_pos != -1, "low finding not in output"
    assert kev_pos < low_pos, "KEV finding should rank before low finding with fix"


def test_top_actions_includes_all_findings_not_only_fixed() -> None:
    """All findings are candidates; fix availability is only a tiebreaker."""
    result = _result()
    result.findings = [
        Finding(
            id="CVE-UNFIXED",
            package="unfixed-pkg",
            version="1.0",
            severity="critical",
            fixed_versions=[],
            known_exploited=False,
        ),
        Finding(
            id="CVE-FIXED",
            package="fixed-pkg",
            version="2.0",
            severity="low",
            fixed_versions=["2.1"],
            known_exploited=False,
        ),
    ]
    text = render(result, "text")
    # The critical unfixed finding must appear in Top actions.
    assert "unfixed-pkg" in text


# Fix 3: markdown sections


def test_markdown_promotes_all_sections() -> None:
    """All double-newline section breaks become ## headings, not just the first."""
    result = _result()
    text = render(result, "markdown")
    # Must start with a single # heading.
    assert text.startswith("# Local SBOM Check")
    # All major sections must be ## headings.
    assert "\n\n## Summary" in text
    assert "\n\n## Top actions" in text


def test_markdown_first_line_is_h1_not_h2() -> None:
    """The very first line of markdown output is H1, not H2."""
    result = _result()
    first_line = render(result, "markdown").splitlines()[0]
    assert first_line.startswith("# ")
    assert not first_line.startswith("## ")


# Fix 5: footer text


def test_verbose_text_mentions_output_json_in_provenance_note() -> None:
    """The verbose data-provenance footer mentions '--output json'."""
    text = render(_result(), "text", verbose=True)
    assert "--output json" in text
    assert "full machine report" in text
