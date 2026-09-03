"""Tests for the local check report renderers."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console

from cra_evidence_cli.local.models import Component, Finding, LocalCheckResult, identifier_coverage
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
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "build/sbom.json"
    assert not uri.startswith("/tmp")  # noqa: S108


def test_sarif_location_falls_back_when_sbom_path_is_tmp() -> None:
    """When sbom_path is a /tmp absolute path, the URI falls back to 'sbom.json'."""
    result = _result()
    result.sbom_path = Path("/tmp/syft-12345/sbom.json")  # noqa: S108
    result.findings = [Finding(id="CVE-2026-0003", package="pkg", version="1.0.0", severity="low")]
    doc = json.loads(render(result, "sarif"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "sbom.json"
    assert not uri.startswith("/tmp")  # noqa: S108


def test_sarif_location_uses_sbom_output_from_provenance() -> None:
    """When sbom_path is absent but provenance has sbom_output, use that."""
    result = _result()
    result.sbom_path = None
    result.provenance = {"engine": "grype-local", "sbom_output": "out/generated.json"}
    result.findings = [Finding(id="CVE-2026-0004", package="pkg", version="1.0.0", severity="low")]
    doc = json.loads(render(result, "sarif"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
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


# Identifier field presence


def _result_with_components(components: list[Component]) -> LocalCheckResult:
    result = _result()
    result.components = components
    result.identifier_coverage = identifier_coverage(components)
    return result


_MIXED_COMPONENTS = [
    Component(name="internal-lib", version="1.0", purl=None),
    Component(name="requests", version="2.31.0", purl="pkg:pypi/requests@2.31.0"),
]
_FULLY_IDENTIFIED_COMPONENTS = [
    Component(name="requests", version="2.31.0", purl="pkg:pypi/requests@2.31.0"),
    Component(name="flask", version="3.0.0", purl="pkg:pypi/flask@3.0.0"),
]
_GENERIC_IDENTIFIER_COMPONENTS = [
    Component(
        name="firmware.bin",
        version="1.0",
        purl="pkg:generic/example/firmware.bin@1.0",
    )
]


def test_local_identifier_coverage_describes_field_presence() -> None:
    coverage = identifier_coverage(_MIXED_COMPONENTS)
    assert "field-presence count" in coverage["note"]
    assert "does not validate PURL types or CPE syntax" in coverage["note"]


def test_identifier_coverage_absent_when_no_components() -> None:
    """No components to measure means no coverage row, not a claim of completeness."""
    result = _result_with_components([])
    assert result.identifier_coverage is None
    for fmt in ("text", "markdown"):
        assert "Identifier field presence" not in render(result, fmt)
    data = json.loads(render(result, "json"))
    assert data["identifier_coverage"] is None
    sarif = json.loads(render(result, "sarif"))
    assert sarif["runs"][0]["tool"]["driver"]["properties"]["identifierCoverage"] is None


def test_identifier_coverage_incomplete_shown_in_text_with_caveat() -> None:
    text = render(_result_with_components(_MIXED_COMPONENTS), "text")
    assert (
        "Identifier field presence: 1/2 components contain a non-blank PURL or CPE string" in text
    )
    assert "does not mean those components are clean" in text


def test_identifier_coverage_incomplete_shown_in_markdown() -> None:
    text = render(_result_with_components(_MIXED_COMPONENTS), "markdown")
    assert (
        "Identifier field presence: 1/2 components contain a non-blank PURL or CPE string" in text
    )
    assert "field-presence count" in text


def test_identifier_coverage_incomplete_shown_in_json() -> None:
    data = json.loads(render(_result_with_components(_MIXED_COMPONENTS), "json"))
    coverage = data["identifier_coverage"]
    assert coverage["total_components"] == 2
    assert coverage["components_with_identifier_field"] == 1
    assert coverage["all_components_have_identifier_field"] is False
    assert "field-presence count" in coverage["note"]


def test_identifier_coverage_incomplete_shown_in_sarif_properties() -> None:
    sarif = json.loads(render(_result_with_components(_MIXED_COMPONENTS), "sarif"))
    coverage = sarif["runs"][0]["tool"]["driver"]["properties"]["identifierCoverage"]
    assert coverage["total_components"] == 2
    assert coverage["components_with_identifier_field"] == 1
    assert coverage["all_components_have_identifier_field"] is False
    assert "field-presence count" in coverage["note"]


def test_full_identifier_field_presence_is_still_shown() -> None:
    """Full field presence still prints a row, distinct from 'not measured'."""
    text = render(_result_with_components(_FULLY_IDENTIFIED_COMPONENTS), "text")
    assert (
        "Identifier field presence: 2/2 components contain a non-blank PURL or CPE string" in text
    )


def test_generic_purl_presence_is_not_called_matchable() -> None:
    text = render(_result_with_components(_GENERIC_IDENTIFIER_COMPONENTS), "text")

    assert "Identifier field presence: 1/1" in text
    assert "does not validate PURL types" in text
    assert "matchable identifier" not in text


def test_full_identifier_field_presence_never_reads_as_a_pass() -> None:
    """Full field presence must never be phrased as clean, safe, or passing.

    A component list where every entry has a PURL can still produce zero
    findings because nothing was found in what could be checked, not because
    the components are proven safe.
    """
    result = _result_with_components(_FULLY_IDENTIFIED_COMPONENTS)
    for fmt in ("text", "markdown"):
        rendered = render(result, fmt)
        # The disclaimer is present, and it is a negation ("does not mean"),
        # never an unqualified claim of safety, cleanliness, or a pass.
        assert "does not mean the components are safe" in rendered
        assert "(clean)" not in rendered
        assert "Passed" not in rendered
    data = json.loads(render(result, "json"))
    coverage = data["identifier_coverage"]
    assert coverage["all_components_have_identifier_field"] is True
    assert coverage["components_with_identifier_field"] == coverage["total_components"] == 2
    assert "does not mean the components are safe" in coverage["note"]
    sarif = json.loads(render(result, "sarif"))
    sarif_coverage = sarif["runs"][0]["tool"]["driver"]["properties"]["identifierCoverage"]
    assert sarif_coverage["all_components_have_identifier_field"] is True
    assert "does not mean the components are safe" in sarif_coverage["note"]


def test_identifier_coverage_does_not_change_exit_note() -> None:
    """Coverage reporting is additive and never alters the exit-code wording."""
    complete = _result_with_components(_FULLY_IDENTIFIED_COMPONENTS)
    incomplete = _result_with_components(_MIXED_COMPONENTS)
    for result in (complete, incomplete):
        assert "Exit 0 means no configured blocking findings" in render(result, "text", exit_code=0)
        assert "Exit 10:" in render(result, "text", exit_code=10)
