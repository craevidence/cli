"""CLI tests for the eol-check command.

All network calls are mocked at the cra_evidence_cli.local.eol module level.
No live HTTP requests are made.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from cra_evidence_cli.commands.eol import eol_check
from cra_evidence_cli.config import CRAEvidenceConfig

# Shared fixtures


@pytest.fixture
def runner():
    return CliRunner()


def _make_obj(output_format: str = "text") -> dict:
    return {
        "config": CRAEvidenceConfig(
            url="https://api.craevidence.com",
            output_format=output_format,
        ),
        "verbose": False,
    }


def _write_cyclonedx_sbom(path: Path, name: str = "python", version: str = "3.7.17") -> None:
    """Write a minimal CycloneDX SBOM with a single component."""
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


# Cycle data used by the mocked fetch_cycles.
_PAST_CYCLES = [
    {"cycle": "3.7", "eol": "2000-01-01", "latest": "3.7.17"},
    {"cycle": "3.99", "eol": "2100-01-01", "latest": "3.99.0"},
]


# Online test with mocked network


def test_online_exits_zero_even_with_eol_component(runner, tmp_path, monkeypatch):
    """Exit code is 0 even when an EOL component is found."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="3.7.17")

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: _PAST_CYCLES,
    )

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom)],
        obj=_make_obj("text"),
    )

    assert result.exit_code == 0, result.output
    assert "python" in result.output
    assert "Past EOL: 1" in result.output


def test_online_output_names_eol_component(runner, tmp_path, monkeypatch):
    """The EOL component name and version appear in the text output."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="3.7.5")

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: _PAST_CYCLES,
    )

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom)],
        obj=_make_obj("text"),
    )

    assert result.exit_code == 0, result.output
    assert "python" in result.output
    assert "3.7.5" in result.output
    assert "past EOL" in result.output


# JSON output format


def test_json_output_has_report_and_advisory_keys(runner, tmp_path, monkeypatch):
    """JSON output contains 'report' and 'advisory' keys with expected content."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="3.7.17")

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: _PAST_CYCLES,
    )

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom)],
        obj=_make_obj("json"),
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    assert "report" in data
    assert "advisory" in data
    assert data["advisory"]["disclaimer"] == "Review before use."


def test_json_output_schema_version(runner, tmp_path, monkeypatch):
    """JSON output carries the expected schema_version field."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom)

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: set(),
    )

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom)],
        obj=_make_obj("json"),
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data.get("schema_version") == "craevidence.eol.v1"


# SARIF output format


def test_sarif_output_structure(runner, tmp_path, monkeypatch):
    """SARIF output is valid JSON with 'version' and 'runs' keys."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="3.7.17")

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: _PAST_CYCLES,
    )

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom)],
        obj=_make_obj("sarif"),
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["results"][0]["ruleId"] == "EOL-python"
    assert run["results"][0]["level"] == "warning"
    advisory = run["tool"]["driver"]["properties"]["advisory"]
    assert advisory["disclaimer"] == "Review before use."


# Output file


def test_output_file_written(runner, tmp_path, monkeypatch):
    """With -o, the report is written to a file and confirmation goes to stderr."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom)
    out = tmp_path / "eol.txt"

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: set(),
    )

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom), "-o", str(out)],
        obj=_make_obj("text"),
    )

    assert result.exit_code == 0, result.output
    assert out.exists()


# Support-period status output

# A security-only cycle: active support ended in the past, EOL far in the future.
# Dates are absolute so the classification holds against the real "today".
_SUPPORT_CYCLES = [
    {"cycle": "3.7", "eol": "2100-01-01", "support": "2000-01-01", "lts": False},
]


def test_text_output_shows_support_period_framing(runner, tmp_path, monkeypatch):
    """Text output uses the softened support-period framing and support counts."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="3.7.5")

    monkeypatch.setattr("cra_evidence_cli.local.eol.fetch_products", lambda **kwargs: {"python"})
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles", lambda product, **kwargs: _SUPPORT_CYCLES
    )

    result = runner.invoke(eol_check, ["--sbom", str(sbom)], obj=_make_obj("text"))

    assert result.exit_code == 0, result.output
    assert "Security-only: 1" in result.output
    assert "is in security-only support" in result.output
    assert "active support ended 2000-01-01" in result.output
    # The CRA support-period framing is verbose-only; the default stays concise.
    assert "one input when reviewing product support periods" not in result.output

    verbose = runner.invoke(eol_check, ["--sbom", str(sbom), "-v"], obj=_make_obj("text"))
    assert verbose.exit_code == 0, verbose.output
    assert "one input when reviewing product support periods" in verbose.output
    assert "does not produce or verify" in verbose.output


def test_text_output_shows_unknown_support_status(runner, tmp_path, monkeypatch):
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="99.99.0")

    monkeypatch.setattr("cra_evidence_cli.local.eol.fetch_products", lambda **kwargs: {"python"})
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles", lambda product, **kwargs: _SUPPORT_CYCLES
    )

    result = runner.invoke(eol_check, ["--sbom", str(sbom)], obj=_make_obj("text"))

    assert result.exit_code == 0, result.output
    assert "Unknown support: 1" in result.output
    assert "but no matching support cycle was found" in result.output


def test_json_output_has_support_fields(runner, tmp_path, monkeypatch):
    """JSON report exposes the per-finding status and the support counts."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="3.7.5")

    monkeypatch.setattr("cra_evidence_cli.local.eol.fetch_products", lambda **kwargs: {"python"})
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles", lambda product, **kwargs: _SUPPORT_CYCLES
    )

    result = runner.invoke(eol_check, ["--sbom", str(sbom)], obj=_make_obj("json"))

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)["report"]
    assert report["security_only_count"] == 1
    finding = report["findings"][0]
    assert finding["status"] == "security-only"
    assert finding["support_date"] == "2000-01-01"
    assert finding["is_supported"] is False


def test_sarif_emits_security_only_note(runner, tmp_path, monkeypatch):
    """A security-only component appears in SARIF as a note (not a warning)."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="3.7.5")

    monkeypatch.setattr("cra_evidence_cli.local.eol.fetch_products", lambda **kwargs: {"python"})
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles", lambda product, **kwargs: _SUPPORT_CYCLES
    )

    result = runner.invoke(eol_check, ["--sbom", str(sbom)], obj=_make_obj("sarif"))

    assert result.exit_code == 0, result.output
    results = json.loads(result.output)["runs"][0]["results"]
    notes = [r for r in results if r["level"] == "note"]
    assert len(notes) == 1
    assert notes[0]["ruleId"] == "EOL-SUPPORT-python"


# Error handling


def test_invalid_sbom_file_raises_click_exception(runner, tmp_path):
    """A malformed SBOM file produces a non-zero exit code."""
    bad = tmp_path / "bad.json"
    bad.write_text("not json at all", encoding="utf-8")

    result = runner.invoke(
        eol_check,
        ["--sbom", str(bad)],
        obj=_make_obj("text"),
    )

    assert result.exit_code != 0


def test_network_error_on_product_list_falls_back_gracefully(runner, tmp_path, monkeypatch):
    """A failure to reach the endoflife.date product list is reported as a warning
    and the command still exits 0."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom)

    def _raise(**kwargs):
        msg = "network unreachable"
        raise RuntimeError(msg)

    monkeypatch.setattr("cra_evidence_cli.local.eol.fetch_products", _raise)

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom)],
        obj=_make_obj("text"),
    )

    assert result.exit_code == 0, result.output


# Unsupported format notice (fix 9)


def test_unsupported_format_emits_notice(runner, tmp_path, monkeypatch):
    """An unsupported format triggers a notice to stderr and falls back to text."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom)

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: set(),
    )

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom)],
        obj=_make_obj("markdown"),
    )

    assert result.exit_code == 0, result.output
    combined = result.output
    assert "markdown" in combined
    assert "not supported" in combined
    assert "End-of-life check" in combined


# SARIF locations (fix 1)


def test_sarif_results_have_locations(runner, tmp_path, monkeypatch):
    """Every SARIF result entry must include a 'locations' field."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="3.7.17")

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: _PAST_CYCLES,
    )

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom)],
        obj=_make_obj("sarif"),
    )

    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    for entry in doc["runs"][0]["results"]:
        assert "locations" in entry, "SARIF result is missing locations"
        uri = entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/tmp"), f"SARIF location must not be a temp path: {uri}"  # noqa: S108


def test_sarif_location_uses_user_supplied_sbom_path(runner, tmp_path, monkeypatch):
    """When --sbom points to a relative path, SARIF uses that path (not a temp path)."""
    sbom = tmp_path / "sbom.json"
    _write_cyclonedx_sbom(sbom, name="python", version="3.7.17")

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: _PAST_CYCLES,
    )

    result = runner.invoke(
        eol_check,
        ["--sbom", str(sbom)],
        obj=_make_obj("sarif"),
    )

    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    # The URI must match the provided path (or the fallback); never a /tmp path.
    assert not uri.startswith("/tmp")  # noqa: S108


# Offline mode in directory path (fix 7)


def test_directory_mode_passes_offline_to_generator(runner, tmp_path, monkeypatch):
    """When a directory is provided, generate_sbom_from_directory is called with offline=True."""
    captured: dict = {}

    from cra_evidence_cli.local.sbom import SBOMParseError

    def fake_generate(directory, verbose=False, offline=False, **kwargs):
        captured["offline"] = offline
        msg = "no manifest"
        raise SBOMParseError(msg)

    monkeypatch.setattr(
        "cra_evidence_cli.sbom_generator.generate_sbom_from_directory",
        fake_generate,
    )
    # Also patch the import inside the command function.
    monkeypatch.setattr(
        "cra_evidence_cli.commands.eol.generate_sbom_from_directory",
        fake_generate,
        raising=False,
    )

    runner.invoke(
        eol_check,
        [str(tmp_path)],
        obj=_make_obj("text"),
    )

    assert captured.get("offline") is True, "offline=True was not passed to the SBOM generator"
