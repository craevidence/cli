"""Tests for cra_evidence_cli.commands.egress (CliRunner, no network, no Syft)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner

from cra_evidence_cli.commands.egress import egress_check
from cra_evidence_cli.config import CRAEvidenceConfig


def _make_obj(output_format: str = "text") -> dict:
    return {
        "config": CRAEvidenceConfig(
            url="https://api.craevidence.com",
            output_format=output_format,
        ),
        "verbose": False,
    }


def _write_sbom(path: Path, extra_components: list | None = None) -> None:
    """Write a minimal CycloneDX SBOM with the given extra components."""
    base_components = [
        {
            "type": "library",
            "name": "sentry-sdk",
            "version": "1.44.0",
            "purl": "pkg:pypi/sentry-sdk@1.44.0",
        },
        {
            "type": "library",
            "name": "boto3",
            "version": "1.34.0",
            "purl": "pkg:pypi/boto3@1.34.0",
        },
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        },
    ]
    components = base_components + (extra_components or [])
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
    }
    path.write_text(json.dumps(sbom), encoding="utf-8")


# Text output


def test_egress_check_text_exit_zero(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("text"))

    assert result.exit_code == 0, f"Unexpected exit {result.exit_code}: {result.output}"


def test_egress_check_text_contains_sdk_names(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("text"))

    assert "sentry" in result.output
    assert "boto3" in result.output
    assert "requests" in result.output


def test_egress_check_text_contains_scope_note_when_verbose(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("text"))
    assert "attack-surface and data-flow documentation" not in result.output

    verbose = runner.invoke(egress_check, ["--sbom", str(sbom_path), "-v"], obj=_make_obj("text"))
    assert "attack-surface and data-flow documentation" in verbose.output
    assert "GDPR may also apply" in verbose.output


def test_egress_check_text_uses_clean_heading(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("text"))
    assert result.exit_code == 0, result.output
    assert result.output.startswith("Remote data processing scan")


def test_egress_check_text_source_not_scanned_when_sbom_flag(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("text"))

    assert "Source not scanned" in result.output


# JSON output


def test_egress_check_json_exit_zero(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("json"))

    assert result.exit_code == 0


def test_egress_check_json_structure(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("json"))

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "report" in data, "JSON output must have a 'report' key"
    assert "advisory" in data, "JSON output must have an 'advisory' key"
    assert "disclaimer" in data["advisory"]
    assert data["advisory"]["disclaimer"] == "Review before use."


def test_egress_check_json_report_contains_sdks(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("json"))

    data = json.loads(result.output)
    sdk_names = [s["name"] for s in data["report"]["sdks"]]
    assert "sentry-sdk" in sdk_names
    assert "boto3" in sdk_names


def test_egress_check_json_contains_network_libs(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("json"))

    data = json.loads(result.output)
    assert "requests" in data["report"]["network_libs"]


# Directory branch with source scanning (monkeypatched SBOM generator)


def test_egress_check_directory_scans_source(tmp_path: Path, monkeypatch):
    """Directory path: generator is monkeypatched; source file with an external URL must appear."""
    # Write a source file containing an external URL.
    (tmp_path / "client.py").write_text(
        'BASE = "https://api.custom-service.io/events"\n', encoding="utf-8"
    )

    # Write a minimal SBOM that the monkeypatched generator will "return".
    fake_sbom = tmp_path / "_fake_sbom.json"
    _write_sbom(fake_sbom)

    fake_result = SimpleNamespace(file_path=fake_sbom)

    import cra_evidence_cli.commands.egress as egress_mod

    monkeypatch.setattr(
        egress_mod,
        "generate_sbom_from_directory",
        lambda *args, **kwargs: fake_result,
        raising=False,
    )
    # Patch the import inside the function's local scope via the module attribute.
    # generate_sbom_from_directory is imported lazily inside the function, so we
    # patch at the source module level too.
    import cra_evidence_cli.sbom_generator as gen_mod

    monkeypatch.setattr(
        gen_mod, "generate_sbom_from_directory", lambda *args, **kwargs: fake_result
    )

    runner = CliRunner()
    result = runner.invoke(egress_check, [str(tmp_path)], obj=_make_obj("text"))

    assert result.exit_code == 0, f"Unexpected exit {result.exit_code}: {result.output}"
    assert "api.custom-service.io" in result.output, (
        "External endpoint from source file must appear in text output; got:\n" + result.output
    )


def test_egress_check_directory_json_endpoint_present(tmp_path: Path, monkeypatch):
    """Directory + JSON: endpoint found in source must appear in report.endpoints."""
    (tmp_path / "client.py").write_text(
        'BASE = "https://api.metrics-sink.net/ingest"\n', encoding="utf-8"
    )

    fake_sbom = tmp_path / "_fake_sbom.json"
    _write_sbom(fake_sbom)
    fake_result = SimpleNamespace(file_path=fake_sbom)

    import cra_evidence_cli.sbom_generator as gen_mod

    monkeypatch.setattr(
        gen_mod, "generate_sbom_from_directory", lambda *args, **kwargs: fake_result
    )

    runner = CliRunner()
    result = runner.invoke(egress_check, [str(tmp_path)], obj=_make_obj("json"))

    assert result.exit_code == 0
    data = json.loads(result.output)
    endpoint_hosts = [ep["host"] for ep in data["report"]["endpoints"]]
    assert "api.metrics-sink.net" in endpoint_hosts, (
        "Source endpoint must appear in JSON report; endpoints found: "
        + str(endpoint_hosts)
    )


# Output file


def test_egress_check_output_file_text(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)
    out_file = tmp_path / "sub" / "report.txt"

    runner = CliRunner()
    result = runner.invoke(
        egress_check,
        ["--sbom", str(sbom_path), "-o", str(out_file)],
        obj=_make_obj("text"),
    )

    assert result.exit_code == 0
    assert out_file.exists(), "Output file must be created"


def test_egress_check_output_file_json(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)
    out_file = tmp_path / "report.json"

    runner = CliRunner()
    result = runner.invoke(
        egress_check,
        ["--sbom", str(sbom_path), "-o", str(out_file)],
        obj=_make_obj("json"),
    )

    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert "report" in data
    assert "advisory" in data


# Exit 0 invariant even when findings exist


def test_egress_check_exit_zero_with_findings(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("text"))

    # Even though sentry-sdk and boto3 are detected, exit must be 0.
    assert result.exit_code == 0


# SARIF output


def test_egress_check_sarif_structure(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    runner = CliRunner()
    result = runner.invoke(egress_check, ["--sbom", str(sbom_path)], obj=_make_obj("sarif"))

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    assert "runs" in data
    rule_ids = [r["ruleId"] for r in data["runs"][0]["results"]]
    assert any(rid.startswith("EGRESS-SDK-") for rid in rule_ids)


def test_directory_without_components_scans_source_instead_of_crashing(tmp_path, monkeypatch):
    # A directory with no resolvable manifest -> generated SBOM has no components ->
    # load_sbom raises -> egress falls back to a source-only scan, not exit 1.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "main.py").write_text('url = "http://evil.example.com/x"\n', encoding="utf-8")
    bad_sbom = tmp_path / "gen.json"
    bad_sbom.write_text('{"not_an_sbom": true}', encoding="utf-8")
    monkeypatch.setattr(
        "cra_evidence_cli.sbom_generator.generate_sbom_from_directory",
        lambda *a, **k: SimpleNamespace(file_path=bad_sbom),
    )
    result = CliRunner().invoke(egress_check, [str(proj)], obj=_make_obj())
    assert result.exit_code == 0, result.output
    # Source WAS scanned (the directory branch ran), so the skip message is absent.
    assert "Source not scanned" not in result.output
