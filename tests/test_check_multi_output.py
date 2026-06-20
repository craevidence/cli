"""check: extra per-format report files (--json-output / --sarif-output / --markdown-output).

One scan can emit several report files in a single run (for example SARIF for code
scanning plus JSON for archival), independent of the global --output format, and the
files are written even when a gate fails so CI can still upload them.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import check as check_module
from cra_evidence_cli.local.disclaimer import DISCLAIMER_MARKER
from cra_evidence_cli.local.models import Finding, LocalCheckResult


def _write_sbom(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "leftpad", "version": "1.0.0"}],
            }
        )
    )


def _result(findings: list[Finding] | None = None) -> LocalCheckResult:
    return LocalCheckResult(
        target="x",
        target_type="sbom",
        sbom_path=None,
        components=[],
        findings=findings or [],
        dimensions=[],
        coverage=[],
        provenance={"engine": "test"},
        attributions=[],
        sources_consulted=[],
    )


def _invoke(monkeypatch, tmp_path, extra_args, *, result=None, output="text"):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    fixed = result if result is not None else _result()
    monkeypatch.setattr(check_module, "run_local_check", lambda **kwargs: fixed)
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    return CliRunner().invoke(
        cli,
        ["--output", output, "check", "--sbom", str(sbom), *extra_args],
    )


def test_json_output_writes_valid_json_with_disclaimer(monkeypatch, tmp_path):
    out = tmp_path / "report.json"
    res = _invoke(monkeypatch, tmp_path, ["--json-output", str(out)])
    assert res.exit_code == 0, res.output
    data = json.loads(out.read_text())
    assert data["schema_version"] == "craevidence.local_check.v1"
    assert DISCLAIMER_MARKER in data["advisory"]["disclaimer"].lower()


def test_sarif_output_writes_sarif_2_1_0_with_advisory(monkeypatch, tmp_path):
    out = tmp_path / "report.sarif"
    res = _invoke(monkeypatch, tmp_path, ["--sarif-output", str(out)])
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
    advisory = doc["runs"][0]["tool"]["driver"]["properties"]["advisory"]
    assert DISCLAIMER_MARKER in advisory["disclaimer"].lower()


def test_markdown_output_writes_markdown_summary(monkeypatch, tmp_path):
    out = tmp_path / "report.md"
    res = _invoke(monkeypatch, tmp_path, ["--markdown-output", str(out)])
    assert res.exit_code == 0, res.output
    body = out.read_text()
    assert body.startswith("# Local SBOM Check")
    assert DISCLAIMER_MARKER not in body.lower()


def test_all_three_formats_written_in_one_run(monkeypatch, tmp_path):
    js = tmp_path / "r.json"
    sarif = tmp_path / "r.sarif"
    md = tmp_path / "r.md"
    res = _invoke(
        monkeypatch,
        tmp_path,
        ["--json-output", str(js), "--sarif-output", str(sarif), "--markdown-output", str(md)],
    )
    assert res.exit_code == 0, res.output
    # Three distinct formats from a single scan.
    assert json.loads(js.read_text())["schema_version"] == "craevidence.local_check.v1"
    assert json.loads(sarif.read_text())["version"] == "2.1.0"
    assert md.read_text().startswith("# Local SBOM Check")
    # The default --output text summary still prints to stdout.
    assert "Local SBOM Check" in res.output


def test_extra_output_independent_of_global_output_format(monkeypatch, tmp_path):
    sarif = tmp_path / "r.sarif"
    res = _invoke(monkeypatch, tmp_path, ["--sarif-output", str(sarif)], output="json")
    assert res.exit_code == 0, res.output
    # stdout honours --output json (res.stdout is stdout-only; res.output mixes in stderr) ...
    assert json.loads(res.stdout)["schema_version"] == "craevidence.local_check.v1"
    # ... while the extra file is SARIF regardless.
    assert json.loads(sarif.read_text())["version"] == "2.1.0"


def test_extra_outputs_written_even_when_gate_fails(monkeypatch, tmp_path):
    out = tmp_path / "r.json"
    res = _invoke(
        monkeypatch,
        tmp_path,
        ["--json-output", str(out), "--fail-on", "critical"],
        result=_result(
            findings=[Finding(id="CVE-2025-0001", package="p", version="1", severity="critical")]
        ),
    )
    assert res.exit_code == 10  # VulnerabilityThresholdExceeded (critical)
    # The artifact must survive the failing gate so CI can still upload it.
    assert out.exists()
    assert json.loads(out.read_text())["schema_version"] == "craevidence.local_check.v1"


def test_extra_output_creates_missing_parent_dir(monkeypatch, tmp_path):
    out = tmp_path / "nope" / "deeper" / "r.json"
    res = _invoke(monkeypatch, tmp_path, ["--json-output", str(out)])
    assert res.exit_code == 0, res.output
    assert out.exists()


def test_wrote_note_emitted_to_stderr(monkeypatch, tmp_path):
    out = tmp_path / "r.json"
    res = _invoke(monkeypatch, tmp_path, ["--json-output", str(out)])
    assert res.exit_code == 0, res.output
    assert f"Wrote json report to {out}" in res.stderr


def test_api_key_never_leaks_into_any_output(monkeypatch, tmp_path):
    # check is a no-key command: even when a key is configured (env and flag),
    # it must not echo the raw key to stdout, stderr, or any written report.
    canary = "cra_LEAKCANARY0123456789abcdefghij_ZZ"
    monkeypatch.setattr(check_module, "run_local_check", lambda **kwargs: _result())
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    out = tmp_path / "r.json"
    res = CliRunner().invoke(
        cli,
        [
            "--api-key", canary, "--output", "json",
            "check", "--sbom", str(sbom), "--json-output", str(out),
        ],
        env={"CRA_EVIDENCE_API_KEY": canary},
    )
    assert res.exit_code == 0, res.output
    assert canary not in res.output
    assert canary not in (res.stderr or "")
    assert canary not in out.read_text()


def test_output_file_creates_missing_parent_dir(monkeypatch, tmp_path):
    out = tmp_path / "nope" / "deeper" / "report.json"
    res = _invoke(monkeypatch, tmp_path, ["-o", str(out)], output="json")
    assert res.exit_code == 0, res.output
    assert out.exists()
    assert json.loads(out.read_text())["schema_version"] == "craevidence.local_check.v1"


def test_check_rejects_sbom_with_explicit_path(monkeypatch, tmp_path):
    # --sbom together with an explicit positional PATH is rejected, not silently
    # resolved by ignoring the PATH (mirrors the --image guard).
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    res = CliRunner().invoke(cli, ["check", "--sbom", str(sbom), "."])
    assert res.exit_code != 0
    assert "Use only one input mode" in res.output
