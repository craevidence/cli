import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.evidence_checker.engine import run_evidence_check


def _write_config(tmp_path: Path) -> Path:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "cvd.md").write_text(
        "# Coordinated Vulnerability Disclosure\n"
        "## Reporter Contact\n"
        "security@example.com\n"
        "## Triage Workflow\n"
        "Review incoming reports.\n"
    )
    sboms = tmp_path / "sboms"
    sboms.mkdir()
    (sboms / "firmware.cdx.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []})
    )
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "static.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
    config = {
        "metadata": {"id": "demo-check", "title": "Demo checker run"},
        "checks": [
            {
                "id": "cvd-policy",
                "type": "markdown_headings",
                "path": "docs/cvd.md",
                "maps_to": "cra:vulnerability_info_sharing_confirmed",
                "required_headings": ["Reporter Contact", "Triage Workflow"],
            },
            {
                "id": "static-analysis",
                "type": "sarif",
                "path": "reports/static.sarif",
            },
        ],
        "components": [
            {
                "slug": "firmware",
                "sbom": "sboms/firmware.cdx.json",
            }
        ],
    }
    config_path = tmp_path / "checker.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    return config_path


def test_checker_converts_cra_passed_mapping_to_needs_review(tmp_path):
    config_path = _write_config(tmp_path)

    result = run_evidence_check(config_path)

    assert result["summary"] == {"total": 3, "passed": 2, "failed": 0, "needs_review": 1}
    cvd = result["results"][0]
    assert cvd["raw_result"] == "Passed"
    assert cvd["result"] == "Needs Review"
    assert cvd["entry_id"] == "cra:vulnerability_info_sharing_confirmed"
    assessment = result["evaluation_log"]["evaluations"][0]["assessment-logs"][0]
    assert "title" not in result["evaluation_log"]
    assert result["evaluation_log"]["result"] == "Needs Review"
    assert result["evaluation_log"]["target"]["id"] == "local-workspace"
    assert result["evaluation_log"]["metadata"]["author"]["type"] == "Software"
    assert result["evaluation_log"]["evaluations"][0]["control"] == {
        "reference-id": "CRA",
        "entry-id": "cra:vulnerability_info_sharing_confirmed",
    }
    assert assessment["result"] == "Needs Review"
    assert assessment["requirement"]["entry-id"] == "cra:vulnerability_info_sharing_confirmed"
    assert assessment["requirement"]["reference-id"] == "CRA"
    assert assessment["description"] == "Cvd Policy"
    assert "not allowed to auto-confirm CRA obligations" in assessment["message"]
    assert assessment["applicability"] == ["Declared evidence"]
    assert assessment["start"]
    assert "id" not in assessment
    assert "artifacts" not in assessment
    assert any(step.startswith("Artifact SHA-256:") for step in assessment["steps"])
    assert cvd["artifact"]["sha256"]
    mapping_ref = result["evaluation_log"]["metadata"]["mapping-references"][1]
    assert mapping_ref["title"] == "CRA Evidence review mapping labels"
    assert "not a machine-readable CRA source index" in mapping_ref["description"]


def test_evidence_check_command_writes_outputs_without_api_key(tmp_path):
    config_path = _write_config(tmp_path)
    out_dir = tmp_path / "out"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "--output",
            "json",
            "evidence",
            "check",
            "--config",
            str(config_path),
            "--out-dir",
            str(out_dir),
            "--fail-on",
            "none",
        ],
        env={"HOME": str(tmp_path), "CRA_NO_WARN": "1"},
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["needs_review"] == 1
    assert (out_dir / "evaluation-log.yaml").exists()
    assert (out_dir / "evidence-results.json").exists()
    assert (out_dir / "evidence-report.md").exists()

    evaluation_log = yaml.safe_load((out_dir / "evaluation-log.yaml").read_text())
    assert evaluation_log["metadata"]["type"] == "EvaluationLog"
    assert evaluation_log["evaluations"][0]["assessment-logs"][0]["result"] == "Needs Review"


def test_evidence_check_fail_on_failed_exits_nonzero(tmp_path):
    config = {
        "checks": [
            {
                "id": "missing-policy",
                "type": "file_exists",
                "path": "missing.md",
            }
        ]
    }
    config_path = tmp_path / "checker.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "evidence",
            "check",
            "--config",
            str(config_path),
            "--out-dir",
            str(tmp_path / "out"),
        ],
        env={"HOME": str(tmp_path), "CRA_NO_WARN": "1"},
    )

    assert result.exit_code == 2
    assert (tmp_path / "out" / "evaluation-log.yaml").exists()
