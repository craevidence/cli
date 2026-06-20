"""draft risk-assessment / threat-model scaffolds from an SBOM."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner

from cra_evidence_cli.commands.draft import draft
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.local.models import Finding


def _obj() -> dict:
    return {
        "config": CRAEvidenceConfig(url="https://api.craevidence.com", output_format="text"),
        "verbose": False,
    }


@pytest.fixture(autouse=True)
def _stub_local_scan(monkeypatch):
    monkeypatch.setattr(
        "cra_evidence_cli.commands.draft.run_local_check",
        lambda **kwargs: SimpleNamespace(findings=[]),
    )


def _sbom(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"type": "library", "name": "urllib3", "version": "1.0"},
                    {"type": "library", "name": "jinja2", "version": "2.4"},
                ],
            }
        )
    )
    return path


def test_risk_assessment_seeds_from_components(tmp_path: Path) -> None:
    sbom = _sbom(tmp_path / "sbom.json")
    result = CliRunner().invoke(
        draft, ["risk-assessment", "--sbom", str(sbom), "--product", "demo"], obj=_obj()
    )
    assert result.exit_code == 0, result.output
    assert "type: RiskCatalog" in result.output
    # Risk subjects are seeded from the real component names.
    assert "urllib3" in result.output
    assert "jinja2" in result.output
    assert "Risk assessment context" in result.output
    assert "Update delivery and verification risk" in result.output
    assert "Vulnerability handling process risk" in result.output


def test_risk_assessment_seeds_from_local_scan_findings(tmp_path: Path, monkeypatch) -> None:
    sbom = _sbom(tmp_path / "sbom.json")

    monkeypatch.setattr(
        "cra_evidence_cli.commands.draft.run_local_check",
        lambda **kwargs: SimpleNamespace(
            findings=[
                Finding(
                    id="CVE-2021-44228",
                    package="log4j-core",
                    version="2.14.1",
                    severity="critical",
                )
            ]
        ),
    )

    result = CliRunner().invoke(
        draft, ["risk-assessment", "--sbom", str(sbom), "--product", "demo"], obj=_obj()
    )

    assert result.exit_code == 0, result.output
    assert "CVE-2021-44228 affecting log4j-core" in result.output
    assert "severity: Critical" in result.output
    assert "not a reasoned risk assessment" in result.output


def test_risk_assessment_findings_suppress_component_truncation_warning(
    tmp_path: Path, monkeypatch
) -> None:
    sbom = tmp_path / "many.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"type": "library", "name": f"pkg-{idx}", "version": "1.0"}
                    for idx in range(11)
                ],
            }
        )
    )
    monkeypatch.setattr(
        "cra_evidence_cli.commands.draft.run_local_check",
        lambda **kwargs: SimpleNamespace(
            findings=[
                Finding(
                    id="CVE-2026-0001",
                    package="pkg-1",
                    version="1.0",
                    severity="high",
                )
            ]
        ),
    )

    result = CliRunner().invoke(
        draft, ["risk-assessment", "--sbom", str(sbom), "--product", "demo"], obj=_obj()
    )

    assert result.exit_code == 0, result.output
    assert "CVE-2026-0001 affecting pkg-1" in result.output
    assert "seeding the first 10 of 11 components" not in result.output


def test_risk_assessment_exactly_ten_findings_has_no_truncation_warning(
    tmp_path: Path, monkeypatch
) -> None:
    sbom = _sbom(tmp_path / "sbom.json")
    monkeypatch.setattr(
        "cra_evidence_cli.commands.draft.run_local_check",
        lambda **kwargs: SimpleNamespace(
            findings=[
                Finding(
                    id=f"CVE-2026-{idx:04d}",
                    package=f"pkg-{idx}",
                    version="1.0",
                    severity="medium",
                )
                for idx in range(10)
            ]
        ),
    )

    result = CliRunner().invoke(
        draft, ["risk-assessment", "--sbom", str(sbom), "--product", "demo"], obj=_obj()
    )

    assert result.exit_code == 0, result.output
    assert "CVE-2026-0009 affecting pkg-9" in result.output
    assert "seeding the first 10 vulnerability findings" not in result.output


def test_threat_model_type_and_no_key(tmp_path: Path) -> None:
    sbom = _sbom(tmp_path / "sbom.json")
    result = CliRunner().invoke(draft, ["threat-model", "--sbom", str(sbom)], obj=_obj())
    assert result.exit_code == 0, result.output
    assert "type: ThreatCatalog" in result.output


def test_scaffold_output_file_is_valid_yaml_with_review_marker(tmp_path: Path) -> None:
    sbom = _sbom(tmp_path / "sbom.json")
    out = tmp_path / "nested" / "risk.yaml"
    result = CliRunner().invoke(
        draft, ["risk-assessment", "--sbom", str(sbom), "-o", str(out)], obj=_obj()
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    written = out.read_text()
    assert "draft / review before use" in written
    # The file (comment header + YAML) parses.
    assert yaml.safe_load(written)["metadata"]["type"] == "RiskCatalog"


def test_threat_model_directory_without_components_scaffolds(tmp_path: Path, monkeypatch) -> None:
    # A directory with no resolvable dependency manifest must still scaffold (empty
    # inventory) instead of crashing with an SBOM parse error.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "x.py").write_text("print(1)\n", encoding="utf-8")
    bad_sbom = tmp_path / "gen.json"
    bad_sbom.write_text('{"not_an_sbom": true}', encoding="utf-8")
    monkeypatch.setattr(
        "cra_evidence_cli.sbom_generator.generate_sbom_from_directory",
        lambda *a, **k: SimpleNamespace(file_path=bad_sbom),
    )
    result = CliRunner().invoke(draft, ["threat-model", str(proj)], obj=_obj())
    assert result.exit_code == 0, result.output
    assert "type: ThreatCatalog" in result.output


def test_risk_assessment_slugifies_multiword_product(tmp_path: Path) -> None:
    sbom = _sbom(tmp_path / "sbom.json")
    out = tmp_path / "risk.yaml"
    result = CliRunner().invoke(
        draft,
        ["risk-assessment", "--sbom", str(sbom), "--product", "My IoT Gateway", "-o", str(out)],
        obj=_obj(),
    )
    assert result.exit_code == 0, result.output
    doc = yaml.safe_load(out.read_text())
    assert doc["metadata"]["id"] == "my-iot-gateway-risk-catalog"
    assert doc["metadata"]["description"] == "Cybersecurity risk assessment starter."


def test_risk_assessment_warns_when_more_than_ten_components(tmp_path: Path) -> None:
    sbom = tmp_path / "many.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"type": "library", "name": f"pkg-{idx}", "version": "1.0"}
                    for idx in range(11)
                ],
            }
        )
    )

    result = CliRunner().invoke(
        draft, ["risk-assessment", "--sbom", str(sbom), "--product", "demo"], obj=_obj()
    )

    assert result.exit_code == 0, result.output
    assert "seeding the first 10 of 11 components" in result.output
