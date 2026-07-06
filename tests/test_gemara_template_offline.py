"""Tests for the no-key offline path of `compliance-as-code template`."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from cra_evidence_cli.commands.gemara import gemara
from cra_evidence_cli.config import CRAEvidenceConfig


def _obj_without_key() -> dict:
    # No api_key set: the offline path must not require one.
    return {
        "config": CRAEvidenceConfig(url="https://api.craevidence.com", output_format="text"),
        "verbose": False,
    }


def test_offline_policy_template_needs_no_key(tmp_path: Path) -> None:
    out = tmp_path / "cvd-policy.yaml"
    runner = CliRunner()
    result = runner.invoke(
        gemara,
        [
            "template",
            "--type",
            "policy",
            "--product",
            "my-iot-device",
            "--org",
            "Acme Ltd",
            "--output",
            str(out),
            "--offline",
        ],
        obj=_obj_without_key(),
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    doc = yaml.safe_load(out.read_text())
    assert doc["metadata"]["type"] == "Policy"
    # Placeholder identity comes straight from --product / --org.
    assert "my-iot-device" in doc["title"]
    assert doc["metadata"]["author"]["name"] == "Acme Ltd"


def test_offline_risk_catalog_template_renders_without_components(tmp_path: Path) -> None:
    out = tmp_path / "risk-catalog.yaml"
    runner = CliRunner()
    result = runner.invoke(
        gemara,
        [
            "template",
            "--type",
            "risk-catalog",
            "--product",
            "my-iot-device",
            "--output",
            str(out),
            "--offline",
        ],
        obj=_obj_without_key(),
    )
    assert result.exit_code == 0, result.output
    doc = yaml.safe_load(out.read_text())
    assert doc["metadata"]["type"] == "RiskCatalog"
    assert "Install cue to validate locally" in result.output


def test_offline_risk_catalog_can_seed_from_local_sbom(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"type": "library", "name": "urllib3", "version": "2.0.0"},
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "risk-catalog.yaml"

    result = CliRunner().invoke(
        gemara,
        [
            "template",
            "--type",
            "risk-catalog",
            "--product",
            "my-iot-device",
            "--output",
            str(out),
            "--offline",
            "--sbom",
            str(sbom),
        ],
        obj=_obj_without_key(),
    )

    assert result.exit_code == 0, result.output
    doc = yaml.safe_load(out.read_text())
    titles = [risk["title"] for risk in doc["risks"]]
    assert "Risk related to urllib3" in titles


def test_capability_catalog_not_in_type_map() -> None:
    """CapabilityCatalog is not in GEMARA_TYPE_MAP: the backend renderer rejects it."""
    from cra_evidence_cli.commands.gemara import GEMARA_TYPE_MAP

    assert "CapabilityCatalog" not in GEMARA_TYPE_MAP


def test_offline_never_calls_the_api(monkeypatch, tmp_path: Path) -> None:
    # If the offline path touched the API, this stub would raise.
    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        msg = "offline template must not call the API"
        raise AssertionError(msg)

    monkeypatch.setattr("cra_evidence_cli.commands.gemara._fetch_product", _boom)
    monkeypatch.setattr("cra_evidence_cli.commands.gemara.validate_config", _boom)

    out = tmp_path / "control-catalog.yaml"
    runner = CliRunner()
    result = runner.invoke(
        gemara,
        [
            "template",
            "--type",
            "control-catalog",
            "--product",
            "p",
            "--output",
            str(out),
            "--offline",
        ],
        obj=_obj_without_key(),
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
