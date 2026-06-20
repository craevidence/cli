"""draft threat-model --diagram: seed a ThreatCatalog from a Mermaid diagram."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from cra_evidence_cli.commands.draft import draft
from cra_evidence_cli.config import CRAEvidenceConfig

_DIAGRAM = """graph TD
  User[User] -->|HTTPS| GW[API Gateway]
  GW --> Auth[Auth Service]
  GW --> App[App Server]
  App --> DB[(Database)]
  App -->|metrics| Ext[Datadog]
  subgraph internal
    Auth
    App
    DB
  end
"""


def _obj() -> dict:
    return {
        "config": CRAEvidenceConfig(url="https://api.craevidence.com", output_format="text"),
        "verbose": False,
    }


def _run_to_doc(tmp_path: Path, args: list[str]) -> dict:
    mmd = tmp_path / "arch.mmd"
    mmd.write_text(_DIAGRAM)
    out = tmp_path / "threats.yaml"
    result = CliRunner().invoke(
        draft, ["threat-model", "--diagram", str(mmd), "-o", str(out), *args], obj=_obj()
    )
    assert result.exit_code == 0, result.output
    return yaml.safe_load(out.read_text())


def test_diagram_seeds_threat_catalog(tmp_path: Path) -> None:
    doc = _run_to_doc(tmp_path, ["--product", "demo"])
    assert doc["metadata"]["type"] == "ThreatCatalog"
    group_ids = {g["id"] for g in doc["groups"]}
    assert "cross-boundary" in group_ids
    assert "internal" in group_ids  # the subgraph became a trust-boundary group


def test_every_threat_description_is_a_bracketed_prompt(tmp_path: Path) -> None:
    # The honesty guarantee: no entry may read as a finished/assessed threat.
    doc = _run_to_doc(tmp_path, [])
    assert doc["threats"]
    for threat in doc["threats"]:
        assert threat["description"].lstrip().startswith("["), threat


def test_one_threat_per_flow_cross_boundary_first(tmp_path: Path) -> None:
    doc = _run_to_doc(tmp_path, [])
    titles = [t["title"] for t in doc["threats"]]
    # 5 edges -> 5 flow threats (not a STRIDE explosion).
    flow_titles = [t for t in titles if t.startswith("Threat on data flow:")]
    assert len(flow_titles) == 5
    groups = [t["group"] for t in doc["threats"] if t["title"].startswith("Threat on data flow:")]
    # The first flow threat crosses a boundary.
    assert groups[0] == "cross-boundary"
    # A datastore yields an at-rest threat.
    assert any(t["title"].startswith("Threat on data at rest:") for t in doc["threats"])


def test_capabilities_reference_diagram_node_ids(tmp_path: Path) -> None:
    doc = _run_to_doc(tmp_path, [])
    blob = json.dumps(doc)
    # Node ids from the diagram are used as capability reference ids.
    for node_id in ("User", "GW", "Auth", "App", "DB", "Ext"):
        assert f'"reference-id": "{node_id}"' in blob


def test_with_sbom_adds_third_party_component_threat(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "urllib3", "version": "1.0"}],
            }
        )
    )
    doc = _run_to_doc(tmp_path, ["--sbom", str(sbom)])
    assert any(t["title"] == "Threat from third-party components" for t in doc["threats"])
    assert "urllib3" in json.dumps(doc)
