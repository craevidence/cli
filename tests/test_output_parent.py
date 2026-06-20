"""Writing -o to a path whose parent does not exist must create it, not error."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cra_evidence_cli.commands import eol as eol_module
from cra_evidence_cli.commands.draft import draft
from cra_evidence_cli.commands.eol import eol_check
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.local.eol import EolReport


def _obj() -> dict:
    return {
        "config": CRAEvidenceConfig(url="https://api.craevidence.com", output_format="text"),
        "verbose": False,
    }


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


def test_draft_security_txt_creates_missing_parent(tmp_path: Path) -> None:
    out = tmp_path / "nope" / "deeper" / "security.txt"
    result = CliRunner().invoke(draft, ["security.txt", "-o", str(out)], obj=_obj())
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert "Contact:" in out.read_text()


def test_eol_check_creates_missing_parent(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        eol_module,
        "evaluate_components",
        lambda components, **kwargs: EolReport(total_components=len(components)),
    )
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    out = tmp_path / "nope" / "deeper" / "eol.txt"
    result = CliRunner().invoke(
        eol_check, ["--sbom", str(sbom), "-o", str(out)], obj=_obj()
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
