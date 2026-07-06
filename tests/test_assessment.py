"""Tests for the local CRA assessment feature: requirements, matrix, gate,
templates, multi-select, detection, and the command group."""

from __future__ import annotations

import json
from pathlib import Path

import click
import pytest
import yaml
from click.testing import CliRunner

from cra_evidence_cli.assessment import config as cfg
from cra_evidence_cli.assessment import detect, gate, matrix, requirements, select, templates
from cra_evidence_cli.commands.assessment import assessment
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.exceptions import ConfigurationError


def _obj(output: str = "text") -> dict:
    return {
        "config": CRAEvidenceConfig(url="https://api.craevidence.com", output_format=output),
        "verbose": False,
    }


# requirements

def test_registry_shape() -> None:
    assert len(requirements.REQUIREMENTS) == 22
    assert len(requirements.WAIVABLE_KEYS) == 13
    assert len(requirements.MANDATORY_KEYS) == 9
    assert len(requirements.PART_II_KEYS) == 8
    # Only Part I(2) letters are waivable; Part I(1) and Part II never are.
    assert all(key.startswith("part_i_2_") for key in requirements.WAIVABLE_KEYS)
    assert not requirements.is_waivable("part_i_1")
    assert all(not requirements.is_waivable(key) for key in requirements.PART_II_KEYS)
    assert requirements.is_waivable("part_i_2_a")


# matrix

def test_build_matrix_has_all_keys_and_marker() -> None:
    mat = matrix.build_matrix(product="p", template_id="consumer-iot")
    assert [e.key for e in mat.requirements] == list(requirements.CANONICAL_KEYS)
    text = matrix.dump_matrix(mat)
    assert "review before use" in text.lower()  # honesty marker
    # round-trips
    parsed = matrix.parse_matrix(yaml.safe_load(text))
    assert [e.key for e in parsed.requirements] == list(requirements.CANONICAL_KEYS)


def test_build_matrix_rejects_mandatory_not_applicable() -> None:
    with pytest.raises(matrix.MatrixError):
        matrix.build_matrix(product="p", template_id="t", not_applicable={"part_ii_1": "x"})


def test_build_matrix_rejects_blank_justification() -> None:
    with pytest.raises(matrix.MatrixError):
        matrix.build_matrix(product="p", template_id="t", not_applicable={"part_i_2_g": "  "})


def test_parse_template_rejects_blank_na_justification() -> None:
    data = {"id": "x", "title": "X", "applicability": {"not_applicable": {"part_i_2_g": ""}}}
    with pytest.raises(templates.TemplateError):
        templates._parse_template("x", data)


def test_matrix_marks_waivable_not_applicable() -> None:
    mat = matrix.build_matrix(
        product="p", template_id="t", not_applicable={"part_i_2_g": "no personal data"}
    )
    row = mat.by_key()["part_i_2_g"]
    assert row.applicability_status == "not_applicable"
    assert row.justification == "no personal data"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update({"kind": "wrong"}),
        lambda d: d.update({"schema_version": 99}),
        lambda d: d["requirements"].append({"key": "not_a_key"}),
        lambda d: d["requirements"].append(
            {"key": "part_i_1", "applicability_status": "maybe"}
        ),
    ],
)
def test_parse_matrix_rejects_invalid(mutate) -> None:
    mat = matrix.build_matrix(product="p", template_id="t")
    data = yaml.safe_load(matrix.dump_matrix(mat))
    mutate(data)
    with pytest.raises(matrix.MatrixError):
        matrix.parse_matrix(data)


def test_write_exclusive_refuses_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "a.yaml"
    matrix.write_exclusive(target, "first")
    assert target.read_text() == "first"
    with pytest.raises(FileExistsError):
        matrix.write_exclusive(target, "second")
    assert target.read_text() == "first"  # untouched


# gate

def _fresh_matrix() -> matrix.AssessmentMatrix:
    return matrix.build_matrix(product="p", template_id="consumer-iot")


def test_gate_fresh_template_fails_mandatory() -> None:
    result = gate.evaluate_gate(_fresh_matrix(), cfg.ExceptionsFile())
    assert result.exit_code() == gate.EXIT_MISSING_MANDATORY
    # part_i_1 plus the 8 Part II duties = 9 mandatory gaps.
    assert len({f.key for f in result.blocking}) == 9


def test_gate_passes_when_all_implemented() -> None:
    mat = _fresh_matrix()
    for entry in mat.requirements:
        if entry.applicability_status == "applicable":
            entry.implementation_status = "implemented"
            entry.how_applied = entry.how_applied or "done"
    result = gate.evaluate_gate(mat, cfg.ExceptionsFile())
    assert result.exit_code() == 0
    assert result.blocking == []


def test_gate_unjustified_waiver_exit_26() -> None:
    mat = matrix.build_matrix(
        product="p", template_id="t", not_applicable={"part_i_2_g": "reason"}
    )
    for entry in mat.requirements:
        if entry.applicability_status == "applicable":
            entry.implementation_status = "implemented"
            entry.how_applied = "done"
    # blank the justification -> unjustified waiver
    mat.by_key()["part_i_2_g"].justification = ""
    result = gate.evaluate_gate(mat, cfg.ExceptionsFile())
    assert result.exit_code() == gate.EXIT_UNJUSTIFIED_WAIVER


def test_gate_missing_mandatory_row_fails() -> None:
    mat = _fresh_matrix()
    mat.requirements = [e for e in mat.requirements if e.key != "part_ii_5"]
    result = gate.evaluate_gate(mat, cfg.ExceptionsFile())
    assert "part_ii_5" in {f.key for f in result.blocking}
    assert result.exit_code() == gate.EXIT_MISSING_MANDATORY


def test_gate_exception_addressed_elsewhere_satisfies_mandatory() -> None:
    mat = _fresh_matrix()
    for entry in mat.requirements:
        if entry.applicability_status == "applicable":
            entry.implementation_status = "implemented"
            entry.how_applied = "done"
    # leave part_ii_3 unaddressed, then satisfy it via an exception
    mat.by_key()["part_ii_3"].implementation_status = "planned"
    mat.by_key()["part_ii_3"].how_applied = ""
    failing = gate.evaluate_gate(mat, cfg.ExceptionsFile())
    assert failing.exit_code() == gate.EXIT_MISSING_MANDATORY
    exc = cfg.ExceptionsFile(
        by_key={
            "part_ii_3": cfg.ExceptionEntry("part_ii_3", "addressed_elsewhere", "external pentest")
        }
    )
    assert gate.evaluate_gate(mat, exc).exit_code() == 0


def test_gate_advisory_only_when_condition_not_in_fail_on() -> None:
    # fail_on only the waiver condition: a missing mandatory becomes advisory.
    result = gate.evaluate_gate(
        _fresh_matrix(), cfg.ExceptionsFile(), fail_on=(cfg.CONDITION_UNJUSTIFIED_WAIVER,)
    )
    assert result.exit_code() == 0
    assert result.blocking == []
    assert any(f.condition == gate.CONDITION_MISSING_MANDATORY for f in result.advisory)


# gate config

def test_gate_config_rejects_unknown_key(tmp_path: Path) -> None:
    path = tmp_path / "g.yaml"
    path.write_text("nope: 1\n")
    with pytest.raises(ConfigurationError):
        cfg.load_gate_config(path)


def test_gate_config_fail_on_parsing(tmp_path: Path) -> None:
    path = tmp_path / "g.yaml"
    path.write_text("fail_on: missing_mandatory\n")
    conf = cfg.load_gate_config(path)
    assert conf is not None
    assert conf.fail_on == ("missing_mandatory",)


def test_exceptions_rejects_mandatory_not_applicable(tmp_path: Path) -> None:
    path = tmp_path / "e.yaml"
    path.write_text(
        "schema_version: 1\nkind: cra-assessment-exceptions\n"
        "exceptions:\n  - key: part_ii_1\n    status: not_applicable\n    justification: x\n"
    )
    with pytest.raises(ConfigurationError):
        cfg.load_exceptions(path)


def test_exceptions_requires_justification(tmp_path: Path) -> None:
    path = tmp_path / "e.yaml"
    path.write_text(
        "schema_version: 1\nkind: cra-assessment-exceptions\n"
        "exceptions:\n  - key: part_i_2_g\n    status: not_applicable\n    justification: ''\n"
    )
    with pytest.raises(ConfigurationError):
        cfg.load_exceptions(path)


def test_exceptions_valid(tmp_path: Path) -> None:
    path = tmp_path / "e.yaml"
    path.write_text(
        "schema_version: 1\nkind: cra-assessment-exceptions\n"
        "exceptions:\n  - key: part_i_2_g\n    status: not_applicable\n"
        "    justification: no personal data\n"
    )
    loaded = cfg.load_exceptions(path)
    assert loaded.by_key["part_i_2_g"].justification == "no personal data"


# templates

def test_every_bundled_template_loads_and_is_legal() -> None:
    all_templates = templates.list_templates()
    assert all_templates, "no bundled templates found"
    for template in all_templates:
        # The core legal invariant: a template may only pre-mark Part I(2) letters
        # not-applicable. A mandatory duty must never be waived by a template.
        for key in template.not_applicable:
            assert requirements.is_waivable(key), f"{template.id} waives mandatory {key}"
        assert template.risks, f"{template.id} has no risks"
        assert template.controls, f"{template.id} has no controls"
        # builds a valid matrix
        mat = templates.build_applicability_matrix(template, "p")
        assert [e.key for e in mat.requirements] == list(requirements.CANONICAL_KEYS)


def test_build_risk_catalog_shape() -> None:
    template = templates.load_template("consumer-iot")
    ids = {template.risks[0].id}
    doc = templates.build_risk_catalog(template, "Cam", "Acme", ids)
    assert doc["metadata"]["type"] == "RiskCatalog"
    assert len(doc["risks"]) == 1
    assert doc["risks"][0]["id"] == template.risks[0].id
    assert doc["groups"], "groups must be derived"


def test_build_control_catalog_shape() -> None:
    template = templates.load_template("consumer-iot")
    ids = {template.controls[0].id}
    doc = templates.build_control_catalog(template, "Cam", "Acme", ids)
    assert doc["metadata"]["type"] == "ControlCatalog"
    assert len(doc["controls"]) == 1
    assert doc["metadata"]["applicability-groups"][0]["id"] == "all-products"


def test_merge_template_risks_renumbers() -> None:
    template = templates.load_template("consumer-iot")
    base = {"groups": [], "risks": [{"id": "R01", "title": "existing", "group": "g",
                                     "severity": "Low", "description": "", "impact": ""}]}
    merged = templates.merge_template_risks(base, template)
    ids = [r["id"] for r in merged["risks"]]
    assert ids == [f"R{i:02d}" for i in range(1, len(ids) + 1)]
    assert len(ids) == len([r for r in template.risks if r.recommended]) + 1


def test_load_unknown_template_raises() -> None:
    with pytest.raises(templates.TemplateError):
        templates.load_template("does-not-exist")


# multiselect

def test_parse_tokens() -> None:
    assert select._parse_tokens("1,3-5 7", 10) == {1, 3, 4, 5, 7}
    assert select._parse_tokens("99", 3) == set()
    assert select._parse_tokens("", 3) == set()


def test_multiselect_non_interactive_keeps_recommended() -> None:
    chosen = select.multiselect(
        "t", [("a", "A"), ("b", "B"), ("c", "C")], ["a", "c"], interactive=False
    )
    assert chosen == {"a", "c"}


def test_multiselect_interactive_toggle(monkeypatch) -> None:
    answers = iter(["2", ""])  # toggle option 2 on, then confirm
    monkeypatch.setattr(click, "prompt", lambda *a, **k: next(answers))
    chosen = select.multiselect(
        "t", [("a", "A"), ("b", "B")], ["a"], interactive=True
    )
    assert chosen == {"a", "b"}


# detect

def _synthetic(template_id: str, files: list[str]) -> templates.Template:
    return templates.Template(template_id, template_id, "", detect_files=files)


def test_detect_picks_unique_marker(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        detect,
        "list_templates",
        lambda: [_synthetic("alpha", ["alpha.marker"]), _synthetic("beta", ["beta.marker"])],
    )
    (tmp_path / "beta.marker").write_text("x")
    assert detect.detect_template(tmp_path) == "beta"


def test_detect_none_on_tie(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        detect,
        "list_templates",
        lambda: [_synthetic("alpha", ["m.cfg"]), _synthetic("beta", ["m.cfg"])],
    )
    (tmp_path / "m.cfg").write_text("x")
    assert detect.detect_template(tmp_path) is None


def test_detect_returns_none_on_empty(tmp_path: Path) -> None:
    assert detect.detect_template(tmp_path) is None


# command group

def test_cmd_templates_text_and_json() -> None:
    runner = CliRunner()
    text = runner.invoke(assessment, ["templates"], obj=_obj("text"))
    assert text.exit_code == 0, text.output
    assert "consumer-iot" in text.output
    js = runner.invoke(assessment, ["templates"], obj=_obj("json"))
    assert js.exit_code == 0, js.output
    data = json.loads(js.output)
    assert any(item["id"] == "consumer-iot" for item in data)


def test_cmd_new_writes_three_files_and_refuses_overwrite(tmp_path: Path) -> None:
    runner = CliRunner()
    args = ["new", "--template", "consumer-iot", "--product", "Cam",
            "--output-dir", str(tmp_path), "--non-interactive"]
    first = runner.invoke(assessment, args, obj=_obj())
    assert first.exit_code == 0, first.output
    for name in ("assessment.yaml", "risk-catalog.yaml", "control-catalog.yaml"):
        assert (tmp_path / name).exists()
    # O_EXCL: a second run must refuse, exit 4
    second = runner.invoke(assessment, args, obj=_obj())
    assert second.exit_code == 4
    assert "refusing to overwrite" in second.output.lower()


def test_cmd_new_unknown_template_exits_4(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        assessment,
        ["new", "--template", "nope", "--output-dir", str(tmp_path), "--non-interactive"],
        obj=_obj(),
    )
    assert result.exit_code == 4
    assert "unknown template" in result.output.lower()


def test_cmd_check_exit_codes(tmp_path: Path) -> None:
    runner = CliRunner()
    runner.invoke(
        assessment,
        ["new", "--template", "consumer-iot", "--output-dir", str(tmp_path), "--non-interactive"],
        obj=_obj(),
    )
    mpath = tmp_path / "assessment.yaml"
    # fresh -> 25
    fresh = runner.invoke(assessment, ["check", "--matrix", str(mpath)], obj=_obj())
    assert fresh.exit_code == 25, fresh.output
    assert "not an audit" in fresh.output.lower()
    # satisfy every applicable requirement -> 0
    mat = matrix.load_matrix(mpath)
    for entry in mat.requirements:
        if entry.applicability_status == "applicable":
            entry.implementation_status = "implemented"
            entry.how_applied = "done"
    mpath.write_text(matrix.dump_matrix(mat))
    ok = runner.invoke(assessment, ["check", "--matrix", str(mpath)], obj=_obj())
    assert ok.exit_code == 0, ok.output


def test_cmd_check_missing_matrix_exits_5(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        assessment, ["check", "--matrix", str(tmp_path / "nope.yaml")], obj=_obj()
    )
    assert result.exit_code == 5
    assert "no assessment matrix" in result.output.lower()


def test_cmd_check_json_output(tmp_path: Path) -> None:
    runner = CliRunner()
    runner.invoke(
        assessment,
        ["new", "--template", "consumer-iot", "--output-dir", str(tmp_path), "--non-interactive"],
        obj=_obj(),
    )
    result = runner.invoke(
        assessment, ["check", "--matrix", str(tmp_path / "assessment.yaml")], obj=_obj("json")
    )
    assert result.exit_code == 25
    data = json.loads(result.output)
    assert data["exit_code"] == 25
    assert data["blocking"]
    assert "compliance" in data["disclaimer"].lower()


def test_templates_unsupported_format_emits_notice() -> None:
    """'assessment templates' with an unsupported format emits a stderr notice."""
    runner = CliRunner()
    result = runner.invoke(assessment, ["templates"], obj=_obj("sarif"))
    assert result.exit_code == 0, result.output
    combined = result.output
    assert "sarif" in combined
    assert "not supported" in combined
    # Falls back to text listing.
    assert "consumer-iot" in combined


def test_check_unsupported_format_emits_notice(tmp_path: Path) -> None:
    """'assessment check' with an unsupported format emits a stderr notice."""
    runner = CliRunner()
    runner.invoke(
        assessment,
        ["new", "--template", "consumer-iot", "--output-dir", str(tmp_path), "--non-interactive"],
        obj=_obj(),
    )
    mpath = tmp_path / "assessment.yaml"
    result = runner.invoke(
        assessment, ["check", "--matrix", str(mpath)], obj=_obj("sarif")
    )
    # Exit code is non-zero (25) because the fresh matrix has gaps.
    combined = result.output
    assert "sarif" in combined
    assert "not supported" in combined
