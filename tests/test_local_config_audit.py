"""Unit tests for cra_evidence_cli.local.config_audit. No network, no API key."""

from __future__ import annotations

from pathlib import Path

from cra_evidence_cli.local import config_audit as ca


def _write(root: Path, name: str, body: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _rules(report) -> set[str]:
    return {f.rule for f in report.findings}


def test_classify_file_kinds(tmp_path):
    assert ca.classify_file(tmp_path / "Dockerfile") == "dockerfile"
    assert ca.classify_file(tmp_path / "Dockerfile.prod") == "dockerfile"
    assert ca.classify_file(tmp_path / "build.dockerfile") == "dockerfile"
    assert ca.classify_file(tmp_path / "main.tf") == "terraform"
    assert ca.classify_file(tmp_path / "pod.yaml") == "yaml"
    assert ca.classify_file(tmp_path / "pod.yml") == "yaml"
    assert ca.classify_file(tmp_path / "app.py") is None


def test_dockerfile_user_root(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER root\n")
    report = ca.evaluate(tmp_path)
    assert "container-user-root" in _rules(report)
    finding = next(f for f in report.findings if f.rule == "container-user-root")
    assert finding.cra_point == "(2)(b)"
    assert finding.line == 2


def test_dockerfile_no_user_flagged(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nRUN echo hi\n")
    report = ca.evaluate(tmp_path)
    assert "container-no-user" in _rules(report)
    finding = next(f for f in report.findings if f.rule == "container-no-user")
    assert finding.line is None


def test_dockerfile_with_user_not_flagged_for_no_user(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\n")
    report = ca.evaluate(tmp_path)
    assert "container-no-user" not in _rules(report)


def test_dockerfile_remote_add(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nADD https://example.com/x /x\n")
    report = ca.evaluate(tmp_path)
    assert "remote-add" in _rules(report)


def test_yaml_privileged_and_escalation(tmp_path):
    _write(
        tmp_path,
        "pod.yaml",
        "securityContext:\n  privileged: true\n  allowPrivilegeEscalation: true\n",
    )
    rules = _rules(ca.evaluate(tmp_path))
    assert "privileged-container" in rules
    assert "privilege-escalation" in rules


def test_yaml_run_as_root_and_caps_and_hostnet(tmp_path):
    _write(
        tmp_path,
        "pod.yml",
        "spec:\n  hostNetwork: true\n  securityContext:\n    runAsNonRoot: false\n"
        "  capabilities:\n    add: [SYS_ADMIN]\n",
    )
    rules = _rules(ca.evaluate(tmp_path))
    assert {"host-network", "run-as-root-allowed", "dangerous-capability"} <= rules


def test_yaml_bind_all_interfaces(tmp_path):
    _write(tmp_path, "svc.yaml", "args:\n  - --bind=0.0.0.0\n")
    assert "bind-all-interfaces" in _rules(ca.evaluate(tmp_path))


def test_yaml_documentation_address_not_bind_all(tmp_path):
    _write(tmp_path, "svc.yaml", "notes: use 0.0.0.0 only in examples\n")
    assert "bind-all-interfaces" not in _rules(ca.evaluate(tmp_path))


def test_yaml_listen_address_is_bind_all(tmp_path):
    _write(tmp_path, "svc.yaml", "listen_address: 0.0.0.0\n")
    assert "bind-all-interfaces" in _rules(ca.evaluate(tmp_path))


def test_terraform_world_open_ingress_and_public_acl(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        'cidr_blocks = ["0.0.0.0/0"]\nacl = "public-read"\n',
    )
    rules = _rules(ca.evaluate(tmp_path))
    assert "world-open-ingress" in rules
    assert "public-bucket-acl" in rules


def test_world_open_ingress_not_double_counted_as_bind_all(tmp_path):
    # 0.0.0.0/0 in terraform is world-open-ingress, not bind-all-interfaces.
    _write(tmp_path, "main.tf", 'cidr_blocks = ["0.0.0.0/0"]\n')
    rules = _rules(ca.evaluate(tmp_path))
    assert "world-open-ingress" in rules
    assert "bind-all-interfaces" not in rules


def test_clean_config_no_findings(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\n")
    _write(tmp_path, "ok.yaml", "spec:\n  replicas: 2\n")
    report = ca.evaluate(tmp_path)
    assert report.findings == []
    assert report.files_scanned == 2


def test_non_config_file_ignored(tmp_path):
    # A .py file containing a trigger string must not be scanned.
    _write(tmp_path, "app.py", 'cfg = "privileged: true"\n')
    report = ca.evaluate(tmp_path)
    assert report.findings == []
    assert report.files_scanned == 0


def test_skip_dirs_ignored(tmp_path):
    _write(tmp_path, "node_modules/dep/Dockerfile", "FROM alpine\nUSER root\n")
    assert ca.evaluate(tmp_path).findings == []


def test_finding_cap_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(ca, "_MAX_FINDINGS", 2)
    _write(tmp_path, "pod.yaml", "privileged: true\n" * 10)
    report = ca.evaluate(tmp_path)
    assert len(report.findings) == 2
    assert report.capped is True


def test_to_dict_keys(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER root\n")
    report = ca.evaluate(tmp_path)
    rd = report.to_dict()
    for key in ("files_scanned", "finding_count", "capped", "findings"):
        assert key in rd
    fd = report.findings[0].to_dict()
    for key in ("rule", "cra_point", "location", "line", "message"):
        assert key in fd


def test_evaluate_single_file(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM alpine\nUSER root\n", encoding="utf-8")
    report = ca.evaluate(f)
    assert "container-user-root" in _rules(report)
    assert report.files_scanned == 1
