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


# --- dockerfile-secret-arg tests ---

def test_dockerfile_arg_password_flagged(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nARG DB_PASSWORD\n")
    assert "dockerfile-secret-arg" in _rules(ca.evaluate(tmp_path))


def test_dockerfile_env_secret_with_value_flagged(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nENV APP_SECRET=changeme\n")
    assert "dockerfile-secret-arg" in _rules(ca.evaluate(tmp_path))


def test_dockerfile_arg_token_flagged(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nARG GITHUB_TOKEN\n")
    assert "dockerfile-secret-arg" in _rules(ca.evaluate(tmp_path))


def test_dockerfile_arg_api_key_flagged(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nARG STRIPE_API_KEY\n")
    assert "dockerfile-secret-arg" in _rules(ca.evaluate(tmp_path))


def test_dockerfile_arg_private_key_flagged(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nARG TLS_PRIVATE_KEY\n")
    assert "dockerfile-secret-arg" in _rules(ca.evaluate(tmp_path))


def test_dockerfile_arg_credential_flagged(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nARG DB_CREDENTIAL\n")
    assert "dockerfile-secret-arg" in _rules(ca.evaluate(tmp_path))


def test_dockerfile_arg_port_not_flagged(tmp_path):
    # PORT, APP_NAME, DEBUG, etc. should not fire.
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nARG APP_PORT\nARG DEBUG\n")
    assert "dockerfile-secret-arg" not in _rules(ca.evaluate(tmp_path))


def test_dockerfile_arg_token_endpoint_url_flagged_with_name_only_message(tmp_path):
    # TOKEN_ENDPOINT_URL contains TOKEN so it fires; the message must explain
    # that the check matches the variable name only and may have false positives.
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nARG TOKEN_ENDPOINT_URL\n")
    report = ca.evaluate(tmp_path)
    assert "dockerfile-secret-arg" in _rules(report)
    finding = next(f for f in report.findings if f.rule == "dockerfile-secret-arg")
    assert "variable NAME only" in finding.message


def test_dockerfile_arg_public_key_not_flagged(tmp_path):
    # PUBLIC_KEY does not match any of the listed credential patterns and must not fire.
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nARG PUBLIC_KEY\n")
    assert "dockerfile-secret-arg" not in _rules(ca.evaluate(tmp_path))


def test_dockerfile_secret_arg_line_number_recorded(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nARG DB_PASSWORD\n")
    report = ca.evaluate(tmp_path)
    finding = next(f for f in report.findings if f.rule == "dockerfile-secret-arg")
    assert finding.line == 3


# --- walker dotdir tests ---

def test_github_workflows_scanned(tmp_path):
    _write(
        tmp_path,
        ".github/workflows/ci.yml",
        "on:\n  pull_request_target:\njobs:\n  build:\n",
    )
    report = ca.evaluate(tmp_path)
    assert "workflow-pull-request-target" in _rules(report)


def test_other_dotdir_skipped(tmp_path):
    # A workflow file placed under .myapp (not .github) must not be scanned.
    _write(
        tmp_path,
        ".myapp/workflows/ci.yml",
        "on:\n  pull_request_target:\njobs:\n  build:\n",
    )
    report = ca.evaluate(tmp_path)
    assert "workflow-pull-request-target" not in _rules(report)
    assert report.files_scanned == 0


def test_dot_git_still_skipped(tmp_path):
    _write(tmp_path, ".git/config", "[core]\n  repositoryformatversion = 0\n")
    report = ca.evaluate(tmp_path)
    assert report.files_scanned == 0


# --- workflow rule tests ---

def test_workflow_script_injection_issue_title(tmp_path):
    body = (
        "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        '    steps:\n      - run: echo "${{ github.event.issue.title }}"\n'
    )
    _write(tmp_path, ".github/workflows/ci.yml", body)
    assert "workflow-script-injection" in _rules(ca.evaluate(tmp_path))


def test_workflow_script_injection_pr_title(tmp_path):
    body = (
        "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        '    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n'
    )
    _write(tmp_path, ".github/workflows/ci.yml", body)
    assert "workflow-script-injection" in _rules(ca.evaluate(tmp_path))


def test_workflow_script_injection_head_ref(tmp_path):
    body = (
        "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: git checkout ${{ github.event.head_ref }}\n"
    )
    _write(tmp_path, ".github/workflows/ci.yml", body)
    assert "workflow-script-injection" in _rules(ca.evaluate(tmp_path))


def test_workflow_script_injection_safe_context_not_flagged(tmp_path):
    # github.sha, github.run_id are controlled values and not flagged.
    body = (
        "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ${{ github.sha }}\n"
    )
    _write(tmp_path, ".github/workflows/ci.yml", body)
    assert "workflow-script-injection" not in _rules(ca.evaluate(tmp_path))


def test_workflow_script_injection_env_indirection_not_flagged(tmp_path):
    # The recommended safe pattern: bind event data to an env var, then use $VAR
    # in run. The env-assignment line must NOT be flagged.
    body = (
        "on: [issues]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - env:\n          TITLE: ${{ github.event.issue.title }}\n"
        '        run: echo "$TITLE"\n'
    )
    _write(tmp_path, ".github/workflows/ci.yml", body)
    assert "workflow-script-injection" not in _rules(ca.evaluate(tmp_path))


def test_dockerfile_secret_arg_second_var_flagged(tmp_path):
    # A credential-named variable after a benign one on the same ENV line fires.
    _write(tmp_path, "Dockerfile", "FROM alpine\nUSER app\nENV NORMAL=x API_KEY=y\n")
    assert "dockerfile-secret-arg" in _rules(ca.evaluate(tmp_path))


def test_dockerfile_secret_word_in_value_not_flagged(tmp_path):
    # The word only in a value, not a variable name, must not fire.
    _write(tmp_path, "Dockerfile", 'FROM alpine\nUSER app\nENV MESSAGE="enter password"\n')
    assert "dockerfile-secret-arg" not in _rules(ca.evaluate(tmp_path))


def test_workflow_pull_request_target_flagged(tmp_path):
    body = (
        "on:\n  pull_request_target:\n    types: [opened]\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
    )
    _write(tmp_path, ".github/workflows/pr.yml", body)
    assert "workflow-pull-request-target" in _rules(ca.evaluate(tmp_path))


def test_workflow_pull_request_target_inline_flagged(tmp_path):
    # Inline trigger form: on: pull_request_target
    body = "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    _write(tmp_path, ".github/workflows/pr.yml", body)
    assert "workflow-pull-request-target" in _rules(ca.evaluate(tmp_path))


def test_workflow_pull_request_target_list_flagged(tmp_path):
    # List trigger form: on: [pull_request_target, push]
    body = (
        "on: [pull_request_target, push]\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
    )
    _write(tmp_path, ".github/workflows/pr.yml", body)
    assert "workflow-pull-request-target" in _rules(ca.evaluate(tmp_path))


def test_workflow_pull_request_not_flagged(tmp_path):
    # pull_request (not pull_request_target) must not fire.
    body = (
        "on:\n  pull_request:\n    branches: [main]\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
    )
    _write(tmp_path, ".github/workflows/pr.yml", body)
    assert "workflow-pull-request-target" not in _rules(ca.evaluate(tmp_path))


def test_workflow_set_output_deprecated(tmp_path):
    body = (
        "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        '    steps:\n      - run: echo "::set-output name=version::1.0"\n'
    )
    _write(tmp_path, ".github/workflows/ci.yml", body)
    assert "workflow-set-output-deprecated" in _rules(ca.evaluate(tmp_path))


def test_workflow_save_state_deprecated(tmp_path):
    body = (
        "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        '    steps:\n      - run: echo "::save-state name=key::val"\n'
    )
    _write(tmp_path, ".github/workflows/ci.yml", body)
    assert "workflow-set-output-deprecated" in _rules(ca.evaluate(tmp_path))


def test_workflow_github_output_not_flagged(tmp_path):
    # The modern GITHUB_OUTPUT syntax must not fire.
    body = (
        "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        '    steps:\n      - run: echo "version=1.0" >> $GITHUB_OUTPUT\n'
    )
    _write(tmp_path, ".github/workflows/ci.yml", body)
    assert "workflow-set-output-deprecated" not in _rules(ca.evaluate(tmp_path))


def test_workflow_file_counted_in_files_scanned(tmp_path):
    _write(
        tmp_path,
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
    )
    report = ca.evaluate(tmp_path)
    assert report.files_scanned == 1


def test_workflow_yaml_outside_workflows_classified_as_yaml(tmp_path):
    # A YAML file in .github but not under workflows/ is plain yaml, not workflow.
    p = tmp_path / ".github" / "dependabot.yml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("version: 2\n", encoding="utf-8")
    assert ca.classify_file(p) == "yaml"


def test_classify_workflow(tmp_path):
    p = tmp_path / ".github" / "workflows" / "ci.yml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("on: [push]\n", encoding="utf-8")
    assert ca.classify_file(p) == "workflow"
