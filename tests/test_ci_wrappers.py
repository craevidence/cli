"""Tests for customer-facing CI wrapper metadata."""

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_github_action_uses_cli_signing_path():
    action_path = REPO_ROOT / "action.yml"
    action_text = action_path.read_text(encoding="utf-8")
    action = yaml.safe_load(action_text)

    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["create-product"]["default"] == "true"
    assert action["inputs"]["target-markets"]["default"] == ""
    assert action["inputs"]["sign"]["default"] == "false"
    assert action["inputs"]["signature-identity"]["required"] is False
    assert action["inputs"]["signature-issuer"]["required"] is False
    assert action["inputs"]["fail-untrusted"]["default"] == "false"
    assert "signature-trust-status" in action["outputs"]
    assert "response" in action["outputs"]

    assert "craevidence --output json" in action_text
    assert "--sign" in action_text
    assert "--target-markets" in action_text
    assert "target-markets such as DE,FR,ES" in action_text
    assert "--signature-bundle" in action_text
    assert "permissions: id-token: write" in action_text
    assert "exit \"${CLI_EXIT}\"" in action_text
    # Pinned by full commit SHA (supply-chain hardening), version-agnostic so a
    # dependency bump of the action does not break this assertion.
    assert re.search(r"actions/setup-python@[0-9a-f]{40}\b", action_text), (
        "action.yml must pin actions/setup-python by full commit SHA"
    )
    assert "/api/v1/ci/upload" not in action_text
    assert "curl -s" not in action_text


def test_github_action_warns_on_branch_named_versions():
    action_path = REPO_ROOT / "action.yml"
    action_text = action_path.read_text(encoding="utf-8")

    assert "This upload is using the branch name" in action_text
    assert "Default environment rules classify" in action_text
    # Warn only for artifact types that create version records, on branch
    # refs, when the version equals the branch name.
    assert "sbom|hbom|document)" in action_text
    assert '[ "${GITHUB_REF_TYPE_VAL:-}" = "branch" ]' in action_text
    assert '[ "${INPUT_VERSION}" = "${GITHUB_REF_NAME_VAL:-}" ]' in action_text
    assert "main|master|release/*)" in action_text


def test_gitlab_component_uses_cli_signing_path():
    component_path = REPO_ROOT / "gitlab-ci-component.yml"
    component_text = component_path.read_text(encoding="utf-8")
    documents = list(yaml.safe_load_all(component_text))
    # GitLab's component loader accepts at most two documents (spec + content);
    # everything after the spec header must live in a single document.
    assert len(documents) == 2
    spec, content = documents
    assert ".cra-evidence-upload" in content
    assert "cra-evidence-upload" in content
    assert ".cra-evidence-check" in content

    inputs = spec["spec"]["inputs"]
    assert inputs["create-product"]["default"] is True
    assert inputs["target-markets"]["default"] == ""
    assert inputs["sign"]["default"] is False
    assert inputs["signature-identity"]["type"] == "string"
    assert inputs["signature-issuer"]["type"] == "string"
    assert inputs["fail-untrusted"]["default"] is False

    # The caller-selectable package spec is gone: the CLI is installed from a
    # version-pinned wheel verified by checksum.
    assert "cli-package" not in inputs
    assert "CRA_CLI_PACKAGE" not in component_text
    assert 'CLI_VERSION="3.7.0"' in component_text
    assert component_text.count("sha256sum -c -") >= 2

    upload_template = content[".cra-evidence-upload"]
    assert upload_template["image"] == "python:3.12-slim"
    # Only the signing variant requests a Sigstore OIDC token.
    assert "id_tokens" not in upload_template
    assert upload_template["variables"]["CRA_TARGET_MARKETS"] == ""

    signed_template = content[".cra-evidence-upload-signed"]
    assert signed_template["extends"] == ".cra-evidence-upload"
    assert signed_template["id_tokens"]["SIGSTORE_ID_TOKEN"]["aud"] == "sigstore"
    assert content["cra-evidence-upload"]["extends"] == ".cra-evidence-upload-signed"

    variables = content["cra-evidence-upload"]["variables"]
    assert variables["CRA_TARGET_MARKETS"] == "$[[ inputs.target-markets ]]"
    assert variables["CRA_SIGN"] == "$[[ inputs.sign ]]"
    assert variables["CRA_SIGNATURE_IDENTITY"] == "$[[ inputs.signature-identity ]]"
    assert variables["CRA_SIGNATURE_ISSUER"] == "$[[ inputs.signature-issuer ]]"

    assert "craevidence \"$@\"" in component_text
    assert "--sign" in component_text
    assert "--target-markets" in component_text
    assert "CRA_TARGET_MARKETS is only safe when the product already exists" in component_text
    assert "--signature-bundle" in component_text
    assert "aud: sigstore" in component_text
    assert "/api/v1/ci/upload" not in component_text
    assert "curl -s" not in component_text


def test_gitlab_component_pins_the_packaged_version():
    component_text = (REPO_ROOT / "gitlab-ci-component.yml").read_text(encoding="utf-8")
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_version = re.search(
        r'^version = "([^"]+)"', pyproject_text, re.MULTILINE
    ).group(1)

    pinned_versions = re.findall(r'CLI_VERSION="([0-9][0-9a-z.]*)"', component_text)
    assert len(pinned_versions) == 2, "both templates must pin the CLI version"
    assert set(pinned_versions) == {project_version}

    pinned_hashes = re.findall(r'CLI_WHEEL_SHA256="([a-f0-9]{64})"', component_text)
    assert len(pinned_hashes) == 2, "both templates must pin the wheel checksum"
    assert len(set(pinned_hashes)) == 1, "both templates must pin the same checksum"
