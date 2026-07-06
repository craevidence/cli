"""Tests for customer-facing CI wrapper metadata."""

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
    assert "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405" in action_text
    assert "/api/v1/ci/upload" not in action_text
    assert "curl -s" not in action_text


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

    upload_template = content[".cra-evidence-upload"]
    assert upload_template["image"] == "python:3.12-slim"
    assert upload_template["id_tokens"]["SIGSTORE_ID_TOKEN"]["aud"] == "sigstore"
    assert upload_template["variables"]["CRA_CLI_PACKAGE"] == "craevidence>=3.6.0,<4"
    assert upload_template["variables"]["CRA_TARGET_MARKETS"] == ""

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
