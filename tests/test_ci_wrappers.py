"""Tests for customer-facing CI wrapper metadata."""

import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_github_action_uses_cli_signing_path():
    action_path = REPO_ROOT / "action.yml"
    action_text = action_path.read_text(encoding="utf-8")
    action = yaml.safe_load(action_text)

    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["create-product"]["default"] == "false"
    assert action["inputs"]["target-markets"]["default"] == ""
    assert action["inputs"]["sign"]["default"] == "false"
    assert action["inputs"]["signature-identity"]["required"] is False
    assert action["inputs"]["signature-issuer"]["required"] is False
    assert action["inputs"]["fail-untrusted"]["default"] == "false"
    assert action["inputs"]["include-experimental"]["default"] == "false"
    assert "signature-trust-status" in action["outputs"]
    assert "response" in action["outputs"]
    assert "code-check" in action["inputs"]["command"]["description"]

    assert "craevidence --output json" in action_text
    assert "ARGS=(code-check" in action_text
    assert "ARGS+=(--include-experimental)" in action_text
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
    assert ".cra-evidence-code-check" in content

    inputs = spec["spec"]["inputs"]
    assert inputs["create-product"]["default"] is False
    assert inputs["target-markets"]["default"] == ""
    assert inputs["sign"]["default"] is False
    assert inputs["signature-identity"]["type"] == "string"
    assert inputs["signature-issuer"]["type"] == "string"
    assert inputs["fail-untrusted"]["default"] is False

    # The caller-selectable package spec is gone: the CLI is installed from a
    # version-pinned wheel verified by checksum.
    assert "cli-package" not in inputs
    assert "CRA_CLI_PACKAGE" not in component_text
    # The exact pinned version is asserted against pyproject.toml in
    # test_gitlab_component_pins_the_packaged_version.
    assert re.search(r'CLI_VERSION="[0-9][0-9a-z.]*"', component_text)
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
    assert content[".cra-evidence-code-check"]["extends"] == ".cra-evidence-check"
    assert (
        content[".cra-evidence-code-check"]["variables"]["CRA_CHECK_COMMAND"]
        == "code-check"
    )
    assert (
        content[".cra-evidence-code-check"]["variables"]
        ["CRA_CODE_CHECK_INCLUDE_EXPERIMENTAL"]
        == "false"
    )
    assert 'set -- "$@" --include-experimental' in component_text

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

    for platform in (
        "MANYLINUX_X86_64",
        "MUSLLINUX_X86_64",
        "MANYLINUX_AARCH64",
        "MUSLLINUX_AARCH64",
    ):
        hashes = re.findall(
            rf'CLI_WHEEL_SHA256_{platform}="([a-f0-9]{{64}})"', component_text
        )
        assert len(hashes) == 2, f"both templates must pin {platform}"
        assert len(set(hashes)) == 1


def test_package_version_matches_pyproject():
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_version = re.search(
        r'^version = "([^"]+)"', pyproject_text, re.MULTILINE
    ).group(1)
    init_text = (REPO_ROOT / "cra_evidence_cli" / "__init__.py").read_text(
        encoding="utf-8"
    )
    dunder_version = re.search(
        r'^__version__ = "([^"]+)"', init_text, re.MULTILINE
    ).group(1)
    assert dunder_version == project_version


def test_dockerfile_requires_the_engine_sbom_command():
    dockerfile_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "grype sbom --help | grep -F 'grype sbom SOURCE'" in dockerfile_text
    assert "grype sbom --help | grep -F -- '--offline'" in dockerfile_text


def test_dockerfile_opengrep_pin_matches_committed_release_lock():
    dockerfile_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    lock = json.loads(
        (
            REPO_ROOT
            / "cra_evidence_cli"
            / "_engine"
            / "opengrep-release.json"
        ).read_text(encoding="utf-8")
    )

    assert f"ARG OPENGREP_VERSION={lock['version']}" in dockerfile_text
    assert f"ARG OPENGREP_COMMIT={lock['commit']}" in dockerfile_text
    assert lock["assets"]["opengrep_manylinux_x86"] in dockerfile_text
    assert lock["assets"]["opengrep_manylinux_aarch64"] in dockerfile_text
    assert "https://github.com/opengrep/opengrep" in dockerfile_text
    assert 're.finditer(rb"(?:lib[A-Za-z0-9_+.-]+\\.' in dockerfile_text
    assert 'assert libraries, f"no native dependencies found in {asset}"' in dockerfile_text


def test_rulepack_workflow_verifies_the_committed_opengrep_lock():
    workflow_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    lock = json.loads(
        (
            REPO_ROOT
            / "cra_evidence_cli"
            / "_engine"
            / "opengrep-release.json"
        ).read_text(encoding="utf-8")
    )

    assert lock["certificate_identity"] in workflow_text
    assert lock["certificate_issuer"] in workflow_text
    assert lock["assets"]["opengrep_manylinux_x86"] in workflow_text
    assert lock["assets"]["opengrep_manylinux_aarch64"] in workflow_text


def test_image_comparison_inventory_cannot_fail_on_finding_severity():
    script = (REPO_ROOT / "scripts" / "check-image-gate.sh").read_text(
        encoding="utf-8"
    )
    inventory = script.split(
        'echo "check-image-gate: fixed-finding comparison inventory', maxsplit=1
    )[1]

    assert '"${inventory_grype_bin}" -o table --only-fixed "${image}"' in inventory
    assert '"${inventory_grype_bin}" -o table --fail-on' not in inventory


def test_release_packaging_reuses_the_promoted_engine_artifact():
    workflow_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    workflow = yaml.safe_load(workflow_text)
    build_steps = workflow["jobs"]["build-and-sbom"]["steps"]
    image_steps = workflow["jobs"]["publish-images"]["steps"]
    publish_steps = workflow["jobs"]["publish-pypi"]["steps"]
    build_names = [step.get("name", "") for step in build_steps]
    image_names = [step.get("name", "") for step in image_steps]
    publish_names = [step.get("name", "") for step in publish_steps]

    assert "Extract the promoted engine payload" in build_names
    assert "Build and verify all engine distributions" in build_names
    assert "Preserve the promoted engine payload for release packaging" in build_names
    assert "Fetch and verify the pinned official Opengrep payload" in build_names
    assert "Preserve the verified Opengrep payload for release packaging" in build_names
    assert "Verify bundled licence material" in build_names
    assert "Restore the verified Opengrep source payload" in image_names
    assert "Bind the Opengrep source payload to the release source" in image_names
    assert "Attach pinned Opengrep build source to the GitHub release" in image_names
    assert image_names.index(
        "Attach pinned Opengrep build source to the GitHub release"
    ) < image_names.index("Build and push the canonical multi-arch image to GHCR")
    assert "Restore the promoted engine payload" in publish_names
    assert "Restore the verified Opengrep payload" in publish_names
    assert "Bind the engine payload to the release source" in publish_names
    assert "Verify the complete release distribution set" in publish_names
    assert "Attach pinned Opengrep build source to the GitHub release" not in publish_names
    assert not any(
        step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        for step in publish_steps
    )

    digest = "sha256:02f1fbc3f1bdcc2c3354600f40d11aa4f5de3203f1933a30167d73c3f4ee211f"
    assert workflow_text.count(digest) == 4
    assert '"${payload}/IMAGE_DIGEST"' in workflow_text
    assert "actual=$(cat engine/IMAGE_DIGEST)" in workflow_text
    assert "python release-src/scripts/check_dist.py" in workflow_text
    assert "--opengrep-dir opengrep" in workflow_text


def test_release_has_one_pypi_publisher_in_the_pypi_job():
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
    )
    publishers: list[tuple[str, dict]] = []
    for job_name, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            if step.get("uses", "").startswith("pypa/gh-action-pypi-publish@"):
                publishers.append((job_name, step))

    assert len(publishers) == 1
    assert publishers[0][0] == "publish-pypi"


def test_all_engine_image_pins_use_the_dockerfile_digest():
    workflow_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    dockerfile_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    digest_pattern = r"craevidence/grype-engine@(sha256:[a-f0-9]{64})"
    dockerfile_digests = re.findall(digest_pattern, dockerfile_text)
    workflow_digests = re.findall(digest_pattern, workflow_text)

    assert len(dockerfile_digests) == 1
    assert len(workflow_digests) == 4
    assert set(workflow_digests) == set(dockerfile_digests)


def test_v4_release_docs_use_the_v4_major_tag_before_release():
    release_text = (REPO_ROOT / "docs" / "releasing.md").read_text(
        encoding="utf-8"
    )

    assert "## The `v4` major tag" in release_text
    assert "refs/tags/v4" in release_text
    assert "refs/tags/v3" not in release_text
    assert "latest `v3.x`" not in release_text
    assert release_text.index("git tag v4 <commit>") < release_text.index(
        "Create the GitHub release"
    )
