"""Supply-chain invariants for the container C/C++ semantic frontend."""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def test_dockerfile_pins_and_catalogues_the_debian_frontend():
    content = DOCKERFILE.read_text(encoding="utf-8")

    assert "ARG LIBCLANG_VERSION=1:18.1.8-18+b1" in content
    for package in (
        "libclang-common-18-dev",
        "libstdc++-14-dev",
        "libc6-dev",
        "linux-libc-dev",
        "libclang1-18",
        "libllvm18",
        "libedit2",
        "libxml2",
        "libz3-4",
        "libbsd0",
        "libmd0",
    ):
        assert package in content
    assert "amd64) triple=x86_64-linux-gnu" in content
    assert "arm64) triple=aarch64-linux-gnu" in content
    assert "Path('/var/lib/dpkg/status')" in content
    assert "package inventory version conflict" in content
    assert "COPY --from=builder /semantic-runtime/ /" in content


def test_container_build_and_ci_assert_both_debian_profiles():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    profiles = (
        "libclang-18.1.8-debian13-c17-security-evidence-v2",
        "libclang-18.1.8-debian13-cpp17-security-evidence-v2",
    )

    for profile in profiles:
        assert profile in dockerfile
        assert profile in workflow
    assert 'root / "semantic/DPKG-STATUS"' in workflow
    assert "semantic frontend package inventory is incomplete" in workflow
    assert "semantic frontend package is missing from the runtime inventory" in workflow
    assert "semantic runtime unexpectedly contains a compiler driver or linker" in workflow


def test_c_family_schemas_accept_both_supported_frontend_versions():
    expected = {
        "Ubuntu clang version 18.1.3 (1ubuntu1)",
        "Debian clang version 18.1.8 (18+b1)",
    }
    for name in (
        "c_semantic_evidence.schema.json",
        "cpp_semantic_evidence.schema.json",
    ):
        schema = json.loads(
            (REPO_ROOT / "cra_evidence_cli" / "local" / name).read_text(
                encoding="utf-8"
            )
        )
        versions = schema["properties"]["adapter"]["properties"][
            "library_version"
        ]["enum"]
        assert set(versions) == expected


def test_release_ci_pins_arm64_emulation_before_release_buildx():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    qemu_action = "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8"
    binfmt_image = (
        "tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
    )
    release_marker = "Attach pinned Opengrep build source to the GitHub release"
    release_workflow = workflow[workflow.index(release_marker) :]

    assert release_workflow.count(qemu_action) == 1
    assert release_workflow.count(binfmt_image) == 1
    assert release_workflow.index(qemu_action) < release_workflow.index(
        "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e"
    )
