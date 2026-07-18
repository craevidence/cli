"""Fixture tests for scripts/reconcile_release_sboms.sh.

Each test runs the real script with stubbed `gh` and `cosign` executables
prepended to PATH, so every branch is exercised deterministically without a
network. The gh stub is data-driven from a per-test state directory: `release
view` prints assets.txt, `release download` serves files from remote/, and
`release upload` copies files into remote/ and records their names. The cosign
stub binds a bundle to the sha256 of the signed file and to an identity marker
(`tag` for a refs/tags identity, `run` otherwise), so identity acceptance and
byte-level tampering are both real: a bundle only verifies for the exact bytes
it was created over and under the identity that produced it.
"""

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "reconcile_release_sboms.sh"
BASH = shutil.which("bash") or "/usr/bin/bash"

RELEASE_TAG = "v9.9.9"
TAG_IDENTITY = (
    "https://github.com/craevidence/cli/.github/workflows/ci.yml@refs/tags/v9.9.9"
)
RUN_IDENTITY = (
    "https://github.com/craevidence/cli/.github/workflows/ci.yml@refs/heads/main"
)
DOC_AMD64 = "sbom-9.9.9-linux-amd64.cdx.json"
DOC_ARM64 = "sbom-9.9.9-linux-arm64.cdx.json"
BUNDLE_AMD64 = DOC_AMD64 + ".cosign.bundle"
BUNDLE_ARM64 = DOC_ARM64 + ".cosign.bundle"
FRESH_AMD64 = b'{"bomFormat":"CycloneDX","platform":"linux/amd64","build":"fresh"}\n'
FRESH_ARM64 = b'{"bomFormat":"CycloneDX","platform":"linux/arm64","build":"fresh"}\n'
REMOTE_AMD64 = b'{"bomFormat":"CycloneDX","platform":"linux/amd64","build":"remote"}\n'

GH_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
state="@STATE@"
case "${1:-} ${2:-}" in
  "release view")
    cat "${state}/assets.txt"
    ;;
  "release download")
    shift 3
    pattern=""
    dir=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --pattern) pattern="$2"; shift 2 ;;
        --dir) dir="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    [ -f "${state}/remote/${pattern}" ] || exit 1
    cp "${state}/remote/${pattern}" "${dir}/${pattern}"
    ;;
  "release upload")
    shift 3
    for a in "$@"; do
      if [ "$a" = "--clobber" ]; then continue; fi
      cp "$a" "${state}/remote/"
      n="$(basename "$a")"
      grep -Fqx -- "$n" "${state}/assets.txt" || echo "$n" >> "${state}/assets.txt"
    done
    ;;
  *)
    echo "gh stub: unexpected arguments: $*" >&2
    exit 1
    ;;
esac
"""

COSIGN_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
mode="${1:-}"
shift
case "${mode}" in
  sign-blob)
    bundle=""
    doc=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --yes) shift ;;
        --bundle) bundle="$2"; shift 2 ;;
        *) doc="$1"; shift ;;
      esac
    done
    hash="$(sha256sum "${doc}" | cut -d' ' -f1)"
    printf 'signed:run:%s' "${hash}" > "${bundle}"
    ;;
  verify-blob)
    bundle=""
    identity=""
    doc=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --bundle) bundle="$2"; shift 2 ;;
        --certificate-identity) identity="$2"; shift 2 ;;
        --certificate-oidc-issuer) shift 2 ;;
        *) doc="$1"; shift ;;
      esac
    done
    [ -f "${bundle}" ] || exit 1
    [ -f "${doc}" ] || exit 1
    case "${identity}" in
      *refs/tags/*) marker="tag" ;;
      *) marker="run" ;;
    esac
    hash="$(sha256sum "${doc}" | cut -d' ' -f1)"
    [ "$(cat "${bundle}")" = "signed:${marker}:${hash}" ]
    ;;
  *)
    echo "cosign stub: unexpected mode ${mode}" >&2
    exit 1
    ;;
esac
"""


def bundle_bytes(data: bytes, marker: str) -> bytes:
    """Return the stub bundle content binding `data` under `marker` identity."""
    return f"signed:{marker}:{hashlib.sha256(data).hexdigest()}".encode()


class Harness:
    """Per-test release state, working directory, and stubbed tool PATH."""

    def __init__(self, tmp_path: Path) -> None:
        self.bin = tmp_path / "bin"
        self.state = tmp_path / "state"
        self.remote = self.state / "remote"
        self.assets = self.state / "assets.txt"
        self.work = tmp_path / "work"
        self.dest = tmp_path / "dest"
        for d in (self.bin, self.remote, self.work):
            d.mkdir(parents=True)
        self.assets.write_text("")
        self._write_stub("gh", GH_STUB.replace("@STATE@", str(self.state)))
        self._write_stub("cosign", COSIGN_STUB)
        (self.work / DOC_AMD64).write_bytes(FRESH_AMD64)
        (self.work / DOC_ARM64).write_bytes(FRESH_ARM64)

    def _write_stub(self, name: str, body: str) -> None:
        stub = self.bin / name
        stub.write_text(body)
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    def attach(self, name: str, data: bytes) -> None:
        """Publish an asset: store its bytes in remote/ and list it."""
        (self.remote / name).write_bytes(data)
        with self.assets.open("a") as fh:
            fh.write(name + "\n")

    def remote_names(self) -> set[str]:
        return {p.name for p in self.remote.iterdir()}

    def asset_names(self) -> list[str]:
        return self.assets.read_text().splitlines()

    def run(self, *files: str) -> subprocess.CompletedProcess:
        return self.run_args(
            RELEASE_TAG, TAG_IDENTITY, RUN_IDENTITY, str(self.dest), *files
        )

    def run_args(self, *args: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}")
        return subprocess.run(  # noqa: S603
            [BASH, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            env=env,
            cwd=self.work,
        )


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_unattached_document_is_signed_and_uploaded(harness):
    r = harness.run(DOC_AMD64)
    assert r.returncode == 0
    assert f"published freshly signed {DOC_AMD64} and {BUNDLE_AMD64}" in r.stdout
    assert (harness.remote / DOC_AMD64).read_bytes() == FRESH_AMD64
    assert (harness.remote / BUNDLE_AMD64).read_bytes() == bundle_bytes(
        FRESH_AMD64, "run"
    )
    assert DOC_AMD64 in harness.asset_names()
    assert BUNDLE_AMD64 in harness.asset_names()
    assert (harness.dest / DOC_AMD64).read_bytes() == FRESH_AMD64
    assert (harness.dest / BUNDLE_AMD64).read_bytes() == bundle_bytes(
        FRESH_AMD64, "run"
    )
    assert f"working set {DOC_AMD64} verifies" in r.stdout


def test_valid_attached_pair_is_kept_and_not_replaced(harness):
    harness.attach(DOC_AMD64, REMOTE_AMD64)
    harness.attach(BUNDLE_AMD64, bundle_bytes(REMOTE_AMD64, "tag"))
    r = harness.run(DOC_AMD64)
    assert r.returncode == 0
    assert "keeping the published copy" in r.stdout
    # The published bytes win over the fresh local ones.
    assert (harness.dest / DOC_AMD64).read_bytes() == REMOTE_AMD64
    # Nothing was uploaded: the remote copy is byte-identical to the seed.
    assert (harness.remote / DOC_AMD64).read_bytes() == REMOTE_AMD64
    assert (harness.remote / BUNDLE_AMD64).read_bytes() == bundle_bytes(
        REMOTE_AMD64, "tag"
    )
    assert f"working set {DOC_AMD64} verifies" in r.stdout


def test_attached_document_without_bundle_is_replaced(harness):
    harness.attach(DOC_AMD64, REMOTE_AMD64)
    r = harness.run(DOC_AMD64)
    assert r.returncode == 0
    assert f"published freshly signed {DOC_AMD64} and {BUNDLE_AMD64}" in r.stdout
    # The stale remote document was clobbered with the fresh bytes.
    assert (harness.remote / DOC_AMD64).read_bytes() == FRESH_AMD64
    assert (harness.remote / BUNDLE_AMD64).read_bytes() == bundle_bytes(
        FRESH_AMD64, "run"
    )
    assert BUNDLE_AMD64 in harness.asset_names()


def test_attached_bundle_without_document_is_replaced(harness):
    harness.attach(BUNDLE_AMD64, bundle_bytes(REMOTE_AMD64, "tag"))
    r = harness.run(DOC_AMD64)
    assert r.returncode == 0
    assert f"published freshly signed {DOC_AMD64} and {BUNDLE_AMD64}" in r.stdout
    assert (harness.remote / DOC_AMD64).read_bytes() == FRESH_AMD64
    # The orphaned bundle was clobbered with one matching the fresh document.
    assert (harness.remote / BUNDLE_AMD64).read_bytes() == bundle_bytes(
        FRESH_AMD64, "run"
    )
    assert DOC_AMD64 in harness.asset_names()


def test_attached_pair_that_does_not_verify_fails_without_uploading(harness):
    harness.attach(DOC_AMD64, REMOTE_AMD64)
    tampered = bundle_bytes(b"different published bytes", "tag")
    harness.attach(BUNDLE_AMD64, tampered)
    assets_before = harness.asset_names()
    r = harness.run(DOC_AMD64)
    assert r.returncode == 1
    assert "cannot be trusted" in r.stderr
    # Nothing was uploaded or re-signed: remote state is untouched.
    assert (harness.remote / DOC_AMD64).read_bytes() == REMOTE_AMD64
    assert (harness.remote / BUNDLE_AMD64).read_bytes() == tampered
    assert harness.asset_names() == assets_before
    assert harness.remote_names() == {DOC_AMD64, BUNDLE_AMD64}


def test_attached_pair_signed_under_run_identity_is_kept(harness):
    harness.attach(DOC_AMD64, REMOTE_AMD64)
    harness.attach(BUNDLE_AMD64, bundle_bytes(REMOTE_AMD64, "run"))
    r = harness.run(DOC_AMD64)
    assert r.returncode == 0
    assert "keeping the published copy" in r.stdout
    assert (harness.dest / DOC_AMD64).read_bytes() == REMOTE_AMD64
    assert (harness.remote / DOC_AMD64).read_bytes() == REMOTE_AMD64


def test_missing_fresh_document_fails(harness):
    (harness.work / DOC_AMD64).unlink()
    r = harness.run(DOC_AMD64)
    assert r.returncode == 1
    assert f"{DOC_AMD64} does not exist" in r.stderr


def test_too_few_arguments_is_a_usage_error(harness):
    r = harness.run_args(RELEASE_TAG, TAG_IDENTITY, RUN_IDENTITY, str(harness.dest))
    assert r.returncode == 2
    assert "usage:" in r.stderr


def test_mixed_kept_and_replaced_documents(harness):
    harness.attach(DOC_AMD64, REMOTE_AMD64)
    harness.attach(BUNDLE_AMD64, bundle_bytes(REMOTE_AMD64, "tag"))
    r = harness.run(DOC_AMD64, DOC_ARM64)
    assert r.returncode == 0
    assert f"{DOC_AMD64} is attached and verifies" in r.stdout
    assert f"published freshly signed {DOC_ARM64} and {BUNDLE_ARM64}" in r.stdout
    # amd64 keeps the published bytes; arm64 is freshly signed and uploaded.
    assert (harness.dest / DOC_AMD64).read_bytes() == REMOTE_AMD64
    assert (harness.dest / DOC_ARM64).read_bytes() == FRESH_ARM64
    assert (harness.remote / DOC_AMD64).read_bytes() == REMOTE_AMD64
    assert (harness.remote / DOC_ARM64).read_bytes() == FRESH_ARM64
    assert (harness.remote / BUNDLE_ARM64).read_bytes() == bundle_bytes(
        FRESH_ARM64, "run"
    )
    assert {p.name for p in harness.dest.iterdir()} == {
        DOC_AMD64,
        BUNDLE_AMD64,
        DOC_ARM64,
        BUNDLE_ARM64,
    }
    assert f"working set {DOC_AMD64} verifies" in r.stdout
    assert f"working set {DOC_ARM64} verifies" in r.stdout
