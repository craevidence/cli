"""Fixture tests for scripts/registry-crane.sh.

Each test runs the real script with a stubbed `crane` on PATH so the registry
behaviour (digest success, raw manifest success, definitive absence, auth and
transport failures, a bare 404, malformed output, and transient recovery) is
exercised deterministically without a network. The stub keys off `$1` being
`digest` or `manifest`, which is how the script invokes crane.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "registry-crane.sh"
BASH = shutil.which("bash") or "/usr/bin/bash"

VALID_DIGEST = "sha256:" + "e0" * 32

MANIFEST_UNKNOWN = (
    "Error: GET https://ghcr.io/v2/owner/name/manifests/1.0.0: "
    "MANIFEST_UNKNOWN: manifest unknown"
)
HEAD_404 = (
    "Error: HEAD https://ghcr.io/v2/owner/name/manifests/1.0.0: "
    "unexpected status code 404 Not Found"
)


def _write_stub(directory: Path, body: str) -> None:
    stub = directory / "crane"
    stub.write_text("#!/usr/bin/env bash\n" + body)
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run(tmp_path, stub_body, args, attempts="2"):
    _write_stub(tmp_path, stub_body)
    env = dict(
        os.environ,
        PATH=f"{tmp_path}:{os.environ['PATH']}",
        REGISTRY_CRANE_ATTEMPTS=attempts,
    )
    return subprocess.run(  # noqa: S603
        [BASH, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
    )


def test_digest_success_prints_found(tmp_path):
    body = f'printf "{VALID_DIGEST}\\n"; exit 0\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/owner/name:1.0.0"])
    assert r.returncode == 0
    assert r.stdout.strip() == f"FOUND {VALID_DIGEST}"


def test_raw_success_streams_manifest(tmp_path):
    # Only respond to manifest mode; a digest call would be a contract error.
    body = (
        'if [ "$1" = "manifest" ]; then printf "{\\"schemaVersion\\":2}"; exit 0; fi\n'
        'echo "unexpected mode $1" >&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["raw", "ghcr.io/owner/name:1.0.0"])
    assert r.returncode == 0
    assert '"schemaVersion":2' in r.stdout


def test_terminal_manifest_unknown_returns_notfound(tmp_path):
    body = f'echo "{MANIFEST_UNKNOWN}" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/owner/name:1.0.0"])
    assert r.returncode == 0
    assert r.stdout.strip() == "NOTFOUND"


@pytest.mark.parametrize(
    ("first", "last", "expected_code", "expect_notfound"),
    [
        # HEAD 404 preliminary line, then the terminal MANIFEST_UNKNOWN: the
        # last line authorizes NOTFOUND, proving the tail -n1 anchoring reads it.
        (HEAD_404, MANIFEST_UNKNOWN, 0, True),
        # MANIFEST_UNKNOWN first, a different error last: the terminal line is
        # NOT an absence, so it must fail closed and never print NOTFOUND.
        (
            MANIFEST_UNKNOWN,
            "Error: GET https://ghcr.io/v2/owner/name/manifests/1.0.0: something else",
            1,
            False,
        ),
    ],
)
def test_only_last_stderr_line_decides_absence(
    tmp_path, first, last, expected_code, expect_notfound
):
    body = f'printf "{first}\\n{last}\\n" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/owner/name:1.0.0"])
    assert r.returncode == expected_code
    assert ("NOTFOUND" in r.stdout) is expect_notfound


@pytest.mark.parametrize(
    "err",
    [
        "Error: GET https://ghcr.io/v2/owner/name/manifests/1.0.0: DENIED: denied",
        "Error: GET https://index.docker.io/v2/craevidence/cli/manifests/1.0.0: "
        "UNAUTHORIZED: authentication required",
        "Error: GET https://quay.io/v2/craevidence/cli/manifests/1.0.0: "
        "NAME_UNKNOWN: repository not found",
        "Error: GET https://ghcr.io/v2/owner/name/manifests/1.0.0: "
        "unexpected status code 404 Not Found",
        "dial tcp: lookup ghcr.io on 1.1.1.1:53: no such host",
        "Error: fetching token: 401 Unauthorized",
    ],
)
def test_non_absence_terminal_errors_fail_closed(tmp_path, err):
    # Every terminal error that is not the structured MANIFEST_UNKNOWN line must
    # retry then exit fatal, never authorize a NOTFOUND.
    body = f'echo "{err}" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/owner/name:1.0.0"])
    assert r.returncode == 1
    assert "NOTFOUND" not in r.stdout


def test_manifest_unknown_for_a_different_ref_is_not_absence(tmp_path):
    # A structured MANIFEST_UNKNOWN naming a different repository/reference than
    # the one requested must never authorize NOTFOUND for the requested ref.
    body = (
        'echo "Error: GET https://ghcr.io/v2/other/repo/manifests/9.9.9: '
        'MANIFEST_UNKNOWN: manifest unknown" >&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["digest", "ghcr.io/owner/name:1.0.0"])
    assert r.returncode == 1
    assert "NOTFOUND" not in r.stdout


def test_absence_binds_to_a_digest_reference(tmp_path):
    # For an @digest ref the manifest reference in the error URL is the digest.
    digest = "sha256:" + "ab" * 32
    digest_ref = f"ghcr.io/owner/name@{digest}"
    body = (
        f'echo "Error: GET https://ghcr.io/v2/owner/name/manifests/{digest}: '
        'MANIFEST_UNKNOWN: manifest unknown" >&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["raw", digest_ref])
    assert r.returncode == 4


def test_absence_rejects_a_different_digest(tmp_path):
    # A MANIFEST_UNKNOWN for a different digest than requested must fail closed.
    requested = "sha256:" + "ab" * 32
    other = "sha256:" + "cd" * 32
    body = (
        f'echo "Error: GET https://ghcr.io/v2/owner/name/manifests/{other}: '
        'MANIFEST_UNKNOWN: manifest unknown" >&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["raw", f"ghcr.io/owner/name@{requested}"])
    assert r.returncode == 1


def test_manifest_unknown_for_a_different_host_is_not_absence(tmp_path):
    # A MANIFEST_UNKNOWN naming a different registry than requested (same repo
    # path) must fail closed, so a Quay error cannot satisfy a GHCR request.
    body = (
        'echo "Error: GET https://quay.io/v2/owner/name/manifests/1.0.0: '
        'MANIFEST_UNKNOWN: manifest unknown" >&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["digest", "ghcr.io/owner/name:1.0.0"])
    assert r.returncode == 1
    assert "NOTFOUND" not in r.stdout


def test_requested_path_only_in_diagnostic_message_is_not_absence(tmp_path):
    # The failed URL names a different manifest; the requested path appears only
    # in the diagnostic text after MANIFEST_UNKNOWN. This must fail closed.
    body = (
        'echo "Error: GET https://ghcr.io/v2/other/repo/manifests/9.9.9: '
        'MANIFEST_UNKNOWN: requested /v2/owner/name/manifests/1.0.0: unavailable" '
        '>&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["digest", "ghcr.io/owner/name:1.0.0"])
    assert r.returncode == 1
    assert "NOTFOUND" not in r.stdout


def test_hostless_dockerhub_short_name_absence(tmp_path):
    # The production Docker Hub value is the short name craevidence/cli (no
    # host). crane resolves it under index.docker.io, so a missing tag must
    # still classify as NOTFOUND, not fail closed.
    body = (
        'echo "Error: GET https://index.docker.io/v2/craevidence/cli/manifests/1.0.0: '
        'MANIFEST_UNKNOWN: manifest unknown" >&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["digest", "craevidence/cli:1.0.0"])
    assert r.returncode == 0
    assert r.stdout.strip() == "NOTFOUND"


def test_untagged_ref_resolves_as_latest(tmp_path):
    # An untagged reference means the latest tag, so a missing latest manifest
    # must classify as NOTFOUND for the untagged request.
    body = (
        'echo "Error: GET https://index.docker.io/v2/craevidence/cli/manifests/latest: '
        'MANIFEST_UNKNOWN: manifest unknown" >&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["digest", "craevidence/cli"])
    assert r.returncode == 0
    assert r.stdout.strip() == "NOTFOUND"


@pytest.mark.parametrize("ref", ["alpine:1.0.0", "docker.io/alpine:1.0.0"])
def test_single_component_dockerhub_ref_uses_library_namespace(tmp_path, ref):
    # A single-component Docker Hub repository lives in the implicit library/
    # namespace, so the error URL names library/<repo> and a missing tag must
    # classify as NOTFOUND.
    body = (
        'echo "Error: GET https://index.docker.io/v2/library/alpine/manifests/1.0.0: '
        'MANIFEST_UNKNOWN: manifest unknown; unknown tag=1.0.0" >&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["digest", ref])
    assert r.returncode == 0
    assert r.stdout.strip() == "NOTFOUND"


def test_read_timeout_fails_closed(tmp_path):
    # A crane read exceeding REGISTRY_CRANE_TIMEOUT is killed before it can print
    # its digest, so it must fail closed. Without the timeout the stub would
    # sleep then print a valid digest and the result would be FOUND, so this
    # proves the timeout is enforced.
    _write_stub(tmp_path, f'sleep 3; printf "{VALID_DIGEST}\\n"; exit 0\n')
    env = dict(
        os.environ,
        PATH=f"{tmp_path}:{os.environ['PATH']}",
        REGISTRY_CRANE_ATTEMPTS="1",
        REGISTRY_CRANE_TIMEOUT="1",
    )
    r = subprocess.run(  # noqa: S603
        [BASH, str(SCRIPT), "digest", "ghcr.io/owner/name:1.0.0"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 1
    assert "FOUND" not in r.stdout
    assert "NOTFOUND" not in r.stdout


def test_malformed_digest_is_not_accepted(tmp_path):
    body = 'printf "not-a-sha\\n"; exit 0\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/owner/name:1.0.0"], attempts="2")
    # Resolved but no valid digest: retried then fatal, never a bogus FOUND.
    assert r.returncode == 1
    assert "FOUND" not in r.stdout


def test_transient_then_success_recovers(tmp_path):
    marker = tmp_path / "attempts"
    body = (
        f'n=$(cat "{marker}" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "{marker}"\n'
        f'if [ "$n" -ge 2 ]; then printf "{VALID_DIGEST}\\n"; exit 0; '
        f'else echo "dial tcp: lookup ghcr.io on 1.1.1.1:53: no such host" >&2; exit 1; fi\n'
    )
    r = _run(tmp_path, body, ["digest", "ghcr.io/owner/name:1.0.0"], attempts="3")
    assert r.returncode == 0
    assert r.stdout.strip() == f"FOUND {VALID_DIGEST}"


def test_raw_absence_exits_4(tmp_path):
    body = (
        'if [ "$1" = "manifest" ]; then '
        f'echo "{MANIFEST_UNKNOWN}" >&2; exit 1; fi\n'
        'echo "unexpected mode $1" >&2; exit 1\n'
    )
    r = _run(tmp_path, body, ["raw", "ghcr.io/owner/name:1.0.0"])
    assert r.returncode == 4


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "1.5", " "])
def test_invalid_attempts_rejected(tmp_path, bad):
    _write_stub(tmp_path, "exit 0\n")
    env = dict(
        os.environ,
        PATH=f"{tmp_path}:{os.environ['PATH']}",
        REGISTRY_CRANE_ATTEMPTS=bad,
    )
    r = subprocess.run(  # noqa: S603
        [BASH, str(SCRIPT), "digest", "ghcr.io/owner/name:1.0.0"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 2


@pytest.mark.parametrize("args", [[], ["digest"], ["bogus", "ref"], ["digest", "a", "b"]])
def test_usage_errors(tmp_path, args):
    r = _run(tmp_path, "exit 0\n", args)
    assert r.returncode == 2
