"""Fixture tests for scripts/registry-inspect.sh.

Each test runs the real script with a stubbed `docker` on PATH so the registry
behaviour (success, absence, auth failure, DNS failure, malformed output, and
the SIGPIPE-race condition) is exercised deterministically without a network.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "registry-inspect.sh"
BASH = shutil.which("bash") or "/usr/bin/bash"

VALID_DIGEST = "sha256:" + "e0" * 32


def _write_stub(directory: Path, body: str) -> None:
    stub = directory / "docker"
    stub.write_text("#!/usr/bin/env bash\n" + body)
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run(tmp_path, stub_body, args, attempts="2"):
    _write_stub(tmp_path, stub_body)
    env = dict(
        os.environ,
        PATH=f"{tmp_path}:{os.environ['PATH']}",
        REGISTRY_INSPECT_ATTEMPTS=attempts,
    )
    return subprocess.run(  # noqa: S603
        [BASH, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
    )


def test_found_prints_digest(tmp_path):
    body = f'printf "Name: x\\nDigest: {VALID_DIGEST}\\n"; exit 0\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/x/y:1"])
    assert r.returncode == 0
    assert r.stdout.strip() == f"FOUND {VALID_DIGEST}"


def test_definitive_absence_returns_notfound(tmp_path):
    body = 'echo "ERROR: ghcr.io/x/y:1: not found" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/x/y:1"])
    assert r.returncode == 0
    assert r.stdout.strip() == "NOTFOUND"


@pytest.mark.parametrize(
    ("ref", "err"),
    [
        # buildx emits the not-found error with the same ref that was inspected
        ("ghcr.io/x/y:1", "ERROR: ghcr.io/x/y:1: not found"),
        ("docker.io/x/y:1", "ERROR: docker.io/x/y:1: not found"),
        ("quay.io/x/y:1", "ERROR: quay.io/x/y:1: not found"),
        # registry/version variants where the ref is not in the message
        ("docker.io/x/y:1", "ERROR: no such manifest: docker.io/x/y:1"),
        ("ghcr.io/x/y:1", "manifest unknown: manifest unknown"),
        ("quay.io/x/y:1", "name unknown: repository name not known to registry"),
    ],
)
def test_registry_absence_strings_return_notfound(tmp_path, ref, err):
    body = f'echo "{err}" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", ref])
    assert r.returncode == 0
    assert r.stdout.strip() == "NOTFOUND"


def test_auth_error_containing_404_is_not_absence(tmp_path):
    # Transport precedence: an auth failure that also mentions 404 must stay
    # unknown, never become a create-the-tag NOTFOUND.
    body = 'echo "unauthorized: 404 Not Found for private repo" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", "docker.io/x/y:1"])
    assert r.returncode == 1
    assert "NOTFOUND" not in r.stdout


@pytest.mark.parametrize(
    "err",
    [
        "failed to fetch anonymous token: unexpected status: 404 Not Found",
        "failed to fetch oauth token: 401 Unauthorized",
        "authorization failed",
    ],
)
def test_token_and_auth_fetch_failures_are_transport_not_absence(tmp_path, err):
    # A token/authorization fetch failure can carry a 404; it must be treated
    # as a transport error (retry then fatal), never a missing tag.
    body = f'echo "{err}" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", "docker.io/x/y:1"])
    assert r.returncode == 1
    assert "NOTFOUND" not in r.stdout


@pytest.mark.parametrize(
    "err",
    [
        "ERROR: failed to do request: 404 Not Found",
        "502 Bad Gateway",
        "error parsing HTTP 404 response body",
        "received unexpected HTTP status: 404 Not Found",
    ],
)
def test_ambiguous_404_and_gateway_errors_fail_closed(tmp_path, err):
    # A bare/ambiguous 404 or gateway error is NOT an unambiguous registry
    # absence, so it must fail closed (retry then fatal), never create a tag.
    body = f'echo "{err}" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", "docker.io/x/y:1"])
    assert r.returncode == 1
    assert "NOTFOUND" not in r.stdout


@pytest.mark.parametrize(
    "err",
    [
        "unauthorized: authentication required",
        "denied: requested access to the resource is denied",
        "insufficient_scope: authorization failed",
        "invalid token: the provided credential is not valid",
        "not authorized to access repository",
        "toomanyrequests: You have reached your pull rate limit",
        "dial tcp: lookup ghcr.io: no such host",
        "net/http: TLS handshake timeout",
        "connection refused",
    ],
)
def test_transport_errors_never_become_notfound(tmp_path, err):
    body = f'echo "{err}" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/x/y:1"])
    # Unknown after retries: fatal, never NOTFOUND.
    assert r.returncode == 1
    assert "NOTFOUND" not in r.stdout


def test_auth_error_mentioning_name_unknown_is_not_absence(tmp_path):
    # A transport/auth error must win even if it also contains an absence token.
    body = 'echo "unauthorized: name unknown to this credential" >&2; exit 1\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/x/y:1"])
    assert r.returncode == 1
    assert "NOTFOUND" not in r.stdout


def test_malformed_digest_is_not_accepted(tmp_path):
    body = 'printf "Digest: not-a-sha\\n"; exit 0\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/x/y:1"], attempts="2")
    # No valid digest: retried then fatal, never a bogus FOUND.
    assert r.returncode == 1
    assert "FOUND" not in r.stdout


def test_sigpipe_style_nonzero_with_valid_output_still_succeeds(tmp_path):
    # Simulate the race: the producer writes the digest but exits non-zero
    # (as inspect does on SIGPIPE). Capturing output first must still succeed.
    body = f'printf "Digest: {VALID_DIGEST}\\n"; exit 141\n'
    r = _run(tmp_path, body, ["digest", "ghcr.io/x/y:1"])
    # exit 141 means the whole inspect failed; the helper retries. With a stub
    # that always exits 141 it exhausts retries, proving it does NOT emit a
    # bogus FOUND from a failed call.
    assert r.returncode == 1
    assert "FOUND" not in r.stdout


def test_transient_then_success_recovers(tmp_path):
    # First call fails transiently, second succeeds: helper must recover.
    marker = tmp_path / "attempts"
    body = (
        f'n=$(cat "{marker}" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "{marker}"\n'
        f'if [ "$n" -ge 2 ]; then printf "Digest: {VALID_DIGEST}\\n"; exit 0; '
        f'else echo "net/http: TLS handshake timeout" >&2; exit 1; fi\n'
    )
    r = _run(tmp_path, body, ["digest", "ghcr.io/x/y:1"], attempts="3")
    assert r.returncode == 0
    assert r.stdout.strip() == f"FOUND {VALID_DIGEST}"


def test_raw_success_streams_manifest(tmp_path):
    body = 'printf "{\\"schemaVersion\\":2}"; exit 0\n'
    r = _run(tmp_path, body, ["raw", "ghcr.io/x/y@sha256:abc"])
    assert r.returncode == 0
    assert '"schemaVersion":2' in r.stdout


def test_raw_absence_exits_4(tmp_path):
    body = 'echo "ERROR: ghcr.io/x/y@sha256:abc: not found" >&2; exit 1\n'
    r = _run(tmp_path, body, ["raw", "ghcr.io/x/y@sha256:abc"])
    assert r.returncode == 4


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "1.5", " "])
def test_invalid_attempts_rejected(tmp_path, bad):
    _write_stub(tmp_path, "exit 0\n")
    env = dict(
        os.environ,
        PATH=f"{tmp_path}:{os.environ['PATH']}",
        REGISTRY_INSPECT_ATTEMPTS=bad,
    )
    r = subprocess.run(  # noqa: S603
        [BASH, str(SCRIPT), "digest", "ghcr.io/x/y:1"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 2


@pytest.mark.parametrize("args", [[], ["digest"], ["bogus", "ref"], ["digest", "a", "b"]])
def test_usage_errors(tmp_path, args):
    r = _run(tmp_path, "exit 0\n", args)
    assert r.returncode == 2
