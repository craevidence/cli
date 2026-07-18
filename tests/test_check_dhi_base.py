"""Tests for scripts/check-dhi-base.sh zero-pin handling.

The script is exercised with a stubbed `docker` on PATH so the zero-pin
classification is deterministic without a registry. A Dockerfile with no
pinned dhi.io digest must fail strict mode (the publishing contract) and pass
lenient mode (the contributor path).
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "check-dhi-base.sh"
BASH = shutil.which("bash") or "/usr/bin/bash"


def _run(tmp_path: Path, args: list[str]) -> subprocess.CompletedProcess:
    stub = tmp_path / "docker"
    stub.write_text("#!/usr/bin/env bash\nexit 0\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    env = dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}")
    return subprocess.run(  # noqa: S603
        [BASH, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
    )


def test_strict_fails_on_zero_pinned_digests(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.14\n")
    r = _run(tmp_path, ["--strict", str(dockerfile)])
    assert r.returncode == 6
    assert "strict mode requires the hardened base" in r.stderr


def test_lenient_passes_on_zero_pinned_digests(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.14\n")
    r = _run(tmp_path, [str(dockerfile)])
    assert r.returncode == 0
    assert "no pinned dhi.io digests" in r.stdout


def test_missing_dockerfile_is_a_usage_error(tmp_path):
    r = _run(tmp_path, ["--strict", str(tmp_path / "absent")])
    assert r.returncode == 2
