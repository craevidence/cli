"""Tests for CRA Evidence engine identity verification."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from cra_evidence_cli import engine


def _completed(payload: object, returncode: int = 0):
    return SimpleNamespace(
        returncode=returncode,
        stdout=json.dumps(payload),
        stderr="",
    )


# A deliberately synthetic identity. It must never be a real published
# revision: craevidence-v0.116.1-p1 identifies the engine already in production,
# which has no `sbom` command and MUST be rejected, and predicting a future
# revision here would put an unreleased identity in the repository.
SYNTHETIC_ENGINE_VERSION = "craevidence-vX.Y.Z-test"

# The engine identity shipped in craevidence/cli:4.1.0. Its command list has no
# `sbom`, so it must be rejected as a product engine even though it is stamped.
PUBLISHED_ENGINE_WITHOUT_SBOM = "craevidence-v0.116.1-p1"


@pytest.fixture(autouse=True)
def _clear_engine_override(monkeypatch):
    monkeypatch.delenv("CRA_EVIDENCE_ENGINE", raising=False)


def _supported_engine_run(*args, **kwargs):
    command = args[0]
    if command[1:] == ["version", "--output", "json"]:
        return _completed(
            {
                "application": "grype",
                "version": SYNTHETIC_ENGINE_VERSION,
                "syftVersion": "v1.50.0",
            }
        )
    if command[1:] == ["sbom", "--help"]:
        return SimpleNamespace(
            returncode=0,
            stdout="Usage:\n  grype sbom SOURCE [flags]\n\nFlags:\n  --offline\n",
            stderr="",
        )
    message = f"unexpected command: {command}"
    raise AssertionError(message)


def test_inspect_engine_accepts_stamped_fork(monkeypatch):
    monkeypatch.delenv("CRA_EVIDENCE_ENGINE", raising=False)
    monkeypatch.setattr(engine.shutil, "which", lambda _: "/opt/bin/grype")
    monkeypatch.setattr(
        engine.subprocess,
        "run",
        _supported_engine_run,
    )

    inspection = engine.inspect_engine()

    assert inspection.reason == ""
    assert inspection.identity is not None
    assert inspection.identity.path == "/opt/bin/grype"
    assert inspection.identity.version == SYNTHETIC_ENGINE_VERSION
    assert inspection.identity.syft_version == "1.50.0"


def test_environment_override_precedes_bundled_engine_and_path(monkeypatch):
    commands = []

    def recorded_run(*args, **kwargs):
        commands.append(args[0])
        return _supported_engine_run(*args, **kwargs)

    monkeypatch.setenv("CRA_EVIDENCE_ENGINE", "/custom/grype")
    monkeypatch.setattr(engine, "_bundled_engine_path", lambda: None)
    monkeypatch.setattr(
        engine.shutil,
        "which",
        lambda _: (_ for _ in ()).throw(AssertionError("PATH must not be read")),
    )
    monkeypatch.setattr(engine.subprocess, "run", recorded_run)

    inspection = engine.inspect_engine()

    assert inspection.identity is not None
    assert inspection.identity.path == "/custom/grype"
    assert all(command[0] == "/custom/grype" for command in commands)


def test_non_executable_bundled_engine_is_rejected(monkeypatch, tmp_path):
    bundled = tmp_path / "grype"
    bundled.write_bytes(b"synthetic test executable")
    bundled.chmod(0o644)
    monkeypatch.delenv("CRA_EVIDENCE_ENGINE", raising=False)
    monkeypatch.setattr(engine, "_bundled_engine_path", lambda: bundled)
    monkeypatch.setattr(
        engine.shutil,
        "which",
        lambda _: (_ for _ in ()).throw(AssertionError("PATH must not be read")),
    )
    inspection = engine.inspect_engine()

    assert inspection.identity is None
    assert inspection.reason == "the bundled engine is not executable"


def test_inspect_engine_rejects_stock_grype(monkeypatch):
    monkeypatch.setattr(engine.shutil, "which", lambda _: "/usr/bin/grype")
    monkeypatch.setattr(
        engine.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {
                "application": "grype",
                "version": "0.116.1",
                "syftVersion": "v1.50.0",
            }
        ),
    )

    inspection = engine.inspect_engine()

    assert inspection.identity is None
    assert inspection.reason == "stock or unstamped Grype is not a supported engine"


def test_inspect_engine_rejects_missing_embedded_syft_version(monkeypatch):
    monkeypatch.setattr(engine.shutil, "which", lambda _: "/opt/bin/grype")
    monkeypatch.setattr(
        engine.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {"application": "grype", "version": "craevidence-v0.116.1-p1"}
        ),
    )

    inspection = engine.inspect_engine()

    assert inspection.identity is None
    assert inspection.reason == "the embedded Syft version is missing or invalid"


def test_inspect_engine_rejects_non_json_identity(monkeypatch):
    monkeypatch.setattr(engine.shutil, "which", lambda _: "/opt/bin/grype")
    monkeypatch.setattr(
        engine.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="Version: craevidence-v0.116.1-p1",
            stderr="",
        ),
    )

    inspection = engine.inspect_engine()

    assert inspection.identity is None
    assert inspection.reason == "engine identity output is not valid JSON"


def test_inspect_engine_rejects_old_fork_without_sbom_command(monkeypatch):
    monkeypatch.setattr(engine.shutil, "which", lambda _: "/opt/bin/grype")

    def old_fork_run(*args, **kwargs):
        command = args[0]
        if command[1:] == ["version", "--output", "json"]:
            return _completed(
                {
                    "application": "grype",
                    "version": PUBLISHED_ENGINE_WITHOUT_SBOM,
                    "syftVersion": "v1.50.0",
                }
            )
        return SimpleNamespace(
            returncode=0,
            stdout="Usage:\n  grype [IMAGE] [flags]\n",
            stderr="",
        )

    monkeypatch.setattr(engine.subprocess, "run", old_fork_run)

    inspection = engine.inspect_engine()

    assert inspection.identity is None
    assert inspection.reason == (
        "the installed CRA Evidence engine does not support the required "
        "SBOM generation options"
    )


def test_inspect_engine_rejects_sbom_command_without_offline(monkeypatch):
    monkeypatch.setattr(engine.shutil, "which", lambda _: "/opt/bin/grype")

    def no_offline_run(*args, **kwargs):
        command = args[0]
        if command[1:] == ["version", "--output", "json"]:
            return _completed(
                {
                    "application": "grype",
                    "version": SYNTHETIC_ENGINE_VERSION,
                    "syftVersion": "v1.50.0",
                }
            )
        return SimpleNamespace(
            returncode=0,
            stdout="Usage:\n  grype sbom SOURCE [flags]\n",
            stderr="",
        )

    monkeypatch.setattr(engine.subprocess, "run", no_offline_run)

    inspection = engine.inspect_engine()

    assert inspection.identity is None
    assert inspection.reason == (
        "the installed CRA Evidence engine does not support the required "
        "SBOM generation options"
    )
