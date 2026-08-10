"""Tests for pinned official Opengrep payload acquisition."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from cra_evidence_cli.local.rules_pack import TESTED_OPENGREP_VERSION
from scripts import fetch_opengrep_release as fetch


def test_release_pin_matches_rulepack_engine_version():
    assert fetch.VERSION == TESTED_OPENGREP_VERSION


def test_fetch_release_verifies_and_records_every_asset(tmp_path, monkeypatch):
    binary = b"verified opengrep bytes"
    asset = fetch.ReleaseAsset("opengrep_test", hashlib.sha256(binary).hexdigest())
    verified: list[str] = []

    def fake_download(url: str, destination: Path) -> None:
        if destination.name == asset.name:
            destination.write_bytes(binary)
        elif destination.name == "LICENSE":
            destination.write_text("GNU LESSER GENERAL PUBLIC LICENSE", encoding="utf-8")
        elif destination.name == "COPYRIGHT":
            destination.write_text("Copyright holders\n", encoding="utf-8")
        else:
            destination.write_bytes(b"signature material")

    def fake_verify(cosign, executable, certificate, signature):
        assert cosign == "/usr/bin/cosign"
        assert certificate.is_file()
        assert signature.is_file()
        verified.append(executable.name)

    def fake_source(destination: Path, git: str) -> dict:
        assert git == "/usr/bin/git"
        destination.write_bytes(b"deterministic source with submodules")
        return {
            "submodule_count": 40,
            "tracked_file_count": 15000,
            "excluded_paths": [
                {
                    "path": "tests/semgrep-rules",
                    "reason": "non-build rule test corpus excluded from redistribution",
                }
            ],
        }

    monkeypatch.setattr(fetch, "ASSETS", (asset,))
    monkeypatch.setattr(fetch, "_download", fake_download)
    monkeypatch.setattr(fetch, "_verify_signature", fake_verify)
    monkeypatch.setattr(fetch, "_build_source_archive", fake_source)

    fetch.fetch_release(tmp_path / "payload", "/usr/bin/cosign", "/usr/bin/git")

    payload = tmp_path / "payload"
    manifest = json.loads((payload / "MANIFEST.json").read_text(encoding="utf-8"))
    assert verified == [asset.name]
    assert manifest["commit"] == fetch.COMMIT
    assert manifest["assets"] == [
        {
            "name": asset.name,
            "sha256": asset.sha256,
            "signature_verified": True,
            "native_dependencies": [],
        }
    ]
    assert manifest["source_archive"]["signature_verified"] is False
    assert manifest["source_archive"]["commit"] == fetch.COMMIT
    assert manifest["source_archive"]["submodule_count"] == 40
    assert manifest["source_archive"]["tracked_file_count"] == 15000
    assert (payload / "COPYRIGHT").read_text(encoding="utf-8") == (
        "Copyright holders\n"
    )
    assert json.loads(
        (payload / "NATIVE-DEPENDENCIES.json").read_text(encoding="utf-8")
    ) == {asset.name: []}
    assert (payload / "SHA256SUMS").read_text(encoding="utf-8") == (
        f"{asset.sha256}  {asset.name}\n"
    )
    notice = (payload / "NOTICE").read_text(encoding="utf-8")
    assert "https://github.com/opengrep/opengrep" in notice
    assert f"opengrep-{fetch.VERSION}-source.tar.gz" in notice


def test_fetch_release_rejects_hash_mismatch_before_signature(tmp_path, monkeypatch):
    asset = fetch.ReleaseAsset("opengrep_test", "0" * 64)

    def fake_download(url: str, destination: Path) -> None:
        destination.write_bytes(b"unexpected bytes")

    monkeypatch.setattr(fetch, "ASSETS", (asset,))
    monkeypatch.setattr(fetch, "_download", fake_download)
    monkeypatch.setattr(
        fetch,
        "_verify_signature",
        lambda *args: pytest.fail("signature verification must follow hash validation"),
    )

    with pytest.raises(fetch.FetchError, match="SHA-256 mismatch"):
        fetch.fetch_release(tmp_path / "payload", "/usr/bin/cosign")


def test_source_paths_exclude_rule_test_submodule(monkeypatch, tmp_path):
    paths = b"src/main.ml\x00tests/semgrep-rules/python/example.yaml\x00"

    def fake_git(*args, **kwargs):
        return subprocess.CompletedProcess([], 0, stdout=paths, stderr=b"")

    monkeypatch.setattr(fetch, "_run_git", fake_git)

    assert fetch._source_paths("git", tmp_path) == [Path("src/main.ml")]


def test_source_submodules_reject_uninitialized_checkout(monkeypatch, tmp_path):
    def fake_git(*args, **kwargs):
        return subprocess.CompletedProcess(
            [],
            0,
            stdout="-977c2a9b30e472c303930104414184c76bbadda8 interfaces\n",
            stderr="",
        )

    monkeypatch.setattr(fetch, "_run_git", fake_git)

    with pytest.raises(fetch.FetchError, match="not at its pinned commit"):
        fetch._source_submodules("git", tmp_path)


def test_native_dependency_inventory_reads_linked_library_names(tmp_path):
    binary = tmp_path / "opengrep"
    binary.write_bytes(
        b"prefix\x00libc.so.6\x00libSystem.B.dylib\x00libstdc++.so.6\x00suffix"
    )

    assert fetch._native_dependencies(binary) == [
        "libSystem.B.dylib",
        "libc.so.6",
        "libstdc++.so.6",
    ]
