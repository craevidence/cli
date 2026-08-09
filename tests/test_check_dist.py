"""Tests for release distribution content checks."""

from __future__ import annotations

import importlib.util
import sys
import tarfile
import zipfile
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "check_dist.py"
_spec = importlib.util.spec_from_file_location("check_dist", _MODULE_PATH)
check_dist = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = check_dist
_spec.loader.exec_module(check_dist)


def _write_release_set(dist_dir: Path, engine_dir: Path) -> None:
    version = check_dist._project_version()
    engine_dir.mkdir()
    (engine_dir / "LICENSE").write_bytes(b"license bytes\n")
    (engine_dir / "NOTICE").write_bytes(b"notice bytes\n")
    for engine_name in set(check_dist.WHEEL_ENGINES.values()):
        (engine_dir / engine_name).write_bytes(f"binary:{engine_name}".encode())

    for platform, engine_name in check_dist.WHEEL_ENGINES.items():
        wheel = dist_dir / f"craevidence-{version}-py3-none-{platform}.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            info = zipfile.ZipInfo("cra_evidence_cli/_engine/grype")
            info.external_attr = 0o100755 << 16
            archive.writestr(info, (engine_dir / engine_name).read_bytes())
            archive.writestr(
                "cra_evidence_cli/_engine/LICENSE",
                (engine_dir / "LICENSE").read_bytes(),
            )
            archive.writestr(
                "cra_evidence_cli/_engine/NOTICE",
                (engine_dir / "NOTICE").read_bytes(),
            )
    with tarfile.open(dist_dir / f"craevidence-{version}.tar.gz", "w:gz"):
        pass


def test_engine_free_sdist_check_accepts_package_metadata_only():
    errors = check_dist._check_engine_free_sdist(
        [
            "craevidence-4.2.0/cra_evidence_cli/_engine/__init__.py",
            "craevidence-4.2.0/cra_evidence_cli/engine.py",
        ]
    )

    assert errors == []


def test_engine_free_sdist_check_rejects_bundled_engine():
    engine_path = "craevidence-4.2.0/cra_evidence_cli/_engine/grype"

    errors = check_dist._check_engine_free_sdist([engine_path])

    assert len(errors) == 1
    assert engine_path in errors[0]


def test_dist_directory_applies_engine_free_check_to_sdist(tmp_path, monkeypatch):
    wheel = tmp_path / "craevidence-4.2.0-py3-none-any.whl"
    sdist = tmp_path / "craevidence-4.2.0.tar.gz"
    wheel.touch()
    sdist.touch()
    engine_path = "craevidence-4.2.0/cra_evidence_cli/_engine/grype"

    monkeypatch.setattr(check_dist, "_names_from_wheel", lambda path: [])
    monkeypatch.setattr(
        check_dist,
        "_names_from_sdist",
        lambda path: [engine_path],
    )
    monkeypatch.setattr(check_dist, "_check", lambda label, names: [])

    errors = check_dist._check_dist_dir(tmp_path)

    assert len(errors) == 1
    assert engine_path in errors[0]


def test_release_set_matches_promoted_payload(tmp_path):
    dist_dir = tmp_path / "dist"
    engine_dir = tmp_path / "engine"
    dist_dir.mkdir()
    _write_release_set(dist_dir, engine_dir)

    assert check_dist._check_release_set(dist_dir, engine_dir) == []


def test_release_set_rejects_tampered_engine_bytes(tmp_path):
    dist_dir = tmp_path / "dist"
    engine_dir = tmp_path / "engine"
    dist_dir.mkdir()
    _write_release_set(dist_dir, engine_dir)
    (engine_dir / "grype-linux-amd64").write_bytes(b"different promoted bytes")

    errors = check_dist._check_release_set(dist_dir, engine_dir)

    assert len(errors) == 2
    assert all("does not match promoted payload" in error for error in errors)


def test_release_set_rejects_unexpected_distribution_name(tmp_path):
    dist_dir = tmp_path / "dist"
    engine_dir = tmp_path / "engine"
    dist_dir.mkdir()
    _write_release_set(dist_dir, engine_dir)
    (dist_dir / "craevidence-4.2.0-py3-none-any.whl").touch()

    errors = check_dist._check_release_set(dist_dir, engine_dir)

    assert len(errors) == 1
    assert "release distribution set mismatch" in errors[0]


def test_release_wheel_rejects_non_executable_engine(tmp_path):
    engine_dir = tmp_path / "engine"
    engine_dir.mkdir()
    engine = engine_dir / "grype-linux-amd64"
    engine.write_bytes(b"engine bytes")
    (engine_dir / "LICENSE").write_bytes(b"license bytes")
    (engine_dir / "NOTICE").write_bytes(b"notice bytes")
    wheel = tmp_path / "wheel.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        info = zipfile.ZipInfo("cra_evidence_cli/_engine/grype")
        info.external_attr = 0o100644 << 16
        archive.writestr(info, engine.read_bytes())
        archive.writestr("cra_evidence_cli/_engine/LICENSE", b"license bytes")
        archive.writestr("cra_evidence_cli/_engine/NOTICE", b"notice bytes")

    errors = check_dist._check_release_wheel(wheel, engine, engine_dir)

    assert errors == ["wheel.whl: bundled engine is not executable"]


def test_release_wheel_rejects_notice_mismatch(tmp_path):
    engine_dir = tmp_path / "engine"
    engine_dir.mkdir()
    engine = engine_dir / "grype-linux-amd64"
    engine.write_bytes(b"engine bytes")
    (engine_dir / "LICENSE").write_bytes(b"license bytes")
    (engine_dir / "NOTICE").write_bytes(b"promoted notice")
    wheel = tmp_path / "wheel.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        info = zipfile.ZipInfo("cra_evidence_cli/_engine/grype")
        info.external_attr = 0o100755 << 16
        archive.writestr(info, engine.read_bytes())
        archive.writestr("cra_evidence_cli/_engine/LICENSE", b"license bytes")
        archive.writestr("cra_evidence_cli/_engine/NOTICE", b"different notice")

    errors = check_dist._check_release_wheel(wheel, engine, engine_dir)

    assert errors == ["wheel.whl: engine NOTICE differs from the promoted payload"]
