"""Tests for platform wheel construction from a promoted engine payload."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import tarfile
from pathlib import Path

import pytest

from scripts import (
    check_dist,
    prepare_release_dist,
    recover_pypi_attestations,
    verify_pypi_release,
)

_MODULE_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "build_engine_distributions.py"
)
_spec = importlib.util.spec_from_file_location("build_engine_distributions", _MODULE_PATH)
bed = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = bed
_spec.loader.exec_module(bed)


def _synthetic_engine(name: str) -> bytes:
    if name.startswith("grype-linux-"):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        machine = 62 if name.endswith("amd64") else 183
        header[18:20] = machine.to_bytes(2, "little")
        header[32:40] = (64).to_bytes(8, "little")
        header[54:56] = (56).to_bytes(2, "little")
        return bytes(header)
    cpu = 0x01000007 if name.endswith("amd64") else 0x0100000C
    return b"\xcf\xfa\xed\xfe" + cpu.to_bytes(4, "little")


def _write_payload(path: Path) -> None:
    path.mkdir()
    manifest_lines = []
    for target in bed.WHEEL_TARGETS:
        binary = path / target.engine_name
        binary.write_bytes(_synthetic_engine(target.engine_name))
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        manifest_lines.append(f"{digest}  grype-test-{target.engine_name[6:]}")
    (path / "SHA256SUMS").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    (path / "LICENSE").write_text("Apache License\n", encoding="utf-8")
    (path / "NOTICE").write_text(
        "This product includes a modified build of Anchore Grype.\n",
        encoding="utf-8",
    )


def test_expected_distribution_set_has_six_platform_wheels_and_sdist():
    names = bed.expected_distribution_filenames("1.2.3")

    assert names == (
        "craevidence-1.2.3-py3-none-manylinux_2_17_x86_64.whl",
        "craevidence-1.2.3-py3-none-musllinux_1_2_x86_64.whl",
        "craevidence-1.2.3-py3-none-manylinux_2_17_aarch64.whl",
        "craevidence-1.2.3-py3-none-musllinux_1_2_aarch64.whl",
        "craevidence-1.2.3-py3-none-macosx_12_0_x86_64.whl",
        "craevidence-1.2.3-py3-none-macosx_12_0_arm64.whl",
        "craevidence-1.2.3.tar.gz",
    )


def test_release_scripts_share_one_platform_set():
    expected = {
        platform_tag
        for target in bed.WHEEL_TARGETS
        for platform_tag in (target.platform_tag, *target.retag_platforms)
    }

    assert set(prepare_release_dist.WHEEL_PLATFORM_TAGS) == expected
    assert set(check_dist.WHEEL_ENGINES) == expected
    assert set(verify_pypi_release.WHEEL_PLATFORM_TAGS) == expected
    assert set(recover_pypi_attestations.WHEEL_PLATFORM_TAGS) == expected


def test_validate_engine_payload_accepts_complete_matching_payload(tmp_path):
    payload = tmp_path / "engine"
    _write_payload(payload)

    bed.validate_engine_payload(payload)


def test_validate_engine_payload_rejects_tampered_binary(tmp_path):
    payload = tmp_path / "engine"
    _write_payload(payload)
    (payload / "grype-linux-amd64").write_bytes(b"tampered")

    with pytest.raises(bed.DistributionBuildError, match="SHA-256 mismatch"):
        bed.validate_engine_payload(payload)


def test_validate_engine_payload_rejects_missing_modification_notice(tmp_path):
    payload = tmp_path / "engine"
    _write_payload(payload)
    (payload / "NOTICE").write_text("unrelated notice\n", encoding="utf-8")

    with pytest.raises(bed.DistributionBuildError, match="modified build of Anchore Grype"):
        bed.validate_engine_payload(payload)


def test_validate_engine_payload_rejects_dynamic_linux_binary(tmp_path):
    payload = tmp_path / "engine"
    _write_payload(payload)
    binary = payload / "grype-linux-amd64"
    value = bytearray(binary.read_bytes())
    value[56:58] = (1).to_bytes(2, "little")
    value.extend((3).to_bytes(4, "little") + bytes(52))
    binary.write_bytes(value)
    manifest = (payload / "SHA256SUMS").read_text(encoding="utf-8")
    digest = hashlib.sha256(value).hexdigest()
    lines = [
        f"{digest}  grype-test-linux-amd64"
        if line.endswith("grype-test-linux-amd64")
        else line
        for line in manifest.splitlines()
    ]
    (payload / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(bed.DistributionBuildError, match="dynamically linked"):
        bed.validate_engine_payload(payload)


def test_engine_free_source_validation_accepts_package_without_binary(tmp_path):
    package = tmp_path / bed.ENGINE_PACKAGE_PATH
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")

    bed._validate_engine_free_source(tmp_path)


def test_build_source_distribution_rejects_bundled_binary_before_build(
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "source"
    binary = source / bed.ENGINE_BINARY_PATH
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"engine")

    def fail_if_build_runs(*args, **kwargs):
        message = "source build must not run"
        raise AssertionError(message)

    monkeypatch.setattr(bed, "_build_sdist", fail_if_build_runs)

    with pytest.raises(
        bed.DistributionBuildError,
        match="source distribution input contains the bundled engine executable",
    ):
        bed.build_source_distribution("1.2.3", source, tmp_path / "dist")


def test_normalize_sdist_removes_build_time_from_archive_bytes(tmp_path):
    normalized = []
    for index, mtime in enumerate((1_700_000_000, 1_800_000_000)):
        source = tmp_path / f"source-{index}.tar.gz"
        with tarfile.open(source, "w:gz") as archive:
            info = tarfile.TarInfo("craevidence-1.2.3/module.py")
            content = b"print('same bytes')\n"
            info.size = len(content)
            info.mtime = mtime
            info.pax_headers = {"mtime": f"{mtime}.123"}
            archive.addfile(info, io.BytesIO(content))
        destination = tmp_path / f"normalized-{index}.tar.gz"
        bed._normalize_sdist(source, destination)
        normalized.append(destination)

    assert normalized[0].read_bytes() == normalized[1].read_bytes()
    with tarfile.open(normalized[0], "r:gz") as archive:
        assert archive.getmembers()[0].mtime == int(bed.SOURCE_DATE_EPOCH)
