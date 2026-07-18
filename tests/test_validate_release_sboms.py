"""Tests for the release SBOM validator."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "validate_release_sboms.py"
_spec = importlib.util.spec_from_file_location("validate_release_sboms", _MODULE_PATH)
vrs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vrs)

VERSION = "3.8.1"
IMAGE = "ghcr.io/craevidence/craevidence"
DIGEST_AMD64 = "sha256:" + "a" * 64
DIGEST_ARM64 = "sha256:" + "b" * 64
LABEL = "sbom-under-test.cdx.json"


def _sbom(image: str = IMAGE, digest: str = DIGEST_AMD64, **overrides: object) -> dict:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "container", "name": image, "version": digest},
        },
        "components": [
            {"type": "library", "name": "openssl", "version": "3.0.13"},
        ],
    }
    document.update(overrides)
    return document


def _write_assets(directory: Path) -> tuple[Path, Path]:
    amd64_path = directory / vrs.asset_filename(VERSION, "amd64")
    arm64_path = directory / vrs.asset_filename(VERSION, "arm64")
    amd64_path.write_text(json.dumps(_sbom(digest=DIGEST_AMD64)), encoding="utf-8")
    arm64_path.write_text(json.dumps(_sbom(digest=DIGEST_ARM64)), encoding="utf-8")
    return amd64_path, arm64_path


def _main_args(directory: Path) -> list[str]:
    return [
        "--version",
        VERSION,
        "--image",
        IMAGE,
        "--digest-amd64",
        DIGEST_AMD64,
        "--digest-arm64",
        DIGEST_ARM64,
        "--dir",
        str(directory),
    ]


def test_asset_filename_exact_names():
    assert vrs.asset_filename("3.8.1", "amd64") == "sbom-3.8.1-linux-amd64.cdx.json"
    assert vrs.asset_filename("3.8.1", "arm64") == "sbom-3.8.1-linux-arm64.cdx.json"


def test_validate_sbom_passes_on_valid_document():
    assert vrs.validate_sbom(_sbom(), IMAGE, DIGEST_AMD64, LABEL) is None


def test_main_valid_pair_exits_zero(tmp_path, capsys):
    _write_assets(tmp_path)
    exit_code = vrs.main(_main_args(tmp_path))
    assert exit_code == 0
    out = capsys.readouterr().out
    assert vrs.asset_filename(VERSION, "amd64") in out
    assert vrs.asset_filename(VERSION, "arm64") in out
    assert DIGEST_AMD64 in out
    assert DIGEST_ARM64 in out


def test_wrong_bom_format_rejected():
    sbom = _sbom(bomFormat="SPDX")
    with pytest.raises(vrs.SbomValidationError) as excinfo:
        vrs.validate_sbom(sbom, IMAGE, DIGEST_AMD64, LABEL)
    message = str(excinfo.value)
    assert LABEL in message
    assert "bomFormat" in message


def test_wrong_spec_version_rejected():
    sbom = _sbom(specVersion="1.5")
    with pytest.raises(vrs.SbomValidationError) as excinfo:
        vrs.validate_sbom(sbom, IMAGE, DIGEST_AMD64, LABEL)
    message = str(excinfo.value)
    assert LABEL in message
    assert "specVersion" in message


def test_boolean_document_version_rejected():
    sbom = _sbom(version=True)
    with pytest.raises(vrs.SbomValidationError) as excinfo:
        vrs.validate_sbom(sbom, IMAGE, DIGEST_AMD64, LABEL)
    message = str(excinfo.value)
    assert LABEL in message
    assert "version" in message


def test_zero_document_version_rejected():
    sbom = _sbom(version=0)
    with pytest.raises(vrs.SbomValidationError) as excinfo:
        vrs.validate_sbom(sbom, IMAGE, DIGEST_AMD64, LABEL)
    assert "version" in str(excinfo.value)


def test_components_not_a_list_rejected():
    sbom = _sbom(components={"name": "openssl"})
    with pytest.raises(vrs.SbomValidationError) as excinfo:
        vrs.validate_sbom(sbom, IMAGE, DIGEST_AMD64, LABEL)
    assert "components" in str(excinfo.value)


def test_empty_components_list_rejected():
    sbom = _sbom(components=[])
    with pytest.raises(vrs.SbomValidationError) as excinfo:
        vrs.validate_sbom(sbom, IMAGE, DIGEST_AMD64, LABEL)
    assert "components" in str(excinfo.value)


def test_non_object_component_entry_rejected():
    sbom = _sbom(components=[{"name": "openssl"}, "not-an-object"])
    with pytest.raises(vrs.SbomValidationError) as excinfo:
        vrs.validate_sbom(sbom, IMAGE, DIGEST_AMD64, LABEL)
    message = str(excinfo.value)
    assert "components[1]" in message


def test_subject_name_mismatch_rejected():
    sbom = _sbom(image="ghcr.io/someone-else/image")
    with pytest.raises(vrs.SbomValidationError) as excinfo:
        vrs.validate_sbom(sbom, IMAGE, DIGEST_AMD64, LABEL)
    message = str(excinfo.value)
    assert "metadata.component.name" in message
    assert IMAGE in message
    assert "ghcr.io/someone-else/image" in message


def test_subject_digest_mismatch_rejected():
    other_digest = "sha256:" + "c" * 64
    sbom = _sbom(digest=other_digest)
    with pytest.raises(vrs.SbomValidationError) as excinfo:
        vrs.validate_sbom(sbom, IMAGE, DIGEST_AMD64, LABEL)
    message = str(excinfo.value)
    assert "metadata.component.version" in message
    assert DIGEST_AMD64 in message
    assert other_digest in message


def test_main_missing_file_exits_nonzero(tmp_path, capsys):
    _, arm64_path = _write_assets(tmp_path)
    arm64_path.unlink()
    exit_code = vrs.main(_main_args(tmp_path))
    assert exit_code == 1
    err = capsys.readouterr().err
    assert vrs.asset_filename(VERSION, "arm64") in err
    assert "missing" in err


def test_main_invalid_json_exits_nonzero(tmp_path, capsys):
    _, arm64_path = _write_assets(tmp_path)
    arm64_path.write_text("{not valid json", encoding="utf-8")
    exit_code = vrs.main(_main_args(tmp_path))
    assert exit_code == 1
    err = capsys.readouterr().err
    assert vrs.asset_filename(VERSION, "arm64") in err
    assert "JSON" in err


def test_main_non_object_document_exits_nonzero(tmp_path, capsys):
    _write_assets(tmp_path)
    amd64_path = tmp_path / vrs.asset_filename(VERSION, "amd64")
    amd64_path.write_text(json.dumps([_sbom()]), encoding="utf-8")
    exit_code = vrs.main(_main_args(tmp_path))
    assert exit_code == 1
    err = capsys.readouterr().err
    assert vrs.asset_filename(VERSION, "amd64") in err
    assert "object" in err


def test_main_wrong_digest_exits_nonzero(tmp_path, capsys):
    amd64_path, _ = _write_assets(tmp_path)
    amd64_path.write_text(json.dumps(_sbom(digest=DIGEST_ARM64)), encoding="utf-8")
    exit_code = vrs.main(_main_args(tmp_path))
    assert exit_code == 1
    err = capsys.readouterr().err
    assert vrs.asset_filename(VERSION, "amd64") in err
    assert "metadata.component.version" in err
