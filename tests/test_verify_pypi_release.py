"""Tests for the PyPI release verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "verify_pypi_release.py"
_spec = importlib.util.spec_from_file_location("verify_pypi_release", _MODULE_PATH)
vpr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vpr)

VERSION = "3.7.0"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_dist(dist_dir: Path, version: str) -> dict[str, bytes]:
    wheel, sdist = vpr.expected_filenames(version)
    contents = {
        wheel: b"wheel-bytes-for-" + version.encode(),
        sdist: b"sdist-bytes-for-" + version.encode(),
    }
    for name, data in contents.items():
        (dist_dir / name).write_bytes(data)
    return contents


def _pypi_data(contents: dict[str, bytes]) -> dict:
    return {
        "urls": [
            {
                "filename": name,
                "digests": {"sha256": _sha256(data)},
                "url": f"https://files.pythonhosted.org/{name}",
            }
            for name, data in contents.items()
        ],
    }


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._payload


def test_expected_filenames_exact_names():
    wheel, sdist = vpr.expected_filenames("1.2.3")
    assert wheel == "craevidence-1.2.3-py3-none-any.whl"
    assert sdist == "craevidence-1.2.3.tar.gz"


def test_verify_passes_on_match(tmp_path):
    contents = _write_dist(tmp_path, VERSION)
    assert vpr.verify(VERSION, tmp_path, _pypi_data(contents)) is None


def test_verify_raises_hash_mismatch_with_both_hashes(tmp_path):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    local_hash = _sha256(contents[wheel])
    data = _pypi_data(contents)
    wrong_hash = _sha256(b"different-wheel-bytes")
    for entry in data["urls"]:
        if entry["filename"] == wheel:
            entry["digests"]["sha256"] = wrong_hash

    with pytest.raises(vpr.HashMismatchError) as excinfo:
        vpr.verify(VERSION, tmp_path, data)
    message = str(excinfo.value)
    assert local_hash in message
    assert wrong_hash in message


def test_verify_raises_missing_on_pypi_when_sdist_absent(tmp_path):
    contents = _write_dist(tmp_path, VERSION)
    wheel, sdist = vpr.expected_filenames(VERSION)
    data = {
        "urls": [
            {
                "filename": wheel,
                "digests": {"sha256": _sha256(contents[wheel])},
                "url": "https://files.pythonhosted.org/wheel",
            },
        ],
    }
    with pytest.raises(vpr.MissingOnPyPIError) as excinfo:
        vpr.verify(VERSION, tmp_path, data)
    assert sdist in str(excinfo.value)


def test_verify_raises_when_local_sdist_missing(tmp_path):
    wheel, sdist = vpr.expected_filenames(VERSION)
    (tmp_path / wheel).write_bytes(b"only-the-wheel")
    contents = {wheel: b"only-the-wheel", sdist: b"unused"}
    with pytest.raises(vpr.VerificationError) as excinfo:
        vpr.verify(VERSION, tmp_path, _pypi_data(contents))
    error = excinfo.value
    assert not isinstance(error, vpr.MissingOnPyPIError)
    assert not isinstance(error, vpr.HashMismatchError)
    assert sdist in str(error)


def test_verify_ignores_unrelated_dist_file(tmp_path):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    sidecar = tmp_path / f"{wheel}.publish.attestation"
    sidecar.write_bytes(b"unrelated sidecar content")
    assert vpr.verify(VERSION, tmp_path, _pypi_data(contents)) is None


def test_pypi_sha256_ignores_unrelated_filenames(tmp_path):
    contents = _write_dist(tmp_path, VERSION)
    wheel, sdist = vpr.expected_filenames(VERSION)
    data = _pypi_data(contents)
    data["urls"].append(
        {
            "filename": "craevidence-9.9.9-py3-none-any.whl",
            "digests": {"sha256": _sha256(b"other-version")},
            "url": "https://files.pythonhosted.org/other",
        },
    )
    result = vpr.pypi_sha256(data, VERSION)
    assert set(result) == {wheel, sdist}


def test_verify_rejects_unexpected_remote_distribution(tmp_path):
    contents = _write_dist(tmp_path, VERSION)
    data = _pypi_data(contents)
    data["urls"].append(
        {
            "filename": f"craevidence-{VERSION}-py2-none-any.whl",
            "digests": {"sha256": _sha256(b"rogue-distribution")},
            "url": "https://files.pythonhosted.org/rogue",
        },
    )
    with pytest.raises(vpr.VerificationError) as excinfo:
        vpr.verify(VERSION, tmp_path, data)
    error = excinfo.value
    assert not isinstance(error, vpr.MissingOnPyPIError)
    assert not isinstance(error, vpr.HashMismatchError)
    assert "unexpected" in str(error)


def test_verify_fails_fast_when_absent_wheel_hides_a_mismatched_sdist(tmp_path):
    # Regression orientation: the wheel (checked first) is absent while the
    # sdist is present with a wrong hash. The former implementation raised the
    # retryable missing-wheel error and never checked the sdist; verify must now
    # report the hash mismatch instead.
    _write_dist(tmp_path, VERSION)
    _wheel, sdist = vpr.expected_filenames(VERSION)
    data = {
        "urls": [
            {
                "filename": sdist,
                "digests": {"sha256": _sha256(b"tampered")},
                "url": "https://files.pythonhosted.org/sdist",
            },
        ],
    }
    with pytest.raises(vpr.HashMismatchError):
        vpr.verify(VERSION, tmp_path, data)


def test_main_retries_until_sdist_appears(tmp_path, monkeypatch):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    incomplete = json.dumps(
        {
            "urls": [
                {
                    "filename": wheel,
                    "digests": {"sha256": _sha256(contents[wheel])},
                    "url": "https://files.pythonhosted.org/wheel",
                },
            ],
        },
    ).encode()
    complete = json.dumps(_pypi_data(contents)).encode()

    responses = iter([incomplete, complete])
    timeouts: list[object] = []

    def fake_opener(_url, timeout=None):
        timeouts.append(timeout)
        return _FakeResponse(next(responses))

    sleep_calls: list[float] = []

    monkeypatch.setattr(vpr, "DEFAULT_OPENER", fake_opener)
    monkeypatch.setattr(vpr, "DEFAULT_SLEEP", lambda seconds: sleep_calls.append(seconds))

    exit_code = vpr.main(["--version", VERSION, "--dist-dir", str(tmp_path)])
    assert exit_code == 0
    assert sleep_calls
    assert timeouts
    assert all(timeout == vpr.REQUEST_TIMEOUT for timeout in timeouts)


def test_main_fails_fast_on_hash_mismatch(tmp_path, monkeypatch):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    data = _pypi_data(contents)
    for entry in data["urls"]:
        if entry["filename"] == wheel:
            entry["digests"]["sha256"] = _sha256(b"tampered")
    payload = json.dumps(data).encode()

    def fake_opener(_url, timeout=None):
        return _FakeResponse(payload)

    sleep_calls: list[float] = []

    monkeypatch.setattr(vpr, "DEFAULT_OPENER", fake_opener)
    monkeypatch.setattr(vpr, "DEFAULT_SLEEP", lambda seconds: sleep_calls.append(seconds))

    exit_code = vpr.main(["--version", VERSION, "--dist-dir", str(tmp_path)])
    assert exit_code == 1
    assert sleep_calls == []
