"""Tests for the PyPI attestation sidecar recovery script."""

from __future__ import annotations

import base64
import importlib.util
import json
import urllib.error
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "recover_pypi_attestations.py"
_spec = importlib.util.spec_from_file_location("recover_pypi_attestations", _MODULE_PATH)
rpa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rpa)

VERSION = "3.8.1"
REPOSITORY = "craevidence/cli"


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._payload


class _FakeOpener:
    """URL-dispatching opener serving a fixed payload or exception per URL."""

    def __init__(self) -> None:
        self._responses: dict[str, object] = {}
        self.timeouts: list[object] = []
        self.urls: list[str] = []

    def add(self, url: str, item: dict | Exception) -> None:
        self._responses[url] = item

    def __call__(self, url: str, timeout: object = None) -> _FakeResponse:
        self.timeouts.append(timeout)
        self.urls.append(url)
        item = self._responses[url]
        if isinstance(item, Exception):
            raise item
        return _FakeResponse(json.dumps(item).encode())


def _no_network_opener(url: str, timeout: object = None) -> _FakeResponse:
    msg = f"unexpected network call: {url}"
    raise AssertionError(msg)


def _http_error(url: str, code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "error", None, None)


def _provenance_url(version: str, filename: str) -> str:
    return rpa.PYPI_PROVENANCE_URL.format(
        package=rpa.PACKAGE,
        version=version,
        filename=filename,
    )


def _attestation(filename: str, statement_overrides: dict | None = None) -> dict:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://docs.pypi.org/attestations/publish/v1",
        "subject": [{"name": filename, "digest": {"sha256": "ab" * 32}}],
        "predicate": None,
    }
    if statement_overrides:
        statement.update(statement_overrides)
    encoded = base64.b64encode(json.dumps(statement).encode()).decode()
    return {"envelope": {"statement": encoded, "signature": "sig"}, "verification_material": {}}


def _bundle(attestations: list[dict], repository: str = REPOSITORY) -> dict:
    return {
        "publisher": {
            "kind": "GitHub",
            "repository": repository,
            "workflow": "ci.yml",
            "environment": "pypi",
        },
        "attestations": attestations,
    }


def _sidecar_names(version: str) -> tuple[str, str]:
    wheel, sdist = rpa.expected_filenames(version)
    return f"{wheel}.publish.attestation", f"{sdist}.publish.attestation"


def _run_main(tmp_path, monkeypatch, opener):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.setattr(rpa, "DEFAULT_OPENER", opener)
    return rpa.main(["--version", VERSION, "--dir", str(tmp_path)])


def test_expected_filenames_exact_names():
    wheel, sdist = rpa.expected_filenames("1.2.3")
    assert wheel == "craevidence-1.2.3-py3-none-any.whl"
    assert sdist == "craevidence-1.2.3.tar.gz"


def test_main_leaves_present_sidecars_untouched_without_network(tmp_path, monkeypatch, capsys):
    wheel_sidecar, sdist_sidecar = _sidecar_names(VERSION)
    (tmp_path / wheel_sidecar).write_bytes(b"wheel sentinel bytes")
    (tmp_path / sdist_sidecar).write_bytes(b"sdist sentinel bytes")

    exit_code = _run_main(tmp_path, monkeypatch, _no_network_opener)
    assert exit_code == 0
    assert (tmp_path / wheel_sidecar).read_bytes() == b"wheel sentinel bytes"
    assert (tmp_path / sdist_sidecar).read_bytes() == b"sdist sentinel bytes"
    out = capsys.readouterr().out
    assert out.count("present") == 2


def test_main_recovers_missing_sidecar_from_second_bundle(tmp_path, monkeypatch, capsys):
    wheel, _sdist = rpa.expected_filenames(VERSION)
    wheel_sidecar, sdist_sidecar = _sidecar_names(VERSION)
    (tmp_path / sdist_sidecar).write_bytes(b"sdist sentinel bytes")

    non_matching = _attestation(wheel, {"predicateType": "https://example.com/other/v1"})
    good = _attestation(wheel)
    provenance = {
        "version": 1,
        "attestation_bundles": [
            _bundle([_attestation(wheel)], repository="someone-else/cli"),
            _bundle([non_matching, good]),
        ],
    }
    opener = _FakeOpener()
    opener.add(_provenance_url(VERSION, wheel), provenance)

    exit_code = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 0
    written = json.loads((tmp_path / wheel_sidecar).read_text())
    assert written == good
    assert written != non_matching
    assert (tmp_path / sdist_sidecar).read_bytes() == b"sdist sentinel bytes"
    assert opener.urls == [_provenance_url(VERSION, wheel)]
    assert all(timeout == rpa.REQUEST_TIMEOUT for timeout in opener.timeouts)
    out = capsys.readouterr().out
    assert f"{wheel_sidecar}: recovered" in out
    assert f"{sdist_sidecar}: present" in out


def test_main_skips_missing_sidecar_when_provenance_404(tmp_path, monkeypatch, capsys):
    wheel, sdist = rpa.expected_filenames(VERSION)
    wheel_sidecar, sdist_sidecar = _sidecar_names(VERSION)
    (tmp_path / wheel_sidecar).write_bytes(b"wheel sentinel bytes")
    sdist_url = _provenance_url(VERSION, sdist)
    opener = _FakeOpener()
    opener.add(sdist_url, _http_error(sdist_url, 404))

    exit_code = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 0
    assert not (tmp_path / sdist_sidecar).exists()
    out = capsys.readouterr().out
    assert f"{sdist_sidecar}: not on PyPI; skipping" in out


def test_main_fails_when_no_bundle_has_expected_publisher(tmp_path, monkeypatch, capsys):
    wheel, _sdist = rpa.expected_filenames(VERSION)
    wheel_sidecar, sdist_sidecar = _sidecar_names(VERSION)
    (tmp_path / sdist_sidecar).write_bytes(b"sdist sentinel bytes")
    provenance = {
        "version": 1,
        "attestation_bundles": [
            _bundle([_attestation(wheel)], repository="someone-else/cli"),
        ],
    }
    opener = _FakeOpener()
    opener.add(_provenance_url(VERSION, wheel), provenance)

    exit_code = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 1
    assert not (tmp_path / wheel_sidecar).exists()
    err = capsys.readouterr().err
    assert "publisher" in err


def test_main_fails_when_no_attestation_names_the_file(tmp_path, monkeypatch, capsys):
    wheel, _sdist = rpa.expected_filenames(VERSION)
    wheel_sidecar, sdist_sidecar = _sidecar_names(VERSION)
    (tmp_path / sdist_sidecar).write_bytes(b"sdist sentinel bytes")
    other_name = _attestation("craevidence-9.9.9-py3-none-any.whl")
    provenance = {"version": 1, "attestation_bundles": [_bundle([other_name])]}
    opener = _FakeOpener()
    opener.add(_provenance_url(VERSION, wheel), provenance)

    exit_code = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 1
    assert not (tmp_path / wheel_sidecar).exists()
    err = capsys.readouterr().err
    assert wheel in err


def test_main_fails_on_http_500(tmp_path, monkeypatch, capsys):
    wheel, _sdist = rpa.expected_filenames(VERSION)
    _wheel_sidecar, sdist_sidecar = _sidecar_names(VERSION)
    (tmp_path / sdist_sidecar).write_bytes(b"sdist sentinel bytes")
    wheel_url = _provenance_url(VERSION, wheel)
    opener = _FakeOpener()
    opener.add(wheel_url, _http_error(wheel_url, 500))

    exit_code = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 1
    assert "500" in capsys.readouterr().err


def test_select_attestation_requires_single_subject_naming_the_file():
    wheel, _sdist = rpa.expected_filenames(VERSION)
    two_subjects = _attestation(
        wheel,
        {
            "subject": [
                {"name": wheel, "digest": {"sha256": "ab" * 32}},
                {"name": "extra", "digest": {"sha256": "cd" * 32}},
            ],
        },
    )
    provenance = {"version": 1, "attestation_bundles": [_bundle([two_subjects])]}
    with pytest.raises(rpa.RecoveryError):
        rpa.select_attestation(provenance, wheel, REPOSITORY)


def test_fetch_provenance_404_raises_not_available():
    def opener_404(url, timeout=None):
        raise _http_error(url, 404)

    with pytest.raises(rpa.ProvenanceNotAvailableError):
        rpa.fetch_provenance(VERSION, f"craevidence-{VERSION}.tar.gz", opener=opener_404)


def test_invalid_provenance_json_is_a_recovery_error():
    def opener(url: str, timeout: object = None) -> _FakeResponse:
        return _FakeResponse(b"not-json{")

    with pytest.raises(rpa.RecoveryError, match="not valid JSON"):
        rpa.fetch_provenance(VERSION, "craevidence-3.8.1.tar.gz", opener=opener)


def test_non_object_provenance_is_a_recovery_error():
    def opener(url: str, timeout: object = None) -> _FakeResponse:
        return _FakeResponse(json.dumps(["not", "an", "object"]).encode())

    with pytest.raises(rpa.RecoveryError, match="not a JSON object"):
        rpa.fetch_provenance(VERSION, "craevidence-3.8.1.tar.gz", opener=opener)
