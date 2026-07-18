"""Tests for the PyPI release verifier."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import urllib.error
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


def _http_404(url: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, 404, "Not Found", None, None)


def _version_url(version: str) -> str:
    return vpr.PYPI_JSON_URL.format(package=vpr.PACKAGE, version=version)


def _provenance_url(version: str, filename: str) -> str:
    return vpr.PYPI_PROVENANCE_URL.format(
        package=vpr.PACKAGE,
        version=version,
        filename=filename,
    )


def _attestation(
    filename: str,
    sha256: str,
    statement_overrides: dict | None = None,
) -> dict:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://docs.pypi.org/attestations/publish/v1",
        "subject": [{"name": filename, "digest": {"sha256": sha256}}],
        "predicate": None,
    }
    if statement_overrides:
        statement.update(statement_overrides)
    encoded = base64.b64encode(json.dumps(statement).encode()).decode()
    return {"envelope": {"statement": encoded, "signature": "sig"}}


def _bundle(attestations: list[dict], repository: str = "craevidence/cli") -> dict:
    return {
        "publisher": {
            "kind": "GitHub",
            "repository": repository,
            "workflow": "ci.yml",
            "environment": "pypi",
        },
        "attestations": attestations,
    }


def _provenance_payload(
    filename: str,
    sha256: str,
    *,
    repository: str = "craevidence/cli",
    statement_overrides: dict | None = None,
    version: int | None = 1,
) -> dict:
    payload = {
        "attestation_bundles": [
            _bundle(
                [_attestation(filename, sha256, statement_overrides)],
                repository=repository,
            ),
        ],
    }
    if version is not None:
        payload["version"] = version
    return payload


class _FakeOpener:
    """URL-dispatching opener: per-URL queues of payload dicts or exceptions.

    The last queued item for a URL is served repeatedly once the queue is
    down to one entry, so retries keep getting a response.
    """

    def __init__(self) -> None:
        self._queues: dict[str, list[object]] = {}
        self.timeouts: list[object] = []
        self.urls: list[str] = []

    def add(self, url: str, item: dict | Exception) -> None:
        self._queues.setdefault(url, []).append(item)

    def replace(self, url: str, item: dict | Exception) -> None:
        self._queues[url] = [item]

    def __call__(self, url: str, timeout: object = None) -> _FakeResponse:
        self.timeouts.append(timeout)
        self.urls.append(url)
        queue = self._queues[url]
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        return _FakeResponse(json.dumps(item).encode())


def _opener_with_provenance(
    contents: dict[str, bytes],
    version: str = VERSION,
) -> _FakeOpener:
    opener = _FakeOpener()
    opener.add(_version_url(version), _pypi_data(contents))
    for name, data in contents.items():
        opener.add(
            _provenance_url(version, name),
            _provenance_payload(name, _sha256(data)),
        )
    return opener


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
    incomplete = {
        "urls": [
            {
                "filename": wheel,
                "digests": {"sha256": _sha256(contents[wheel])},
                "url": "https://files.pythonhosted.org/wheel",
            },
        ],
    }

    opener = _FakeOpener()
    opener.add(_version_url(VERSION), incomplete)
    opener.add(_version_url(VERSION), _pypi_data(contents))
    for name, data in contents.items():
        opener.add(
            _provenance_url(VERSION, name),
            _provenance_payload(name, _sha256(data)),
        )

    sleep_calls: list[float] = []

    monkeypatch.setattr(vpr, "DEFAULT_OPENER", opener)
    monkeypatch.setattr(vpr, "DEFAULT_SLEEP", lambda seconds: sleep_calls.append(seconds))

    exit_code = vpr.main(["--version", VERSION, "--dist-dir", str(tmp_path)])
    assert exit_code == 0
    assert sleep_calls
    assert opener.timeouts
    assert all(timeout == vpr.REQUEST_TIMEOUT for timeout in opener.timeouts)


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


def _run_main(tmp_path, monkeypatch, opener, extra_args: list[str] | None = None):
    sleep_calls: list[float] = []
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.setattr(vpr, "DEFAULT_OPENER", opener)
    monkeypatch.setattr(vpr, "DEFAULT_SLEEP", lambda seconds: sleep_calls.append(seconds))
    argv = ["--version", VERSION, "--dist-dir", str(tmp_path), *(extra_args or [])]
    exit_code = vpr.main(argv)
    return exit_code, sleep_calls


def test_main_succeeds_with_valid_provenance(tmp_path, monkeypatch, capsys):
    contents = _write_dist(tmp_path, VERSION)
    wheel, sdist = vpr.expected_filenames(VERSION)
    opener = _opener_with_provenance(contents)

    exit_code, sleep_calls = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 0
    assert sleep_calls == []
    assert _provenance_url(VERSION, wheel) in opener.urls
    assert _provenance_url(VERSION, sdist) in opener.urls
    assert all(timeout == vpr.REQUEST_TIMEOUT for timeout in opener.timeouts)
    out = capsys.readouterr().out
    assert "provenance" in out


def test_main_fails_fast_on_wrong_publisher_repository(tmp_path, monkeypatch, capsys):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    opener = _opener_with_provenance(contents)
    opener.replace(
        _provenance_url(VERSION, wheel),
        _provenance_payload(wheel, _sha256(contents[wheel]), repository="someone-else/cli"),
    )

    exit_code, sleep_calls = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 1
    assert sleep_calls == []
    err = capsys.readouterr().err
    assert "publisher" in err
    assert "someone-else/cli" in err


def test_main_fails_fast_on_wrong_predicate_type(tmp_path, monkeypatch, capsys):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    opener = _opener_with_provenance(contents)
    opener.replace(
        _provenance_url(VERSION, wheel),
        _provenance_payload(
            wheel,
            _sha256(contents[wheel]),
            statement_overrides={"predicateType": "https://example.com/other/v1"},
        ),
    )

    exit_code, sleep_calls = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 1
    assert sleep_calls == []
    assert "predicate" in capsys.readouterr().err


def test_main_fails_fast_when_subject_bound_to_other_sha256(tmp_path, monkeypatch, capsys):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    opener = _opener_with_provenance(contents)
    opener.replace(
        _provenance_url(VERSION, wheel),
        _provenance_payload(wheel, _sha256(b"not-the-local-bytes")),
    )

    exit_code, sleep_calls = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 1
    assert sleep_calls == []
    assert "subject" in capsys.readouterr().err


def test_main_retries_when_provenance_not_yet_available(tmp_path, monkeypatch):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    opener = _FakeOpener()
    opener.add(_version_url(VERSION), _pypi_data(contents))
    wheel_url = _provenance_url(VERSION, wheel)
    opener.add(wheel_url, _http_404(wheel_url))
    opener.add(wheel_url, _provenance_payload(wheel, _sha256(contents[wheel])))
    for name, data in contents.items():
        if name != wheel:
            opener.add(
                _provenance_url(VERSION, name),
                _provenance_payload(name, _sha256(data)),
            )

    exit_code, sleep_calls = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 0
    assert sleep_calls
    assert opener.urls.count(wheel_url) == 2


def test_fetch_provenance_404_raises_retryable_error():
    def opener_404(url, timeout=None):
        raise _http_404(url)

    with pytest.raises(vpr.ProvenanceNotAvailableError) as excinfo:
        vpr.fetch_provenance(VERSION, "craevidence-3.7.0.tar.gz", opener=opener_404)
    assert isinstance(excinfo.value, vpr.MissingOnPyPIError)


def test_fetch_provenance_other_http_error_is_fatal():
    def opener_500(url, timeout=None):
        raise urllib.error.HTTPError(url, 500, "Server Error", None, None)

    with pytest.raises(vpr.VerificationError) as excinfo:
        vpr.fetch_provenance(VERSION, "craevidence-3.7.0.tar.gz", opener=opener_500)
    assert not isinstance(excinfo.value, vpr.MissingOnPyPIError)
    assert "500" in str(excinfo.value)


def test_main_accepts_expected_publisher_in_second_bundle(tmp_path, monkeypatch):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    opener = _opener_with_provenance(contents)
    payload = _provenance_payload(wheel, _sha256(contents[wheel]))
    other = _bundle(
        [_attestation(wheel, _sha256(contents[wheel]))],
        repository="someone-else/cli",
    )
    payload["attestation_bundles"].insert(0, other)
    opener.replace(_provenance_url(VERSION, wheel), payload)

    exit_code, sleep_calls = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 0
    assert sleep_calls == []


def test_main_accepts_publish_attestation_after_other_attestation(tmp_path, monkeypatch):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    opener = _opener_with_provenance(contents)
    other = _attestation(
        wheel,
        _sha256(contents[wheel]),
        {"predicateType": "https://example.com/other/v1"},
    )
    good = _attestation(wheel, _sha256(contents[wheel]))
    payload = {"version": 1, "attestation_bundles": [_bundle([other, good])]}
    opener.replace(_provenance_url(VERSION, wheel), payload)

    exit_code, sleep_calls = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 0
    assert sleep_calls == []


def test_main_fails_fast_when_no_bundle_has_expected_publisher(tmp_path, monkeypatch, capsys):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    opener = _opener_with_provenance(contents)
    sha = _sha256(contents[wheel])
    payload = {
        "version": 1,
        "attestation_bundles": [
            _bundle([_attestation(wheel, sha)], repository="someone-else/cli"),
            _bundle([_attestation(wheel, sha)], repository="another-org/cli"),
        ],
    }
    opener.replace(_provenance_url(VERSION, wheel), payload)

    exit_code, sleep_calls = _run_main(tmp_path, monkeypatch, opener)
    assert exit_code == 1
    assert sleep_calls == []
    err = capsys.readouterr().err
    assert "publisher" in err
    assert "someone-else/cli" in err
    assert "another-org/cli" in err


def test_verify_provenance_rejects_when_no_attestation_subject_matches():
    filename = "craevidence-3.7.0.tar.gz"
    local_hash = _sha256(b"local-bytes")
    payload = _provenance_payload(filename, _sha256(b"other-bytes"))

    with pytest.raises(vpr.ProvenanceError) as excinfo:
        vpr.verify_provenance(payload, filename, local_hash, "craevidence/cli")
    message = str(excinfo.value)
    assert "subject" in message
    assert "checked 1" in message


def test_verify_provenance_rejects_version_2():
    filename = "craevidence-3.7.0.tar.gz"
    sha = _sha256(b"sdist-bytes")
    payload = _provenance_payload(filename, sha, version=2)

    with pytest.raises(vpr.ProvenanceError) as excinfo:
        vpr.verify_provenance(payload, filename, sha, "craevidence/cli")
    assert "version" in str(excinfo.value)


def test_verify_provenance_rejects_missing_version():
    filename = "craevidence-3.7.0.tar.gz"
    sha = _sha256(b"sdist-bytes")
    payload = _provenance_payload(filename, sha, version=None)
    assert "version" not in payload

    with pytest.raises(vpr.ProvenanceError) as excinfo:
        vpr.verify_provenance(payload, filename, sha, "craevidence/cli")
    assert "version" in str(excinfo.value)


def _write_matching_assets(assets_dir, contents) -> None:
    for name, data in contents.items():
        attestation = _attestation(name, _sha256(data))
        path = assets_dir / f"{name}.publish.attestation"
        path.write_text(json.dumps(attestation))


def test_main_attestations_dir_passes_when_assets_match(tmp_path, monkeypatch):
    contents = _write_dist(tmp_path, VERSION)
    assets = tmp_path / "assets"
    assets.mkdir()
    opener = _opener_with_provenance(contents)
    _write_matching_assets(assets, contents)

    exit_code, sleep_calls = _run_main(
        tmp_path,
        monkeypatch,
        opener,
        ["--attestations-dir", str(assets)],
    )
    assert exit_code == 0
    assert sleep_calls == []


def test_main_attestations_dir_fails_on_non_matching_asset(tmp_path, monkeypatch, capsys):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    assets = tmp_path / "assets"
    assets.mkdir()
    opener = _opener_with_provenance(contents)
    _write_matching_assets(assets, contents)
    rogue = _attestation(wheel, _sha256(b"not-what-pypi-accepted"))
    (assets / f"{wheel}.publish.attestation").write_text(json.dumps(rogue))

    exit_code, sleep_calls = _run_main(
        tmp_path,
        monkeypatch,
        opener,
        ["--attestations-dir", str(assets)],
    )
    assert exit_code == 1
    assert sleep_calls == []
    assert "attestation asset" in capsys.readouterr().err


def test_main_attestations_dir_fails_on_missing_asset(tmp_path, monkeypatch, capsys):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    assets = tmp_path / "assets"
    assets.mkdir()
    opener = _opener_with_provenance(contents)
    _write_matching_assets(assets, contents)
    (assets / f"{wheel}.publish.attestation").unlink()

    exit_code, sleep_calls = _run_main(
        tmp_path,
        monkeypatch,
        opener,
        ["--attestations-dir", str(assets)],
    )
    assert exit_code == 1
    assert sleep_calls == []
    assert "missing attestation asset" in capsys.readouterr().err


def test_main_attestations_dir_fails_on_unparsable_asset(tmp_path, monkeypatch, capsys):
    contents = _write_dist(tmp_path, VERSION)
    wheel, _sdist = vpr.expected_filenames(VERSION)
    assets = tmp_path / "assets"
    assets.mkdir()
    opener = _opener_with_provenance(contents)
    _write_matching_assets(assets, contents)
    (assets / f"{wheel}.publish.attestation").write_text("{not json")

    exit_code, sleep_calls = _run_main(
        tmp_path,
        monkeypatch,
        opener,
        ["--attestations-dir", str(assets)],
    )
    assert exit_code == 1
    assert sleep_calls == []
    assert "not valid JSON" in capsys.readouterr().err
