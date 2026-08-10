"""Tests for the release distribution acquirer.

The network, gh, and build seams are replaced with fakes so the per-file
priority (PyPI, then release asset, then build) is exercised against real
temporary directories and real sha256 digests.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "prepare_release_dist.py"
_spec = importlib.util.spec_from_file_location("prepare_release_dist", _MODULE_PATH)
prd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prd)

VERSION = "3.8.1"
TAG = "v3.8.1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _FakeResponse:
    """Context-managed response supporting whole and chunked reads."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._pos = 0

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            data = self._payload[self._pos :]
            self._pos = len(self._payload)
            return data
        data = self._payload[self._pos : self._pos + size]
        self._pos += size
        return data


def _make_opener(pypi_contents: dict[str, bytes], served_overrides: dict[str, bytes] | None = None):
    """Opener serving the version JSON and file downloads for pypi_contents.

    Digests in the JSON always come from pypi_contents; served_overrides can
    substitute the bytes actually served for a filename to force a mismatch.
    An empty pypi_contents makes the JSON endpoint return HTTP 404.
    """
    served_overrides = served_overrides or {}
    json_url = prd.PYPI_JSON_URL.format(package=prd.PACKAGE, version=VERSION)
    file_urls: dict[str, bytes] = {}
    entries = []
    for name, data in pypi_contents.items():
        url = f"https://files.pythonhosted.org/packages/{name}"
        file_urls[url] = served_overrides.get(name, data)
        entries.append({"filename": name, "digests": {"sha256": _sha256(data)}, "url": url})
    json_payload = json.dumps({"urls": entries}).encode()

    def opener(url: str, timeout: int | None = None) -> _FakeResponse:
        assert timeout == prd.REQUEST_TIMEOUT
        if url == json_url:
            if not pypi_contents:
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            return _FakeResponse(json_payload)
        return _FakeResponse(file_urls[url])

    return opener


class _Runner:
    """Fake subprocess runner for gh acquisition and engine distribution builds."""

    def __init__(
        self,
        assets: dict[str, bytes] | None = None,
        build_files: dict[str, bytes] | None = None,
        allow_build: bool = True,
    ) -> None:
        self.assets = assets or {}
        self.build_files = build_files or {}
        self.allow_build = allow_build
        self.build_calls = 0
        self.commands: list[list[str]] = []

    def __call__(self, cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        self.commands.append(cmd)
        if cmd[:3] == ["gh", "release", "view"]:
            assert cmd[3] == TAG
            stdout = "".join(f"{name}\n" for name in sorted(self.assets))
            return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
        if cmd[:3] == ["gh", "release", "download"]:
            assert cmd[3] == TAG
            name = cmd[cmd.index("--pattern") + 1]
            dest_dir = Path(cmd[cmd.index("--dir") + 1])
            (dest_dir / name).write_bytes(self.assets[name])
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[0] == sys.executable and Path(cmd[1]).name == "build_engine_distributions.py":
            if not self.allow_build:
                pytest.fail(f"build must not be invoked, got: {cmd}")
            self.build_calls += 1
            assert kwargs["env"]["SOURCE_DATE_EPOCH"] == "946684800"
            out_dir = Path(cmd[cmd.index("--out-dir") + 1])
            for name, data in self.build_files.items():
                (out_dir / name).write_bytes(data)
            return subprocess.CompletedProcess(cmd, 0)
        pytest.fail(f"unexpected command: {cmd}")
        raise AssertionError


def _no_subprocess(cmd: list[str], **_kwargs) -> subprocess.CompletedProcess:
    pytest.fail(f"no subprocess expected, got: {cmd}")
    raise AssertionError


def _distribution_bytes(prefix: bytes = b"bytes") -> dict[str, bytes]:
    return {
        name: prefix + b":" + name.encode()
        for name in prd.expected_filenames(VERSION)
    }


def test_all_files_on_pypi_downloaded_and_not_published(tmp_path):
    names = prd.expected_filenames(VERSION)
    contents = _distribution_bytes(b"pypi")
    dist = tmp_path / "dist"

    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        dist,
        opener=_make_opener(contents),
        runner=_no_subprocess,
    )

    for name in names:
        assert (dist / name).read_bytes() == contents[name]
        assert result[name] == {"source": "pypi", "publish": False}


def test_nothing_anywhere_builds_once_and_publishes_all(tmp_path):
    build_files = _distribution_bytes(b"built")
    dist = tmp_path / "dist"
    runner = _Runner(assets={}, build_files=build_files)

    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        dist,
        engine_dir=tmp_path / "engine",
        opengrep_dir=tmp_path / "opengrep",
        opener=_make_opener({}),
        runner=runner,
    )

    assert runner.build_calls == 1
    for name, data in build_files.items():
        assert (dist / name).read_bytes() == data
        assert result[name] == {"source": "built", "publish": True}


def test_build_requires_promoted_engine_payload(tmp_path):
    runner = _Runner(assets={}, build_files=_distribution_bytes(b"built"))

    with pytest.raises(
        prd.AcquisitionError,
        match="Grype and Opengrep payloads are required",
    ):
        prd.acquire(
            VERSION,
            TAG,
            tmp_path / "src",
            tmp_path / "dist",
            opener=_make_opener({}),
            runner=runner,
        )

    assert runner.build_calls == 0


def test_wheels_on_pypi_sdist_from_release_asset_no_build(tmp_path):
    wheels = prd.expected_wheel_filenames(VERSION)
    sdist = prd.expected_filenames(VERSION)[-1]
    pypi_wheels = {name: f"pypi:{name}".encode() for name in wheels}
    asset_sdist = b"checkpointed-sdist-bytes"
    dist = tmp_path / "dist"
    runner = _Runner(assets={sdist: asset_sdist}, allow_build=False)

    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        dist,
        opener=_make_opener(pypi_wheels),
        runner=runner,
    )

    assert runner.build_calls == 0
    for wheel in wheels:
        assert (dist / wheel).read_bytes() == pypi_wheels[wheel]
        assert result[wheel] == {"source": "pypi", "publish": False}
    assert (dist / sdist).read_bytes() == asset_sdist
    assert result[sdist] == {"source": "release-asset", "publish": True}


def test_build_fills_wheel_without_overwriting_pypi_sdist(tmp_path):
    wheels = prd.expected_wheel_filenames(VERSION)
    sdist = prd.expected_filenames(VERSION)[-1]
    pypi_sdist = b"canonical-pypi-sdist-bytes"
    rebuilt_sdist = b"rebuilt-sdist-with-different-bytes"
    assert pypi_sdist != rebuilt_sdist
    dist = tmp_path / "dist"
    runner = _Runner(
        assets={},
        build_files={
            **{name: f"built:{name}".encode() for name in wheels},
            sdist: rebuilt_sdist,
        },
    )

    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        dist,
        engine_dir=tmp_path / "engine",
        opengrep_dir=tmp_path / "opengrep",
        opener=_make_opener({sdist: pypi_sdist}),
        runner=runner,
    )

    assert runner.build_calls == 1
    assert (dist / sdist).read_bytes() == pypi_sdist
    assert result[sdist] == {"source": "pypi", "publish": False}
    for wheel in wheels:
        assert result[wheel] == {"source": "built", "publish": True}


def test_pypi_download_hash_mismatch_is_fatal(tmp_path):
    wheel = prd.expected_wheel_filenames(VERSION)[0]
    contents = _distribution_bytes(b"declared")
    dist = tmp_path / "dist"

    with pytest.raises(prd.AcquisitionError, match="sha256 mismatch") as excinfo:
        prd.acquire(
            VERSION,
            TAG,
            tmp_path / "src",
            dist,
            opener=_make_opener(contents, served_overrides={wheel: b"tampered-bytes"}),
            runner=_no_subprocess,
        )

    assert wheel in str(excinfo.value)
    assert not (dist / wheel).exists()


def test_gh_release_view_failure_is_fatal(tmp_path):
    def failing_runner(cmd, **_kwargs):
        assert cmd[:3] == ["gh", "release", "view"]
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="release not found")

    with pytest.raises(prd.AcquisitionError, match="gh release view failed"):
        prd.acquire(
            VERSION,
            TAG,
            tmp_path / "src",
            tmp_path / "dist",
            opener=_make_opener({}),
            runner=failing_runner,
        )


def test_main_writes_github_output_lines(tmp_path, monkeypatch, capsys):
    wheels = prd.expected_wheel_filenames(VERSION)
    sdist = prd.expected_filenames(VERSION)[-1]
    wheel_bytes = {name: f"pypi:{name}".encode() for name in wheels}

    def fake_fetch(version, **_kwargs):
        assert version == VERSION
        return {
            name: {
                "sha256": _sha256(data),
                "url": f"https://example.invalid/{name}",
            }
            for name, data in wheel_bytes.items()
        }

    def fake_download_url(url, dest, **_kwargs):
        dest.write_bytes(wheel_bytes[dest.name])

    def fake_build(
        version, release_src, engine_dir, opengrep_dir, out_dir, runner=None
    ):
        assert version == VERSION
        (out_dir / sdist).write_bytes(b"built-sdist-bytes")

    monkeypatch.setattr(prd, "fetch_pypi_files", fake_fetch)
    monkeypatch.setattr(prd, "download_url", fake_download_url)
    monkeypatch.setattr(prd, "list_release_assets", lambda tag, runner=None: set())
    monkeypatch.setattr(prd, "build_distributions", fake_build)
    output_file = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    rc = prd.main(
        [
            "--version",
            VERSION,
            "--tag",
            TAG,
            "--release-src",
            str(tmp_path / "src"),
            "--engine-dir",
            str(tmp_path / "engine"),
            "--opengrep-dir",
            str(tmp_path / "opengrep"),
            "--dist-dir",
            str(tmp_path / "dist"),
        ],
    )

    assert rc == 0
    lines = output_file.read_text().splitlines()
    assert "wheel_publish=false" in lines
    assert "sdist_publish=true" in lines
    assert "wheel_source=pypi" in lines
    assert "sdist_source=built" in lines
    stdout = capsys.readouterr().out
    assert f"{wheels[0]}: source=pypi" in stdout
    assert f"{sdist}: source=built" in stdout


def test_build_output_missing_wheel_is_fatal(tmp_path, monkeypatch, capsys):
    names = prd.expected_filenames(VERSION)
    missing_wheel = names[0]
    sdist = names[-1]
    runner = _Runner(
        assets={},
        build_files={name: f"built:{name}".encode() for name in names[1:]},
    )

    with pytest.raises(prd.AcquisitionError, match="build output is missing") as excinfo:
        prd.acquire(
            VERSION,
            TAG,
            tmp_path / "src",
            tmp_path / "dist",
            engine_dir=tmp_path / "engine",
            opengrep_dir=tmp_path / "opengrep",
            opener=_make_opener({}),
            runner=runner,
        )
    assert missing_wheel in str(excinfo.value)

    monkeypatch.setattr(prd, "fetch_pypi_files", lambda version, **_kwargs: {})
    monkeypatch.setattr(prd, "list_release_assets", lambda tag, runner=None: set())
    monkeypatch.setattr(
        prd,
        "build_distributions",
        lambda version, release_src, engine_dir, opengrep_dir, out_dir, runner=None: (
            out_dir / sdist
        ).write_bytes(b"s"),
    )
    rc = prd.main(
        [
            "--version",
            VERSION,
            "--tag",
            TAG,
            "--release-src",
            str(tmp_path / "src"),
            "--engine-dir",
            str(tmp_path / "engine"),
            "--opengrep-dir",
            str(tmp_path / "opengrep"),
            "--dist-dir",
            str(tmp_path / "dist2"),
        ],
    )
    assert rc == 1
    assert "build output is missing" in capsys.readouterr().err


def test_no_build_fails_when_a_build_would_be_needed(tmp_path):
    # Nothing on PyPI and no release assets: with allow_build=False the
    # acquisition must fail instead of building from an unanchored source.
    runner = _Runner(assets={}, allow_build=False)
    with pytest.raises(prd.AcquisitionError, match="trusted source anchor"):
        prd.acquire(
            VERSION,
            TAG,
            tmp_path / "src",
            tmp_path / "dist",
            opener=_make_opener({}),
            runner=runner,
            allow_build=False,
        )
    assert runner.build_calls == 0


def test_no_build_passes_when_everything_is_on_pypi(tmp_path):
    contents = _distribution_bytes()
    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        tmp_path / "dist",
        opener=_make_opener(contents),
        runner=_Runner(allow_build=False),
        allow_build=False,
    )
    assert all(not info["publish"] for info in result.values())
