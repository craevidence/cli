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
    """Fake subprocess runner for gh release view/download and python -m build."""

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
        if cmd[0] == sys.executable and cmd[1:3] == ["-m", "build"]:
            if not self.allow_build:
                pytest.fail(f"build must not be invoked, got: {cmd}")
            self.build_calls += 1
            assert kwargs["env"]["SOURCE_DATE_EPOCH"] == "946684800"
            out_dir = Path(cmd[cmd.index("--outdir") + 1])
            for name, data in self.build_files.items():
                (out_dir / name).write_bytes(data)
            return subprocess.CompletedProcess(cmd, 0)
        pytest.fail(f"unexpected command: {cmd}")
        raise AssertionError


def _no_subprocess(cmd: list[str], **_kwargs) -> subprocess.CompletedProcess:
    pytest.fail(f"no subprocess expected, got: {cmd}")
    raise AssertionError


def test_both_files_on_pypi_downloaded_and_not_published(tmp_path):
    wheel, sdist = prd.expected_filenames(VERSION)
    contents = {wheel: b"pypi-wheel-bytes", sdist: b"pypi-sdist-bytes"}
    dist = tmp_path / "dist"

    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        dist,
        opener=_make_opener(contents),
        runner=_no_subprocess,
    )

    assert (dist / wheel).read_bytes() == contents[wheel]
    assert (dist / sdist).read_bytes() == contents[sdist]
    assert result[wheel] == {"source": "pypi", "publish": False}
    assert result[sdist] == {"source": "pypi", "publish": False}


def test_nothing_anywhere_builds_once_and_publishes_both(tmp_path):
    wheel, sdist = prd.expected_filenames(VERSION)
    build_files = {wheel: b"built-wheel-bytes", sdist: b"built-sdist-bytes"}
    dist = tmp_path / "dist"
    runner = _Runner(assets={}, build_files=build_files)

    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        dist,
        opener=_make_opener({}),
        runner=runner,
    )

    assert runner.build_calls == 1
    assert (dist / wheel).read_bytes() == build_files[wheel]
    assert (dist / sdist).read_bytes() == build_files[sdist]
    assert result[wheel] == {"source": "built", "publish": True}
    assert result[sdist] == {"source": "built", "publish": True}


def test_wheel_on_pypi_sdist_from_release_asset_no_build(tmp_path):
    wheel, sdist = prd.expected_filenames(VERSION)
    asset_sdist = b"checkpointed-sdist-bytes"
    dist = tmp_path / "dist"
    runner = _Runner(assets={sdist: asset_sdist}, allow_build=False)

    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        dist,
        opener=_make_opener({wheel: b"pypi-wheel-bytes"}),
        runner=runner,
    )

    assert runner.build_calls == 0
    assert (dist / wheel).read_bytes() == b"pypi-wheel-bytes"
    assert (dist / sdist).read_bytes() == asset_sdist
    assert result[wheel] == {"source": "pypi", "publish": False}
    assert result[sdist] == {"source": "release-asset", "publish": True}


def test_build_fills_wheel_without_overwriting_pypi_sdist(tmp_path):
    wheel, sdist = prd.expected_filenames(VERSION)
    pypi_sdist = b"canonical-pypi-sdist-bytes"
    rebuilt_sdist = b"rebuilt-sdist-with-different-bytes"
    assert pypi_sdist != rebuilt_sdist
    dist = tmp_path / "dist"
    runner = _Runner(
        assets={},
        build_files={wheel: b"built-wheel-bytes", sdist: rebuilt_sdist},
    )

    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        dist,
        opener=_make_opener({sdist: pypi_sdist}),
        runner=runner,
    )

    assert runner.build_calls == 1
    assert (dist / sdist).read_bytes() == pypi_sdist
    assert (dist / wheel).read_bytes() == b"built-wheel-bytes"
    assert result[sdist] == {"source": "pypi", "publish": False}
    assert result[wheel] == {"source": "built", "publish": True}


def test_pypi_download_hash_mismatch_is_fatal(tmp_path):
    wheel, sdist = prd.expected_filenames(VERSION)
    contents = {wheel: b"declared-wheel-bytes", sdist: b"pypi-sdist-bytes"}
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
    wheel, sdist = prd.expected_filenames(VERSION)
    wheel_bytes = b"pypi-wheel-bytes"

    def fake_fetch(version, **_kwargs):
        assert version == VERSION
        return {wheel: {"sha256": _sha256(wheel_bytes), "url": "https://example.invalid/w"}}

    def fake_download_url(url, dest, **_kwargs):
        assert url == "https://example.invalid/w"
        dest.write_bytes(wheel_bytes)

    def fake_build(release_src, out_dir, runner=None):
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
    assert f"{wheel}: source=pypi" in stdout
    assert f"{sdist}: source=built" in stdout


def test_build_output_missing_wheel_is_fatal(tmp_path, monkeypatch, capsys):
    _wheel, sdist = prd.expected_filenames(VERSION)
    runner = _Runner(assets={}, build_files={sdist: b"built-sdist-bytes"})

    with pytest.raises(prd.AcquisitionError, match="build output is missing"):
        prd.acquire(
            VERSION,
            TAG,
            tmp_path / "src",
            tmp_path / "dist",
            opener=_make_opener({}),
            runner=runner,
        )

    monkeypatch.setattr(prd, "fetch_pypi_files", lambda version, **_kwargs: {})
    monkeypatch.setattr(prd, "list_release_assets", lambda tag, runner=None: set())
    monkeypatch.setattr(
        prd,
        "build_distributions",
        lambda release_src, out_dir, runner=None: (out_dir / sdist).write_bytes(b"s"),
    )
    rc = prd.main(
        [
            "--version",
            VERSION,
            "--tag",
            TAG,
            "--release-src",
            str(tmp_path / "src"),
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
    wheel, sdist = prd.expected_filenames(VERSION)
    contents = {wheel: b"wheel-bytes", sdist: b"sdist-bytes"}
    result = prd.acquire(
        VERSION,
        TAG,
        tmp_path / "src",
        tmp_path / "dist",
        opener=_make_opener(contents),
        runner=_Runner(allow_build=False),
        allow_build=False,
    )
    assert result[wheel]["publish"] is False
    assert result[sdist]["publish"] is False
