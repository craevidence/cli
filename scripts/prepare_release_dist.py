"""Release distribution acquirer.

Fills a dist directory with the canonical bytes of the two distributions for
package ``craevidence`` at ``VERSION``:

  - craevidence-VERSION-py3-none-any.whl
  - craevidence-VERSION.tar.gz

PyPI is immutable, so a file already listed there is canonical and must not be
rebuilt (an sdist rebuild produces different bytes). Each file is acquired from
the first available source, in order:

  1. PyPI: download and verify content integrity by sha256 against the digest
     PyPI declares (this does not verify provenance or attestations). The file
     does not need publishing.
  2. GitHub release asset with the exact filename, downloaded via ``gh``. The
     file needs publishing.
  3. Build from the release source checkout with ``python -m build`` and
     SOURCE_DATE_EPOCH pinned. Built files need publishing. The build runs at
     most once, into a temporary directory, and only the still-missing files
     are copied so previously acquired files are never overwritten.

When the GITHUB_OUTPUT environment variable is set, the publish decision is
written there as ``wheel_publish=true|false`` and ``sdist_publish=true|false``
(true means the file is not on PyPI and must be published).

With ``--no-build``, a distribution available neither on PyPI nor as a release
asset is an error instead of a build: callers use this when the release source
has no trusted anchor and freshly built bytes would be unverifiable.

Run: python scripts/prepare_release_dist.py --version X.Y.Z --tag vX.Y.Z \
    --release-src release-src --dist-dir dist
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

PACKAGE = "craevidence"
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"
REQUEST_TIMEOUT = 30
SOURCE_DATE_EPOCH = "946684800"

# Injection points so acquisition can be exercised without network or
# subprocesses. Tests replace these per call; production uses the defaults.
DEFAULT_OPENER = urllib.request.urlopen
DEFAULT_RUNNER = subprocess.run


class AcquisitionError(Exception):
    """A distribution could not be acquired or failed integrity checks."""


def expected_filenames(version: str) -> tuple[str, str]:
    """Return the wheel and sdist filenames for the given version."""
    wheel = f"{PACKAGE}-{version}-py3-none-any.whl"
    sdist = f"{PACKAGE}-{version}.tar.gz"
    return wheel, sdist


def sha256_file(path: Path) -> str:
    """Return the sha256 hex digest of the file at path."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_pypi_files(
    version: str,
    *,
    opener=DEFAULT_OPENER,
    timeout: int = REQUEST_TIMEOUT,
) -> dict[str, dict[str, str]]:
    """Return filename -> {"sha256", "url"} for the version's files on PyPI.

    Only the two expected filenames are returned. HTTP 404 means the version
    has no files on PyPI yet and yields an empty dict; any other HTTP error is
    fatal.
    """
    url = PYPI_JSON_URL.format(package=PACKAGE, version=version)
    try:
        with opener(url, timeout=timeout) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        msg = f"PyPI request failed for {url}: HTTP {error.code}"
        raise AcquisitionError(msg) from error
    data = json.loads(payload)
    expected = set(expected_filenames(version))
    result: dict[str, dict[str, str]] = {}
    for entry in data.get("urls", []):
        filename = entry.get("filename")
        if filename in expected:
            result[filename] = {
                "sha256": entry.get("digests", {}).get("sha256", ""),
                "url": entry.get("url", ""),
            }
    return result


def download_url(
    url: str,
    dest: Path,
    *,
    opener=DEFAULT_OPENER,
    timeout: int = REQUEST_TIMEOUT,
) -> None:
    """Stream the response for url into dest."""
    with opener(url, timeout=timeout) as response, dest.open("wb") as handle:
        for chunk in iter(lambda: response.read(65536), b""):
            handle.write(chunk)


def list_release_assets(tag: str, runner=DEFAULT_RUNNER) -> set[str]:
    """Return the asset filenames attached to the GitHub release for tag."""
    result = runner(  # noqa: S603
        ["gh", "release", "view", tag, "--json", "assets", "--jq", ".assets[].name"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        msg = f"gh release view failed for {tag}: {result.stderr.strip()}"
        raise AcquisitionError(msg)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def download_release_asset(
    tag: str,
    name: str,
    dest_dir: Path,
    runner=DEFAULT_RUNNER,
) -> None:
    """Download the named asset from the GitHub release for tag into dest_dir."""
    result = runner(  # noqa: S603
        ["gh", "release", "download", tag, "--pattern", name, "--dir", str(dest_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        msg = f"gh release download failed for {name}: {result.stderr.strip()}"
        raise AcquisitionError(msg)
    if not (dest_dir / name).is_file():
        msg = f"gh release download did not produce {name}"
        raise AcquisitionError(msg)


def build_distributions(
    release_src: str | os.PathLike[str],
    out_dir: Path,
    runner=DEFAULT_RUNNER,
) -> None:
    """Build the wheel and sdist from release_src into out_dir.

    SOURCE_DATE_EPOCH is pinned so the wheel build is byte-reproducible.
    """
    env = {**os.environ, "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}
    result = runner(  # noqa: S603
        [sys.executable, "-m", "build", "--outdir", str(out_dir), str(release_src)],
        env=env,
        check=False,
    )
    if result.returncode != 0:
        msg = f"python -m build failed with exit code {result.returncode}"
        raise AcquisitionError(msg)


def acquire(
    version: str,
    tag: str,
    release_src: str | os.PathLike[str],
    dist_dir: str | os.PathLike[str],
    *,
    opener=DEFAULT_OPENER,
    runner=DEFAULT_RUNNER,
    allow_build: bool = True,
) -> dict[str, dict]:
    """Acquire both distributions into dist_dir and decide publishing.

    Returns filename -> {"source": "pypi" | "release-asset" | "built",
    "publish": bool}. Raises AcquisitionError on any failure, including a
    sha256 mismatch against PyPI's declared digest or an expected file that is
    still missing after all sources are exhausted.
    """
    dist = Path(dist_dir)
    dist.mkdir(parents=True, exist_ok=True)
    names = expected_filenames(version)
    result: dict[str, dict] = {}

    pypi_files = fetch_pypi_files(version, opener=opener)
    for name in names:
        if name not in pypi_files:
            continue
        dest = dist / name
        download_url(pypi_files[name]["url"], dest, opener=opener)
        declared = pypi_files[name]["sha256"]
        actual = sha256_file(dest)
        if actual != declared:
            dest.unlink()
            msg = f"sha256 mismatch for {name}: downloaded {actual}, PyPI declares {declared}"
            raise AcquisitionError(msg)
        result[name] = {"source": "pypi", "publish": False}

    missing = [name for name in names if name not in result]
    if missing:
        assets = list_release_assets(tag, runner=runner)
        for name in list(missing):
            if name not in assets:
                continue
            download_release_asset(tag, name, dist, runner=runner)
            result[name] = {"source": "release-asset", "publish": True}
            missing.remove(name)

    if missing:
        if not allow_build:
            names_list = ", ".join(missing)
            msg = (
                f"{names_list} available neither on PyPI nor as release assets, "
                "and building is not allowed without a trusted source anchor"
            )
            raise AcquisitionError(msg)
        with tempfile.TemporaryDirectory() as build_out:
            out = Path(build_out)
            build_distributions(release_src, out, runner=runner)
            for name in missing:
                built = out / name
                if not built.is_file():
                    msg = f"build output is missing {name}"
                    raise AcquisitionError(msg)
                shutil.copy2(built, dist / name)
                result[name] = {"source": "built", "publish": True}

    for name in names:
        if not (dist / name).is_file():
            msg = f"expected distribution still missing after acquisition: {name}"
            raise AcquisitionError(msg)
    return result


def write_github_output(version: str, result: dict[str, dict]) -> None:
    """Append the publish decisions to the file named by GITHUB_OUTPUT, if set."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    wheel, sdist = expected_filenames(version)
    lines = (
        f"wheel_publish={str(result[wheel]['publish']).lower()}\n"
        f"sdist_publish={str(result[sdist]['publish']).lower()}\n"
        f"wheel_source={result[wheel]['source']}\n"
        f"sdist_source={result[sdist]['source']}\n"
    )
    with Path(output_path).open("a", encoding="utf-8") as handle:
        handle.write(lines)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Acquire the canonical release distributions into a dist directory.",
    )
    parser.add_argument("--version", required=True, help="Release version, for example 3.8.1.")
    parser.add_argument("--tag", required=True, help="Git release tag, for example v3.8.1.")
    parser.add_argument(
        "--release-src",
        required=True,
        help="Path to the release source checkout used if a build is needed.",
    )
    parser.add_argument(
        "--dist-dir",
        default="dist",
        help="Directory that receives the two distributions.",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help=(
            "Fail instead of building when a distribution is available neither "
            "on PyPI nor as a release asset (used when the source has no "
            "trusted anchor)."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        result = acquire(
            args.version,
            args.tag,
            args.release_src,
            args.dist_dir,
            allow_build=not args.no_build,
        )
    except AcquisitionError as error:
        sys.stderr.write(f"release dist preparation failed: {error}\n")
        return 1
    for name in expected_filenames(args.version):
        info = result[name]
        decision = "publish" if info["publish"] else "already on PyPI"
        sys.stdout.write(f"{name}: source={info['source']} decision={decision}\n")
    write_github_output(args.version, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
