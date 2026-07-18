"""PyPI release verifier.

Checks that the two expected distributions for a released version are served by
PyPI with a sha256 that matches the locally built files. For package
``craevidence`` at ``VERSION`` the two distributions are exactly:

  - craevidence-VERSION-py3-none-any.whl
  - craevidence-VERSION.tar.gz

Only those two names are considered locally: any other files in the local dist
directory (for example publish sidecar files) are ignored. On PyPI the served
set must be exactly those two distributions, so an unexpected distribution
filename is a failure. This verifies availability and content integrity by
sha256 only. It does not verify provenance or attestations.

Run: python scripts/verify_pypi_release.py --version X.Y.Z
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PACKAGE = "craevidence"
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"

# Injection points so main can be exercised without network. Tests replace
# these on the module; production uses the standard library defaults.
DEFAULT_OPENER = urllib.request.urlopen
DEFAULT_SLEEP = time.sleep
FETCH_ATTEMPTS = 6
RETRY_DELAY = 20
REQUEST_TIMEOUT = 30


class VerificationError(Exception):
    """A release did not match the expected distributions or hashes."""


class MissingOnPyPIError(VerificationError):
    """An expected distribution is not yet listed on PyPI (retryable)."""


class HashMismatchError(VerificationError):
    """An expected distribution has a different sha256 on PyPI (not retryable)."""


def expected_filenames(version: str) -> tuple[str, str]:
    """Return the wheel and sdist filenames for the given version."""
    wheel = f"{PACKAGE}-{version}-py3-none-any.whl"
    sdist = f"{PACKAGE}-{version}.tar.gz"
    return wheel, sdist


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_sha256(dist_dir: str | os.PathLike[str], version: str) -> dict[str, str]:
    """Return sha256 for only the two expected files found in dist_dir.

    Raises VerificationError naming any expected file that is absent. Files in
    dist_dir other than the two expected names are never read.
    """
    base = Path(dist_dir)
    result: dict[str, str] = {}
    for filename in expected_filenames(version):
        path = base / filename
        if not path.is_file():
            msg = f"missing local distribution: {path}"
            raise VerificationError(msg)
        result[filename] = _sha256_file(path)
    return result


def pypi_sha256(pypi_data: dict, version: str) -> dict[str, str]:
    """Return filename -> sha256 from pypi_data, restricted to expected files."""
    expected = set(expected_filenames(version))
    result: dict[str, str] = {}
    for entry in pypi_data.get("urls", []):
        filename = entry.get("filename")
        if filename in expected:
            result[filename] = entry.get("digests", {}).get("sha256", "")
    return result


def verify(version: str, dist_dir: str | os.PathLike[str], pypi_data: dict) -> None:
    """Verify PyPI serves exactly the two expected distributions with matching bytes.

    Raises VerificationError if a local file is missing or PyPI serves an
    unexpected distribution, HashMismatchError if a present distribution has a
    different sha256, or MissingOnPyPIError if an expected distribution is not
    yet listed on PyPI. Returns None on success.
    """
    local = local_sha256(dist_dir, version)
    remote = pypi_sha256(pypi_data, version)
    expected = expected_filenames(version)

    # PyPI must serve nothing beyond the two expected distributions for this
    # version. Attestation sidecars are not listed as distributions, so this
    # stays strict without being tripped by them.
    remote_all = {
        entry.get("filename")
        for entry in pypi_data.get("urls", [])
        if entry.get("filename")
    }
    unexpected = remote_all - set(expected)
    if unexpected:
        names = ", ".join(sorted(unexpected))
        msg = f"PyPI serves unexpected distributions for {version}: {names}"
        raise VerificationError(msg)

    # Fail fast on any present distribution whose hash differs, before treating
    # an absent distribution as a retryable propagation gap.
    for filename in expected:
        if filename in remote and remote[filename] and remote[filename] != local[filename]:
            msg = (
                f"sha256 mismatch for {filename}: "
                f"local {local[filename]} vs PyPI {remote[filename]}"
            )
            raise HashMismatchError(msg)
    for filename in expected:
        if filename not in remote or not remote[filename]:
            msg = f"expected distribution not yet on PyPI: {filename}"
            raise MissingOnPyPIError(msg)


def fetch_pypi_json(
    version: str,
    *,
    opener=urllib.request.urlopen,
    attempts: int = 6,
    sleep=time.sleep,
    delay: int = 20,
    timeout: int = REQUEST_TIMEOUT,
) -> dict:
    """Fetch and parse the PyPI JSON for the version.

    Retries on HTTP 404 up to attempts, since the version JSON may not be
    published yet. Each request is bounded by timeout seconds. Raises
    VerificationError once attempts are exhausted.
    """
    url = PYPI_JSON_URL.format(package=PACKAGE, version=version)
    last_error: str = ""
    for attempt in range(1, attempts + 1):
        try:
            with opener(url, timeout=timeout) as response:
                payload = response.read()
            return json.loads(payload)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                msg = f"PyPI request failed for {url}: HTTP {error.code}"
                raise VerificationError(msg) from error
            last_error = f"HTTP 404 for {url}"
        if attempt < attempts:
            sleep(delay)
    msg = f"version JSON not available after {attempts} attempts: {last_error}"
    raise VerificationError(msg)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    default_version = os.environ.get("RELEASE_TAG", "").lstrip("v")
    parser = argparse.ArgumentParser(
        description="Verify a released version on PyPI matches local dist files.",
    )
    parser.add_argument(
        "--version",
        default=default_version,
        help="Version to verify (defaults to RELEASE_TAG with a leading v stripped).",
    )
    parser.add_argument(
        "--dist-dir",
        default="dist",
        help="Directory containing the locally built distributions.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    version = args.version
    if not version:
        sys.stderr.write("no version given: pass --version or set RELEASE_TAG\n")
        return 1

    attempts = FETCH_ATTEMPTS
    delay = RETRY_DELAY
    for attempt in range(1, attempts + 1):
        try:
            pypi_data = fetch_pypi_json(
                version,
                opener=DEFAULT_OPENER,
                attempts=attempts,
                sleep=DEFAULT_SLEEP,
                delay=delay,
            )
            verify(version, args.dist_dir, pypi_data)
        except MissingOnPyPIError as error:
            if attempt < attempts:
                DEFAULT_SLEEP(delay)
                continue
            sys.stderr.write(f"verification failed: {error}\n")
            return 1
        except VerificationError as error:
            sys.stderr.write(f"verification failed: {error}\n")
            return 1
        else:
            wheel, sdist = expected_filenames(version)
            sys.stdout.write(
                f"verified {PACKAGE} {version} on PyPI: {wheel} and {sdist} "
                f"match local sha256\n",
            )
            return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
