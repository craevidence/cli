"""PyPI release verifier.

Checks that the two expected distributions for a released version are served by
PyPI with a sha256 that matches the locally built files. For package
``craevidence`` at ``VERSION`` the two distributions are exactly:

  - craevidence-VERSION-py3-none-any.whl
  - craevidence-VERSION.tar.gz

Only those two names are considered locally: any other files in the local dist
directory (for example publish sidecar files) are ignored. On PyPI the served
set must be exactly those two distributions, so an unexpected distribution
filename is a failure.

This verifies availability, content integrity by sha256, and PyPI Trusted
Publishing provenance binding: for each distribution it fetches the PyPI
integrity provenance, requires provenance version 1, searches every
attestation bundle for the expected publisher (GitHub repository, workflow,
environment), and searches every attestation in the matching bundles for an
in-toto statement whose subject names the file with the locally computed
sha256. With --attestations-dir it additionally requires each
{filename}.publish.attestation release asset to equal one of the
attestations PyPI accepted for that file. It does not verify Sigstore
bundle signatures.

Run: python scripts/verify_pypi_release.py --version X.Y.Z
"""

from __future__ import annotations

import argparse
import base64
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
PYPI_PROVENANCE_URL = "https://pypi.org/integrity/{package}/{version}/{filename}/provenance"
DEFAULT_REPOSITORY = "craevidence/cli"
EXPECTED_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
EXPECTED_PREDICATE_TYPE = "https://docs.pypi.org/attestations/publish/v1"
EXPECTED_PROVENANCE_VERSION = 1

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


class ProvenanceError(VerificationError):
    """A distribution's PyPI provenance does not match expectations (not retryable)."""


class ProvenanceNotAvailableError(MissingOnPyPIError):
    """A distribution's PyPI provenance is not yet published (retryable)."""


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


def fetch_provenance(
    version: str,
    filename: str,
    *,
    opener=urllib.request.urlopen,
    timeout: int = REQUEST_TIMEOUT,
) -> dict:
    """Fetch and parse the PyPI integrity provenance for one distribution.

    Raises ProvenanceNotAvailableError on HTTP 404 (the provenance may not be
    published yet, so callers may retry) and VerificationError on any other
    HTTP error. Each request is bounded by timeout seconds.
    """
    url = PYPI_PROVENANCE_URL.format(package=PACKAGE, version=version, filename=filename)
    try:
        with opener(url, timeout=timeout) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            msg = f"provenance not yet on PyPI for {filename}"
            raise ProvenanceNotAvailableError(msg) from error
        msg = f"PyPI provenance request failed for {url}: HTTP {error.code}"
        raise VerificationError(msg) from error
    return json.loads(payload)


def _expected_publisher(repository: str) -> dict[str, str]:
    return {
        "kind": "GitHub",
        "repository": repository,
        "workflow": "ci.yml",
        "environment": "pypi",
    }


def _matching_bundles(provenance: dict, repository: str) -> list[dict]:
    """Return the attestation bundles whose publisher matches exactly."""
    expected = _expected_publisher(repository)
    matched = []
    for bundle in provenance.get("attestation_bundles") or []:
        publisher = bundle.get("publisher") or {}
        if all(publisher.get(key) == value for key, value in expected.items()):
            matched.append(bundle)
    return matched


def _statement_mismatch(attestation: dict, filename: str, local_sha256_hex: str) -> str | None:
    """Return why the attestation's statement does not match, or None on a match."""
    encoded_statement = (attestation.get("envelope") or {}).get("statement", "")
    try:
        statement = json.loads(base64.b64decode(encoded_statement))
    except (ValueError, TypeError) as error:
        return f"statement does not decode: {error}"
    if not isinstance(statement, dict):
        return "decoded statement is not a JSON object"
    if statement.get("_type") != EXPECTED_STATEMENT_TYPE:
        return f"statement type is {statement.get('_type')!r}"
    if statement.get("predicateType") != EXPECTED_PREDICATE_TYPE:
        return f"predicate type is {statement.get('predicateType')!r}"
    expected_subject = [{"name": filename, "digest": {"sha256": local_sha256_hex}}]
    if statement.get("subject") != expected_subject:
        return f"subject is {statement.get('subject')!r}"
    return None


def _bounded(items: list[str], limit: int = 5, width: int = 300) -> str:
    """Join items for an error message, capping count and per-item length."""
    shown = [item if len(item) <= width else item[:width] + "..." for item in items[:limit]]
    text = "; ".join(shown)
    remaining = len(items) - len(shown)
    if remaining > 0:
        text += f"; and {remaining} more"
    return text


def verify_provenance(
    provenance: dict,
    filename: str,
    local_sha256_hex: str,
    repository: str,
) -> None:
    """Verify one distribution's PyPI provenance against local facts.

    Requires the provenance version to be 1. Searches every attestation
    bundle for a publisher matching the GitHub Trusted Publisher for the
    given repository (workflow ci.yml, environment pypi), then searches
    every attestation in the matching bundles for an in-toto PyPI publish
    statement whose subject is exactly the given filename with the given
    sha256. Raises ProvenanceError when the version is wrong, no bundle has
    the expected publisher, or no attestation carries a matching statement.
    Does not verify the Sigstore bundle signatures.
    """
    version = provenance.get("version")
    if version != EXPECTED_PROVENANCE_VERSION:
        msg = (
            f"unsupported provenance version for {filename}: "
            f"{version!r}, expected {EXPECTED_PROVENANCE_VERSION}"
        )
        raise ProvenanceError(msg)

    bundles = provenance.get("attestation_bundles") or []
    if not bundles:
        msg = f"no attestation bundles in provenance for {filename}"
        raise ProvenanceError(msg)

    matched = _matching_bundles(provenance, repository)
    if not matched:
        expected = _expected_publisher(repository)
        present = [
            repr({key: (bundle.get("publisher") or {}).get(key) for key in expected})
            for bundle in bundles
        ]
        msg = (
            f"no provenance bundle for {filename} has the expected publisher "
            f"{expected!r}; publishers present: {_bounded(present)}"
        )
        raise ProvenanceError(msg)

    checked = 0
    reasons: list[str] = []
    for bundle in matched:
        for attestation in bundle.get("attestations") or []:
            checked += 1
            reason = _statement_mismatch(attestation, filename, local_sha256_hex)
            if reason is None:
                return
            reasons.append(reason)
    if checked == 0:
        msg = f"no attestations in provenance bundle for {filename}"
        raise ProvenanceError(msg)
    msg = (
        f"no matching publish attestation for {filename}: checked {checked} "
        f"attestation(s) in {len(matched)} matching bundle(s): {_bounded(reasons)}"
    )
    raise ProvenanceError(msg)


def verify_attestation_asset(
    provenance: dict,
    filename: str,
    repository: str,
    attestations_dir: str | os.PathLike[str],
) -> None:
    """Verify a downloaded attestation asset equals one PyPI accepted.

    Loads {filename}.publish.attestation from attestations_dir as JSON and
    requires it to be equal to one of the attestations in the provenance
    bundles whose publisher matches the given repository. Raises
    ProvenanceError when the file is missing, is not valid JSON, or equals
    none of the accepted attestations.
    """
    path = Path(attestations_dir) / f"{filename}.publish.attestation"
    if not path.is_file():
        msg = f"missing attestation asset: {path}"
        raise ProvenanceError(msg)
    try:
        asset = json.loads(path.read_text())
    except ValueError as error:
        msg = f"attestation asset {path} is not valid JSON: {error}"
        raise ProvenanceError(msg) from error
    for bundle in _matching_bundles(provenance, repository):
        if any(attestation == asset for attestation in bundle.get("attestations") or []):
            return
    msg = (
        f"attestation asset {path} does not equal any attestation "
        f"PyPI accepted for {filename}"
    )
    raise ProvenanceError(msg)


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
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPOSITORY,
        help=(
            "GitHub repository expected in the provenance publisher "
            f"(defaults to GITHUB_REPOSITORY, then {DEFAULT_REPOSITORY})."
        ),
    )
    parser.add_argument(
        "--attestations-dir",
        default=None,
        help=(
            "Directory containing {filename}.publish.attestation release assets. "
            "When set, each asset must equal an attestation PyPI accepted for "
            "that file. When unset, the check is skipped."
        ),
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
            local = local_sha256(args.dist_dir, version)
            for filename in expected_filenames(version):
                provenance = fetch_provenance(version, filename, opener=DEFAULT_OPENER)
                verify_provenance(provenance, filename, local[filename], args.repository)
                if args.attestations_dir:
                    verify_attestation_asset(
                        provenance,
                        filename,
                        args.repository,
                        args.attestations_dir,
                    )
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
                f"match local sha256 and carry matching Trusted Publishing provenance\n",
            )
            return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
