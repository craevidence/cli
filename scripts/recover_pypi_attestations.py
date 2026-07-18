"""PyPI publish attestation sidecar recovery.

The release pipeline writes a {filename}.publish.attestation sidecar for each
distribution it uploads to PyPI and later attaches those sidecars to the
GitHub release. If a run stops after the upload but before the attachment,
the sidecar is gone while PyPI has already accepted the attestation. PyPI
serves accepted attestations through its integrity API, so the sidecar can
be rebuilt from there.

For package ``craevidence`` at ``VERSION`` the two distributions are exactly:

  - craevidence-VERSION-py3-none-any.whl
  - craevidence-VERSION.tar.gz

For each expected sidecar this script leaves existing files untouched,
recovers missing ones from the PyPI integrity provenance (requiring the
expected Trusted Publisher and an in-toto PyPI publish statement naming the
distribution), and skips distributions whose provenance PyPI does not serve,
since those have not been published yet. It recovers accepted publish
attestations only; it does not verify subject hashes or Sigstore bundle
signatures, which scripts/verify_pypi_release.py enforces.

Run: python scripts/recover_pypi_attestations.py --version X.Y.Z --dir DIR
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

PACKAGE = "craevidence"
PYPI_PROVENANCE_URL = "https://pypi.org/integrity/{package}/{version}/{filename}/provenance"
DEFAULT_REPOSITORY = "craevidence/cli"
EXPECTED_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
EXPECTED_PREDICATE_TYPE = "https://docs.pypi.org/attestations/publish/v1"

STATUS_PRESENT = "present"
STATUS_RECOVERED = "recovered"
STATUS_SKIPPED = "not on PyPI; skipping"

# Injection points so main can be exercised without network. Tests replace
# these on the module; production uses the standard library defaults.
DEFAULT_OPENER = urllib.request.urlopen
REQUEST_TIMEOUT = 30


class RecoveryError(Exception):
    """A missing sidecar could not be recovered from PyPI provenance."""


class ProvenanceNotAvailableError(RecoveryError):
    """The distribution or its provenance is not on PyPI (nothing to recover)."""


def expected_filenames(version: str) -> tuple[str, str]:
    """Return the wheel and sdist filenames for the given version."""
    wheel = f"{PACKAGE}-{version}-py3-none-any.whl"
    sdist = f"{PACKAGE}-{version}.tar.gz"
    return wheel, sdist


def fetch_provenance(
    version: str,
    filename: str,
    *,
    opener=urllib.request.urlopen,
    timeout: int = REQUEST_TIMEOUT,
) -> dict:
    """Fetch and parse the PyPI integrity provenance for one distribution.

    Raises ProvenanceNotAvailableError on HTTP 404 (the distribution or its
    provenance is not on PyPI) and RecoveryError on any other HTTP error.
    Each request is bounded by timeout seconds.
    """
    url = PYPI_PROVENANCE_URL.format(package=PACKAGE, version=version, filename=filename)
    try:
        with opener(url, timeout=timeout) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            msg = f"provenance not on PyPI for {filename}"
            raise ProvenanceNotAvailableError(msg) from error
        msg = f"PyPI provenance request failed for {url}: HTTP {error.code}"
        raise RecoveryError(msg) from error
    try:
        provenance = json.loads(payload)
    except ValueError as error:
        msg = f"provenance for {filename} is not valid JSON: {error}"
        raise RecoveryError(msg) from error
    if not isinstance(provenance, dict):
        msg = f"provenance for {filename} is not a JSON object"
        raise RecoveryError(msg)
    return provenance


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


def _statement_matches(attestation: dict, filename: str) -> bool:
    """Return whether the attestation carries a publish statement for filename.

    Only the statement type, predicate type, and subject name are checked
    here; the release verifier binds the subject digest to the local bytes.
    """
    encoded_statement = (attestation.get("envelope") or {}).get("statement", "")
    try:
        statement = json.loads(base64.b64decode(encoded_statement))
    except (ValueError, TypeError):
        return False
    if not isinstance(statement, dict):
        return False
    if statement.get("_type") != EXPECTED_STATEMENT_TYPE:
        return False
    if statement.get("predicateType") != EXPECTED_PREDICATE_TYPE:
        return False
    subject = statement.get("subject")
    if not isinstance(subject, list) or len(subject) != 1:
        return False
    entry = subject[0]
    return isinstance(entry, dict) and entry.get("name") == filename


def select_attestation(provenance: dict, filename: str, repository: str) -> dict:
    """Select the accepted publish attestation for filename from provenance.

    Searches every attestation bundle for a publisher matching the GitHub
    Trusted Publisher for the given repository (workflow ci.yml, environment
    pypi), then returns the first attestation in the matching bundles whose
    in-toto PyPI publish statement names the file. Raises RecoveryError when
    no bundle has the expected publisher or no attestation in the matching
    bundles carries a matching statement: if PyPI serves provenance for the
    file, an accepted publish attestation must exist.
    """
    matched = _matching_bundles(provenance, repository)
    if not matched:
        expected = _expected_publisher(repository)
        msg = f"no provenance bundle for {filename} has the expected publisher {expected!r}"
        raise RecoveryError(msg)
    for bundle in matched:
        for attestation in bundle.get("attestations") or []:
            if _statement_matches(attestation, filename):
                return attestation
    msg = (
        f"no publish attestation for {filename} in {len(matched)} "
        f"matching provenance bundle(s)"
    )
    raise RecoveryError(msg)


def recover(
    version: str,
    directory: str | os.PathLike[str],
    repository: str,
    *,
    opener=urllib.request.urlopen,
) -> dict[str, str]:
    """Fill in missing attestation sidecars in directory from PyPI provenance.

    Returns a summary mapping each expected sidecar filename to its outcome:
    already present, recovered from PyPI, or skipped because PyPI serves no
    provenance for the distribution. Existing sidecar files are never
    rewritten. Raises RecoveryError when provenance is served but holds no
    acceptable attestation, or on a non-404 HTTP error.
    """
    base = Path(directory)
    summary: dict[str, str] = {}
    for filename in expected_filenames(version):
        sidecar = f"{filename}.publish.attestation"
        path = base / sidecar
        if path.is_file():
            summary[sidecar] = STATUS_PRESENT
            continue
        try:
            provenance = fetch_provenance(version, filename, opener=opener)
        except ProvenanceNotAvailableError:
            summary[sidecar] = STATUS_SKIPPED
            continue
        attestation = select_attestation(provenance, filename, repository)
        path.write_text(json.dumps(attestation, sort_keys=False))
        summary[sidecar] = STATUS_RECOVERED
    return summary


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recover missing PyPI publish attestation sidecars for a version.",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Released version whose attestation sidecars to recover.",
    )
    parser.add_argument(
        "--dir",
        required=True,
        help="Directory holding the {filename}.publish.attestation sidecars.",
    )
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPOSITORY,
        help=(
            "GitHub repository expected in the provenance publisher "
            f"(defaults to GITHUB_REPOSITORY, then {DEFAULT_REPOSITORY})."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        summary = recover(args.version, args.dir, args.repository, opener=DEFAULT_OPENER)
    except RecoveryError as error:
        sys.stderr.write(f"recovery failed: {error}\n")
        return 1
    for sidecar, status in summary.items():
        sys.stdout.write(f"{sidecar}: {status}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
