"""Release SBOM validator.

Checks the two per-platform CycloneDX SBOMs published as release assets for a
version. For version ``VERSION`` the two files are exactly:

  - sbom-VERSION-linux-amd64.cdx.json
  - sbom-VERSION-linux-arm64.cdx.json

For each document it validates the structure (bomFormat CycloneDX, spec
version 1.6, an integer document version of at least 1, a non-empty
components list whose entries are objects) and the subject binding: the
metadata component must name the canonical image repository and carry that
platform's manifest digest as its version. It does not verify signatures or
attestations, only structure and binding.

Run: python scripts/validate_release_sboms.py --version X.Y.Z \
  --image ghcr.io/craevidence/craevidence \
  --digest-amd64 sha256:... --digest-arm64 sha256:... --dir sbom-assets
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

EXPECTED_BOM_FORMAT = "CycloneDX"
EXPECTED_SPEC_VERSION = "1.6"
PLATFORMS = ("amd64", "arm64")


class SbomValidationError(Exception):
    """An SBOM document failed a structural or binding check."""


def asset_filename(version: str, platform: str) -> str:
    """Return the release asset filename for the version and platform."""
    return f"sbom-{version}-linux-{platform}.cdx.json"


def validate_sbom(sbom: dict, image: str, digest: str, label: str) -> None:
    """Validate one CycloneDX SBOM document against the expected binding.

    Checks bomFormat, specVersion, the document version (an int of at least
    1; a boolean is rejected), that components is a non-empty list of
    objects, and that metadata.component names the given image with the
    given digest as its version. Raises SbomValidationError naming the label
    and the failed check. Returns None on success.
    """
    bom_format = sbom.get("bomFormat")
    if bom_format != EXPECTED_BOM_FORMAT:
        msg = f"{label}: bomFormat is {bom_format!r}, expected {EXPECTED_BOM_FORMAT!r}"
        raise SbomValidationError(msg)

    spec_version = sbom.get("specVersion")
    if spec_version != EXPECTED_SPEC_VERSION:
        msg = f"{label}: specVersion is {spec_version!r}, expected {EXPECTED_SPEC_VERSION!r}"
        raise SbomValidationError(msg)

    document_version = sbom.get("version")
    if type(document_version) is not int or document_version < 1:
        msg = f"{label}: version must be an integer of at least 1, got {document_version!r}"
        raise SbomValidationError(msg)

    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        msg = f"{label}: components must be a non-empty list, got {components!r}"
        raise SbomValidationError(msg)
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            msg = f"{label}: components[{index}] is not an object: {component!r}"
            raise SbomValidationError(msg)

    metadata = sbom.get("metadata")
    subject = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(subject, dict):
        msg = f"{label}: metadata.component is missing or not an object"
        raise SbomValidationError(msg)
    subject_name = subject.get("name")
    if subject_name != image:
        msg = f"{label}: metadata.component.name is {subject_name!r}, expected {image!r}"
        raise SbomValidationError(msg)
    subject_version = subject.get("version")
    if subject_version != digest:
        msg = (
            f"{label}: metadata.component.version is {subject_version!r}, "
            f"expected digest {digest!r}"
        )
        raise SbomValidationError(msg)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the per-platform release SBOMs against the image digests.",
    )
    parser.add_argument("--version", required=True, help="Released version, for example 3.8.1.")
    parser.add_argument(
        "--image",
        required=True,
        help="Canonical image repository the SBOMs must name as their subject.",
    )
    parser.add_argument(
        "--digest-amd64",
        required=True,
        help="Manifest digest (sha256:...) of the linux/amd64 image.",
    )
    parser.add_argument(
        "--digest-arm64",
        required=True,
        help="Manifest digest (sha256:...) of the linux/arm64 image.",
    )
    parser.add_argument(
        "--dir",
        default="sbom-assets",
        help="Directory holding the SBOM files under their release asset names.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    base = Path(args.dir)
    digests = {
        "amd64": args.digest_amd64,
        "arm64": args.digest_arm64,
    }

    for platform in PLATFORMS:
        digest = digests[platform]
        filename = asset_filename(args.version, platform)
        path = base / filename
        if not path.is_file():
            sys.stderr.write(f"validation failed: missing SBOM file: {path}\n")
            return 1
        try:
            sbom = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            sys.stderr.write(f"validation failed: {filename}: invalid JSON: {error}\n")
            return 1
        if not isinstance(sbom, dict):
            sys.stderr.write(
                f"validation failed: {filename}: document is not a JSON object\n",
            )
            return 1
        try:
            validate_sbom(sbom, args.image, digest, filename)
        except SbomValidationError as error:
            sys.stderr.write(f"validation failed: {error}\n")
            return 1
        sys.stdout.write(
            f"validated {filename}: CycloneDX {EXPECTED_SPEC_VERSION}, "
            f"subject {args.image}@{digest}\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
