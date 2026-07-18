#!/usr/bin/env bash
# Reconcile per-platform SBOM release assets with signed bundles.
#
# SBOM assets are published security evidence, and release assets are mutable,
# so an SBOM is trusted only through its signed bundle. For each SBOM document
# given (a freshly generated file in the working directory):
#
#   - When the release carries BOTH the document and its .cosign.bundle, both
#     are downloaded and the document must verify against the bundle under one
#     of the two exact accepted identities. A verification failure is tampered
#     evidence and fails the run. A verified pair is kept unchanged.
#   - Anything without a complete attached pair (document missing, bundle
#     missing, or both) is replaced: the fresh document is signed now and both
#     files are uploaded with --clobber.
#
# Afterward every document in the destination directory is verified against
# its bundle, whichever branch produced it, so the working set handed to
# validation and evidence upload is verified in one place.
#
# Usage:
#   reconcile_release_sboms.sh <release_tag> <tag_identity> <run_identity> \
#     <dest_dir> <sbom_file>...
#
# Requires gh (GH_TOKEN) and cosign on PATH; COSIGN_YES=true for keyless
# signing in CI.
set -euo pipefail

if [ "$#" -lt 5 ]; then
  echo "usage: $0 <release_tag> <tag_identity> <run_identity> <dest_dir> <sbom_file>..." >&2
  exit 2
fi
release_tag="$1"
tag_identity="$2"
run_identity="$3"
dest_dir="$4"
shift 4

oidc_issuer="https://token.actions.githubusercontent.com"
mkdir -p "${dest_dir}"
existing="$(gh release view "${release_tag}" --json assets --jq '.assets[].name')"

verify_pair() {
  local doc="$1" bundle="$2" identity
  for identity in "${tag_identity}" "${run_identity}"; do
    if cosign verify-blob \
        --bundle "${bundle}" \
        --certificate-identity "${identity}" \
        --certificate-oidc-issuer "${oidc_issuer}" \
        "${doc}" > /dev/null 2>&1; then
      printf '%s' "${identity}"
      return 0
    fi
  done
  return 1
}

for f in "$@"; do
  if [ ! -f "${f}" ]; then
    echo "reconcile-sboms: fresh document ${f} does not exist" >&2
    exit 1
  fi
  b="${f}.cosign.bundle"
  if grep -Fqx -- "${f}" <<< "${existing}" && grep -Fqx -- "${b}" <<< "${existing}"; then
    gh release download "${release_tag}" --pattern "${f}" --dir "${dest_dir}" --clobber
    gh release download "${release_tag}" --pattern "${b}" --dir "${dest_dir}" --clobber
    if identity="$(verify_pair "${dest_dir}/${f}" "${dest_dir}/${b}")"; then
      echo "${f} is attached and verifies (${identity}); keeping the published copy"
    else
      echo "reconcile-sboms: retained ${f} does not verify against its bundle under either accepted identity; the published evidence cannot be trusted" >&2
      exit 1
    fi
  else
    cosign sign-blob --yes --bundle "${b}" "${f}"
    gh release upload "${release_tag}" "${f}" "${b}" --clobber
    cp "${f}" "${b}" "${dest_dir}/"
    echo "published freshly signed ${f} and ${b}"
  fi
done

# One verification pass over the complete working set, whichever branch
# produced each pair, so nothing unverified can reach validation or the
# evidence upload.
for f in "$@"; do
  if identity="$(verify_pair "${dest_dir}/${f}" "${dest_dir}/${f}.cosign.bundle")"; then
    echo "working set ${f} verifies (${identity})"
  else
    echo "reconcile-sboms: working set ${f} does not verify against its bundle" >&2
    exit 1
  fi
done
