#!/usr/bin/env bash
# Run the Docker image vulnerability gate with a pinned Grype version.
#
# CI and the local pre-push check both call this script, so the gate always
# runs the same scanner version, the same database freshness policy, and the
# same flags. Scanner versions differ in which advisory identifiers they
# report for the same finding, so an unpinned scanner changes the gate result.
#
# Usage: scripts/check-image-gate.sh IMAGE
#
# Exits 0 when the gate passes. Exits nonzero on findings at or above the
# threshold and on any infrastructure failure (download, checksum, database
# update), so a broken gate can never pass silently.
set -euo pipefail

GRYPE_VERSION="0.116.1"
GRYPE_SHA256_LINUX_AMD64="0122df7b655981abe547ad3d2190d65551dac6a2bfc80b4dc2a989b5d0587458"
GRYPE_SHA256_LINUX_ARM64="a8d7504a149629324eb5f4ce3dc25dfd211bbfe047e64ee2bf7844b466c3d84d"
INVENTORY_GRYPE_VERSION="0.111.0"
INVENTORY_GRYPE_SHA256_LINUX_AMD64="18ed2048d7a233566b681121d4632364f5f25d72cca86acc4c7ac57210d78a87"
INVENTORY_GRYPE_SHA256_LINUX_ARM64="1a8b9bd691ce274e44056e7572cdf8c6970bdf9ec694001f7b4b17962b121b43"

if [ "$#" -ne 1 ]; then
  echo "usage: $0 IMAGE" >&2
  exit 1
fi
image="$1"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    expected_sha256="${GRYPE_SHA256_LINUX_AMD64}"
    inventory_expected_sha256="${INVENTORY_GRYPE_SHA256_LINUX_AMD64}"
    arch="amd64"
    ;;
  Linux/aarch64 | Linux/arm64)
    expected_sha256="${GRYPE_SHA256_LINUX_ARM64}"
    inventory_expected_sha256="${INVENTORY_GRYPE_SHA256_LINUX_ARM64}"
    arch="arm64"
    ;;
  *)
    echo "check-image-gate: unsupported platform $(uname -s)/$(uname -m)" >&2
    exit 1
    ;;
esac

tarball="grype_${GRYPE_VERSION}_linux_${arch}.tar.gz"
url="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${tarball}"
cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/cra-evidence-cli"
cached="${cache_dir}/${tarball}"
mkdir -p "${cache_dir}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

verify_archive() {
  echo "${expected_sha256}  $1" | sha256sum -c - > /dev/null 2>&1
}

# Reuse the cached archive only when its checksum still matches; otherwise
# download fresh with bounded retries. A checksum mismatch for a released
# version is always a hard failure, never accepted.
if [ ! -f "${cached}" ] || ! verify_archive "${cached}"; then
  rm -f "${cached}"
  for attempt in 1 2 3; do
    if curl -fsSL "${url}" -o "${workdir}/${tarball}"; then
      break
    fi
    if [ "${attempt}" -eq 3 ]; then
      echo "check-image-gate: download failed after 3 attempts: ${url}" >&2
      exit 1
    fi
    sleep 5
  done
  if ! verify_archive "${workdir}/${tarball}"; then
    echo "check-image-gate: checksum mismatch for ${tarball}" >&2
    exit 1
  fi
  mv "${workdir}/${tarball}" "${cached}"
fi

tar -xzf "${cached}" -C "${workdir}" grype
grype_bin="${workdir}/grype"

running_version="$("${grype_bin}" version 2> /dev/null | awk '/^Version:/{print $2; exit}')"
if [ "${running_version}" != "${GRYPE_VERSION}" ]; then
  echo "check-image-gate: expected Grype ${GRYPE_VERSION}, got '${running_version}'" >&2
  exit 1
fi

# The gate is only meaningful against a current vulnerability database, so a
# failed update fails the gate instead of silently scanning stale data.
if ! "${grype_bin}" db update; then
  echo "check-image-gate: vulnerability database update failed" >&2
  exit 1
fi
"${grype_bin}" db status

echo "check-image-gate: scanning ${image} with Grype ${GRYPE_VERSION}"
GRYPE_CONFIG="${repo_root}/.github/grype.yaml" \
  "${grype_bin}" -o table --fail-on high --only-fixed "${image}"

# Grype versions can disagree about a database record for the same package.
# Run the independently pinned comparison version as a second inventory. This
# prints fixed findings at every severity without controlling the release gate.
inventory_tarball="grype_${INVENTORY_GRYPE_VERSION}_linux_${arch}.tar.gz"
inventory_url="https://github.com/anchore/grype/releases/download/v${INVENTORY_GRYPE_VERSION}/${inventory_tarball}"
inventory_cached="${cache_dir}/${inventory_tarball}"
if [ ! -f "${inventory_cached}" ] || \
   ! echo "${inventory_expected_sha256}  ${inventory_cached}" | sha256sum -c - > /dev/null 2>&1; then
  rm -f "${inventory_cached}"
  curl -fsSL "${inventory_url}" -o "${workdir}/${inventory_tarball}"
  if ! echo "${inventory_expected_sha256}  ${workdir}/${inventory_tarball}" | sha256sum -c - > /dev/null 2>&1; then
    echo "check-image-gate: checksum mismatch for ${inventory_tarball}" >&2
    exit 1
  fi
  mv "${workdir}/${inventory_tarball}" "${inventory_cached}"
fi
mkdir -p "${workdir}/inventory"
tar -xzf "${inventory_cached}" -C "${workdir}/inventory" grype
inventory_grype_bin="${workdir}/inventory/grype"
inventory_version="$("${inventory_grype_bin}" version 2> /dev/null | awk '/^Version:/{print $2; exit}')"
if [ "${inventory_version}" != "${INVENTORY_GRYPE_VERSION}" ]; then
  echo "check-image-gate: expected inventory Grype ${INVENTORY_GRYPE_VERSION}, got '${inventory_version}'" >&2
  exit 1
fi
echo "check-image-gate: fixed-finding comparison inventory with Grype ${inventory_version}"
GRYPE_CONFIG="${repo_root}/.github/grype.yaml" \
  "${inventory_grype_bin}" -o table --only-fixed "${image}"
