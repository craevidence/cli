#!/usr/bin/env bash
# Install a pinned, checksum-verified crane (google/go-containerregistry).
#
# CI resolves image digests, copies release indexes between registries, and
# moves tags with crane, so the same crane version must be used everywhere. An
# unpinned binary would let registry behaviour drift between runs. A checksum
# mismatch for a released version is always a hard failure, never accepted.
#
# Usage: scripts/install-crane.sh [DEST_DIR]
#   DEST_DIR defaults to /usr/local/bin. The crane binary is placed there and
#   the installed version is asserted to equal CRANE_VERSION.
#
# Exits 0 on success. Exits nonzero on download, checksum, or version mismatch,
# so a broken install can never leave an unpinned or wrong crane on PATH.
set -euo pipefail

CRANE_VERSION="0.21.7"
CRANE_SHA256_LINUX_AMD64="1a57bc98207fa1c0d04bf760699099e26f8383499bfd55b99c1b919a928a7230"
CRANE_SHA256_LINUX_ARM64="b6ee979d9411dfb05ce35ab9e156fe5de7def11a230764a7856ffa2eb971fa88"

dest_dir="${1:-/usr/local/bin}"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) expected_sha256="${CRANE_SHA256_LINUX_AMD64}"; asset="x86_64" ;;
  Linux/aarch64 | Linux/arm64) expected_sha256="${CRANE_SHA256_LINUX_ARM64}"; asset="arm64" ;;
  *)
    echo "install-crane: unsupported platform $(uname -s)/$(uname -m)" >&2
    exit 1
    ;;
esac

tarball="go-containerregistry_Linux_${asset}.tar.gz"
url="https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/${tarball}"
cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/cra-evidence-cli"
cached="${cache_dir}/crane_${CRANE_VERSION}_${asset}.tar.gz"
mkdir -p "${cache_dir}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

verify_archive() {
  echo "${expected_sha256}  $1" | sha256sum -c - > /dev/null 2>&1
}

# Reuse the cached archive only when its checksum still matches; otherwise
# download fresh with bounded retries.
if [ ! -f "${cached}" ] || ! verify_archive "${cached}"; then
  rm -f "${cached}"
  for attempt in 1 2 3; do
    if curl -fsSL --connect-timeout 10 --max-time 300 "${url}" -o "${workdir}/${tarball}"; then
      break
    fi
    if [ "${attempt}" -eq 3 ]; then
      echo "install-crane: download failed after 3 attempts: ${url}" >&2
      exit 1
    fi
    sleep 5
  done
  if ! verify_archive "${workdir}/${tarball}"; then
    echo "install-crane: checksum mismatch for ${tarball}" >&2
    exit 1
  fi
  mv "${workdir}/${tarball}" "${cached}"
fi

tar -xzf "${cached}" -C "${workdir}" crane
mkdir -p "${dest_dir}"
install -m 0755 "${workdir}/crane" "${dest_dir}/crane"

running_version="$("${dest_dir}/crane" version 2> /dev/null | tr -d '[:space:]')"
running_version="${running_version#v}"
if [ "${running_version}" != "${CRANE_VERSION}" ]; then
  echo "install-crane: expected crane ${CRANE_VERSION}, got '${running_version}'" >&2
  exit 1
fi

echo "install-crane: installed crane ${CRANE_VERSION} to ${dest_dir}/crane"
