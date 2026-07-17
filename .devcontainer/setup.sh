#!/usr/bin/env bash
# One-time Codespaces setup: install the CLI and the scanners it shells out to,
# then prime the local vulnerability database so check works in the codespace.
set -euo pipefail

python -m pip install --upgrade pip
pip install -e ".[dev]"

# Install Syft and Grype at pinned versions with checksum verification.
# Checksums match the linux amd64/arm64 release tarballs published on GitHub.
SYFT_VERSION="1.48.0"
GRYPE_VERSION="0.116.0"

MACHINE="$(uname -m)"
case "${MACHINE}" in
    x86_64)
        ARCH="amd64"
        SYFT_SHA256="6cef9a7f37220d9067eaf9cfaaa2fce986e9f320a8d42cbc36658c99af78ea04"
        GRYPE_SHA256="40aff724297312f91ea390d003bed8d8651c74cc7f5b26732db80b3a408d2fc5"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        SYFT_SHA256="6865a3d97c4e28b4b38571c17a2bf512da4494ef1d37613c3122fce0d67e63b0"
        GRYPE_SHA256="7af3eed24f469b0cf3ab5ec4508d9c12f4bb9c2c6be714f32973c7b5d63cb6a5"
        ;;
    *)
        echo "Unsupported architecture: ${MACHINE}" >&2
        exit 1
        ;;
esac

install_tool() {
    local name="$1" version="$2" expected_sha="$3"
    local tarball="${name}_${version}_linux_${ARCH}.tar.gz"
    local url="https://github.com/anchore/${name}/releases/download/v${version}/${tarball}"
    local tmpfile
    tmpfile="$(mktemp)"
    curl -fsSL "${url}" -o "${tmpfile}"
    echo "${expected_sha}  ${tmpfile}" | sha256sum -c - >/dev/null
    sudo tar -xzf "${tmpfile}" -C /usr/local/bin "${name}"
    rm -f "${tmpfile}"
}

install_tool syft "${SYFT_VERSION}" "${SYFT_SHA256}"
install_tool grype "${GRYPE_VERSION}" "${GRYPE_SHA256}"

grype db update || true

cat <<'EOF'

CRA Evidence CLI is ready. Try a no-account local check:

  craevidence check --sbom docs/demo-assets/sbom.demo.json
  craevidence check .

EOF
