#!/usr/bin/env bash
# One-time Codespaces setup: install the CLI and the scanners it shells out to,
# then prime the local vulnerability database so check works in the codespace.
set -euo pipefail

python -m pip install --upgrade pip
pip install -e ".[dev]"

# Install Syft and Grype at pinned versions with checksum verification.
# Checksums match the linux amd64/arm64 release tarballs published on GitHub.
SYFT_VERSION="1.46.0"
GRYPE_VERSION="0.115.0"

MACHINE="$(uname -m)"
case "${MACHINE}" in
    x86_64)
        ARCH="amd64"
        SYFT_SHA256="d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca"
        GRYPE_SHA256="3fad92940650e514c0aa2dad83526942a055e210cec09a8a59d9c024adc2b90e"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        SYFT_SHA256="9fafef4db4f032ce81008d3a1529985d41ceb6ccdf2b388c9ce2f1ed7d32082e"
        GRYPE_SHA256="b8541b9ecc3e936e7db4ff14b71a9474b25f3898ccaad63ee0bfe3449fcd734d"
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
