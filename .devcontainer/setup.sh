#!/usr/bin/env bash
# One-time Codespaces setup: install the CLI and the scanners it shells out to,
# then prime the local vulnerability database so check works in the codespace.
set -euo pipefail

python -m pip install --upgrade pip
pip install -e ".[dev]"

# Install Syft and Grype at pinned versions with checksum verification.
# Checksums match the linux amd64/arm64 release tarballs published on GitHub.
SYFT_VERSION="1.50.0"
GRYPE_VERSION="0.116.1"

MACHINE="$(uname -m)"
case "${MACHINE}" in
    x86_64)
        ARCH="amd64"
        SYFT_SHA256="bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788"
        GRYPE_SHA256="0122df7b655981abe547ad3d2190d65551dac6a2bfc80b4dc2a989b5d0587458"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        SYFT_SHA256="887c57cbcc2d0e8c5c110a4571a3fc7150058b24d74f993ee4663516e5c8ce86"
        GRYPE_SHA256="a8d7504a149629324eb5f4ce3dc25dfd211bbfe047e64ee2bf7844b466c3d84d"
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
