# Installation

How to install the CRA Evidence CLI via PyPI, Docker, container registries, or from source.

Back to the [README](../README.md).

## PyPI

```bash
pip install craevidence          # standard install
pipx install craevidence         # isolated environment (recommended for a CLI)
```

PyPI selects a platform wheel containing the supported CRA Evidence engine on
Linux AMD64/ARM64 and macOS AMD64/ARM64. The source distribution remains
engine-free for upload-only and unsupported-platform installations.
The wheel compatibility floors are glibc 2.17, musl 1.2, and macOS 12.

## Docker

```bash
docker pull craevidence/cli:latest
```

### Container registries

The CLI Docker image is published to multiple registries:

| Registry | Image |
|----------|-------|
| Docker Hub (primary) | `craevidence/cli:latest` |
| GHCR | `ghcr.io/craevidence/craevidence:latest` |
| Quay.io | `quay.io/craevidence/cli:latest` |

### Building the Docker image from source

The published Dockerfile defaults to Docker Hardened Images (DHI) from `dhi.io`
and a digest-pinned CRA Evidence engine artifact. A source build requires read
access to a supported engine image with `/grype`, `/LICENSE`, and `/NOTICE`.
Stock Grype is not a compatible substitute.

If you have a supported engine image but do not have DHI registry access, pass
public Python base images and the engine image via build-args:

```bash
git clone https://github.com/craevidence/cli.git
cd cli
docker build \
  --build-arg BASE_IMAGE_BUILDER=python:3.14 \
  --build-arg BASE_IMAGE=python:3.14-slim \
  --build-arg BASE_IMAGE_NAME=python:3.14-slim \
  --build-arg IMAGE_DESCRIPTION="CLI tool for CI/CD integration with CRA Evidence - public Python base fallback build" \
  --build-arg SECURITY_HARDENED=false \
  --build-arg SECURITY_NO_SHELL=false \
  --build-arg SECURITY_NO_PACKAGE_MANAGER=false \
  --build-arg GRYPE_ENGINE_IMAGE=registry.example/supported-engine@sha256:... \
  -t craevidence-cli:local .
```

The label build-args keep the image identity honest: without them the labels would describe the
hardened base while the image actually contains the public one.

Without the base-image build-args the build uses the pinned DHI digests, which
require DHI credentials. A public-base image built with the same supported
engine provides the same CLI behavior, but it is not the hardened production
image: the public base includes a shell and a package manager, and the labels
record that fact.

## From Source

Install the Python package in editable mode:

```bash
git clone https://github.com/craevidence/cli.git
cd cli
pip install -e .
```

## SBOM Generation from Docker Images

The CLI Docker image includes the local tools needed to generate SBOMs directly
from Docker images. Mount the Docker socket only in trusted CI/CD environments:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CRA_EVIDENCE_API_KEY=xxx \
  craevidence/cli:latest \
  upload-sbom --product my-app --version 1.0 --image nginx:latest
```

> **Security note:** Mounting the Docker socket grants the container full control over the Docker daemon.

Native installs can upload an existing SBOM with `--file`, which needs no engine.

Directory and image generation and local vulnerability matching require the
compatible CRA Evidence Grype engine. Supported PyPI platform wheels and the
published Docker image bundle it. Editable and source-distribution installs do
not; set `CRA_EVIDENCE_ENGINE` to an explicit supported binary when developing
from source. The CLI never downloads an engine at runtime.

Native Windows generation and local engine scanning are not supported, and no
Homebrew formula or separate engine archive is maintained. The macOS wheel
binaries are not Apple Developer ID-signed or notarized. Their execution,
quarantine, and Gatekeeper behavior have not been verified on real macOS
hardware and no Gatekeeper trust is claimed.

### What the engine accepts as a source

Generation supports directory, file, archive, Docker-daemon, Podman, OCI and
registry sources, and uses the same default credential keychain as any other
container tool: a prior `docker login` (or the equivalent config file) is
honoured for private registries.

Standalone-Syft application configuration is **not** forwarded to the engine.
The delivery profile is fixed and versioned, so `SYFT_REGISTRY_AUTH_*` and other
`SYFT_*` variables, a Syft config file, an explicit target platform, custom
TLS/CA or insecure-registry settings, path exclusions and source name/version
aliases have no effect. If you need any of those, generate the SBOM with your
own tooling and upload it with `--file`.
