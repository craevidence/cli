# Installation

How to install the CRA Evidence CLI via PyPI, Docker, container registries, or from source.

Back to the [README](../README.md).

## PyPI

```bash
pip install craevidence          # standard install
pipx install craevidence         # isolated environment (recommended for a CLI)
```

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

The published Dockerfile defaults to Docker Hardened Images (DHI) from `dhi.io`. If you do not have
DHI registry access, pass public Python base images via build-args:

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
  -t craevidence-cli:local .
```

The label build-args keep the image identity honest: without them the labels would describe the
hardened base while the image actually contains the public one.

Without the build-args the build uses the pinned DHI digests, which require DHI credentials. The
fallback image provides the same CLI functionality, but it is not the hardened production image:
the public base includes a shell and a package manager, and the image labels record the base
image actually used.

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

Native installs can upload an existing SBOM with `--file`. Directory and image
generation require the local SBOM generator on `PATH`:

```bash
# macOS
brew install syft

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```
