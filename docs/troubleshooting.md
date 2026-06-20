# Troubleshooting

Back to the [README](../README.md).

### "Syft not installed" when using `--image`

Use the Docker image (Syft is bundled) or install Syft natively:

```bash
brew install syft           # macOS
# Linux: see https://github.com/anchore/syft#installation
```

### "Cannot connect to Docker daemon"

Mount the Docker socket when running inside a container:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  craevidence/cli:latest \
  upload-sbom --image my-app:latest ...
```

### "Image not found"

Pull the image before generating an SBOM from it:

```bash
docker pull nginx:latest
craevidence upload-sbom --product my-app --version 1.0 --image nginx:latest
```

### Timeout during SBOM generation

Large images take longer to analyse. For very large images, run Syft directly and upload the resulting file instead of using `--image`:

```bash
syft my-app:latest -o cyclonedx-json > sbom.json
craevidence upload-sbom --product my-app --version 1.0 --file sbom.json
```

### `401 Unauthorized` while building the CLI Docker image

The source Dockerfile uses Docker Hardened Images from `dhi.io` and pins the
Python 3.14 builder/runtime images by digest. A build error such as
`failed to authorize` or `401 Unauthorized` while loading
`dhi.io/python:3.14` metadata means Docker cannot read that registry metadata
with the current credentials. It is not a CLI build error and it is not a
reason to downgrade Python. Use DHI registry access for fresh pulls, or build
from a machine/cache that already has the pinned Python 3.14 digests available.
