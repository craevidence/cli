# Releasing

Maintainer reference for publishing a CRA Evidence CLI release. Every step
that publishes something is deliberate: nothing here happens implicitly.

## Channels and support policy

A release publishes to PyPI, GHCR, Docker Hub, and Quay, and attaches signed
artifacts and per-platform SBOMs to the GitHub release. All channels are
required: the pipeline fails rather than publishing a partial release.

Only the latest minor release line is supported. Older lines receive no
fixes; users should upgrade to the newest release.

## The release commit

One commit contains everything the release needs:

1. Roll the `[Unreleased]` section of `CHANGELOG.md` into `## [X.Y.Z] - date`.
2. Bump `version` in `pyproject.toml`.
3. Update the pinned CLI wheel version and checksum in
   `gitlab-ci-component.yml` (both templates install it). The checksum is
   predictable before PyPI has the file because wheel builds are
   byte-reproducible: build with the same pinned tools and fixed epoch the
   pipeline uses and take the wheel's SHA-256:

   ```sh
   docker run --rm -v "$PWD":/src:ro python:3.14-slim sh -ec '
     cp -r /src /build && cd /build && rm -rf dist
     python -m pip install -q pip==26.1.2 build==1.5.0
     export SOURCE_DATE_EPOCH=946684800
     python -m build -q
     sha256sum dist/*.whl'
   ```

4. Move the documented component include refs (the `v...` raw URL in
   `gitlab-ci-component.yml` and `docs/ci-cd.md`) to the new tag.

## Before pushing anything

Run the full local gate on the release commit; every check must pass, and the
scan checks must be re-run immediately before the push because the
vulnerability database and base image digests move daily:

```sh
./.venv/bin/python -m pytest -q
./.venv/bin/ruff check .
bash scripts/check-dhi-base.sh --strict
docker build -t craevidence:release-check .
bash scripts/check-image-gate.sh craevidence:release-check
python scripts/check_dist.py
```

## Tag and publish

1. Push the release commit to `main`.
2. Create the release tag at exactly that commit and push it:
   `git tag vX.Y.Z <commit> && git push origin vX.Y.Z`. The pipeline's
   signing identity and checkout both derive from this tag.
3. Create the GitHub release from the existing tag `vX.Y.Z` and publish it.
4. Approve the two protected environments when GitHub asks: `release-images`
   (registry publishing, signing, SBOMs) and `pypi` (the immutable PyPI
   upload).

The pipeline then: builds the canonical multi-arch image once and pushes it
to GHCR; copies the index to Docker Hub and Quay by digest; requires every
version tag to resolve to the canonical digest; signs that digest on each
registry and verifies every signature against the release identity
`.../.github/workflows/ci.yml@refs/tags/vX.Y.Z`; generates per-platform
SBOMs from the released digests, attaches them to the GitHub release, and
uploads the linux/amd64 SBOM to CRA Evidence as a required step; moves the
`latest` tags last; builds, signs, and publishes the PyPI artifacts with a
pre-publish idempotence check and a post-publish verification.

## After the pipeline

Verify the release from a clean environment. Each check is an assertion, not
a glance:

1. All three registries resolve `X.Y.Z` and `latest` to the same digest as
   GHCR, and `cosign verify` passes for each `repo@digest` with the exact
   release identity above.
2. PyPI serves exactly the built wheel and sdist, with hashes equal to the
   GitHub release assets, and the wheel hash equals the checksum pinned in
   `gitlab-ci-component.yml`.
3. The GitHub release carries `sbom-X.Y.Z-linux-amd64.cdx.json` and
   `sbom-X.Y.Z-linux-arm64.cdx.json`.
4. The image labels report the hardened base
   (`org.opencontainers.image.base.name=dhi.io/python:3.14`).

## Reruns and partial failures

Registry copy, signing, and `latest` moves are idempotent over the same
digest: rerunning the release workflow converges instead of diverging. The
PyPI job refuses to publish or clobber when freshly built artifacts differ
from files PyPI already serves; the sdist is not byte-reproducible, so after
a partial publish, complete the remaining channels with the bytes PyPI
already serves rather than rebuilding. Never amend or force-push a released
commit or tag: correct forward with a new commit and, when needed, a new
patch release.

## The `v3` major tag

`uses: craevidence/cli@v3` resolves through the mutable `v3` tag. It always
points at the latest `v3.x` release commit, never at `main`.

- Creation and every later move: verify the target release tag and commit
  first, then update only `refs/tags/v3`
  (`git tag -f v3 <release-commit> && git push --force origin refs/tags/v3`),
  then re-read the remote tag and confirm it points at the intended commit.
- Moving `v3` is the one documented exception to the no-force-push rule, and
  it applies to `refs/tags/v3` only.

## Retro-signed images

The Docker Hub and Quay copies of releases published before per-registry
signing carry post-hoc signatures created by the manually dispatched,
approval-gated workflow in `.github/workflows/retro-sign.yml`. Verify those
with the identity
`https://github.com/craevidence/cli/.github/workflows/retro-sign.yml@refs/heads/main`
instead of a release tag identity.
