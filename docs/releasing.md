# Releasing

Maintainer reference for publishing a CRA Evidence CLI release. Every step
that publishes something is deliberate: nothing here happens implicitly.

## Channels and support policy

A release publishes to PyPI, GHCR, Docker Hub, and Quay, and attaches signed
artifacts and per-platform SBOMs to the GitHub release. All channels are
required for a successful release run. Multi-channel publication is not
transactional: a failed run can leave already-published version artifacts in
place, and a rerun resumes from them instead of replacing them. The `latest`
tags move only after every required channel has succeeded.

Only the latest minor release line is supported. Older lines receive no
fixes; users should upgrade to the newest release.

## The release commit

One commit contains everything the release needs:

1. Roll the `[Unreleased]` section of `CHANGELOG.md` into `## [X.Y.Z] - date`.
2. Bump `version` in `pyproject.toml` AND `__version__` in
   `cra_evidence_cli/__init__.py`; a test fails when they disagree. Bump the
   version before predicting the wheel checksum, because the version is part
   of the wheel bytes.
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
actionlint .github/workflows/*.yml
bash scripts/check-dhi-base.sh --strict
docker build -t craevidence:release-check .
bash scripts/check-image-gate.sh craevidence:release-check
./.venv/bin/python scripts/check_dist.py
```

## Tag and publish

1. Push the release commit to `main`.
2. Create the release tag at exactly that commit and push it:
   `git tag vX.Y.Z <commit> && git push origin vX.Y.Z`. The pipeline's
   signing identity and checkout both derive from this tag.
3. Create the GitHub release from the existing tag `vX.Y.Z` and publish it.
4. Approve the protected deployments when GitHub asks. Three release jobs are
   approval-gated: image publishing and the final `latest` move both use the
   `release-images` environment, and the immutable PyPI upload uses `pypi`.

The pipeline then: validates the release tag against the package version in
a read-only job before any publishing job starts; builds the canonical
multi-arch image once from the release source and pushes it to GHCR, or
reuses the already-published digest when the version tag exists; copies the
index to registries that do not have it and refuses to overwrite a published
version tag that differs; requires every version tag to resolve to the
canonical digest; signs that digest on each registry and verifies every
signature against the release identity
`.../.github/workflows/ci.yml@refs/tags/vX.Y.Z`; generates per-platform
SBOMs from the released digests, attaches them to the GitHub release, and
uploads the linux/amd64 SBOM to CRA Evidence as a required step; acquires
the canonical wheel and sdist (from PyPI when already published, from the
checkpointed release assets, or by building the release source), checks the
wheel against the component pin, signs both files, attaches them to the
GitHub release before any upload, publishes each still-missing file to PyPI
on its own, and verifies PyPI serves exactly the two expected distributions
with matching hashes and accepted Trusted Publishing provenance; and only
after both the container channels and PyPI have succeeded, moves the
`latest` tags in a final approval-gated job.

## After the pipeline

Verify the release from a clean environment. Each check is an assertion, not
a glance:

1. All three registries resolve `X.Y.Z` and `latest` to the same digest as
   GHCR, and `cosign verify` passes for each `repo@digest` under the exact
   tag identity or the exact `refs/heads/main` resume identity, according to
   the run that created that registry copy's signature. Two rules are
   narrower: a reused canonical GHCR digest must already carry the tag
   identity before the pipeline propagates it, and a GHCR digest carrying
   only the branch identity cannot anchor another resume.
2. PyPI serves exactly the built wheel and sdist, with hashes equal to the
   GitHub release assets, and the wheel hash equals the checksum pinned in
   `gitlab-ci-component.yml`.
3. The GitHub release carries `sbom-X.Y.Z-linux-amd64.cdx.json` and
   `sbom-X.Y.Z-linux-arm64.cdx.json`. Release and resume runs invoke
   `scripts/reconcile_release_sboms.sh` during the run, attaching a
   `.cosign.bundle` signature per SBOM that `cosign verify-blob` accepts
   under one of the two exact identities (releases published before this
   behavior, up to v3.8.1, carry unsigned SBOMs until reconciliation is
   re-run against them):
   `.../ci.yml@refs/tags/vX.Y.Z` when the original release run signed it, or
   `.../ci.yml@refs/heads/main` when a resume run created or replaced it.
   Distribution Sigstore bundles follow the same two-identity rule.
4. The image labels report the hardened base
   (`org.opencontainers.image.base.name=dhi.io/python:3.14`).

## Resuming a failed release

If a release run fails partway, do not rerun the failed run: a GitHub rerun
executes the workflow as it was at the release commit, including any defect
that caused the failure. Instead, dispatch the CI workflow from `main` with
the `resume_release` input set to the exact tag (for example `v3.8.1`). Only
the newest stable release can be resumed, because a resume ends by moving the
`latest` tags and an older target would roll them backward; the same
newest-release condition is re-asserted immediately before `latest` moves.
The resume run uses the current pipeline code and resolves the release tag to
a commit exactly once, at validation; every later step uses that commit, so a
tag moved after validation cannot change what is published. The resolved
source is bound to the published artifacts: the package version must match
the tag, and the byte-reproducible wheel built from the source must equal the
wheel PyPI or the release assets already serve.

Every publishing run, release or resume, trusts immutable state and
authenticated state, never bare existence. PyPI files are immutable and are
canonical. A digest reused from the mutable GHCR version tag must already
carry a signature under the exact release tag identity before it is copied or
signed anywhere else. A distribution taken from a mutable release asset must
verify against its checkpointed Sigstore bundle under an accepted identity
before it is published. During reconciliation (`scripts/reconcile_release_sboms.sh`, invoked by
release and resume runs), SBOM assets are kept only when they verify
against their signed bundles; an SBOM without
a complete signed pair is replaced by a freshly generated, freshly signed
document, and one that fails verification
stops the run. Building anything new on a resume requires the GitHub release
to be immutable, which the current publish-then-attach lifecycle does not
produce, so in practice a resume never rebuilds. The run then performs only
the missing operations: an object that already exists and matches is verified
and kept, an absent object is created from authenticated inputs, and any
mismatch fails the run. The exact bytes are checkpointed on the GitHub
release before any PyPI upload, each distribution is published on its own,
and an attestation sidecar lost with a failed runner is recovered from the
accepted provenance PyPI serves.

Failure classes split cleanly. Transport, authentication, service, and
approval failures are retryable: correct the cause and dispatch the resume
again. Integrity conflicts are terminal by design: EVERY digest, signature,
bundle, provenance, source-binding, component-pin, or newest-release conflict
stops the run and needs investigation and, where the published state cannot
be restored, a new patch release. Terminal states include, non-exhaustively:
nothing was published at all, or the canonical image is absent while other
channels exist (a rebuild would have no trusted source); the GHCR version tag
exists but its digest carries no release tag signature; a distribution exists
neither on PyPI nor as a release asset; an unpublished distribution's bytes
exist only as a release asset without a verifiable checkpointed bundle; a
registry already serves the version tag at a different digest; a signature
object exists that matches neither accepted identity; an SBOM and bundle pair
fails verification; a retained release asset differs from the canonical
bytes; the release source does not rebuild the published wheel; or the target
stops being the newest stable release before the latest tags move.

Artifacts created by a resume run are signed with the identity
`.../.github/workflows/ci.yml@refs/heads/main`, which records truthfully that
they were produced by the reviewed pipeline on `main` rather than by the
release tag's workflow. Distribution and SBOM verifiers accept exactly these
two identities and never a pattern. The reused canonical image anchor is
deliberately narrower and accepts only the release tag identity, because a
branch-identity signature is not bound to a version; a consequence is that a
canonical image ever signed only under the branch identity cannot be reused
by a later resume and would need a new patch release.

Never amend or force-push a released commit or tag: correct forward with a
new commit and, when needed, a new patch release.

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

The Docker Hub and Quay copies of releases 3.6.0, 3.6.1, and 3.7.0 were
published before per-registry signing and carry post-hoc signatures created
by a manually dispatched, approval-gated workflow that has since completed
its purpose and been removed. Verify those images with the identity
`https://github.com/craevidence/cli/.github/workflows/retro-sign.yml@refs/heads/main`
instead of a release tag identity.
