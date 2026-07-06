#!/usr/bin/env bash
# Verify that the Docker Hardened Images base digests pinned in the Dockerfile
# still resolve in the dhi.io registry.
#
# The hardened base is rebuilt continuously and older digests are removed, so a
# pinned digest can stop resolving upstream and break the image build. This
# check catches a stale pin locally, before it reaches CI.
#
# Requirements: docker, and a logged-in dhi.io session (docker login dhi.io).
# When docker is missing or dhi.io is not reachable (for example, a contributor
# without a Docker account), the check prints a note and passes, so it never
# blocks people who cannot pull the hardened base.
set -uo pipefail

dockerfile="${1:-Dockerfile}"

if ! command -v docker >/dev/null 2>&1; then
  echo "check-dhi-base: docker not found; skipping the digest check."
  exit 0
fi

mapfile -t refs < <(grep -oE 'dhi\.io/[a-zA-Z0-9/_.:-]+@sha256:[a-f0-9]{64}' "$dockerfile" | sort -u)

if [ "${#refs[@]}" -eq 0 ]; then
  echo "check-dhi-base: no pinned dhi.io digests found in ${dockerfile}."
  exit 0
fi

# Probe reachability with the tag of the first reference. A failure here means
# no dhi.io session (auth) rather than a stale digest, so pass with a note.
probe_tag="${refs[0]%@*}"
if ! docker manifest inspect "$probe_tag" >/dev/null 2>&1; then
  echo "check-dhi-base: cannot reach dhi.io (run 'docker login dhi.io'); skipping."
  exit 0
fi

status=0
for ref in "${refs[@]}"; do
  if docker manifest inspect "$ref" >/dev/null 2>&1; then
    echo "ok    ${ref}"
  else
    tag="${ref%@*}"
    current="$(docker buildx imagetools inspect "$tag" 2>/dev/null | awk '/^Digest:/{print $2; exit}')"
    echo "stale ${ref}"
    echo "      ${tag} now resolves to ${current:-unknown}"
    echo "      update the pinned digest in ${dockerfile} to the value above."
    status=1
  fi
done

exit "$status"
