#!/usr/bin/env bash
# Verify the Docker Hardened Images base digests pinned in the Dockerfile
# against the dhi.io registry.
#
# Usage: scripts/check-dhi-base.sh [--strict] [Dockerfile]
#
# Default (lenient) mode never blocks contributors who cannot pull the
# hardened base: when docker is missing or dhi.io is unreachable, it prints a
# note and passes. It fails (exit 1) only when a pinned digest no longer
# resolves upstream.
#
# Strict mode is the CI and pre-push contract: it exits 0 only when every
# pinned digest still resolves AND is the current digest of its tag. Failures
# are classified instead of skipped:
#   0  fresh: every pin resolves and matches its tag's current digest
#   2  usage error
#   3  docker not available
#   4  registry authentication failed (run 'docker login dhi.io')
#   5  network failure reaching the registry
#   6  a tag or its current digest could not be resolved
#   7  a pinned digest no longer resolves upstream
#   8  a tag has moved to a newer digest than the pin
# When several failures apply, the highest code wins.
set -uo pipefail

strict=0
dockerfile="Dockerfile"
for arg in "$@"; do
  case "${arg}" in
    --strict) strict=1 ;;
    -*)
      echo "usage: $0 [--strict] [Dockerfile]" >&2
      exit 2
      ;;
    *) dockerfile="${arg}" ;;
  esac
done

if ! command -v docker > /dev/null 2>&1; then
  if [ "${strict}" -eq 1 ]; then
    echo "check-dhi-base: docker not found." >&2
    exit 3
  fi
  echo "check-dhi-base: docker not found; skipping the digest check."
  exit 0
fi

if [ ! -f "${dockerfile}" ]; then
  echo "check-dhi-base: ${dockerfile} not found." >&2
  exit 2
fi

mapfile -t refs < <(grep -oE 'dhi\.io/[a-zA-Z0-9/_.:-]+@sha256:[a-f0-9]{64}' "${dockerfile}" | sort -u)

if [ "${#refs[@]}" -eq 0 ]; then
  echo "check-dhi-base: no pinned dhi.io digests found in ${dockerfile}."
  exit 0
fi

# Map a failed registry call to an exit class from its error output.
classify_error() {
  if grep -qiE 'unauthorized|denied|authentication|401|403' <<< "$1"; then
    echo 4
  elif grep -qiE 'no such host|timed? ?out|connection refused|i/o error|network|tls handshake|lookup' <<< "$1"; then
    echo 5
  else
    echo 6
  fi
}

# Probe reachability with the tag of the first reference. A failure here means
# the registry session is broken (auth or network) rather than a stale digest.
probe_tag="${refs[0]%@*}"
if ! probe_err="$(docker manifest inspect "${probe_tag}" 2>&1 > /dev/null)"; then
  if [ "${strict}" -eq 1 ]; then
    echo "check-dhi-base: cannot reach dhi.io for ${probe_tag}:" >&2
    echo "  ${probe_err}" >&2
    exit "$(classify_error "${probe_err}")"
  fi
  echo "check-dhi-base: cannot reach dhi.io (run 'docker login dhi.io'); skipping."
  exit 0
fi

status=0
record() {
  if [ "$1" -gt "${status}" ]; then
    status="$1"
  fi
}

for ref in "${refs[@]}"; do
  tag="${ref%@*}"
  pinned="${ref##*@}"
  if ! docker manifest inspect "${ref}" > /dev/null 2>&1; then
    current="$(docker buildx imagetools inspect "${tag}" 2> /dev/null | awk '/^Digest:/{print $2; exit}')"
    echo "stale ${ref}"
    echo "      ${tag} now resolves to ${current:-unknown}"
    echo "      update the pinned digest in ${dockerfile} to the value above."
    if [ "${strict}" -eq 1 ]; then record 7; else record 1; fi
    continue
  fi
  if [ "${strict}" -eq 1 ]; then
    current="$(docker buildx imagetools inspect "${tag}" 2> /dev/null | awk '/^Digest:/{print $2; exit}')"
    if [ -z "${current}" ]; then
      echo "check-dhi-base: cannot resolve the current digest of ${tag}." >&2
      record 6
    elif [ "${current}" != "${pinned}" ]; then
      echo "moved ${ref}"
      echo "      ${tag} now resolves to ${current}"
      echo "      update the pinned digest in ${dockerfile} before publishing."
      record 8
    else
      echo "fresh ${ref}"
    fi
  else
    echo "ok    ${ref}"
  fi
done

exit "${status}"
