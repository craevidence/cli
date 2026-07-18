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
# are classified per registry operation instead of skipped:
#   0  fresh: every pin resolves and matches its tag's current digest
#   2  usage error
#   3  docker not available
#   4  registry authentication failed (run 'docker login dhi.io')
#   5  network failure reaching the registry
#   6  a tag or its current digest could not be resolved, or strict mode
#      found no pinned dhi.io digest at all
#   7  a pinned digest no longer resolves upstream
#   8  a tag has moved to a newer digest than the pin
# When several failures apply, the highest code wins.
set -uo pipefail

strict=0
dockerfile="Dockerfile"
dockerfile_set=0
for arg in "$@"; do
  case "${arg}" in
    --strict) strict=1 ;;
    -*)
      echo "usage: $0 [--strict] [Dockerfile]" >&2
      exit 2
      ;;
    *)
      if [ "${dockerfile_set}" -eq 1 ]; then
        echo "usage: $0 [--strict] [Dockerfile]" >&2
        exit 2
      fi
      dockerfile="${arg}"
      dockerfile_set=1
      ;;
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

refs=()
while IFS= read -r line; do
  refs+=("${line}")
done < <(grep -oE 'dhi\.io/[a-zA-Z0-9/_.:-]+@sha256:[a-f0-9]{64}' "${dockerfile}" | sort -u)

if [ "${#refs[@]}" -eq 0 ]; then
  # Strict mode is the publishing contract: a build input with no pinned
  # hardened base must never pass as verified. Lenient mode stays permissive
  # for contributor environments.
  if [ "${strict}" -eq 1 ]; then
    echo "check-dhi-base: no pinned dhi.io digests found in ${dockerfile}; strict mode requires the hardened base." >&2
    exit 6
  fi
  echo "check-dhi-base: no pinned dhi.io digests found in ${dockerfile}."
  exit 0
fi

err_file="$(mktemp)"
trap 'rm -f "${err_file}"' EXIT

# Classify the last captured registry error: 4 auth, 5 network, empty when it
# looks like a missing manifest rather than a transport failure.
transport_class() {
  if grep -qiE 'unauthorized|denied|authentication|401|403' "${err_file}"; then
    echo 4
  elif grep -qiE 'no such host|timed? ?out|connection refused|i/o error|network|tls handshake|lookup' "${err_file}"; then
    echo 5
  else
    echo ""
  fi
}

manifest_exists() {
  docker manifest inspect "$1" > /dev/null 2> "${err_file}"
}

current_digest() {
  # Capture the full output before parsing. Piping inspect straight into
  # `awk '...exit'` lets awk close the pipe early, so inspect can die with
  # SIGPIPE and the pipeline reports failure despite a correct read.
  local out
  out="$(docker buildx imagetools inspect "$1" 2> "${err_file}")" || return 1
  printf '%s\n' "${out}" | awk '/^Digest:/{print $2; exit}'
}

report_transport() {
  echo "check-dhi-base: registry error for $1:" >&2
  sed 's/^/  /' "${err_file}" >&2
}

# Probe reachability with the tag of the first reference. A failure here means
# the registry session is broken (auth or network) rather than a stale digest.
probe_tag="${refs[0]%@*}"
if ! manifest_exists "${probe_tag}"; then
  class="$(transport_class)"
  if [ "${strict}" -eq 1 ]; then
    report_transport "${probe_tag}"
    exit "${class:-6}"
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
  if ! manifest_exists "${ref}"; then
    class="$(transport_class)"
    if [ -n "${class}" ]; then
      # Credentials or network broke after the probe; classify, do not call
      # the pin stale. Lenient mode skips like the probe path does.
      report_transport "${ref}"
      if [ "${strict}" -eq 1 ]; then
        record "${class}"
      else
        echo "check-dhi-base: cannot verify ${ref}; skipping."
      fi
      continue
    fi
    current="$(current_digest "${tag}")" || current=""
    if [ -z "${current}" ]; then
      class="$(transport_class)"
      if [ -n "${class}" ]; then
        # The pinned digest did not resolve, but the follow-up tag lookup
        # failed in transport, so the replacement digest is unknown; report
        # the transport failure instead of an unconfirmed stale verdict.
        report_transport "${tag}"
        if [ "${strict}" -eq 1 ]; then
          record "${class}"
        else
          echo "check-dhi-base: cannot verify ${tag}; skipping."
        fi
        continue
      fi
    fi
    echo "stale ${ref}"
    echo "      ${tag} now resolves to ${current:-unknown}"
    echo "      update the pinned digest in ${dockerfile} to the value above."
    if [ "${strict}" -eq 1 ]; then record 7; else record 1; fi
    continue
  fi
  if [ "${strict}" -eq 1 ]; then
    current="$(current_digest "${tag}")" || current=""
    if [ -z "${current}" ]; then
      class="$(transport_class)"
      report_transport "${tag}"
      record "${class:-6}"
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
