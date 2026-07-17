#!/usr/bin/env bash
# Resilient wrapper around `docker buildx imagetools inspect`.
#
# Two problems this solves:
#
# 1. Piping inspect straight into `awk '/Digest/{...; exit}'` lets awk close the
#    pipe after the first match; inspect then receives SIGPIPE and returns
#    non-zero, and `set -o pipefail` turns a correct read into a spurious
#    failure with empty stderr. Capturing the full output to a file first, then
#    parsing the file, removes that race entirely.
#
# 2. Registry reads fail transiently (DNS, TLS, service blips). A single such
#    failure must not fail a release, but a persistent unknown state must fail
#    closed so a release never builds or copies over a tag it could not read.
#    This wrapper retries transient failures with bounded backoff and
#    distinguishes a definitive absence from an unknown state.
#
# Usage:
#   registry-inspect.sh digest <ref>
#     Prints "FOUND <sha256:...>" when the ref resolves to a valid digest, or
#     "NOTFOUND" when the registry gives a definitive absence. Exits non-zero
#     only when the state is still unknown after all retries; the caller must
#     treat a non-zero exit as fatal.
#   registry-inspect.sh raw <ref>
#     Prints the raw manifest to stdout on success. Exits 4 on definitive
#     absence, non-zero on persistent failure.
#
# Attempts default to 5 and can be overridden with a positive integer in
# REGISTRY_INSPECT_ATTEMPTS.
set -uo pipefail

mode="${1:-}"
ref="${2:-}"
if [ -z "${mode}" ] || [ -z "${ref}" ] || [ "$#" -ne 2 ]; then
  echo "usage: registry-inspect.sh digest|raw <ref>" >&2
  exit 2
fi
case "${mode}" in
  digest | raw) ;;
  *)
    echo "registry-inspect: unknown mode '${mode}' (expected digest|raw)" >&2
    exit 2
    ;;
esac

attempts="${REGISTRY_INSPECT_ATTEMPTS:-5}"
if ! printf '%s' "${attempts}" | grep -qE '^[1-9][0-9]*$'; then
  echo "registry-inspect: REGISTRY_INSPECT_ATTEMPTS must be a positive integer, got '${attempts}'" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
err="${work}/err"
out="${work}/out"

# A transport failure (authentication or network) is never an absence: it must
# retry and, if it persists, fail closed as unknown rather than be mistaken for
# a missing tag. Token/authorization fetch failures are included here because
# they can carry a 404 (e.g. "failed to fetch anonymous token: 404 Not Found")
# that would otherwise be mistaken for a missing manifest and wrongly authorize
# creating a tag. This is checked BEFORE is_absence, so it always wins.
is_transport_error() {
  grep -qiE 'unauthoriz|not authoriz|denied|authentication|forbidden|insufficient_scope|invalid.?token|401|403|fetch [a-z ]*token|anonymous token|no such host|timed? ?out|connection refused|i/o timeout|tls handshake|lookup .* no such|temporary failure|network is unreachable|too ?many ?requests|toomanyrequests|rate limit' "${err}"
}

# A definitive absence is the registry unambiguously saying the tag/manifest is
# not there. Only these registry-specific signals count; anything else,
# including a bare HTTP 404 from a proxy/gateway/credential service, is treated
# as unknown and fails closed rather than authorize creating a tag. Transport
# errors are excluded first as a second layer of safety.
#   "<ref>: not found"                    (buildx, all of GHCR/Docker Hub/Quay)
#   "manifest unknown" / "name unknown"   (registry v2 API error codes)
#   "no such manifest"
is_absence() {
  if is_transport_error; then
    return 1
  fi
  grep -qF -- "${ref}: not found" "${err}" \
    || grep -qiE 'manifest unknown|name unknown|manifestunknown|nameunknown|no such manifest' "${err}"
}

for attempt in $(seq 1 "${attempts}"); do
  case "${mode}" in
    digest)
      if docker buildx imagetools inspect "${ref}" > "${out}" 2> "${err}"; then
        digest="$(awk '/^Digest:/{print $2; exit}' "${out}")"
        if printf '%s' "${digest}" | grep -qE '^sha256:[0-9a-f]{64}$'; then
          printf 'FOUND %s\n' "${digest}"
          exit 0
        fi
        # Resolved but no valid digest line: treat as transient and retry.
      elif is_absence; then
        printf 'NOTFOUND\n'
        exit 0
      fi
      ;;
    raw)
      if docker buildx imagetools inspect "${ref}" --raw > "${out}" 2> "${err}"; then
        cat "${out}"
        exit 0
      elif is_absence; then
        echo "registry-inspect: ${ref} not found" >&2
        cat "${err}" >&2
        exit 4
      fi
      ;;
  esac
  if [ "${attempt}" -lt "${attempts}" ]; then
    echo "registry-inspect: transient failure reading ${ref} (attempt ${attempt}/${attempts}); retrying" >&2
    cat "${err}" >&2
    sleep "$((attempt * 2))"
  fi
done

echo "registry-inspect: cannot determine the state of ${ref} after ${attempts} attempts" >&2
cat "${err}" >&2
exit 1
