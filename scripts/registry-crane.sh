#!/usr/bin/env bash
# crane-based registry inspection with fail-closed absence detection.
#
# crane resolves a digest cleanly on stdout with no pipe or awk, so the
# SIGPIPE race of parsing `imagetools inspect` output is gone. The remaining
# problem is classification: crane exits 1 for EVERY failure (missing tag,
# authorization failure, network failure) with no distinct not-found code, and
# it emits a preliminary HEAD 404 before falling back to GET. So the only
# signal that may authorize creating a tag is the terminal, structured
# MANIFEST_UNKNOWN error crane prints for a genuinely missing manifest, AND the
# registry, repository and reference in that error's failed URL must equal the
# ones that were requested. Every other outcome, including a bare 404, DENIED,
# UNAUTHORIZED, NAME_UNKNOWN, a timeout, a transport failure, or a
# MANIFEST_UNKNOWN for a different manifest or registry, is unknown and fails
# closed after bounded retries.
#
# Usage:
#   registry-crane.sh digest <ref>
#     Prints "FOUND <sha256:...>" when the ref resolves to a valid digest, or
#     "NOTFOUND" when crane reports a definitive missing manifest for this ref.
#     Exits nonzero when the state is still unknown after all retries; the
#     caller must treat a nonzero exit as fatal.
#   registry-crane.sh raw <ref>
#     Prints the raw manifest to stdout on success. Exits 4 on a definitive
#     missing manifest for this ref, nonzero on persistent failure.
#
# Refs may be a Docker Hub short name (craevidence/cli:tag) or fully qualified
# (ghcr.io/owner/name:tag or ...@sha256:...). Attempts default to 5
# (REGISTRY_CRANE_ATTEMPTS); each crane read is bounded by REGISTRY_CRANE_TIMEOUT
# seconds (default 120).
set -uo pipefail

mode="${1:-}"
ref="${2:-}"
if [ -z "${mode}" ] || [ -z "${ref}" ] || [ "$#" -ne 2 ]; then
  echo "usage: registry-crane.sh digest|raw <ref>" >&2
  exit 2
fi
case "${mode}" in
  digest | raw) ;;
  *)
    echo "registry-crane: unknown mode '${mode}' (expected digest|raw)" >&2
    exit 2
    ;;
esac

attempts="${REGISTRY_CRANE_ATTEMPTS:-5}"
if ! printf '%s' "${attempts}" | grep -qE '^[1-9][0-9]*$'; then
  echo "registry-crane: REGISTRY_CRANE_ATTEMPTS must be a positive integer, got '${attempts}'" >&2
  exit 2
fi

timeout_secs="${REGISTRY_CRANE_TIMEOUT:-120}"
if ! printf '%s' "${timeout_secs}" | grep -qE '^[1-9][0-9]*$'; then
  echo "registry-crane: REGISTRY_CRANE_TIMEOUT must be a positive integer, got '${timeout_secs}'" >&2
  exit 2
fi

# Docker Hub is reachable under several hostnames; treat them as one registry.
normalize_host() {
  case "$1" in
    docker.io | index.docker.io | registry-1.docker.io) echo "docker.io" ;;
    *) echo "$1" ;;
  esac
}

# Split a reference into host, repository and reference (tag or digest),
# following Docker name resolution: the first path component is a registry host
# only when it contains a dot or colon or equals localhost, otherwise the
# implied host is docker.io; an untagged reference means the latest tag; and a
# single-component Docker Hub repository lives in the implicit library/
# namespace. This matches how crane resolves names, so craevidence/cli:tag maps
# to docker.io/v2/craevidence/cli/manifests/tag and alpine:tag maps to
# docker.io/v2/library/alpine/manifests/tag.
parse_ref() {
  local raw="$1" name first after_slash
  if [ "${raw#*@}" != "${raw}" ]; then
    name="${raw%@*}"
    parsed_reference="${raw#*@}"
  else
    after_slash="${raw##*/}"
    if [ "${after_slash#*:}" != "${after_slash}" ]; then
      parsed_reference="${raw##*:}"
      name="${raw%:*}"
    else
      parsed_reference="latest"
      name="${raw}"
    fi
  fi
  first="${name%%/*}"
  if [ "${first}" != "${name}" ] && printf '%s' "${first}" | grep -qE '[.:]|^localhost$'; then
    parsed_host="$(normalize_host "${first}")"
    parsed_repository="${name#*/}"
  else
    parsed_host="docker.io"
    parsed_repository="${name}"
  fi
  if [ "${parsed_host}" = "docker.io" ] && [ "${parsed_repository#*/}" = "${parsed_repository}" ]; then
    parsed_repository="library/${parsed_repository}"
  fi
}

parse_ref "${ref}"
req_host="${parsed_host}"
req_repository="${parsed_repository}"
req_reference="${parsed_reference}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
err="${work}/err"
out="${work}/out"

# A definitive absence is ONLY a terminal, structured MANIFEST_UNKNOWN line
# whose FAILED URL (captured before ": MANIFEST_UNKNOWN:", not the diagnostic
# text after it) names the requested registry, repository and reference. Parsing
# the URL fields and comparing them rejects a MANIFEST_UNKNOWN reported for a
# different manifest, a different registry, or one whose requested path appears
# only in the diagnostic message. Anything else, including NAME_UNKNOWN, DENIED,
# UNAUTHORIZED, a bare 404, a timeout, or a network failure, fails closed rather
# than authorize creating a tag.
absence_url_re='^Error: (GET|HEAD) (https://[^[:space:]]+/v2/[^[:space:]]+/manifests/[^[:space:]]+): MANIFEST_UNKNOWN:'
is_absence() {
  local last url rest err_host err_repository err_reference
  last="$(tail -n 1 "${err}")"
  [[ "${last}" =~ ${absence_url_re} ]] || return 1
  url="${BASH_REMATCH[2]}"
  rest="${url#https://}"
  err_host="$(normalize_host "${rest%%/v2/*}")"
  rest="${rest#*/v2/}"
  err_repository="${rest%/manifests/*}"
  err_reference="${rest##*/manifests/}"
  [ "${err_host}" = "${req_host}" ] \
    && [ "${err_repository}" = "${req_repository}" ] \
    && [ "${err_reference}" = "${req_reference}" ]
}

for attempt in $(seq 1 "${attempts}"); do
  case "${mode}" in
    digest)
      if timeout "${timeout_secs}" crane digest "${ref}" > "${out}" 2> "${err}"; then
        digest="$(head -n 1 "${out}" | tr -d '[:space:]')"
        if printf '%s' "${digest}" | grep -qE '^sha256:[0-9a-f]{64}$'; then
          printf 'FOUND %s\n' "${digest}"
          exit 0
        fi
        # Resolved but no valid digest: treat as transient and retry.
      elif is_absence; then
        printf 'NOTFOUND\n'
        exit 0
      fi
      ;;
    raw)
      if timeout "${timeout_secs}" crane manifest "${ref}" > "${out}" 2> "${err}"; then
        cat "${out}"
        exit 0
      elif is_absence; then
        echo "registry-crane: ${ref} not found" >&2
        cat "${err}" >&2
        exit 4
      fi
      ;;
  esac
  if [ "${attempt}" -lt "${attempts}" ]; then
    echo "registry-crane: transient failure reading ${ref} (attempt ${attempt}/${attempts}); retrying" >&2
    cat "${err}" >&2
    sleep "$((attempt * 2))"
  fi
done

echo "registry-crane: cannot determine the state of ${ref} after ${attempts} attempts" >&2
cat "${err}" >&2
exit 1
