#!/usr/bin/env bash
# Engine gate for the bundled SAST rule pack.
#
# Runs opengrep against each rule file and its matching fixture individually.
# Batch mode (--config <dir>) is intentionally avoided: it rewrites rule ids
# to dotted paths and causes cross-rule fixture matching.
#
# Requires opengrep to be on PATH. In CI, the workflow installs the version
# pinned in cra_evidence_cli/local/rules_pack.py (TESTED_OPENGREP_VERSION).
# Locally, install it from https://github.com/opengrep/opengrep/releases.
#
# Usage: bash scripts/rulepack_gate.sh [--rules-root <path>] [--fixtures-root <path>]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_ROOT="${REPO_ROOT}/cra_evidence_cli/local/rules"
FIXTURES_ROOT="${REPO_ROOT}/tests/rule_fixtures"

# Parse optional overrides
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rules-root)    RULES_ROOT="$2";    shift 2 ;;
        --fixtures-root) FIXTURES_ROOT="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Language-dir to fixture extension mapping
declare -A LANG_EXT=( [python]="py" [javascript]="js" [go]="go" )

if ! command -v opengrep &>/dev/null; then
    echo "error: opengrep not found on PATH" >&2
    echo "Install the version from TESTED_OPENGREP_VERSION in cra_evidence_cli/local/rules_pack.py" >&2
    exit 1
fi

if [[ ! -d "$RULES_ROOT" ]]; then
    echo "error: rules root not found: $RULES_ROOT" >&2
    exit 1
fi

pass=0
fail=0
missing=0
declare -a failures=()

while IFS= read -r -d '' rule_file; do
    rel="${rule_file#"${RULES_ROOT}/"}"          # e.g. python/injection/cra-python-subprocess-shell.yaml
    lang_dir="${rel%%/*}"                         # e.g. python
    stem="${rule_file##*/}"                       # e.g. cra-python-subprocess-shell.yaml
    rule_id="${stem%.yaml}"                       # e.g. cra-python-subprocess-shell

    ext="${LANG_EXT[$lang_dir]:-}"
    if [[ -z "$ext" ]]; then
        echo "FAIL  $rule_id (unknown language dir: $lang_dir; add it to LANG_EXT)"
        ((fail++)) || true
        failures+=("$rule_id (unknown language dir: $lang_dir)")
        continue
    fi

    fixture_rel="${rel%.yaml}.${ext}"            # e.g. python/injection/cra-python-subprocess-shell.py
    fixture="${FIXTURES_ROOT}/${fixture_rel}"

    if [[ ! -f "$fixture" ]]; then
        echo "MISS  $rule_id -- fixture not found: $fixture"
        ((missing++)) || true
        failures+=("$rule_id (missing fixture)")
        continue
    fi

    if opengrep test --config "$rule_file" "$fixture" &>/dev/null; then
        echo "PASS  $rule_id"
        ((pass++)) || true
    else
        echo "FAIL  $rule_id"
        ((fail++)) || true
        failures+=("$rule_id")
        # Re-run with output so CI logs show the failure detail
        opengrep test --config "$rule_file" "$fixture" || true
    fi
done < <(find "$RULES_ROOT" -name "*.yaml" -print0 | sort -z)

total=$((pass + fail + missing))
echo ""
echo "Results: ${pass}/${total} passed, ${fail} failed, ${missing} missing fixture(s)"

if [[ $total -eq 0 ]]; then
    echo "error: no rule files found under $RULES_ROOT" >&2
    exit 1
fi

if [[ ${#failures[@]} -gt 0 ]]; then
    echo ""
    echo "Failures:"
    for f in "${failures[@]}"; do
        echo "  - $f"
    done
    exit 1
fi

exit 0
