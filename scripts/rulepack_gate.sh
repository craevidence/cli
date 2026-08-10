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
# Usage: bash scripts/rulepack_gate.sh [--rules-root <path>] [--fixtures-root <path>] [--language <group>]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_ROOT="${REPO_ROOT}/cra_evidence_cli/local/rules"
FIXTURES_ROOT="${REPO_ROOT}/tests/rule_fixtures"
LANGUAGE_FILTER=""

# Parse optional overrides
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rules-root)    RULES_ROOT="$2";    shift 2 ;;
        --fixtures-root) FIXTURES_ROOT="$2"; shift 2 ;;
        --language)      LANGUAGE_FILTER="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Language-dir to fixture extension mapping. JavaScript rules declare both
# JavaScript and TypeScript, so both independently maintained variants run.
declare -A LANG_EXTS=(
    [python]="py"
    [javascript]="js ts"
    [go]="go"
    [java]="java"
    [c]="c"
    [cpp]="cpp"
    [rust]="rs"
    [php]="php"
    [csharp]="cs"
)

opengrep_binary="$(command -v opengrep || true)"
if [[ -z "$opengrep_binary" ]]; then
    echo "error: opengrep not found on PATH" >&2
    echo "Install the version from TESTED_OPENGREP_VERSION in cra_evidence_cli/local/rules_pack.py" >&2
    exit 1
fi

python_binary="${REPO_ROOT}/.venv/bin/python"
if [[ ! -x "$python_binary" ]]; then
    python_binary="$(command -v python || true)"
fi
if [[ -z "$python_binary" ]]; then
    echo "error: python is required to verify Opengrep" >&2
    exit 1
fi
actual_version="$("$python_binary" "${REPO_ROOT}/scripts/rulepack_engine.py" --binary "$opengrep_binary")"

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
    if [[ -n "$LANGUAGE_FILTER" && "$lang_dir" != "$LANGUAGE_FILTER" ]]; then
        continue
    fi
    stem="${rule_file##*/}"                       # e.g. cra-python-subprocess-shell.yaml
    rule_id="${stem%.yaml}"                       # e.g. cra-python-subprocess-shell

    extensions="${LANG_EXTS[$lang_dir]:-}"
    if [[ -z "$extensions" ]]; then
        echo "FAIL  $rule_id (unknown language dir: $lang_dir; add it to LANG_EXTS)"
        ((fail++)) || true
        failures+=("$rule_id (unknown language dir: $lang_dir)")
        continue
    fi

    variant_failed=false
    variant_missing=false
    for ext in $extensions; do
        fixture_rel="${rel%.yaml}.${ext}"
        fixture="${FIXTURES_ROOT}/${fixture_rel}"
        if [[ ! -f "$fixture" ]]; then
            echo "MISS  $rule_id -- fixture not found: $fixture"
            ((missing++)) || true
            failures+=("$rule_id (missing .$ext fixture)")
            variant_failed=true
            variant_missing=true
            continue
        fi
        fixture_dir="$(dirname "$fixture")"
        while IFS= read -r -d '' variant; do
            variant_name="$(basename "$variant")"
            if ! "$opengrep_binary" test --taint-intrafile --config "$rule_file" "$variant" &>/dev/null; then
                echo "FAIL  $rule_id ($variant_name)"
                failures+=("$rule_id ($variant_name)")
                "$opengrep_binary" test --taint-intrafile --config "$rule_file" "$variant" || true
                variant_failed=true
            fi
        done < <(find "$fixture_dir" -maxdepth 1 -type f -name "${rule_id}*.${ext}" -print0 | sort -z)
    done

    if [[ "$variant_failed" == false ]]; then
        echo "PASS  $rule_id"
        ((pass++)) || true
    else
        if [[ "$variant_missing" == false ]]; then
            ((fail++)) || true
        fi
    fi
done < <(find "$RULES_ROOT" -name "*.yaml" -print0 | sort -z)

total=$((pass + fail + missing))
echo ""
echo "Results: ${pass}/${total} passed with Opengrep ${actual_version}, ${fail} failed, ${missing} missing fixture(s)"

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
