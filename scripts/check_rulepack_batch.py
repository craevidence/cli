#!/usr/bin/env python3
"""Validate the complete rule pack against a non-ignored fixture corpus."""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

try:
    from scripts.rulepack_engine import verify_engine
except ModuleNotFoundError:  # Direct execution: python scripts/check_rulepack_batch.py
    from rulepack_engine import verify_engine

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = REPO_ROOT / "cra_evidence_cli" / "local" / "rules"
DEFAULT_FIXTURES = REPO_ROOT / "tests" / "rule_fixtures"
DEFAULT_BASELINE = REPO_ROOT / "tests" / "rulepack_batch.json"
MAX_ANNOTATION_DISTANCE = 12

# These are findings from one rule on a line intentionally marked safe for a
# different rule. Each exception records why both annotations are correct.
CROSS_RULE_OK_ALLOWLIST = {
    (
        "python/jwt/cra-python-jwt-decode-missing-algorithms.py",
        "cra-python-jwt-decode-verify-disabled",
        "cra-python-jwt-decode-missing-algorithms",
    ): "Disabling signature verification is independently unsafe.",
    (
        "python/injection/cra-python-taint-sql-inject.py",
        "cra-python-sql-injection",
        "cra-python-taint-sql-inject",
    ): (
        "The taint rule correctly abstains because the value read back is the "
        "safe key, while the pattern rule reports the concatenated query text "
        "regardless of origin. Both verdicts are right for their own scope."
    ),
    (
        "python/sqlalchemy/cra-python-sqlalchemy-order-by-text-interpolation.py",
        "cra-python-sqlalchemy-text-interpolation",
        "cra-python-sqlalchemy-order-by-text-interpolation",
    ): (
        "Wrapping the interpolated clause in text() avoids the narrow "
        "bare-string rule but is still SQL injection."
    ),
    (
        "python/flask/cra-python-flask-response-html-taint.py",
        "cra-python-flask-open-redirect",
        "cra-python-flask-response-html-taint",
    ): (
        "A redirect response is not an HTML-body XSS sink, but a request-controlled "
        "redirect target is independently an open redirect."
    ),
    (
        "go/tls/cra-go-tls-direct-dial-insecure.go",
        "cra-go-tls-insecure",
        "cra-go-tls-direct-dial-insecure",
    ): (
        "The narrow default rule abstains when a custom verification callback is "
        "present. The broader experimental rule reports the configuration for "
        "review because it does not evaluate the callback implementation."
    ),
    (
        "php/deserialization/cra-php-global-unserialize-superglobal.php",
        "cra-php-unserialize-superglobal",
        "cra-php-global-unserialize-superglobal",
    ): (
        "The narrow default rule excludes a namespaced application function. "
        "The broader experimental rule reports the same short-name call for "
        "review because it does not resolve PHP namespace binding."
    ),
    (
        "rust/tls/cra-rust-cratesio-reqwest-invalid-certs.rs",
        "cra-rust-reqwest-invalid-certs",
        "cra-rust-cratesio-reqwest-invalid-certs",
    ): (
        "The narrow default rule abstains on relative paths, variables, and "
        "intermediate builder calls. The broader experimental rule reports "
        "those method-name shapes without proving external crate ownership."
    ),
}


class BatchGateError(RuntimeError):
    pass


def _run_scan(binary: Path, rules: Path, corpus: Path) -> dict:
    command = [
        str(binary),
        "scan",
        "-f",
        str(rules),
        "--no-rewrite-rule-ids",
        "--taint-intrafile",
        "--disable-version-check",
        "--timeout=30",
        "--timeout-threshold=3",
        "--quiet",
        "--json",
        str(corpus),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=300)  # noqa: S603
    if result.returncode != 0:
        message = (
            f"Opengrep exited {result.returncode}: "
            f"{(result.stderr or '').strip()[:600]}"
        )
        raise BatchGateError(message)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        message = "Opengrep batch output was not valid JSON"
        raise BatchGateError(message) from exc


def _relative_path(raw_path: str, corpus: Path) -> str:
    path = Path(raw_path)
    try:
        return path.resolve().relative_to(corpus.resolve()).as_posix()
    except ValueError as exc:
        message = f"result path is outside the fixture corpus: {raw_path}"
        raise BatchGateError(message) from exc


def _normalized_results(document: dict, corpus: Path) -> list[dict]:
    normalized = []
    for result in document.get("results") or []:
        start = result.get("start") or {}
        end = result.get("end") or {}
        normalized.append(
            {
                "rule_id": result.get("check_id"),
                "path": _relative_path(str(result.get("path") or ""), corpus),
                "start": [start.get("line"), start.get("col")],
                "end": [end.get("line"), end.get("col")],
                "severity": (result.get("extra") or {}).get("severity"),
            }
        )
    return sorted(
        normalized,
        key=lambda item: (
            str(item["rule_id"]),
            str(item["path"]),
            item["start"][0] or 0,
            item["start"][1] or 0,
        ),
    )


def _annotations_for_line(path: Path, line: int) -> tuple[set[str], set[str], int | None]:
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks: list[tuple[int, set[str], set[str]]] = []
    current_ok: set[str] = set()
    current_rule: set[str] = set()
    current_start = 0
    code_since_marker = False
    for line_number, raw_value in enumerate(lines, start=1):
        value = raw_value.strip()
        if not value.startswith(("#", "//")):
            if value:
                code_since_marker = True
            continue
        marker = value.removeprefix("#").removeprefix("//").strip()
        if not marker.startswith(("ok:", "ruleid:")):
            continue
        if current_start and code_since_marker:
            blocks.append((current_start, current_ok, current_rule))
            current_ok = set()
            current_rule = set()
        if not current_start or code_since_marker:
            current_start = line_number
        code_since_marker = False
        if marker.startswith("ok:"):
            current_ok.add(marker.removeprefix("ok:").strip())
        elif marker.startswith("ruleid:"):
            current_rule.add(marker.removeprefix("ruleid:").strip())
    if current_start:
        blocks.append((current_start, current_ok, current_rule))
    applicable = [block for block in blocks if block[0] <= line]
    if not applicable:
        return set(), set(), None
    marker_line, ok_ids, rule_ids = applicable[-1]
    if line - marker_line > MAX_ANNOTATION_DISTANCE:
        return set(), set(), None
    return ok_ids, rule_ids, marker_line


def _check_cross_rule_ok(results: list[dict], corpus: Path) -> None:
    unexplained = []
    for result in results:
        line = result["start"][0]
        if not isinstance(line, int):
            continue
        relative = str(result["path"])
        rule_id = str(result["rule_id"])
        ok_ids, _expected_ids, _marker_line = _annotations_for_line(
            corpus / relative, line
        )
        for ok_id in ok_ids:
            if rule_id == ok_id and Path(relative).stem == ok_id:
                # A fixture normally has both positive and negative examples for
                # its own rule. Only that canonical fixture receives same-rule
                # ownership; an ok marker in another rule's fixture is cross-rule.
                continue
            elif (
                relative,
                rule_id,
                ok_id,
            ) not in CROSS_RULE_OK_ALLOWLIST:
                unexplained.append(
                    f"{relative}:{line}: {rule_id} fired on an ok line for {ok_id}"
                )
    if unexplained:
        raise BatchGateError("untriaged cross-rule ok findings:\n" + "\n".join(unexplained))


def _summary(document: dict, corpus: Path) -> tuple[dict, list[dict]]:
    scanned = document.get("paths", {}).get("scanned") or []
    errors = document.get("errors") or []
    results = _normalized_results(document, corpus)
    if not scanned:
        message = "batch scan evaluated zero files"
        raise BatchGateError(message)
    if not results:
        message = "batch scan produced zero findings"
        raise BatchGateError(message)
    if errors:
        message = f"batch scan reported {len(errors)} engine error(s)"
        raise BatchGateError(message)
    counts = collections.Counter(str(result["rule_id"]) for result in results)
    summary = {
        "files_scanned": len(scanned),
        "finding_count": len(results),
        "findings_by_rule": dict(sorted(counts.items())),
        "findings": results,
    }
    return summary, results


def _scan_once(binary: Path, rules: Path, fixtures: Path) -> tuple[dict, list[dict]]:
    with tempfile.TemporaryDirectory(prefix="cra-rulepack-") as temporary:
        corpus = Path(temporary) / "corpus"
        shutil.copytree(fixtures, corpus)
        document = _run_scan(binary, rules, corpus)
        summary, results = _summary(document, corpus)
        _check_cross_rule_ok(results, corpus)
        return summary, results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opengrep", type=Path, default=Path("opengrep"))
    parser.add_argument("--compare-opengrep", type=Path)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--print-baseline", action="store_true")
    args = parser.parse_args()

    engine_version = verify_engine(args.opengrep)

    summary, first_results = _scan_once(args.opengrep, args.rules, args.fixtures)
    repeated_summary, repeated_results = _scan_once(
        args.opengrep, args.rules, args.fixtures
    )
    if summary != repeated_summary or first_results != repeated_results:
        message = "repeated batch scans produced different results"
        raise BatchGateError(message)

    if args.print_baseline:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    else:
        expected = json.loads(args.baseline.read_text(encoding="utf-8"))
        if summary != expected:
            message = (
                "batch result differs from the reviewed baseline:\n"
                f"expected={json.dumps(expected, sort_keys=True)}\n"
                f"actual={json.dumps(summary, sort_keys=True)}"
            )
            raise BatchGateError(message)

    if args.compare_opengrep is not None:
        verify_engine(args.compare_opengrep)
        candidate_summary, candidate_results = _scan_once(
            args.compare_opengrep, args.rules, args.fixtures
        )
        if candidate_summary != summary or candidate_results != first_results:
            message = "candidate Opengrep changes rule-pack results"
            raise BatchGateError(message)

    print(
        f"batch gate passed: {summary['files_scanned']} files, "
        f"{summary['finding_count']} findings, "
        f"{len(summary['findings_by_rule'])} rules, Opengrep {engine_version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
