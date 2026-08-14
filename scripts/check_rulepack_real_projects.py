#!/usr/bin/env python3
"""Reproduce rule-pack results on pinned representative projects."""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import subprocess
import time
from pathlib import Path

try:
    from scripts.rulepack_engine import resolve_engine, verify_engine
except ModuleNotFoundError:  # Direct execution: python scripts/check_rulepack_real_projects.py
    from rulepack_engine import resolve_engine, verify_engine

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "rulepack_real_projects.json"
DEFAULT_RULES = REPO_ROOT / "cra_evidence_cli" / "local" / "rules"
LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".ts", ".tsx"},
    "go": {".go"},
    "java": {".java"},
    "c": {".c", ".h"},
    "cpp": {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"},
    "rust": {".rs"},
    "php": {".php"},
    "csharp": {".cs"},
}


class CorpusGateError(RuntimeError):
    pass


def _git_head(project: Path) -> str:
    git = shutil.which("git")
    if git is None:
        message = "git is required to verify corpus revisions"
        raise CorpusGateError(message)
    result = subprocess.run(  # noqa: S603
        [git, "-C", str(project), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        message = f"cannot read Git commit for {project}: {result.stderr.strip()}"
        raise CorpusGateError(message)
    return result.stdout.strip()


def _tracked_source_count(checkout: Path, scan_path: str, language: str) -> int:
    extensions = LANGUAGE_EXTENSIONS.get(language)
    if not extensions:
        message = f"unsupported corpus language: {language}"
        raise CorpusGateError(message)
    git = shutil.which("git")
    if git is None:
        message = "git is required to count tracked source files"
        raise CorpusGateError(message)
    result = subprocess.run(  # noqa: S603
        [git, "-C", str(checkout), "ls-files", "-z", "--", scan_path],
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        message = f"cannot count tracked source files in {checkout}"
        raise CorpusGateError(message)
    paths = [Path(value.decode("utf-8")) for value in result.stdout.split(b"\0") if value]
    return sum(path.suffix.lower() in extensions for path in paths)


def _error_kind(error: dict) -> str:
    value = error.get("type")
    if isinstance(value, list) and value:
        value = value[0]
    return value if isinstance(value, str) else "Unknown"


def _relative_result(result: dict, target: Path) -> dict:
    raw_path = Path(str(result.get("path") or "")).resolve()
    try:
        relative = raw_path.relative_to(target.resolve()).as_posix()
    except ValueError as exc:
        message = f"result path escapes corpus target: {raw_path}"
        raise CorpusGateError(message) from exc
    start = result.get("start") or {}
    return {
        "rule_id": str(result.get("check_id") or ""),
        "path": relative,
        "line": start.get("line"),
        "column": start.get("col"),
    }


def _scan(binary: Path, rules: Path, target: Path) -> tuple[dict, list[dict], float]:
    command = [
        str(binary),
        "scan",
        "-f",
        str(rules),
        "--no-rewrite-rule-ids",
        "--taint-intrafile",
        "--disable-version-check",
        "--timeout=20",
        "--timeout-threshold=3",
        "--quiet",
        "--json",
        str(target),
    ]
    started = time.monotonic()
    result = subprocess.run(  # noqa: S603
        command,
        capture_output=True,
        text=True,
        timeout=90,
    )
    elapsed = time.monotonic() - started
    if result.returncode != 0:
        message = (
            f"Opengrep exited {result.returncode} for {target}: "
            f"{result.stderr.strip()[:600]}"
        )
        raise CorpusGateError(message)
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        message = f"Opengrep returned invalid JSON for {target}"
        raise CorpusGateError(message) from exc

    scanned = document.get("paths", {}).get("scanned") or []
    if not scanned:
        message = f"Opengrep scanned zero files for {target}"
        raise CorpusGateError(message)
    findings = sorted(
        (_relative_result(item, target) for item in document.get("results") or []),
        key=lambda item: (
            item["rule_id"],
            item["path"],
            item["line"] or 0,
            item["column"] or 0,
        ),
    )
    finding_counts = collections.Counter(item["rule_id"] for item in findings)
    error_counts = collections.Counter(
        _error_kind(item) for item in document.get("errors") or []
    )
    summary = {
        "files_scanned": len(scanned),
        "findings_by_rule": dict(sorted(finding_counts.items())),
        "engine_errors_by_kind": dict(sorted(error_counts.items())),
    }
    return summary, findings, elapsed


def _validate_project(project: dict, corpus_root: Path) -> Path:
    checkout = corpus_root / str(project["directory"])
    if not checkout.is_dir():
        message = f"missing checkout for {project['name']}: {checkout}"
        raise CorpusGateError(message)
    actual_commit = _git_head(checkout)
    if actual_commit != project["commit"]:
        message = (
            f"{project['name']}: expected commit {project['commit']}, "
            f"found {actual_commit}"
        )
        raise CorpusGateError(message)
    license_file = checkout / str(project["license_file"])
    if not license_file.is_file():
        message = f"{project['name']}: missing licence evidence {license_file}"
        raise CorpusGateError(message)
    target = (checkout / str(project["scan_path"])).resolve()
    try:
        target.relative_to(checkout.resolve())
    except ValueError as exc:
        message = f"{project['name']}: scan path escapes checkout"
        raise CorpusGateError(message) from exc
    if not target.exists():
        message = f"{project['name']}: scan path does not exist: {target}"
        raise CorpusGateError(message)
    tracked = _tracked_source_count(
        checkout, str(project["scan_path"]), str(project["language"])
    )
    if tracked != project["tracked_source_files"]:
        message = (
            f"{project['name']}: expected {project['tracked_source_files']} tracked "
            f"source files, found {tracked}"
        )
        raise CorpusGateError(message)
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--opengrep", type=Path, default=Path("opengrep"))
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--project",
        action="append",
        default=[],
        help="Run only the named project. Repeatable.",
    )
    parser.add_argument("--require-complete-parsing", action="store_true")
    args = parser.parse_args()

    args.opengrep = resolve_engine(args.opengrep)
    engine_version = verify_engine(args.opengrep)

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    projects = manifest["projects"]
    if args.project:
        requested = set(args.project)
        known = {str(project["name"]) for project in projects}
        unknown = requested - known
        if unknown:
            message = f"unknown project name(s): {sorted(unknown)}"
            raise CorpusGateError(message)
        projects = [project for project in projects if project["name"] in requested]
    failures: list[str] = []
    for project in projects:
        target = _validate_project(project, args.corpus_root)
        language_rules = args.rules / str(project["language"])
        first_summary, first_findings, first_elapsed = _scan(
            args.opengrep, language_rules, target
        )
        second_summary, second_findings, second_elapsed = _scan(
            args.opengrep, language_rules, target
        )
        if first_summary != second_summary or first_findings != second_findings:
            failures.append(f"{project['name']}: repeated scans differ")
        if first_summary != project["expected"]:
            failures.append(
                f"{project['name']}: expected {project['expected']}, "
                f"found {first_summary}"
            )
        if args.require_complete_parsing and not project["parse_coverage_complete"]:
            failures.append(
                f"{project['name']}: "
                f"{project.get('coverage_blocker', 'parsing is incomplete')}"
            )
        print(
            f"{project['name']}: {first_summary['files_scanned']} files, "
            f"{sum(first_summary['findings_by_rule'].values())} findings, "
            f"{sum(first_summary['engine_errors_by_kind'].values())} errors, "
            f"{first_elapsed:.2f}s/{second_elapsed:.2f}s"
        )

    if failures:
        raise CorpusGateError("real-project gate failed:\n" + "\n".join(failures))
    print(f"real-project gate passed with Opengrep {engine_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
