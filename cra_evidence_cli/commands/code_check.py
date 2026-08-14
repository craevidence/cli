"""Source code security check command (advisory, no API key required).

Runs Opengrep on a local directory using a bundled set of CRA-relevant rules.
Findings are potential weaknesses to review, not a determination. Advisory by
default (exit 0 even when findings are reported); pass --fail-on to gate CI
(exit 27). Secrets and IaC checks live in secrets-check and config-check.
"""

from __future__ import annotations

import asyncio
import copy
import fnmatch
import json
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import click

from cra_evidence_cli.config import validate_config
from cra_evidence_cli.display import warn_unsupported_output_format
from cra_evidence_cli.exceptions import CRAEvidenceError
from cra_evidence_cli.local.disclaimer import advisory_block
from cra_evidence_cli.local.rules_pack import PACK_VERSION, inspect_rule_pack
from cra_evidence_cli.local.sast_scanner import (
    OPENGREP_INSTALL_HINT,
    SASTReport,
    opengrep_path,
    run_scan,
)
from cra_evidence_cli.local.semantic_evidence import (
    SemanticEvidenceError,
    expected_symbol,
    load_semantic_evidence,
)
from cra_evidence_cli.repo_config import resolve_identity

_SAST_EXIT_CODE = 27
_SAST_DEGRADED_EXIT_CODE = 29

_BUNDLED_RULES = Path(__file__).parent.parent / "local" / "rules"

_SCOPE_NOTE = (
    "Secrets and credential patterns are covered by secrets-check. "
    "Infrastructure-as-code misconfigurations are covered by config-check."
)

_HONEST_NOTE = (
    "Findings are potential weaknesses to review, not a determination. "
    "This is not an audit; a clean result does not prove the absence of "
    "vulnerabilities. Source code is not uploaded. With --upload, only sanitized "
    "finding metadata is sent to CRA Evidence."
)

_LANGUAGE_DISPLAY_NAMES = {
    "c": "C",
    "cpp": "C++",
    "csharp": "C#",
    "go": "Go",
    "java": "Java",
    "javascript": "JavaScript and TypeScript",
    "php": "PHP",
    "python": "Python",
    "rust": "Rust",
}


def _default_zero_files_reason(inventory) -> str:
    """Name only the languages the pack actually leaves to experimental rules.

    Derived from the inventory rather than written out, so promoting a rule to
    the default tier cannot leave this text claiming its language is disabled.
    """
    names = [
        _LANGUAGE_DISPLAY_NAMES.get(language, language)
        for language in inventory.experimental_only_languages
    ]
    if not names:
        return "No files matched the enabled default rules."
    if len(names) == 1:
        listed = names[0]
    else:
        listed = ", ".join(names[:-1]) + ", and " + names[-1]
    return (
        "No files matched the enabled default rules. Experimental rules for "
        f"{listed} are disabled; use --include-experimental to enable them."
    )


_IGNORED_DIRECTORY_NAMES = frozenset(
    {
        "tests",
        "test",
        "__tests__",
        "vendor",
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "dist",
        "build",
    }
)

_EXTENSION_LANGUAGE_GROUPS = {
    ".py": ("Python", ("python",)),
    ".go": ("Go", ("go",)),
    ".js": ("JavaScript", ("javascript",)),
    ".jsx": ("JavaScript", ("javascript",)),
    ".mjs": ("JavaScript", ("javascript",)),
    ".cjs": ("JavaScript", ("javascript",)),
    ".ts": ("TypeScript", ("javascript",)),
    ".tsx": ("TypeScript", ("javascript",)),
    ".mts": ("TypeScript", ("javascript",)),
    ".cts": ("TypeScript", ("javascript",)),
    ".java": ("Java", ("java",)),
    ".c": ("C", ("c",)),
    ".h": ("C/C++", ("c", "cpp")),
    ".cc": ("C++", ("cpp",)),
    ".cpp": ("C++", ("cpp",)),
    ".cxx": ("C++", ("cpp",)),
    ".hpp": ("C++", ("cpp",)),
    ".rs": ("Rust", ("rust",)),
    ".php": ("PHP", ("php",)),
    ".cs": ("C#", ("csharp",)),
}


def _code_advisory_block() -> dict:
    return {**advisory_block(), "code_check": _HONEST_NOTE}


def _experimental_only_extensions(inventory) -> frozenset[str]:
    """Extensions whose languages the pack covers with experimental rules only."""
    languages = set(inventory.experimental_only_languages)
    return frozenset(
        extension
        for extension, (_, groups) in _EXTENSION_LANGUAGE_GROUPS.items()
        if languages.issuperset(groups)
    )


def _has_experimental_source(path: Path, extensions: frozenset[str]) -> bool:
    candidates = [path] if path.is_file() else path.rglob("*")
    try:
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                relative_parts = candidate.relative_to(path).parts if path.is_dir() else ()
            except ValueError:
                relative_parts = candidate.parts
            if _IGNORED_DIRECTORY_NAMES.intersection(relative_parts):
                continue
            if candidate.suffix.lower() in extensions:
                return True
    except OSError:
        return False
    return False


def _git_visible_files(path: Path) -> list[Path] | None:
    """Return tracked and non-ignored untracked files when Git can define scope."""
    git = shutil.which("git")
    if git is None:
        return None
    base = path if path.is_dir() else path.parent
    try:
        root_result = subprocess.run(  # noqa: S603
            [git, "-C", str(base), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if root_result.returncode != 0:
        return None
    root = Path(root_result.stdout.strip()).resolve()
    target = path.resolve()
    try:
        pathspec = target.relative_to(root).as_posix()
    except ValueError:
        return None
    try:
        list_result = subprocess.run(  # noqa: S603
            [
                git,
                "-C",
                str(root),
                "ls-files",
                "-co",
                "--exclude-standard",
                "--",
                pathspec,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if list_result.returncode != 0:
        return None
    return [root / line for line in list_result.stdout.splitlines() if line]


def _matches_explicit_exclude(relative: Path, excludes: tuple[str, ...]) -> bool:
    value = relative.as_posix()
    for pattern in excludes:
        normalized = pattern.removeprefix("./").rstrip("/")
        if not normalized:
            continue
        if (
            fnmatch.fnmatch(value, normalized)
            or fnmatch.fnmatch(relative.name, normalized)
            or normalized in relative.parts
        ):
            return True
    return False


def _visible_source_files(path: Path, excludes: tuple[str, ...]) -> list[Path]:
    if path.is_file():
        candidates = [path.resolve()]
        root = path.parent.resolve()
    else:
        root = path.resolve()
        candidates = _git_visible_files(path)
        if candidates is None:
            candidates = list(path.rglob("*"))

    visible: list[Path] = []
    for candidate in candidates:
        if candidate.is_symlink() or not candidate.is_file():
            continue
        try:
            relative = candidate.resolve().relative_to(root)
        except ValueError:
            continue
        if _IGNORED_DIRECTORY_NAMES.intersection(relative.parts[:-1]):
            continue
        if _matches_explicit_exclude(relative, excludes):
            continue
        if candidate.suffix.lower() in _EXTENSION_LANGUAGE_GROUPS:
            visible.append(candidate.resolve())
    return sorted(set(visible))


def _unanalysed_source_files(
    path: Path,
    report: SASTReport,
    enabled_language_groups: set[str],
    excludes: tuple[str, ...],
) -> list[dict]:
    scanned: set[Path] = set()
    for raw in report.scanned_paths:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        scanned.add(candidate.resolve())

    root = path.resolve() if path.is_dir() else path.parent.resolve()
    missing: list[dict] = []
    for candidate in _visible_source_files(path, excludes):
        if candidate in scanned:
            continue
        language, groups = _EXTENSION_LANGUAGE_GROUPS[candidate.suffix.lower()]
        reason = (
            "engine_not_selected"
            if enabled_language_groups.intersection(groups)
            else "no_enabled_rules"
        )
        missing.append(
            {
                "path": candidate.relative_to(root).as_posix(),
                "language": language,
                "reason": reason,
            }
        )
    return missing


def _unanalysed_language_counts(report: SASTReport) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in report.unanalysed_files:
        language = str(item["language"])
        counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items()))


def _coverage_degraded(report: SASTReport) -> bool:
    return bool(not report.scan_failed and (report.engine_errors or report.unanalysed_files))


def _mark_unanalysed_coverage(report: SASTReport) -> None:
    if not report.sarif_raw or not report.unanalysed_files:
        return
    runs = report.sarif_raw.get("runs") or []
    if not runs:
        return
    invocations = runs[0].setdefault("invocations", [])
    if not invocations:
        invocations.append({"executionSuccessful": True})
    invocation = invocations[0]
    invocation["executionSuccessful"] = True
    notifications = invocation.setdefault("toolExecutionNotifications", [])
    notifications.append(
        {
            "level": "warning",
            "message": {
                "text": (
                    "Coverage degraded: "
                    f"{len(report.unanalysed_files)} relevant source file(s) "
                    "were not analysed"
                )
            },
        }
    )


def _replace_failure_reason(report: SASTReport, reason: str) -> None:
    report.failure_reason = reason
    if not report.sarif_raw:
        return
    for run in report.sarif_raw.get("runs") or []:
        for invocation in run.get("invocations") or []:
            for notification in invocation.get("toolExecutionNotifications") or []:
                if notification.get("level") == "error":
                    notification["message"] = {"text": reason}


def _finding_relative_path(finding, scan_root: Path) -> str:
    root = scan_root.resolve()
    base = root.parent if root.is_file() else root
    raw = Path(finding.file.removeprefix("file://"))
    candidates = [raw] if raw.is_absolute() else [(Path.cwd() / raw).resolve(), base / raw]
    for candidate in candidates:
        try:
            return candidate.resolve().relative_to(base).as_posix()
        except ValueError:
            continue
    reason_code = "candidate_path_mismatch"
    message = "candidate path is outside the semantic evidence source root"
    raise SemanticEvidenceError(reason_code, message)


def _finding_identity(finding) -> tuple:
    return (
        finding.rule_id,
        finding.file,
        finding.line,
        finding.start_column,
        finding.end_line,
        finding.end_column,
    )


def _sarif_result_identity(result: dict) -> tuple:
    locations = result.get("locations") or [{}]
    location = locations[0] if locations else {}
    physical = location.get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    return (
        result.get("ruleId") or "",
        artifact.get("uri") or "",
        region.get("startLine"),
        region.get("startColumn"),
        region.get("endLine"),
        region.get("endColumn"),
    )


def _sync_sarif_semantic_results(
    report: SASTReport,
    semantic_rule_ids: set[str],
) -> None:
    if not report.sarif_raw:
        return
    accepted = {
        _finding_identity(finding): finding.semantic_evidence
        for finding in report.findings
        if finding.rule_id in semantic_rule_ids
    }
    for run in report.sarif_raw.get("runs") or []:
        filtered: list[dict] = []
        for result in run.get("results") or []:
            if result.get("ruleId") not in semantic_rule_ids:
                filtered.append(result)
                continue
            identity = _sarif_result_identity(result)
            semantic = accepted.get(identity)
            if semantic is None:
                continue
            result.setdefault("properties", {})["craEvidenceSemanticEvidence"] = semantic
            filtered.append(result)
        run["results"] = filtered


def _semantic_unanalysed_item(path: str, reason_code: str, language: str) -> dict:
    return {
        "path": path,
        "language": _LANGUAGE_DISPLAY_NAMES.get(language, language),
        "reason": reason_code,
    }


def _apply_semantic_evidence(
    report: SASTReport,
    inventory,
    evidence_paths: tuple[Path, ...],
    scan_root: Path,
) -> None:
    policies = inventory.semantic_policies
    candidates = [finding for finding in report.findings if finding.rule_id in policies]
    if not candidates:
        return

    reason_counts: dict[str, int] = {}
    attested = 0
    rejected = 0
    unanalysed = 0
    verified = []
    load_error: SemanticEvidenceError | None = None
    if not evidence_paths:
        load_error = SemanticEvidenceError(
            "semantic_evidence_missing",
            "semantic-required candidates have no evidence envelope",
        )
    else:
        try:
            verified = [
                load_semantic_evidence(evidence_path, scan_root) for evidence_path in evidence_paths
            ]
        except SemanticEvidenceError as exc:
            load_error = exc

    kept = [finding for finding in report.findings if finding.rule_id not in policies]
    existing_unanalysed = {
        (item.get("path"), item.get("language"), item.get("reason"))
        for item in report.unanalysed_files
    }
    for finding in candidates:
        policy = policies[finding.rule_id]
        try:
            relative_path = _finding_relative_path(finding, scan_root)
        except SemanticEvidenceError as exc:
            relative_path = Path(finding.file).name
            candidate_error = exc
        else:
            candidate_error = load_error

        if candidate_error is None and (
            finding.line is None
            or finding.start_column is None
            or finding.end_line is None
            or finding.end_column is None
        ):
            candidate_error = SemanticEvidenceError(
                "candidate_range_missing",
                "semantic-required candidate has no exact SARIF range",
            )

        if candidate_error is not None:
            reason = candidate_error.reason_code
            unanalysed += 1
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            item = _semantic_unanalysed_item(relative_path, reason, policy.language)
            key = (item["path"], item["language"], item["reason"])
            if key not in existing_unanalysed:
                report.unanalysed_files.append(item)
                existing_unanalysed.add(key)
            continue

        symbol = expected_symbol(policy.policy)
        range_matches = tuple(
            (evidence, occurrence)
            for evidence in verified
            if evidence.language == policy.language
            for occurrence in evidence.matching_occurrences(
                path=relative_path,
                start_line=finding.line,
                start_column=finding.start_column,
                end_line=finding.end_line,
                end_column=finding.end_column,
            )
        )
        if not range_matches:
            reason = "semantic_occurrence_missing"
            unanalysed += 1
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            item = _semantic_unanalysed_item(relative_path, reason, policy.language)
            key = (item["path"], item["language"], item["reason"])
            if key not in existing_unanalysed:
                report.unanalysed_files.append(item)
                existing_unanalysed.add(key)
            continue
        if len(range_matches) != 1:
            reason = "semantic_occurrence_ambiguous"
            unanalysed += 1
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            item = _semantic_unanalysed_item(relative_path, reason, policy.language)
            key = (item["path"], item["language"], item["reason"])
            if key not in existing_unanalysed:
                report.unanalysed_files.append(item)
                existing_unanalysed.add(key)
            continue

        evidence, occurrence = range_matches[0]
        if occurrence.symbol != symbol:
            reason = "semantic_symbol_not_attested"
            rejected += 1
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            continue
        semantic = {
            "status": "attested",
            "reason_code": "semantic_symbol_attested",
            "policy": policy.policy,
            "adapter_profile": evidence.adapter_profile,
            "source_tree_sha256": evidence.source_tree_sha256,
            "build_profile_sha256": evidence.build_profile_sha256,
        }
        kept.append(replace(finding, semantic_evidence=semantic))
        attested += 1
        reason_counts["semantic_symbol_attested"] = (
            reason_counts.get("semantic_symbol_attested", 0) + 1
        )

    report.findings = kept
    report.semantic_evidence_summary = {
        "schema_version": "craevidence.semantic_summary.v1",
        "candidate_count": len(candidates),
        "attested": attested,
        "rejected": rejected,
        "unanalysed": unanalysed,
        "reason_counts": dict(sorted(reason_counts.items())),
    }
    _sync_sarif_semantic_results(report, set(policies))
    _mark_unanalysed_coverage(report)


def _severity_label(level: str) -> str:
    return level.upper()


def _render_text(report: SASTReport, verbose: bool = False) -> str:
    lines = ["Source code security check"]
    lines.append(f"Engine: Opengrep {report.engine_version}")
    rules_line = f"Rules: {report.rules_path} ({report.rule_count} enabled)"
    if report.pack_version:
        rules_line += f", pack {report.pack_version}"
    lines.append(rules_line)
    if report.default_rule_count is not None:
        experimental = report.experimental_rule_count or 0
        available = report.available_experimental_rule_count or 0
        lines.append(
            f"Rule tiers: {report.default_rule_count} default, "
            f"{experimental} experimental enabled, {available} experimental available"
        )
    if report.rule_language_counts:
        coverage = ", ".join(
            f"{language} {count}" for language, count in report.rule_language_counts.items()
        )
        lines.append(f"Enabled rules by language: {coverage}")
    lines.append(
        f"Engine target selection: {report.files_scanned} files selected, "
        f"{report.files_skipped} skipped, {len(report.engine_errors)} engine errors"
    )
    lines.append(f"Parser coverage assurance: {report.parser_coverage_assurance}.")
    if report.language_counts:
        languages = ", ".join(
            f"{language} {count}" for language, count in report.language_counts.items()
        )
        lines.append(f"Languages: {languages}")
    if report.engine_errors and not report.scan_failed:
        lines.append(
            "Coverage degraded: "
            f"{len(report.engine_errors)} file parse error(s); other findings are shown."
        )
    if report.unanalysed_files and not report.scan_failed:
        missing_languages = ", ".join(
            f"{language} {count}" for language, count in _unanalysed_language_counts(report).items()
        )
        lines.append(
            "Coverage degraded: "
            f"{len(report.unanalysed_files)} relevant source file(s) not analysed "
            f"({missing_languages})."
        )
        if verbose:
            for item in report.unanalysed_files:
                lines.append(f"  {item['path']} [{item['language']}] {item['reason']}")
    if report.semantic_evidence_summary:
        summary = report.semantic_evidence_summary
        lines.append(
            "Semantic evidence: "
            f"{summary['attested']} attested, {summary['rejected']} rejected, "
            f"{summary['unanalysed']} unanalysed."
        )
        if verbose:
            for reason, count in summary["reason_counts"].items():
                lines.append(f"  {reason}: {count}")

    if report.scan_failed:
        lines.append(f"Scan failed: {report.failure_reason}")
        if report.findings:
            lines.append("Findings from completed analysis are shown below.")
        else:
            lines.append("No findings rendered.")
            lines.append("")
            lines.append(_SCOPE_NOTE)
            lines.append(_HONEST_NOTE)
            return "\n".join(lines)

    finding_count = len(report.findings)
    lines.append(f"Findings: {finding_count}")

    if report.findings:
        by_severity: dict[str, list] = {}
        for f in report.findings:
            by_severity.setdefault(f.severity.lower(), []).append(f)

        for level in ("error", "warning", "note"):
            group = by_severity.get(level)
            if not group:
                continue
            lines.append(f"\n{_severity_label(level)} ({len(group)})")
            for f in group:
                where = f"{f.file}:{f.line}" if f.line else f.file
                cwe = ", ".join(f.cwe_list) if f.cwe_list else ""
                cwe_part = f" [{cwe}]" if cwe else ""
                lines.append(f"  {where}  {f.rule_id}{cwe_part}")
                lines.append(f"    {f.message}")
        for level, group in by_severity.items():
            if level not in ("error", "warning", "note"):
                lines.append(f"\n{_severity_label(level)} ({len(group)})")
                for f in group:
                    where = f"{f.file}:{f.line}" if f.line else f.file
                    lines.append(f"  {where}  {f.rule_id}")
                    lines.append(f"    {f.message}")
    else:
        lines.append("No findings matched.")

    lines.append("")
    lines.append(_SCOPE_NOTE)
    lines.append(_HONEST_NOTE)
    return "\n".join(lines)


def _render_json(report: SASTReport) -> str:
    payload = {
        "schema_version": (
            "craevidence.code_check.v2"
            if report.semantic_evidence_summary
            else "craevidence.code_check.v1"
        ),
        "engine": f"Opengrep {report.engine_version}",
        "rules_path": report.rules_path,
        "rule_count": report.rule_count,
        "files_scanned": report.files_scanned,
        "files_skipped": report.files_skipped,
        "engine_error_count": len(report.engine_errors),
        "engine_errors": report.engine_errors,
        "language_counts": report.language_counts,
        "coverage_degraded": _coverage_degraded(report),
        "unanalysed_file_count": len(report.unanalysed_files),
        "unanalysed_files": report.unanalysed_files,
        "unanalysed_language_counts": _unanalysed_language_counts(report),
        "parser_coverage_assurance": report.parser_coverage_assurance,
    }
    if report.semantic_evidence_summary:
        payload["semantic_evidence"] = report.semantic_evidence_summary
    # The bundled pack version is only meaningful for the bundled rules.
    if report.pack_version:
        payload["pack_version"] = report.pack_version
    if report.default_rule_count is not None:
        payload["rule_tiers"] = {
            "default_enabled": report.default_rule_count,
            "experimental_enabled": report.experimental_rule_count or 0,
            "experimental_available": report.available_experimental_rule_count or 0,
        }
        payload["rule_language_counts"] = report.rule_language_counts
    return json.dumps(
        {
            **payload,
            "scan_failed": report.scan_failed,
            "failure_reason": report.failure_reason,
            "finding_count": len(report.findings),
            "findings": [f.to_dict() for f in report.findings],
            "advisory": _code_advisory_block(),
        },
        indent=2,
    )


def _render_sarif(report: SASTReport) -> str:
    if report.sarif_raw:
        document = copy.deepcopy(report.sarif_raw)
        runs = document.get("runs") or []
        if runs:
            driver = runs[0].setdefault("tool", {}).setdefault("driver", {})
            properties = driver.setdefault("properties", {})
            properties["craEvidenceCoverageDegraded"] = _coverage_degraded(report)
            properties["craEvidenceParserCoverageAssurance"] = report.parser_coverage_assurance
            properties["craEvidenceLanguageCounts"] = report.language_counts
            properties["craEvidenceUnanalysedFileCount"] = len(report.unanalysed_files)
            properties["craEvidenceUnanalysedLanguageCounts"] = _unanalysed_language_counts(report)
            properties["advisory"] = _code_advisory_block()
            if report.semantic_evidence_summary:
                properties["craEvidenceSemanticEvidence"] = report.semantic_evidence_summary
            if report.pack_version:
                properties["craEvidencePackVersion"] = report.pack_version
            if report.default_rule_count is not None:
                properties["craEvidenceRuleTiers"] = {
                    "defaultEnabled": report.default_rule_count,
                    "experimentalEnabled": report.experimental_rule_count or 0,
                    "experimentalAvailable": (report.available_experimental_rule_count or 0),
                }
                properties["craEvidenceRuleLanguageCounts"] = report.rule_language_counts
        return json.dumps(document, indent=2)

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "craevidence code-check",
                        "informationUri": "https://craevidence.com",
                        "properties": {
                            "advisory": _code_advisory_block(),
                            "craEvidenceLanguageCounts": report.language_counts,
                            "craEvidenceUnanalysedFileCount": len(report.unanalysed_files),
                            "craEvidenceUnanalysedLanguageCounts": (
                                _unanalysed_language_counts(report)
                            ),
                            "craEvidenceParserCoverageAssurance": (
                                report.parser_coverage_assurance
                            ),
                            **(
                                {"craEvidenceSemanticEvidence": (report.semantic_evidence_summary)}
                                if report.semantic_evidence_summary
                                else {}
                            ),
                        },
                    }
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": not report.scan_failed,
                        "toolExecutionNotifications": (
                            [
                                {
                                    "level": "error",
                                    "message": {"text": report.failure_reason or "scan failed"},
                                }
                            ]
                            if report.scan_failed
                            else []
                        ),
                    }
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2)


_UPLOAD_SIZE_LIMIT = 10 * 1024 * 1024  # 10 MiB


@click.command("code-check")
@click.argument(
    "path",
    default=Path("."),
    type=click.Path(exists=True, path_type=Path),
    required=False,
)
@click.option(
    "--rules",
    "rules_path",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    help=(
        "Path to an Opengrep rules directory or file. "
        "Defaults to the bundled CRA Evidence rule pack."
    ),
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["note", "warning", "error"], case_sensitive=False),
    help=(
        "Exit 27 if any finding at or above this severity is found. "
        "Exit 29 instead if parser coverage is degraded. "
        "Advisory (exit 0) by default."
    ),
)
@click.option(
    "--timeout",
    "timeout",
    default=300,
    type=int,
    show_default=True,
    help="Maximum seconds to wait for the scan engine.",
)
@click.option(
    "--rule-timeout",
    "rule_timeout",
    default=30,
    type=click.IntRange(min=1),
    show_default=True,
    help="Maximum seconds Opengrep may spend on one rule for one file.",
)
@click.option(
    "--exclude",
    "excludes",
    multiple=True,
    help=(
        "Pattern to exclude from the scan (passed to --exclude). "
        "Repeatable. Added to the default exclude list."
    ),
)
@click.option(
    "--exclude-rule",
    "exclude_rules",
    multiple=True,
    help="Rule id to skip (passed to --exclude-rule). Repeatable.",
)
@click.option(
    "--include-experimental",
    is_flag=True,
    default=False,
    help=(
        "Enable early language rules that are disabled by default and have "
        "limited coverage evidence."
    ),
)
@click.option(
    "--semantic-evidence",
    "semantic_evidence_paths",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help=(
        "Validate semantic-required candidates against an external evidence "
        "envelope. Repeatable. The CLI does not execute the semantic analyzer."
    ),
)
@click.option(
    "--upload",
    "upload",
    is_flag=True,
    default=False,
    help="Upload the SARIF results to CRA Evidence after a successful scan.",
)
@click.option(
    "--product",
    "product",
    default=None,
    help="Product slug or ID (required with --upload).",
)
@click.option(
    "--version",
    "version_number",
    default=None,
    help="Version number (required with --upload).",
)
@click.option(
    "-o",
    "--output-file",
    "output_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Write output to a file instead of stdout.",
)
@click.option(
    "-v",
    "--verbose",
    "verbose_opt",
    is_flag=True,
    help="Enable verbose command output. Advisory limitations are always shown.",
)
@click.pass_context
def code_check(
    ctx: click.Context,
    path: Path,
    rules_path: Path | None,
    fail_on: str | None,
    timeout: int,
    rule_timeout: int,
    excludes: tuple[str, ...],
    exclude_rules: tuple[str, ...],
    include_experimental: bool,
    semantic_evidence_paths: tuple[Path, ...],
    upload: bool,
    product: str | None,
    version_number: str | None,
    output_file: Path | None,
    verbose_opt: bool = False,
) -> None:
    """Check source code for potential security weaknesses (no API key needed).

    Runs the resolved Opengrep executable with CRA-relevant rules covering SQL
    injection, OS command injection, unsafe deserialization, weak cryptographic
    algorithms, and disabled TLS verification. Pass a custom rules directory or
    file with --rules.

    Supported platform wheels and containers include Opengrep. Source installs
    may use CRA_EVIDENCE_OPENGREP or an opengrep executable on PATH. A missing or
    failed engine exits nonzero so CI cannot report an unperformed scan as clean.

    Advisory by default and exits 0 even when findings are reported. Pass
    --fail-on error|warning|note to exit 27 when any finding at or above that
    severity is found, so a CI job can gate on it. Degraded parser coverage
    takes precedence and exits 29 because the scan result is incomplete.

    Secrets are not covered here; use secrets-check. Infrastructure-as-code
    misconfigurations are not covered here; use config-check. Code is never sent
    to CRA Evidence unless --upload is passed.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = verbose_opt or ctx.obj.get("verbose", False)

    warn_unsupported_output_format(output_format, ("text", "json", "sarif"))

    effective_rules = rules_path if rules_path is not None else _BUNDLED_RULES

    bundled_inventory = inspect_rule_pack(_BUNDLED_RULES)
    inventory = bundled_inventory if rules_path is None else None
    semantic_inventory = None
    if rules_path is None:
        semantic_inventory = bundled_inventory
    else:
        resolved_rules = rules_path.resolve(strict=True)
        resolved_bundle = _BUNDLED_RULES.resolve(strict=True)
        if resolved_rules == resolved_bundle or resolved_bundle in resolved_rules.parents:
            semantic_inventory = bundled_inventory
    if semantic_evidence_paths and semantic_inventory is None:
        message = "--semantic-evidence is supported only with the bundled rule pack"
        raise click.UsageError(message)
    effective_exclude_rules = exclude_rules
    if inventory is not None and not include_experimental:
        effective_exclude_rules = (
            *exclude_rules,
            *inventory.experimental_rule_ids,
        )

    if opengrep_path() is None:
        report = SASTReport(
            engine_version="unavailable",
            rules_path=str(effective_rules),
            rule_count=0,
            findings=[],
            scan_failed=True,
            failure_reason=OPENGREP_INSTALL_HINT,
            sarif_raw=None,
        )
    else:
        report = run_scan(
            path=path,
            rules=effective_rules,
            timeout=timeout,
            rule_timeout=rule_timeout,
            excludes=excludes,
            exclude_rules=effective_exclude_rules,
            zero_files_reason="Opengrep scanned zero files",
        )
        if (
            report.failure_reason == "Opengrep scanned zero files"
            and inventory is not None
            and not include_experimental
            and _has_experimental_source(path, _experimental_only_extensions(inventory))
        ):
            _replace_failure_reason(report, _default_zero_files_reason(inventory))
    # Show the bundled pack version when the bundled rules were used.
    if rules_path is None:
        report.pack_version = PACK_VERSION
        default_count, experimental_count, language_counts = inventory.selection(
            include_experimental=include_experimental,
            excluded_rule_ids=exclude_rules,
        )
        report.default_rule_count = default_count
        report.experimental_rule_count = experimental_count
        report.available_experimental_rule_count = len(inventory.experimental_rule_ids)
        report.rule_language_counts = language_counts
        report.rule_count = default_count + experimental_count
        report.unanalysed_files = _unanalysed_source_files(
            path,
            report,
            set(language_counts),
            excludes,
        )
        _mark_unanalysed_coverage(report)
        _apply_semantic_evidence(
            report,
            inventory,
            semantic_evidence_paths,
            path,
        )
    elif semantic_inventory is not None:
        _apply_semantic_evidence(
            report,
            semantic_inventory,
            semantic_evidence_paths,
            path,
        )

    if output_format == "json":
        rendered = _render_json(report)
    elif output_format == "sarif":
        rendered = _render_sarif(report)
    else:
        rendered = _render_text(report, verbose)

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered, encoding="utf-8")
        click.echo(f"Code check report written to {output_file}.", err=True)
    else:
        click.echo(rendered)

    if upload:
        if report.scan_failed:
            # The user explicitly asked to record evidence; a silent exit 0
            # would leave the evidence absent while CI stays green.
            message = f"cannot upload: the scan did not complete ({report.failure_reason})"
            raise click.ClickException(message)
        _do_upload(ctx, config, product, version_number, report)

    if report.scan_failed:
        ctx.exit(1)

    if fail_on:
        if report.engine_errors or report.unanalysed_files:
            ctx.exit(_SAST_DEGRADED_EXIT_CODE)
        if report.findings_at_or_above(fail_on):
            ctx.exit(_SAST_EXIT_CODE)


def _sanitized_sarif(report: SASTReport) -> dict:
    """Remove source excerpts and local environment details before upload."""
    document = copy.deepcopy(report.sarif_raw or json.loads(_render_sarif(report)))

    def scrub_locations(value) -> None:
        if isinstance(value, list):
            for item in value:
                scrub_locations(item)
            return
        if not isinstance(value, dict):
            return
        value.pop("snippet", None)
        value.pop("contextRegion", None)
        value.pop("contents", None)
        artifact = value.get("artifactLocation")
        if isinstance(artifact, dict) and isinstance(artifact.get("uri"), str):
            uri = artifact["uri"]
            candidate = Path(uri.removeprefix("file://"))
            if candidate.is_absolute():
                root = Path(report.scan_root) if report.scan_root else None
                if root and root.is_file():
                    root = root.parent
                try:
                    artifact["uri"] = str(candidate.relative_to(root)) if root else candidate.name
                except ValueError:
                    artifact["uri"] = candidate.name
        for nested in value.values():
            scrub_locations(nested)

    def scrub_flow_messages(value) -> None:
        if isinstance(value, list):
            for item in value:
                scrub_flow_messages(item)
            return
        if not isinstance(value, dict):
            return
        value.pop("message", None)
        for nested in value.values():
            scrub_flow_messages(nested)

    for run in document.get("runs") or []:
        run.pop("originalUriBaseIds", None)
        run.pop("artifacts", None)
        run.pop("versionControlProvenance", None)
        run.pop("graphs", None)
        run.pop("webRequests", None)
        run.pop("webResponses", None)
        run.pop("specialLocations", None)
        for invocation in run.get("invocations") or []:
            invocation.pop("environmentVariables", None)
            invocation.pop("workingDirectory", None)
            invocation.pop("commandLine", None)
            invocation.pop("arguments", None)
            invocation.pop("message", None)
            invocation.pop("toolExecutionNotifications", None)
            if report.engine_errors and not report.scan_failed:
                invocation["toolExecutionNotifications"] = [
                    {
                        "level": "warning",
                        "message": {
                            "text": (
                                "Coverage degraded: "
                                f"{len(report.engine_errors)} file parse error(s)"
                            )
                        },
                    }
                ]
        driver = run.get("tool", {}).get("driver", {})
        properties = driver.setdefault("properties", {})
        properties["craEvidenceCoverageDegraded"] = _coverage_degraded(report)
        properties["craEvidenceParserCoverageAssurance"] = report.parser_coverage_assurance
        properties["craEvidenceLanguageCounts"] = report.language_counts
        properties["advisory"] = _code_advisory_block()
        if report.semantic_evidence_summary:
            properties["craEvidenceSemanticEvidence"] = report.semantic_evidence_summary
        if report.pack_version:
            properties["craEvidencePackVersion"] = report.pack_version
        if report.default_rule_count is not None:
            properties["craEvidenceRuleTiers"] = {
                "defaultEnabled": report.default_rule_count,
                "experimentalEnabled": report.experimental_rule_count or 0,
                "experimentalAvailable": report.available_experimental_rule_count or 0,
            }
            properties["craEvidenceRuleLanguageCounts"] = report.rule_language_counts
        driver_rules = run.get("tool", {}).get("driver", {}).get("rules") or []
        static_messages = {
            rule.get("id"): (
                (rule.get("fullDescription") or {}).get("text")
                or (rule.get("shortDescription") or {}).get("text")
                or "Security finding"
            )
            for rule in driver_rules
            if rule.get("id")
        }
        for result in run.get("results") or []:
            result["message"] = {
                "text": static_messages.get(result.get("ruleId"), "Security finding")
            }
            result.pop("logicalLocations", None)
            result.pop("graphs", None)
            result.pop("stacks", None)
            result.pop("attachments", None)
            result.pop("webRequest", None)
            result.pop("webResponse", None)
            result.pop("hostedViewerUri", None)
            result.pop("workItemUris", None)
            result.pop("relatedLocations", None)
            result.pop("fixes", None)
            scrub_locations(result)
            scrub_flow_messages(result.get("codeFlows") or [])
    return document


def _do_upload(ctx: click.Context, config, product, version_number, report: SASTReport) -> None:
    import tempfile

    from cra_evidence_cli.client import CRAEvidenceClient

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(e.exit_code)

    try:
        validate_config(config)
    except CRAEvidenceError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(e.exit_code)

    sarif_text = json.dumps(_sanitized_sarif(report), indent=2)
    sarif_bytes = sarif_text.encode("utf-8")

    if len(sarif_bytes) > _UPLOAD_SIZE_LIMIT:
        mb = len(sarif_bytes) / (1024 * 1024)
        message = f"cannot upload: SARIF output is {mb:.1f} MiB, which exceeds the 10 MiB limit"
        raise click.ClickException(message)

    with tempfile.NamedTemporaryFile(suffix=".sarif.json", delete=False) as tmp:
        tmp.write(sarif_bytes)
        tmp_path = Path(tmp.name)

    try:
        client = CRAEvidenceClient(config)
        asyncio.run(
            client.upload_sarif(
                product=product,
                version=version_number,
                file_path=tmp_path,
            )
        )
        click.echo("SARIF results uploaded to CRA Evidence.", err=True)
    except CRAEvidenceError as e:
        click.echo(f"Upload error: {e}", err=True)
        sys.exit(e.exit_code)
    finally:
        tmp_path.unlink(missing_ok=True)
