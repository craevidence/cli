"""Local Opengrep SAST wrapper for no-key code checks."""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

OPENGREP_INSTALL_HINT = (
    "Opengrep is unavailable. Use a supported craevidence platform wheel or container, "
    "or install Opengrep from https://github.com/opengrep/opengrep/releases."
)

_BUNDLED_OPENGREP = Path(__file__).parent.parent / "_engine" / "opengrep"

_DEFAULT_EXCLUDES = (
    "tests",
    "test",
    "__tests__",
    "vendor",
    "node_modules",
    ".git",
    "dist",
    "build",
)

_CWE_TAG_RE = re.compile(r"^(CWE-\d+:.+)$")

_LEVEL_ORDER = {"error": 3, "warning": 2, "note": 1}

_RECOVERABLE_PARSE_ERROR_TYPES = frozenset(
    {
        "LexicalError",
        "Lexical error",
        "ParseError",
        "Syntax error",
        "OtherParseError",
        "Other syntax error",
        "AstBuilderError",
        "AST builder error",
        "PartialParsing",
        "PythonSyntaxError",
        "PythonSyntaxPreflightError",
    }
)

_LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".java": "Java",
    ".c": "C",
    ".h": "C/C++",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".rs": "Rust",
    ".php": "PHP",
    ".cs": "C#",
}


def opengrep_path() -> str | None:
    """Resolve an explicit, bundled, or PATH-provided Opengrep executable."""
    configured = os.environ.get("CRA_EVIDENCE_OPENGREP")
    if configured:
        candidate = Path(configured).expanduser()
        return str(candidate)
    if _BUNDLED_OPENGREP.is_file() and os.access(_BUNDLED_OPENGREP, os.X_OK):
        return str(_BUNDLED_OPENGREP)
    return shutil.which("opengrep")


def get_version(binary: str | None = None) -> str:
    """Return the opengrep version string, or 'unknown' on failure."""
    binary = binary or opengrep_path()
    if binary is None:
        return "unknown"
    try:
        result = subprocess.run(  # noqa: S603
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        out = result.stdout.strip() or result.stderr.strip()
        return out.splitlines()[0] if out else "unknown"
    except Exception:
        return "unknown"


@dataclass(frozen=True)
class SASTFinding:
    """A single SAST finding from an Opengrep scan."""

    rule_id: str
    severity: str
    file: str
    line: int | None
    message: str
    cwe_list: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    semantic_evidence: dict | None = None

    def to_dict(self) -> dict:
        result = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "cwe_list": self.cwe_list,
            "fingerprint": self.fingerprint,
        }
        if self.semantic_evidence is not None:
            result["semantic_evidence"] = self.semantic_evidence
        return result


@dataclass
class SASTReport:
    """Aggregated results from an Opengrep scan."""

    engine_version: str
    rules_path: str
    rule_count: int
    findings: list[SASTFinding]
    scan_failed: bool
    failure_reason: str | None
    sarif_raw: dict | None
    pack_version: str | None = None
    files_scanned: int = 0
    files_skipped: int = 0
    engine_errors: list[dict] = field(default_factory=list)
    scan_root: str | None = None
    language_counts: dict[str, int] = field(default_factory=dict)
    default_rule_count: int | None = None
    experimental_rule_count: int | None = None
    available_experimental_rule_count: int | None = None
    rule_language_counts: dict[str, int] = field(default_factory=dict)
    parser_coverage_assurance: str = "limited"
    scanned_paths: tuple[str, ...] = ()
    skipped_paths: tuple[str, ...] = ()
    unanalysed_files: list[dict] = field(default_factory=list)
    semantic_evidence_summary: dict | None = None

    def findings_at_or_above(self, level: str) -> list[SASTFinding]:
        threshold = _LEVEL_ORDER.get(level.lower(), 1)
        return [f for f in self.findings if _LEVEL_ORDER.get(f.severity.lower(), 1) >= threshold]


def _parse_cwe_tags(tags: list[str]) -> list[str]:
    result = []
    for tag in tags:
        m = _CWE_TAG_RE.match(tag)
        if m:
            result.append(m.group(1))
    return result


def _count_languages(paths: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for scanned in paths:
        language = _LANGUAGE_EXTENSIONS.get(Path(scanned).suffix.lower(), "Other")
        counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items()))


def _python_syntax_errors(paths: list[str]) -> list[dict]:
    grammar = f"CPython {sys.version_info.major}.{sys.version_info.minor}"
    errors: list[dict] = []
    for raw_path in paths:
        candidate = Path(raw_path)
        if candidate.suffix.lower() != ".py" or not candidate.is_file():
            continue
        try:
            source = candidate.read_text(encoding="utf-8-sig")
            ast.parse(source, filename=str(candidate))
        except (SyntaxError, UnicodeError) as exc:
            errors.append(
                {
                    "type": "PythonSyntaxError",
                    "path": str(candidate),
                    "line": getattr(exc, "lineno", None),
                    "message": (
                        f"Python standard-library parsing with {grammar} failed; "
                        "Opengrep may have selected this file without producing a "
                        "usable Python AST"
                    ),
                }
            )
        except (RecursionError, MemoryError, OSError) as exc:
            errors.append(
                {
                    "type": "PythonSyntaxPreflightError",
                    "path": str(candidate),
                    "line": None,
                    "message": (
                        f"Python syntax preflight with {grammar} could not complete: "
                        f"{type(exc).__name__}"
                    ),
                }
            )
    return errors


def _parser_assurance(scanned_paths: list[str]) -> str:
    grammar = f"CPython {sys.version_info.major}.{sys.version_info.minor}"
    if any(Path(path).suffix.lower() == ".py" for path in scanned_paths):
        return (
            "limited; selected Python files receive an independent "
            f"{grammar} syntax preflight, while engine selection still does not "
            "prove a usable Opengrep AST"
        )
    return (
        "limited; engine selection does not prove a usable AST and no independent "
        "syntax preflight ran for the selected languages"
    )


def _count_rules(sarif: dict) -> int:
    try:
        driver = sarif["runs"][0]["tool"]["driver"]
        rules = driver.get("rules") or []
        return len(rules)
    except (KeyError, IndexError):
        return 0


def _parse_sarif(sarif: dict) -> list[SASTFinding]:
    findings: list[SASTFinding] = []
    try:
        run = sarif["runs"][0]
    except (KeyError, IndexError):
        return findings

    rules_by_id: dict[str, dict] = {}
    driver = run.get("tool", {}).get("driver", {})
    for rule in driver.get("rules") or []:
        rid = rule.get("id")
        if rid:
            rules_by_id[rid] = rule

    for result in run.get("results") or []:
        rule_id = result.get("ruleId") or ""
        message = (result.get("message") or {}).get("text") or ""

        locations = result.get("locations") or [{}]
        loc = locations[0] if locations else {}
        phys = loc.get("physicalLocation") or {}
        artifact = phys.get("artifactLocation") or {}
        region = phys.get("region") or {}

        file_uri = artifact.get("uri") or ""
        line = region.get("startLine")
        start_column = region.get("startColumn")
        end_line = region.get("endLine")
        end_column = region.get("endColumn")

        fingerprints = result.get("fingerprints") or {}
        fingerprint = fingerprints.get("matchBasedId/v1")

        rule_meta = rules_by_id.get(rule_id) or {}
        props = rule_meta.get("properties") or {}
        tags = props.get("tags") or []
        cwe_list = _parse_cwe_tags(tags)

        # Results usually omit "level"; SARIF then takes the level from the
        # rule's defaultConfiguration, and "warning" when neither is set.
        default_config = rule_meta.get("defaultConfiguration") or {}
        level = result.get("level") or default_config.get("level") or "warning"

        findings.append(
            SASTFinding(
                rule_id=rule_id,
                severity=level,
                file=file_uri,
                line=line,
                message=message,
                cwe_list=cwe_list,
                fingerprint=fingerprint,
                start_column=start_column,
                end_line=end_line,
                end_column=end_column,
            )
        )

    return findings


def _mark_sarif_failure(sarif: dict, reason: str) -> None:
    runs = sarif.get("runs") or []
    if not runs:
        return
    invocations = runs[0].setdefault("invocations", [])
    if not invocations:
        invocations.append({})
    invocation = invocations[0]
    invocation["executionSuccessful"] = False
    notifications = invocation.setdefault("toolExecutionNotifications", [])
    notifications.append({"level": "error", "message": {"text": reason}})


def _engine_error_type(error: dict) -> str:
    error_type = error.get("type")
    if isinstance(error_type, list) and error_type:
        error_type = error_type[0]
    return error_type if isinstance(error_type, str) else ""


def _is_recoverable_parse_error(error: dict) -> bool:
    return _engine_error_type(error) in _RECOVERABLE_PARSE_ERROR_TYPES


def _mark_sarif_degraded(sarif: dict, error_count: int) -> None:
    runs = sarif.get("runs") or []
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
                    f"Coverage degraded: Opengrep reported {error_count} "
                    "recoverable parse error(s)"
                )
            },
        }
    )


def run_scan(
    path: Path,
    rules: Path,
    timeout: int = 300,
    rule_timeout: int = 30,
    excludes: tuple[str, ...] | None = None,
    exclude_rules: tuple[str, ...] = (),
    zero_files_reason: str = "Opengrep scanned zero files",
) -> SASTReport:
    """Run an Opengrep scan and return a SASTReport."""
    binary = opengrep_path()
    engine_version = get_version(binary)
    rules_path = str(rules)

    if binary is None:
        return SASTReport(
            engine_version="not installed",
            rules_path=rules_path,
            rule_count=0,
            findings=[],
            scan_failed=True,
            failure_reason="opengrep not found",
            sarif_raw=None,
        )

    effective_excludes = (*_DEFAULT_EXCLUDES, *(excludes or ()))

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        json_out = tmp.name
    with tempfile.NamedTemporaryFile(suffix=".sarif.json", delete=False) as tmp:
        sarif_out = tmp.name

    cmd = [
        binary,
        "scan",
        "-f",
        str(rules),
        "--no-rewrite-rule-ids",
        f"--json-output={json_out}",
        f"--sarif-output={sarif_out}",
        "--quiet",
        "--disable-version-check",
        # Track taint across functions within a file, not only inside one
        # function. Verified against Opengrep 1.26.0.
        "--taint-intrafile",
        f"--timeout={rule_timeout}",
        "--timeout-threshold=3",
    ]
    for exc in effective_excludes:
        cmd += ["--exclude", exc]
    for rule_id in exclude_rules:
        cmd += ["--exclude-rule", rule_id]
    cmd.append(str(path))

    json_path = Path(json_out)
    sarif_path = Path(sarif_out)
    try:
        try:
            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,
            )
        except subprocess.TimeoutExpired:
            return SASTReport(
                engine_version=engine_version,
                rules_path=rules_path,
                rule_count=0,
                findings=[],
                scan_failed=True,
                failure_reason="scan timed out",
                sarif_raw=None,
            )
        except Exception as exc:
            return SASTReport(
                engine_version=engine_version,
                rules_path=rules_path,
                rule_count=0,
                findings=[],
                scan_failed=True,
                failure_reason=str(exc),
                sarif_raw=None,
            )

        if result.returncode != 0:
            stderr_excerpt = (result.stderr or "").strip()[:400]
            reason = f"engine exited {result.returncode}"
            if stderr_excerpt:
                reason += f": {stderr_excerpt}"
            return SASTReport(
                engine_version=engine_version,
                rules_path=rules_path,
                rule_count=0,
                findings=[],
                scan_failed=True,
                failure_reason=reason,
                sarif_raw=None,
            )

        if not sarif_path.exists():
            return SASTReport(
                engine_version=engine_version,
                rules_path=rules_path,
                rule_count=0,
                findings=[],
                scan_failed=True,
                failure_reason="SARIF output file not found after scan",
                sarif_raw=None,
            )

        try:
            sarif_text = sarif_path.read_text(encoding="utf-8")
            sarif = json.loads(sarif_text)
        except Exception as exc:
            return SASTReport(
                engine_version=engine_version,
                rules_path=rules_path,
                rule_count=0,
                findings=[],
                scan_failed=True,
                failure_reason=f"SARIF output could not be read: {exc}",
                sarif_raw=None,
            )
    finally:
        sarif_path.unlink(missing_ok=True)
        json_text = json_path.read_text(encoding="utf-8") if json_path.exists() else ""
        json_path.unlink(missing_ok=True)

    try:
        scan_data = json.loads(json_text)
    except (json.JSONDecodeError, TypeError):
        return SASTReport(
            engine_version=engine_version,
            rules_path=rules_path,
            rule_count=0,
            findings=[],
            scan_failed=True,
            failure_reason="JSON scan summary could not be read",
            sarif_raw=None,
        )

    paths = scan_data.get("paths") or {}
    scanned_paths = paths.get("scanned") or []
    skipped_paths = paths.get("skipped") or []
    engine_errors = list(scan_data.get("errors") or [])
    engine_errors.extend(_python_syntax_errors(scanned_paths))

    findings = _parse_sarif(sarif)
    rule_count = _count_rules(sarif)
    recoverable_parse_errors = [
        error for error in engine_errors if _is_recoverable_parse_error(error)
    ]
    fatal_engine_errors = [
        error for error in engine_errors if not _is_recoverable_parse_error(error)
    ]
    if not scanned_paths:
        failure_reason = zero_files_reason
    elif fatal_engine_errors:
        failure_reason = (
            f"Opengrep reported {len(fatal_engine_errors)} non-recoverable scan error(s)"
        )
    else:
        failure_reason = None
    if failure_reason:
        _mark_sarif_failure(sarif, failure_reason)
    elif recoverable_parse_errors:
        _mark_sarif_degraded(sarif, len(recoverable_parse_errors))

    return SASTReport(
        engine_version=engine_version,
        rules_path=rules_path,
        rule_count=rule_count,
        findings=findings,
        scan_failed=failure_reason is not None,
        failure_reason=failure_reason,
        sarif_raw=sarif,
        files_scanned=len(scanned_paths),
        files_skipped=len(skipped_paths),
        engine_errors=engine_errors,
        scan_root=str(path.resolve()),
        language_counts=_count_languages(scanned_paths),
        parser_coverage_assurance=_parser_assurance(scanned_paths),
        scanned_paths=tuple(str(value) for value in scanned_paths),
        skipped_paths=tuple(str(value) for value in skipped_paths),
    )
