"""Local Opengrep SAST wrapper for no-key code checks."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

OPENGREP_INSTALL_HINT = (
    "Opengrep is not installed. Install it from https://github.com/opengrep/opengrep "
    "or run: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | sh"
)

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


def opengrep_path() -> str | None:
    """Return the path to the opengrep binary, or None if not installed."""
    return shutil.which("opengrep")


def get_version() -> str:
    """Return the opengrep version string, or 'unknown' on failure."""
    binary = opengrep_path()
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

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "cwe_list": self.cwe_list,
            "fingerprint": self.fingerprint,
        }


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
            )
        )

    return findings


def run_scan(
    path: Path,
    rules: Path,
    timeout: int = 300,
    excludes: tuple[str, ...] | None = None,
    exclude_rules: tuple[str, ...] = (),
) -> SASTReport:
    """Run an Opengrep scan and return a SASTReport."""
    binary = opengrep_path()
    engine_version = get_version()
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

    effective_excludes = excludes if excludes is not None else _DEFAULT_EXCLUDES

    with tempfile.NamedTemporaryFile(suffix=".sarif.json", delete=False) as tmp:
        sarif_out = tmp.name

    cmd = [
        binary,
        "scan",
        "-f",
        str(rules),
        "--no-rewrite-rule-ids",
        f"--sarif-output={sarif_out}",
        "--quiet",
        "--disable-version-check",
        # Track taint across functions within a file, not only inside one
        # function. Verified against Opengrep 1.25.0.
        "--taint-intrafile",
        f"--timeout={timeout}",
    ]
    for exc in effective_excludes:
        cmd += ["--exclude", exc]
    for rule_id in exclude_rules:
        cmd += ["--exclude-rule", rule_id]
    cmd.append(str(path))

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

    findings = _parse_sarif(sarif)
    rule_count = _count_rules(sarif)

    return SASTReport(
        engine_version=engine_version,
        rules_path=rules_path,
        rule_count=rule_count,
        findings=findings,
        scan_failed=False,
        failure_reason=None,
        sarif_raw=sarif,
    )
