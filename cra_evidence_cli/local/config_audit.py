"""Local secure-by-default configuration audit (advisory, no API key required).

Surfaces a curated set of insecure-default and attack-surface patterns in
Dockerfiles, Terraform, and Kubernetes/Compose manifests. This is deliberately
narrow: it is NOT a full infrastructure-as-code scanner (use Checkov, KICS, or
hadolint for breadth). Findings are candidates to review, not a determination,
and a clean result does not prove a secure-by-default configuration.

Maps to CRA Annex I Part I (2)(b) (secure by default configuration) and (2)(j)
(limit attack surfaces, including external interfaces). Note that (2)(b) also
requires the ability to reset the product to its original state and may be
varied by a tailor-made agreement, neither of which a static scan can observe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "vendor",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}

_MAX_FILE_BYTES = 1024 * 1024  # 1 MiB
_MAX_FINDINGS = 500

POINT_SECURE_DEFAULT = "(2)(b)"
POINT_ATTACK_SURFACE = "(2)(j)"


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    cra_point: str
    pattern: re.Pattern[str]
    message: str
    file_kinds: tuple[str, ...]


# Curated, high-signal line rules. Each maps cleanly to (2)(b) or (2)(j).
_LINE_RULES: tuple[_Rule, ...] = (
    _Rule(
        "container-user-root",
        POINT_SECURE_DEFAULT,
        re.compile(r"^\s*USER\s+(0|root)\b"),
        "Dockerfile sets USER to root; the container runs with root privileges.",
        ("dockerfile",),
    ),
    _Rule(
        "remote-add",
        POINT_ATTACK_SURFACE,
        re.compile(r"^\s*ADD\s+https?://"),
        "Dockerfile ADD fetches a remote URL; prefer a verified, pinned download.",
        ("dockerfile",),
    ),
    _Rule(
        "privileged-container",
        POINT_SECURE_DEFAULT,
        re.compile(r"privileged:\s*true\b"),
        "Privileged container requested; it gains near-host-level access.",
        ("yaml",),
    ),
    _Rule(
        "run-as-root-allowed",
        POINT_SECURE_DEFAULT,
        re.compile(r"runAsNonRoot:\s*false\b"),
        "runAsNonRoot is false; the container may run as root.",
        ("yaml",),
    ),
    _Rule(
        "privilege-escalation",
        POINT_SECURE_DEFAULT,
        re.compile(r"allowPrivilegeEscalation:\s*true\b"),
        "allowPrivilegeEscalation is true; processes can gain more privileges.",
        ("yaml",),
    ),
    _Rule(
        "host-network",
        POINT_ATTACK_SURFACE,
        re.compile(r"hostNetwork:\s*true\b|network_mode:\s*[\"']?host\b"),
        "Container shares the host network namespace, widening the attack surface.",
        ("yaml",),
    ),
    _Rule(
        "dangerous-capability",
        POINT_ATTACK_SURFACE,
        re.compile(r"\b(SYS_ADMIN|NET_ADMIN)\b"),
        "A broad Linux capability (SYS_ADMIN/NET_ADMIN) is requested.",
        ("yaml",),
    ),
    _Rule(
        "bind-all-interfaces",
        POINT_ATTACK_SURFACE,
        re.compile(
            r"(?i)(?:--?(?:bind|host|listen|address)"
            r"|\b[\w-]*(?:bind|host|listen|address)[\w-]*\b)"
            r"[^#\n]{0,80}\b0\.0\.0\.0\b(?!/)|\b0\.0\.0\.0:\d+\b"
        ),
        "Service binds to 0.0.0.0 (all network interfaces).",
        ("yaml", "dockerfile"),
    ),
    _Rule(
        "world-open-ingress",
        POINT_ATTACK_SURFACE,
        re.compile(r"0\.0\.0\.0/0"),
        "Ingress rule open to the entire internet (0.0.0.0/0).",
        ("terraform",),
    ),
    _Rule(
        "public-bucket-acl",
        POINT_SECURE_DEFAULT,
        re.compile(r"acl\s*=\s*[\"'](public-read|public-read-write)[\"']"),
        "Storage ACL grants public access by default.",
        ("terraform",),
    ),
)

_USER_DIRECTIVE = re.compile(r"^\s*USER\s+\S")


@dataclass
class ConfigFinding:
    """A single curated configuration finding (advisory)."""

    rule: str
    cra_point: str
    location: str
    line: int | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "cra_point": self.cra_point,
            "location": self.location,
            "line": self.line,
            "message": self.message,
        }


@dataclass
class ConfigReport:
    """Aggregated configuration-audit results (advisory)."""

    findings: list[ConfigFinding]
    files_scanned: int
    capped: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "finding_count": len(self.findings),
            "capped": self.capped,
            "findings": [f.to_dict() for f in self.findings],
        }


def classify_file(path: Path) -> str | None:
    """Return the config kind ('dockerfile'/'terraform'/'yaml') or None to skip."""
    name = path.name
    if (
        name == "Dockerfile"
        or name.startswith("Dockerfile.")
        or name.lower().endswith(".dockerfile")
    ):
        return "dockerfile"
    suffix = path.suffix.lower()
    if suffix == ".tf":
        return "terraform"
    if suffix in (".yaml", ".yml"):
        return "yaml"
    return None


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        with path.open(encoding="utf-8", errors="ignore") as handle:
            first_chunk = handle.read(8192)
            if "\x00" in first_chunk:
                return None
            return first_chunk + handle.read()
    except OSError:
        return None


def _walk(root: Path):
    try:
        entries = list(root.iterdir())
    except (PermissionError, OSError):
        return
    for entry in entries:
        if entry.is_symlink():
            continue
        if entry.is_dir():
            if entry.name in _SKIP_DIRS:
                continue
            yield from _walk(entry)
        elif entry.is_file():
            yield entry


def scan_file(path: Path, kind: str, location: str) -> list[ConfigFinding]:
    """Apply the curated rules for *kind* to a single file."""
    text = _read_text(path)
    if text is None:
        return []
    lines = text.splitlines()
    findings: list[ConfigFinding] = []
    for lineno, line in enumerate(lines, start=1):
        for rule in _LINE_RULES:
            if kind in rule.file_kinds and rule.pattern.search(line):
                findings.append(
                    ConfigFinding(rule.rule_id, rule.cra_point, location, lineno, rule.message)
                )
    if kind == "dockerfile" and not any(_USER_DIRECTIVE.match(line) for line in lines):
        findings.append(
            ConfigFinding(
                "container-no-user",
                POINT_SECURE_DEFAULT,
                location,
                None,
                "Dockerfile defines no USER instruction; the image runs as root by default.",
            )
        )
    return findings


def evaluate(target: Path) -> ConfigReport:
    """Scan *target* (a directory or single file) for curated config findings."""
    base = target if target.is_dir() else target.parent
    paths = _walk(target) if target.is_dir() else iter([target])

    findings: list[ConfigFinding] = []
    files_scanned = 0
    capped = False
    for path in paths:
        if len(findings) >= _MAX_FINDINGS:
            capped = True
            break
        kind = classify_file(path)
        if kind is None:
            continue
        files_scanned += 1
        try:
            rel = str(path.relative_to(base))
        except ValueError:
            rel = str(path)
        for finding in scan_file(path, kind, rel):
            findings.append(finding)
            if len(findings) >= _MAX_FINDINGS:
                capped = True
                break

    return ConfigReport(findings=findings, files_scanned=files_scanned, capped=capped)
