"""Local secure-by-default configuration audit (advisory, no API key required).

Surfaces a curated set of insecure-default and attack-surface patterns in
Dockerfiles, Terraform, Kubernetes/Compose manifests, and GitHub Actions
workflows. This is deliberately narrow: it is NOT a full infrastructure-as-code
scanner (use Checkov, KICS, or hadolint for breadth) and NOT a full workflow
linter (use actionlint for that). Findings are candidates to review, not a
determination, and a clean result does not prove a secure-by-default
configuration.

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

# Dotdirs explicitly allowed to be traversed (others stay skipped).
_ALLOWED_DOTDIRS = {".github"}

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
    # --- Dockerfile secret-named build inputs ---
    # Matches ARG or ENV whose identifier contains a credential-like substring.
    # The pattern checks the variable NAME only; it fires on both
    # `ARG DB_PASSWORD` and `ENV DB_PASSWORD=x`.
    # Because the match is substring-based, a name like TOKEN_ENDPOINT_URL will
    # also fire (it contains "TOKEN"). The message makes this explicit so
    # reviewers can dismiss false positives quickly.
    # Build args and ENV values bake into image layers and history; use
    # BuildKit secret mounts (--mount=type=secret) or inject at runtime instead.
    _Rule(
        "dockerfile-secret-arg",
        POINT_SECURE_DEFAULT,
        re.compile(
            r"^\s*(?:ARG|ENV)\s+(?:\S+\s+)*[A-Za-z_]*"
            r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)"
            r"[A-Za-z0-9_]*(?:\s|=|$)",
            re.IGNORECASE,
        ),
        (
            "Dockerfile ARG/ENV name contains a credential-like substring "
            "(password, passwd, secret, token, api_key, private_key, or "
            "credential). Build args appear in image history and build "
            "provenance; ENV values persist in the image and its layers. If this "
            "variable carries a real secret, use a BuildKit secret mount "
            "(RUN --mount=type=secret) or inject the value at runtime rather than "
            "baking it into the image. This check matches the variable NAME only "
            "and may fire on non-secret identifiers such as TOKEN_ENDPOINT_URL; "
            "confirm before acting."
        ),
        ("dockerfile",),
    ),
    # --- GitHub Actions workflow checks ---
    _Rule(
        "workflow-script-injection",
        POINT_ATTACK_SURFACE,
        # Fire on untrusted event data interpolated into a shell context, but NOT
        # on the safe `NAME: ${{ github.event.* }}` env-assignment indirection
        # that the remediation recommends. The leading negative lookahead skips a
        # bare `<key>: ${{` assignment whose key is not `run`.
        re.compile(
            r"^(?!\s*(?!run\s*:)[A-Za-z_][\w-]*\s*:\s*\$\{\{)"
            r".*\$\{\{\s*github\.event\."
            r"(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body"
            r"|pull_request\.head\.ref|comment\.body|head_commit\.message"
            r"|head_ref|base_ref)"
        ),
        (
            "GitHub Actions run: step interpolates untrusted event data directly "
            "into a shell script via ${{ github.event.* }}. An attacker who "
            "controls the event payload (issue title, PR title, comment body, "
            "branch name) can inject arbitrary shell commands. Store the value "
            "in an environment variable first and reference it as $ENV_VAR."
        ),
        ("workflow",),
    ),
    _Rule(
        "workflow-pull-request-target",
        POINT_SECURE_DEFAULT,
        # Matches the block form (pull_request_target:), the inline form
        # (on: pull_request_target), and the list form (on: [pull_request_target]).
        re.compile(r"^\s*(pull_request_target\s*:|on\s*:.*\bpull_request_target\b)"),
        (
            "Workflow uses the pull_request_target trigger, which runs with "
            "write permissions and repository secrets even for forks. Combined "
            "with a checkout of the PR head ref (actions/checkout with a "
            "github.event.pull_request ref), this is a classic privilege "
            "escalation path. Review whether write permissions and secrets are "
            "needed; if so, separate privileged and unprivileged jobs."
        ),
        ("workflow",),
    ),
    _Rule(
        "workflow-set-output-deprecated",
        POINT_SECURE_DEFAULT,
        re.compile(r"::(set-output|save-state)\s+name="),
        (
            "Workflow uses the deprecated ::set-output or ::save-state workflow "
            "command. GitHub has deprecated these commands; they emit warnings "
            "on current runners and GitHub has announced they will stop working. "
            "Replace ::set-output with GITHUB_OUTPUT (echo 'name=value' >> "
            "$GITHUB_OUTPUT) and ::save-state with GITHUB_STATE."
        ),
        ("workflow",),
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
    """Return the config kind or None to skip.

    Kinds: 'dockerfile', 'terraform', 'yaml', 'workflow'.
    'workflow' applies to YAML files under a .github/workflows directory.
    Those files are also valid YAML, but the workflow rules are distinct so
    they use their own kind to avoid mixing rule sets.
    """
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
        # Check whether this file lives inside a .github/workflows tree.
        parts = path.parts
        for i, part in enumerate(parts):
            if part == ".github" and i + 1 < len(parts) and parts[i + 1] == "workflows":
                return "workflow"
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
            # Skip dotdirs unless explicitly allowed (e.g. .github).
            if entry.name.startswith(".") and entry.name not in _ALLOWED_DOTDIRS:
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
