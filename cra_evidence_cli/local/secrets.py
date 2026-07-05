"""Local hard-coded secret detection (advisory, no API key required).

Scans the working tree and, when the target is a git repository, its commit
history for hard-coded credential patterns. Matches are candidate patterns
only: the tool never verifies that a secret is live (that would require a
network call it deliberately does not make), and a clean run does not prove the
absence of secrets.

A hard-coded credential is a well-known weakness class (CWE-798). Surfacing it
maps to CRA Annex I Part I (2)(a) (no known exploitable vulnerabilities) and
(2)(d) (protection from unauthorised access). Matched values are redacted on
every output path; the raw secret is never printed or written.
"""

from __future__ import annotations

import math
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
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

_MAX_FILE_BYTES = 1024 * 1024  # 1 MiB, matches the other local scanners
_MAX_HITS = 500
_MAX_HISTORY_BYTES = 5 * 1024 * 1024  # bound on git log -p output processed

# High-confidence, low-false-positive provider credential patterns.
_DETECTORS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-secret-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b")),
    (
        "private-key-block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
]

# Generic fallback: a secret-like key assigned a long, high-entropy quoted value.
_NAME_HINTS = (
    r"secret|token|passwd|password|pwd|api[_-]?key|access[_-]?key|"
    r"auth[_-]?token|client[_-]?secret"
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<key>[a-z0-9_]*(?:" + _NAME_HINTS + r"))\s*[:=]\s*"
    r"['\"](?P<val>[^'\"\n]{12,})['\"]"
)
_ENTROPY_THRESHOLD = 3.5
_PLACEHOLDER_TOKENS = (
    "example", "changeme", "change-me", "placeholder", "your_", "your-",
    "yourpassword", "xxxx", "dummy", "redacted", "todo", "fixme", "sample",
    "test", "fake", "<", "${", "{{", "%s", "...",
)


@dataclass
class SecretHit:
    """A single candidate hard-coded secret match."""

    detector: str
    location: str
    line: int | None
    commit: str | None
    redacted: str
    source: str  # "working-tree" or "git-history"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "location": self.location,
            "line": self.line,
            "commit": self.commit,
            "redacted": self.redacted,
            "source": self.source,
        }


@dataclass
class SecretsReport:
    """Aggregated secret-scan results (advisory)."""

    hits: list[SecretHit] = field(default_factory=list)
    files_scanned: int = 0
    working_tree_hits: int = 0
    history_hits: int = 0
    history_scanned: bool = False
    capped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "working_tree_hits": self.working_tree_hits,
            "history_hits": self.history_hits,
            "history_scanned": self.history_scanned,
            "capped": self.capped,
            "hits": [h.to_dict() for h in self.hits],
        }


def _shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits per character) of a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_secret(value: str) -> bool:
    """Heuristic: is a quoted assignment value a plausible real secret?

    Rejects short values, obvious placeholders, templated references, and
    low-variety strings, then requires enough entropy to look random.
    """
    candidate = value.strip()
    if len(candidate) < 12:
        return False
    lowered = candidate.lower()
    if any(token in lowered for token in _PLACEHOLDER_TOKENS):
        return False
    if len(set(candidate)) <= 4:
        return False
    return _shannon_entropy(candidate) >= _ENTROPY_THRESHOLD


def _redact(value: str) -> str:
    """Return a masked form of a match: a short prefix plus length, never the body."""
    stripped = value.strip()
    if len(stripped) <= 8:
        return "****"
    return f"{stripped[:4]}{'*' * min(len(stripped) - 4, 12)} ({len(stripped)} chars)"


def _scan_line(
    line: str, lineno: int | None, location: str, source: str, commit: str | None = None
) -> list[SecretHit]:
    """Return candidate secret hits for a single line of text."""
    out: list[SecretHit] = []
    for name, pattern in _DETECTORS:
        for match in pattern.finditer(line):
            out.append(
                SecretHit(
                    detector=name,
                    location=location,
                    line=lineno,
                    commit=commit,
                    redacted=_redact(match.group(0)),
                    source=source,
                )
            )
    if out:
        # A specific provider match is more informative than the generic
        # fallback, so do not also emit a high-entropy hit for the same line.
        return out
    assignment = _ASSIGNMENT_RE.search(line)
    if assignment and _looks_secret(assignment.group("val")):
        out.append(
            SecretHit(
                detector="high-entropy-assignment",
                location=location,
                line=lineno,
                commit=commit,
                redacted=_redact(assignment.group("val")),
                source=source,
            )
        )
    return out


def _walk(root: Path):
    """Yield file paths under *root*, skipping VCS, dependency, and build dirs."""
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


def _read_text(path: Path) -> str | None:
    """Read a text file, returning None for oversized, binary, or unreadable files."""
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


def scan_working_tree(root: Path) -> tuple[list[SecretHit], int, bool]:
    """Scan files under *root* for candidate secrets. Returns (hits, files, capped)."""
    hits: list[SecretHit] = []
    files_scanned = 0
    capped = False
    base = root if root.is_dir() else root.parent
    paths = _walk(root) if root.is_dir() else iter([root])

    for path in paths:
        if len(hits) >= _MAX_HITS:
            capped = True
            break
        text = _read_text(path)
        if text is None:
            continue
        files_scanned += 1
        try:
            rel = str(path.relative_to(base))
        except ValueError:
            rel = str(path)
        for lineno, line in enumerate(text.splitlines(), start=1):
            for hit in _scan_line(line, lineno, rel, "working-tree"):
                hits.append(hit)
                if len(hits) >= _MAX_HITS:
                    capped = True
                    break
            if capped:
                break
    return hits, files_scanned, capped


def _git_history_target(root: Path) -> tuple[Path, str | None] | None:
    """Return the git top-level dir and optional pathspec for *root*."""
    try:
        inside = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
        )
        top_level = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return None
    if top_level.returncode != 0:
        return None

    repo_root = Path(top_level.stdout.strip())
    try:
        pathspec = root.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        pathspec = None
    if pathspec in ("", "."):
        pathspec = None
    return repo_root, pathspec


def scan_git_history(
    root: Path, pathspec: str | None = None, max_bytes: int = _MAX_HISTORY_BYTES
) -> tuple[list[SecretHit], bool]:
    """Scan added lines across git history for candidate secrets.

    Streams ``git log -p`` and inspects added (``+``) lines, attributing each
    hit to its commit and file. When *pathspec* is supplied, only changes under
    that path are scanned. Bounded by *max_bytes* and the global hit cap; returns
    (hits, capped).
    """
    hits: list[SecretHit] = []
    seen: set[tuple[str, str | None, str]] = set()
    capped = False
    commit: str | None = None
    current_file = "(unknown)"
    seen_bytes = 0

    try:
        command = ["git", "-C", str(root), "log", "-p", "--no-color", "--no-textconv"]
        if pathspec:
            command.extend(["--", pathspec])
        proc = subprocess.Popen(  # noqa: S603
            command,  # noqa: S607
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return [], False

    if proc.stdout is None:
        return [], False

    try:
        for line in proc.stdout:
            seen_bytes += len(line)
            if seen_bytes > max_bytes or len(hits) >= _MAX_HITS:
                capped = True
                break
            if line.startswith("commit "):
                commit = line[7:].strip()[:12]
            elif line.startswith("+++ b/"):
                current_file = line[6:].strip()
            elif line.startswith("+") and not line.startswith("+++"):
                for hit in _scan_line(line[1:], None, current_file, "git-history", commit):
                    key = (hit.detector, hit.commit, hit.redacted)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append(hit)
                    if len(hits) >= _MAX_HITS:
                        capped = True
                        break
    finally:
        proc.stdout.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return hits, capped


def evaluate(target: Path, scan_history: bool) -> SecretsReport:
    """Scan *target* (a directory or file) and return an advisory report.

    When *target* is a directory inside a git repository and *scan_history* is
    True, commit history for the requested target is scanned in addition to the
    working tree.
    """
    wt_hits, files_scanned, wt_capped = scan_working_tree(target)

    history_hits: list[SecretHit] = []
    history_scanned = False
    history_capped = False
    if scan_history and target.is_dir():
        history_target = _git_history_target(target)
        if history_target is not None:
            repo_root, pathspec = history_target
            history_hits, history_capped = scan_git_history(repo_root, pathspec)
            history_scanned = True

    return SecretsReport(
        hits=wt_hits + history_hits,
        files_scanned=files_scanned,
        working_tree_hits=len(wt_hits),
        history_hits=len(history_hits),
        history_scanned=history_scanned,
        capped=wt_capped or history_capped,
    )
