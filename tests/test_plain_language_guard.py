"""Guard: legal citations only appear where they are load-bearing.

The `.cra/` evidence pack describes duties in plain language and must not
carry article, annex, or recital citations. Everywhere else, every individual
citation occurrence must match one of its file's expected citation patterns,
so a line mixing an allowed citation with a stray one still fails. Test files
are swept too; the only test allowed to cite is the one that pins a citation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD_FILE = "tests/test_plain_language_guard.py"

CRA_STRICT = re.compile(
    r"(?i)regulation \(eu\) 2024/2847|\b\d{1,2}\(\d{1,2}\)",
)
CITATION = re.compile(
    r"(?i)\bart(?:icle)?s?\.?\s*\(?\d+(?:\.\d+)?"
    r"|\bannex(?:es)?\s+(?:[ivx]+\b|\d+)"
    r"|\brecital\s+\d+",
)
# Consumes the rest of a citation after the base match, so a pattern must
# cover the WHOLE reference: paragraph/letter parens, section marks, slashed
# paragraph lists, and dotted paragraph numbers.
EXTENSION = re.compile(
    r"^(?:\s*(?:\((?:\d+|[a-z])\)|/\((?:\d+|[a-z])\)|/[IVXivx]+\b|/\d+"
    r"|(?:-|\u2013|\bto\b)\s*(?:\((?:\d+|[a-z])\)|\d+\b)|\band\s+\(\w+\)"
    r"|,?\s*point\s+\d+(?:\(\w+\))?|-[A-Z]\b"
    r"|\u00a7\s*[\w().]+|\.\d+))+"
)
_AFTER = 40

# file -> patterns; EVERY citation occurrence in the file must match one.
ALLOWED: dict[str, list[str]] = {
    "CHANGELOG.md": [r"Annex I\b", r"Article 32\b", r"Regulation \(EU\) 2024/2847"],
    "README.md": [r"Annex I\b"],
    "cra_evidence_cli/assessment/__init__.py": [r"Annex I\b"],
    "cra_evidence_cli/assessment/gate.py": [
        r"Annex I\b", r"Article 13\(4\)", r"Article 13\(8\)",
    ],
    "cra_evidence_cli/assessment/matrix.py": [r"Annex I\b", r"Article 13\(3\)"],
    "cra_evidence_cli/assessment/requirements.py": [
        r"Annex I\b", r"Article 13\(3\)", r"Article 13\(4\)",
        r"\(CRA Article 13\):",
    ],
    "cra_evidence_cli/assessment/templates/consumer-iot.yaml": [r"Annex I\b"],
    "cra_evidence_cli/assessment/templates/microcontroller.yaml": [r"Annex I\b"],
    "cra_evidence_cli/assessment/templates/operating-system.yaml": [r"Annex I\b"],
    "cra_evidence_cli/assessment/templates/router-gateway.yaml": [r"Annex I\b"],
    "cra_evidence_cli/assessment/templates/vpn.yaml": [r"Annex I\b"],
    "cra_evidence_cli/client.py": [r"Annex III/IV", r"CRA Article 20\b"],
    "cra_evidence_cli/commands/assessment.py": [r"Annex I\b"],
    "cra_evidence_cli/commands/diagram.py": [r"Annex VII, point 2\(a\)", r"Annex VII\b"],
    "cra_evidence_cli/commands/distributor.py": [
        r"Article 20\(3\)", r"CRA Article 20\b",
    ],
    "cra_evidence_cli/commands/export.py": [r"Annex VII\b"],
    "cra_evidence_cli/commands/profile.py": [
        r"Article 32\(1\)\([a-d]\)", r"Article 13\(8\)", r"Annex I\b",
    ],
    "cra_evidence_cli/commands/upload.py": [
        r"Annex III/IV", r"Annex III\b", r"Annex IV\b",
    ],
    "cra_evidence_cli/local/config_audit.py": [r"Annex I\b"],
    "cra_evidence_cli/local/eol.py": [r"Article 13\(8\)", r"Annex II\b"],
    "cra_evidence_cli/local/secrets.py": [r"Annex I\b"],
    "cra_evidence_cli/local/signal.py": [
        r"Article 3\(41\)/\(42\)", r"Article 13\(2\)", r"Annex I\b",
        r"Art 12\(2\) of Directive \(EU\) 2022/2555",
    ],
    "docs/account-commands.md": [
        r"Art\. 28\b", r"Annex III/IV", r"Annex VII\b", r"Annex I\b",
    ],
    "docs/ci-cd.md": [r"Annex I\b"],
    "docs/local-commands.md": [r"Annex I\b"],
    "tests/test_diagram_command.py": [r"Annex VII\b", r"Annex II\b"],
}


def _tracked_files() -> list[str]:
    git = shutil.which("git")
    assert git is not None, "git is required to enumerate tracked files"
    out = subprocess.run(  # noqa: S603
        [git, "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.splitlines()


def _line_violations(rel: str, line: str) -> list[str]:
    """Return the citation snippets in ``line`` that ``rel`` may not carry."""
    matches = list(CITATION.finditer(line))
    if rel.startswith(".cra/"):
        matches += list(CRA_STRICT.finditer(line))
    if not matches:
        return []
    if rel.startswith(".cra/") or rel not in ALLOWED:
        return [line[m.start() : m.end() + _AFTER] for m in matches]
    patterns = ALLOWED[rel]
    compiled = [re.compile(p) for p in patterns]
    bad = []
    for m in matches:
        ext = EXTENSION.match(line[m.end() :])
        span_end = m.end() + (ext.end() if ext else 0)
        covered = any(
            pm.start() <= m.start() and pm.end() >= span_end
            for c in compiled
            for pm in c.finditer(line)
        )
        if not covered:
            bad.append(line[m.start() : span_end + _AFTER])
    return bad


def _scan_repo() -> dict[str, list[str]]:
    offenders: dict[str, list[str]] = {}
    for rel in _tracked_files():
        if rel == GUARD_FILE:
            continue
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        bad: list[str] = []
        for line in text.splitlines():
            bad.extend(_line_violations(rel, line))
        if bad:
            offenders[rel] = bad
    return offenders


def test_no_unexpected_citations_anywhere() -> None:
    offenders = _scan_repo()
    assert offenders == {}, (
        "Citation occurrences outside each file's expected patterns "
        f"(add deliberately, never by drift): {offenders}"
    )


def test_allowlist_has_no_stale_entries() -> None:
    tracked = set(_tracked_files())
    stale = sorted(rel for rel in ALLOWED if rel not in tracked)
    assert stale == [], f"Allowlist entries no longer tracked: {stale}"


def test_guard_catches_known_regression_shapes() -> None:
    cases = [
        (".cra/vulnerability-policy.yaml", "implements CRA Art. 13(13) duties"),
        (".cra/risk-catalog.yaml", "per Art 12(2) of a directive"),
        ("cra_evidence_cli/commands/profile.py", '"Module B, Article 33"'),
        ("docs/some-new-page.md", "as required by Annex I"),
        ("README.md", "covers Annex I and Article 99(9) rules"),
        ("tests/test_new_feature.py", 'assert "Article 14" in output'),
        ("cra_evidence_cli/local/eol.py", "per Article 13.8 and Annex 2"),
        ("README.md", "per Annex I \u00a71(b) rules"),
        ("docs/local-commands.md", "see Annex 7 for details"),
        ("cra_evidence_cli/commands/profile.py", "Article 32(99) applies"),
        ("cra_evidence_cli/commands/distributor.py", "CRA Article 20(99)"),
        ("cra_evidence_cli/commands/upload.py", "CRA Annex III/VI subcategory"),
        ("CHANGELOG.md", "Article 32-99 range"),
        ("README.md", "Annex I/IX mapping"),
        ("cra_evidence_cli/commands/profile.py", "Article 32(1)(a)/(z)"),
        ("cra_evidence_cli/assessment/gate.py", "Article 13(8)-(99)"),
        (".cra/vulnerability-policy.yaml", "implements 13(8) duties"),
        (".cra/update-mechanism.yaml", "per Regulation (EU) 2024/2847"),
        ("CHANGELOG.md", "Article 32 to 34 apply"),
        ("CHANGELOG.md", "Article 32\u201334 apply"),
        ("README.md", "Annex I, point 9(z) covers this"),
        ("cra_evidence_cli/commands/profile.py", "Article 32(1)(a) and (z)"),
        ("cra_evidence_cli/commands/profile.py", "Article 32(1)(a)\u2013(z)"),
        ("README.md", "Annex I-A applies"),
    ]
    for rel, line in cases:
        assert _line_violations(rel, line), f"guard missed: {rel}: {line}"
    fine = [
        (
            "cra_evidence_cli/commands/profile.py",
            "Full Quality Assurance (Module H, Article 32(1)(c))",
        ),
        ("README.md", "an Annex I applicability matrix"),
    ]
    for rel, line in fine:
        assert not _line_violations(rel, line), f"false positive: {rel}: {line}"


def test_every_allowed_pattern_is_still_used() -> None:
    stale: list[str] = []
    for rel, patterns in ALLOWED.items():
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        for pat in patterns:
            if not re.search(pat, text):
                stale.append(f"{rel}: {pat}")
    assert stale == [], f"Allowed patterns no longer present: {stale}"
