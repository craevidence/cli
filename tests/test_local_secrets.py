"""Unit tests for cra_evidence_cli.local.secrets.

Working-tree tests need no network and no git. One git-history test shells out
to a real git binary and is skipped when git is unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cra_evidence_cli.local import secrets as sec

# Format-valid sample credentials (not real, never live).
AWS = "AKIAIOSFODNN7EXAMPLE"
GH = "ghp_1234567890abcdefghij1234567890abcdef"
ENT = "x7Kp2mQ9vL4nR8sT1wZ3"
PRIV = "-----BEGIN RSA PRIVATE KEY-----"


def _write(root: Path, name: str, body: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_detects_aws_access_key(tmp_path):
    _write(tmp_path, "a.py", f'KEY = "{AWS}"\n')
    hits, files, capped = sec.scan_working_tree(tmp_path)
    assert files == 1
    assert [h.detector for h in hits] == ["aws-access-key-id"]
    assert hits[0].line == 1
    assert hits[0].source == "working-tree"


def test_detects_github_token(tmp_path):
    _write(tmp_path, "a.txt", f"token={GH}\n")
    hits, _, _ = sec.scan_working_tree(tmp_path)
    assert any(h.detector == "github-token" for h in hits)


def test_detects_private_key_block(tmp_path):
    _write(tmp_path, "key.pem", f"{PRIV}\nMIIB...\n")
    hits, _, _ = sec.scan_working_tree(tmp_path)
    assert any(h.detector == "private-key-block" for h in hits)


def test_high_entropy_assignment_detected(tmp_path):
    _write(tmp_path, "c.py", f'api_key = "{ENT}"\n')
    hits, _, _ = sec.scan_working_tree(tmp_path)
    assert [h.detector for h in hits] == ["high-entropy-assignment"]


def test_placeholder_value_not_detected(tmp_path):
    _write(tmp_path, "d.py", 'password = "your_password_here"\n')
    hits, _, _ = sec.scan_working_tree(tmp_path)
    assert hits == []


def test_templated_value_not_detected(tmp_path):
    _write(tmp_path, "e.py", 'secret = "${VAULT_SECRET}"\n')
    hits, _, _ = sec.scan_working_tree(tmp_path)
    assert hits == []


def test_low_variety_value_not_detected(tmp_path):
    _write(tmp_path, "f.py", 'token = "aaaaaaaaaaaaaaaa"\n')
    hits, _, _ = sec.scan_working_tree(tmp_path)
    assert hits == []


def test_specific_detector_suppresses_generic(tmp_path):
    # A line that matches both a provider regex and the generic assignment
    # should yield exactly one (the specific) hit.
    _write(tmp_path, "g.py", f'api_key = "{GH}"\n')
    hits, _, _ = sec.scan_working_tree(tmp_path)
    assert [h.detector for h in hits] == ["github-token"]


def test_redacted_never_contains_raw_secret(tmp_path):
    _write(tmp_path, "h.py", f'KEY = "{AWS}"\nx = "{ENT}"\n')
    hits, _, _ = sec.scan_working_tree(tmp_path)
    for hit in hits:
        assert AWS not in hit.redacted
        assert ENT not in hit.redacted
    aws_hit = next(h for h in hits if h.detector == "aws-access-key-id")
    assert aws_hit.redacted.startswith("AKIA")
    assert "*" in aws_hit.redacted


def test_skip_dirs_ignored(tmp_path):
    _write(tmp_path, "node_modules/dep.js", f'k="{AWS}"\n')
    _write(tmp_path, ".git/config", f'k="{AWS}"\n')
    hits, _, _ = sec.scan_working_tree(tmp_path)
    assert hits == []


def test_binary_file_skipped(tmp_path):
    (tmp_path / "bin.dat").write_bytes(b"\x00\x01" + AWS.encode() + b"\x02")
    hits, _, _ = sec.scan_working_tree(tmp_path)
    assert hits == []


def test_hit_cap_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(sec, "_MAX_HITS", 2)
    _write(tmp_path, "many.py", "\n".join(f'KEY{i} = "{AWS}"' for i in range(10)))
    hits, _, capped = sec.scan_working_tree(tmp_path)
    assert len(hits) == 2
    assert capped is True


def test_shannon_entropy_ordering():
    assert sec._shannon_entropy("aaaaaaaa") < sec._shannon_entropy("a1B2c3D4")
    assert sec._shannon_entropy("") == 0.0


def test_redact_short_value_fully_masked():
    assert sec._redact("abc") == "****"
    assert sec._redact("short8ch") == "****"


def test_evaluate_non_git_dir_skips_history(tmp_path):
    _write(tmp_path, "a.py", f'KEY = "{AWS}"\n')
    report = sec.evaluate(tmp_path, scan_history=True)
    assert report.history_scanned is False
    assert report.history_hits == 0
    assert report.working_tree_hits == 1


def test_evaluate_single_file(tmp_path):
    f = tmp_path / "only.py"
    f.write_text(f'KEY = "{AWS}"\n', encoding="utf-8")
    report = sec.evaluate(f, scan_history=True)
    assert report.working_tree_hits == 1
    assert report.history_scanned is False  # a file is not a git work tree target


@pytest.mark.skipif(shutil.which("git") is None, reason="git binary not available")
def test_git_history_detection(tmp_path):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }

    def git(*args):
        subprocess.run(  # noqa: S603
            ["git", "-C", str(tmp_path), *args],  # noqa: S607
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )

    git("init", "-q")
    _write(tmp_path, "leak.txt", f"token={GH}\n")
    git("add", "-A")
    git("commit", "-qm", "add leak")
    (tmp_path / "leak.txt").unlink()
    git("add", "-A")
    git("commit", "-qm", "remove leak")

    report = sec.evaluate(tmp_path, scan_history=True)
    assert report.history_scanned is True
    history = [h for h in report.hits if h.source == "git-history"]
    gh = [h for h in history if h.detector == "github-token"]
    assert gh, "github token not recovered from history"
    assert gh[0].commit is not None
    assert GH not in gh[0].redacted
