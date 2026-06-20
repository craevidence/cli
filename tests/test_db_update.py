"""Unit tests for `craevidence db update` and its cache/lock helpers.

No real grype binary or network is touched: ``shutil.which`` and
``subprocess.run`` are monkeypatched in every test that needs them.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cra_evidence_cli.commands import db as db_module
from cra_evidence_cli.commands.db import db
from cra_evidence_cli.local import dbcache
from cra_evidence_cli.local import scanner as scanner_module
from cra_evidence_cli.local.dbcache import db_update_lock, resolve_cache_dir


# resolve_cache_dir
def test_resolve_cache_dir_explicit_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "from_env"))
    explicit = tmp_path / "explicit"
    resolved = resolve_cache_dir(str(explicit))
    assert resolved == str(explicit.resolve())
    assert explicit.is_dir()


def test_resolve_cache_dir_env_when_no_explicit(tmp_path, monkeypatch):
    env_dir = tmp_path / "from_env"
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(env_dir))
    resolved = resolve_cache_dir(None)
    assert resolved == str(env_dir.resolve())
    assert env_dir.is_dir()


def test_resolve_cache_dir_default(tmp_path, monkeypatch):
    monkeypatch.delenv("GRYPE_DB_CACHE_DIR", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    resolved = resolve_cache_dir(None)
    expected = tmp_path / ".cache" / "grype" / "db"
    assert resolved == str(expected.resolve())
    assert expected.is_dir()


# db_update_lock
def test_db_update_lock_acquires_releases_and_creates_file(tmp_path):
    cache_dir = str(tmp_path)
    # Acquire twice sequentially in the same process: the second must not block,
    # proving the first released cleanly.
    with db_update_lock(cache_dir):
        pass
    with db_update_lock(cache_dir):
        pass
    assert (tmp_path / dbcache.LOCK_FILENAME).exists()


# db update - grype absent
def test_db_update_grype_absent_exits_15(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_module.shutil, "which", lambda _: None)

    runner = CliRunner()
    result = runner.invoke(db, ["update", "--cache-dir", str(tmp_path)])

    assert result.exit_code == 15
    assert "Grype is not installed" in result.stderr


# db update - happy path
def test_db_update_happy_path(tmp_path, monkeypatch):
    built_date = "2026-06-14T00:00:00Z"

    monkeypatch.setattr(scanner_module.shutil, "which", lambda _: "/usr/bin/grype")

    def fake_db_run(cmd, *args, **kwargs):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""

        # `grype db update` -> success, no output needed.
        if cmd[1:3] == ["db", "update"]:
            return R()
        msg = f"unexpected command from db.py: {cmd}"
        raise AssertionError(msg)

    def fake_status_run(cmd, *args, **kwargs):
        class R:
            returncode = 0
            stdout = json.dumps(
                {"built": built_date, "schemaVersion": "v6.1.4", "valid": True}
            )
            stderr = ""

        return R()

    # db.py shells out via subprocess in commands.db; metadata via scanner.subprocess.
    monkeypatch.setattr(db_module.subprocess, "run", fake_db_run)
    monkeypatch.setattr(scanner_module.subprocess, "run", fake_status_run)

    runner = CliRunner()
    result = runner.invoke(db, ["update", "--cache-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output + result.stderr
    assert str(Path(tmp_path).resolve()) in result.stdout
    assert built_date in result.stdout


def test_db_update_subprocess_failure_exits_15(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_module.shutil, "which", lambda _: "/usr/bin/grype")

    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 1
            stdout = ""
            stderr = "network unreachable"

        return R()

    monkeypatch.setattr(db_module.subprocess, "run", fake_run)

    runner = CliRunner()
    result = runner.invoke(db, ["update", "--cache-dir", str(tmp_path)])

    assert result.exit_code == 15
    assert "network unreachable" in result.stderr


def test_db_status_reads_local_cache_without_grype_status(tmp_path, monkeypatch):
    db_dir = tmp_path / "6"
    db_dir.mkdir()
    (db_dir / "vulnerability.db").write_bytes(b"db")
    # Real grype v6 import.json: build date and version live inside the source URL.
    (db_dir / "import.json").write_text(
        json.dumps(
            {
                "digest": "xxh64:baafcf2b37494a50",
                "source": (
                    "https://grype.anchore.io/databases/v6/"
                    "vulnerability-db_v6.1.7_2026-06-14T01:05:09Z_1781597641.tar.zst"
                    "?checksum=sha256%3Aabc123"
                ),
                "client_version": "v6.1.4",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(scanner_module.shutil, "which", lambda _: "/usr/bin/grype")

    def _no_subprocess(*args, **kwargs):  # noqa: ANN002, ANN003
        msg = "db status must not call grype"
        raise AssertionError(msg)

    monkeypatch.setattr(scanner_module.subprocess, "run", _no_subprocess)
    monkeypatch.setattr(db_module.subprocess, "run", _no_subprocess)

    result = CliRunner().invoke(db, ["status", "--cache-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "Grype installed: yes" in result.output
    assert "Vulnerability DB present: yes" in result.output
    assert "DB build date: 2026-06-14T01:05:09Z" in result.output
    assert "DB version: 6.1.7" in result.output
    assert "Schema version: 6" in result.output


def test_db_status_missing_cache_reports_absent_db(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_module.shutil, "which", lambda _: None)

    result = CliRunner().invoke(db, ["status", "--cache-dir", str(tmp_path / "cache")])

    assert result.exit_code == 0, result.output
    assert "Grype installed: no" in result.output
    assert "Vulnerability DB present: no" in result.output
    assert "Status: missing" in result.output


def test_db_status_present_db_with_unknown_age_reports_unknown(tmp_path, monkeypatch):
    db_dir = tmp_path / "6"
    db_dir.mkdir()
    (db_dir / "vulnerability.db").write_bytes(b"db")
    monkeypatch.setattr(scanner_module.shutil, "which", lambda _: "/usr/bin/grype")
    monkeypatch.setattr(
        scanner_module.GrypeLocalScanner,
        "_db_mtime_offline",
        lambda self: None,
    )

    result = CliRunner().invoke(db, ["status", "--cache-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "Vulnerability DB present: yes" in result.output
    assert "DB build date: unknown" in result.output
    assert "DB mtime date: unknown" in result.output
    assert "Status: unknown" in result.output


def test_db_cache_creation_error_exits_15(tmp_path):
    cache_file = tmp_path / "not-a-dir"
    cache_file.write_text("x", encoding="utf-8")

    result = CliRunner().invoke(db, ["status", "--cache-dir", str(cache_file)])

    assert result.exit_code == 15
    assert "could not create cache directory" in result.stderr


def test_db_update_and_status_are_separate_subcommands():
    # `update` and `status` are subcommands of the `db` group.
    assert "update" in db.commands
    assert "status" in db.commands

    # The update command declares no boolean switches at all.
    update_cmd = db.commands["update"]
    source = Path(db_module.__file__).read_text()
    assert "is_flag" not in source  # no boolean switches at all on db update
    assert not any(getattr(opt, "is_flag", False) for opt in update_cmd.params)


def test_days_old_handles_naive_and_aware_timestamps():
    # A naive cache mtime must not crash against the aware "now"; both forms
    # parse to a non-negative age. Regression for the offset-naive/aware bug.
    assert db_module._days_old("2020-01-01T00:00:00") >= 0
    assert db_module._days_old("2020-01-01T00:00:00Z") >= 0
    assert db_module._days_old(None) is None
    assert db_module._days_old("not-a-date") is None
