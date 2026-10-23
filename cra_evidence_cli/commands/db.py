"""Local Grype vulnerability database cache management (no API key required).

`craevidence db update` refreshes the local Grype vulnerability database, and
`craevidence db status` inspects it without any network access.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click

from cra_evidence_cli.exceptions import ScanEngineUnavailable
from cra_evidence_cli.local.dbcache import db_update_lock, resolve_cache_dir
from cra_evidence_cli.local.scanner import GrypeLocalScanner

# Use a single long timeout for `grype db update`, which can be slow on a cold cache.
_DB_UPDATE_TIMEOUT_SECONDS = 900
_DB_STALE_DAYS = 30


@click.group("db")
def db() -> None:
    """Manage the local Grype vulnerability database cache.

    `db update` refreshes the cached database over the network; `db status`
    inspects it without any network access.
    """


def _resolve_cache_dir_or_exit(cache_dir_opt: str | None) -> str:
    try:
        return resolve_cache_dir(cache_dir_opt)
    except OSError as exc:
        raw_path = (
            cache_dir_opt
            or os.getenv("GRYPE_DB_CACHE_DIR")
            or str(Path.home() / ".cache" / "grype" / "db")
        )
        click.echo(
            f"Error: could not create cache directory {raw_path}: {exc.strerror or exc}",
            err=True,
        )
        sys.exit(ScanEngineUnavailable().exit_code)


def _find_db_dir(cache_dir: str) -> Path | None:
    path = Path(cache_dir)
    if not path.exists():
        return None
    candidates = [
        item
        for item in path.iterdir()
        if item.is_dir() and (item / "vulnerability.db").exists()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item / "vulnerability.db").stat().st_mtime)


def _read_import_metadata(db_dir: Path | None) -> dict[str, Any]:
    if db_dir is None:
        return {}
    metadata_path = db_dir / "import.json"
    try:
        data = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _schema_version(raw: object) -> str:
    value = str(raw or "")
    return value.lstrip("v").split(".")[0] or "unknown"


def _grype_db_info(metadata: dict[str, Any]) -> dict[str, str | None]:
    """Pull build, archive capture hint, and schema metadata from import.json."""
    built = metadata.get("built") if isinstance(metadata.get("built"), str) else None
    schema_raw: object = metadata.get("schemaVersion")
    version: str | None = None
    capture: str | None = None
    source = metadata.get("source")
    if isinstance(source, str):
        match = re.search(
            r"vulnerability-db_v(\d+\.\d+\.\d+)_(\d{4}-\d{2}-\d{2}T[\d:]+Z)", source
        )
        if match:
            version = match.group(1)
            capture = match.group(2)
            if schema_raw is None:
                schema_raw = version
    return {
        "built": built,
        "capture": capture,
        "version": version,
        "schema": _schema_version(schema_raw),
    }


def _days_old(value: str | None) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # The DB cache mtime is recorded without a timezone; treat it as UTC so
        # the subtraction below does not mix naive and aware datetimes.
        parsed = parsed.replace(tzinfo=UTC)
    return (datetime.now(UTC) - parsed).days


@db.command("update")
@click.option(
    "--cache-dir",
    "cache_dir_opt",
    type=click.Path(file_okay=True, dir_okay=True),
    default=None,
    help="Directory for the Grype DB cache. "
    "Defaults to $GRYPE_DB_CACHE_DIR or ~/.cache/grype/db.",
)
def update(cache_dir_opt: str | None) -> None:
    """Download or refresh the local Grype vulnerability database.

    This is the only local-engine command permitted to make network calls to
    fetch the vulnerability database. It prints a build date when Grype reports
    one and labels the local modification date separately when it does not.
    """
    cache_dir = _resolve_cache_dir_or_exit(cache_dir_opt)
    # The cache location is pinned for the grype child via the subprocess `env=`
    # override below, and GrypeLocalScanner is constructed with the same dir so
    # its metadata read targets it too. We deliberately do NOT mutate the global
    # os.environ, which would leak the cache dir into the rest of the process.
    scanner = GrypeLocalScanner(cache_dir=cache_dir)
    try:
        engine_path = scanner.path
    except ScanEngineUnavailable as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(exc.exit_code)

    # Serialize concurrent `db update` runs (across processes too) so only one
    # download happens at a time. Network IS allowed inside this block.
    with db_update_lock(cache_dir):
        try:
            result = subprocess.run(  # noqa: S603
                [engine_path, "db", "update"],
                capture_output=True,
                text=True,
                timeout=_DB_UPDATE_TIMEOUT_SECONDS,
                env={**os.environ, "GRYPE_DB_CACHE_DIR": cache_dir},
            )
        except subprocess.TimeoutExpired:
            click.echo(
                "Error: `grype db update` timed out after "
                f"{_DB_UPDATE_TIMEOUT_SECONDS}s.",
                err=True,
            )
            sys.exit(ScanEngineUnavailable().exit_code)

        if result.returncode != 0:
            click.echo(
                (result.stderr or "").strip() or "Error: `grype db update` failed.",
                err=True,
            )
            sys.exit(ScanEngineUnavailable().exit_code)

    # Keep a local modification date separate from the database build date.
    metadata = scanner.get_db_metadata()
    built = metadata.get("built") if metadata else None

    click.echo(f"Grype DB cache: {cache_dir}")
    if built:
        click.echo(f"DB build date: {built}")
    else:
        mtime = scanner._db_mtime_offline() or "unknown"
        click.echo("DB build date: unknown")
        click.echo(f"DB mtime date: {mtime}")


@db.command("status")
@click.option(
    "--cache-dir",
    "cache_dir_opt",
    type=click.Path(file_okay=True, dir_okay=True),
    default=None,
    help="Directory for the Grype DB cache. "
    "Defaults to $GRYPE_DB_CACHE_DIR or ~/.cache/grype/db.",
)
def status(cache_dir_opt: str | None) -> None:
    """Inspect the local Grype vulnerability database without network access."""
    cache_dir = _resolve_cache_dir_or_exit(cache_dir_opt)
    scanner = GrypeLocalScanner(cache_dir=cache_dir)
    db_dir = _find_db_dir(cache_dir)
    metadata = _read_import_metadata(db_dir)
    info = _grype_db_info(metadata)
    built = info["built"]
    capture = info["capture"]
    mtime = scanner._db_mtime_offline()
    if built:
        age_value = built
        age_source = "metadata build date"
    elif capture:
        age_value = capture
        age_source = "archive capture date hint"
    elif mtime:
        age_value = mtime
        age_source = "local DB mtime date"
    else:
        age_value = None
        age_source = "unknown"
    age_days = _days_old(age_value)
    stale = age_days is not None and age_days > _DB_STALE_DAYS
    if not db_dir:
        status_value = "missing"
    elif age_days is None:
        status_value = "unknown"
    elif stale:
        status_value = "stale"
    else:
        status_value = "current"

    click.echo(
        f"CRA Evidence engine available: {'yes' if scanner.is_available() else 'no'}"
    )
    click.echo(f"Grype DB cache: {cache_dir}")
    click.echo(f"Vulnerability DB present: {'yes' if db_dir else 'no'}")
    click.echo(f"DB path: {db_dir / 'vulnerability.db' if db_dir else 'not found'}")
    click.echo(f"DB build date: {built or 'unknown'}")
    click.echo(f"Archive capture date hint: {capture or 'unknown'}")
    click.echo(f"DB mtime date: {mtime or 'unknown'}")
    click.echo(f"Status age source: {age_source}")
    click.echo(f"DB version: {info['version'] or 'unknown'}")
    click.echo(f"Schema version: {info['schema']}")
    click.echo(f"Status: {status_value}")
