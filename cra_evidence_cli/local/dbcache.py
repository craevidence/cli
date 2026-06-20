"""Cache-dir resolution and a stdlib file lock for `craevidence db update`.

This module is FS + locking only. It performs NO network calls and never shells
out to grype. The actual DB fetch lives in commands/db.py; here we only decide
WHERE the DB cache lives and SERIALIZE concurrent `db update` runs.

The lock serializes Grype DB updates so a missing or stale DB does not trigger
concurrent downloads. ``fcntl.flock`` serializes across separate CLI processes,
for example two CI steps.
"""

from __future__ import annotations

import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

LOCK_FILENAME = ".cra-db-update.lock"


def resolve_cache_dir(explicit: str | None) -> str:
    """Resolve the Grype DB cache directory and ensure it exists.

    Precedence:
      1. ``explicit`` (the ``--cache-dir`` option), if given.
      2. ``$GRYPE_DB_CACHE_DIR``, if set.
      3. Platform default ``~/.cache/grype/db``.

    The directory is created (parents=True, exist_ok=True). Returns an absolute
    string path.
    """
    if explicit:
        chosen = Path(explicit)
    elif env := os.getenv("GRYPE_DB_CACHE_DIR"):
        chosen = Path(env)
    else:
        chosen = Path.home() / ".cache" / "grype" / "db"

    chosen.mkdir(parents=True, exist_ok=True)
    return str(chosen.resolve())


@contextmanager
def db_update_lock(cache_dir: str) -> Iterator[None]:
    """Hold an exclusive advisory lock for the duration of a DB update.

    Acquires a blocking ``fcntl.flock(LOCK_EX)`` on ``<cache_dir>/.cra-db-update.lock``
    (creating the lock file if missing), yields, then releases and closes the
    handle. Serializes concurrent ``craevidence db update`` invocations so only
    one grype download runs at a time.
    """
    lock_path = Path(cache_dir) / LOCK_FILENAME
    # Open (or create) the lock file; the fd backs the advisory flock.
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
