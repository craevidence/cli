"""Runtime package upgrade: dpkg records follow the files that replace a base package."""

from pathlib import Path

import pytest

from scripts import upgrade_runtime_packages as upgrade_module

REPO_ROOT = Path(__file__).resolve().parents[1]
LIB = "usr/lib/x86_64-linux-gnu"

OLD_STANZA = """Package: libexpat1
Status: install ok installed
Version: 2.8.3-1~deb13u1+dhi5
Architecture: amd64
Maintainer: Docker Hardened Images <dhi@docker.com>"""

NEW_STANZA = """Package: libexpat1
Status: install ok installed
Version: 2.9.0-1~deb13u1
Architecture: amd64
Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>"""

OTHER_STANZA = """Package: libc6
Status: install ok installed
Version: 2.41-12
Architecture: amd64"""


def _runtime(root: Path) -> None:
    dpkg = root / "var/lib/dpkg"
    (dpkg / "info").mkdir(parents=True)
    (dpkg / "status.d").mkdir()
    (dpkg / "status").write_text(f"{OTHER_STANZA}\n\n{OLD_STANZA}\n", encoding="utf-8")
    (dpkg / "status.d" / "libexpat1").write_text(
        "Package: libexpat1\nVersion: 2.8.3-1~deb13u1+dhi5\n", encoding="utf-8"
    )
    (dpkg / "info" / "libexpat1.list").write_text(
        f"/usr\n/usr/lib\n/{LIB}\n/{LIB}/libexpat.so.1.12.3\n", encoding="utf-8"
    )
    (dpkg / "info" / "libexpat1.md5sums").write_text("old\n", encoding="utf-8")
    (dpkg / "info" / "libexpat1-dev.list").write_text("/usr/include/expat.h\n", encoding="utf-8")
    (root / LIB).mkdir(parents=True)
    (root / LIB / "libexpat.so.1.12.3").write_bytes(b"old")
    # The Dockerfile copies the new package files before the script runs.
    (root / LIB / "libexpat.so.1.13.0").write_bytes(b"new")
    (root / LIB / "libexpat.so.1").symlink_to("libexpat.so.1.13.0")


def _staging(path: Path, stanza: str = NEW_STANZA) -> Path:
    (path / "info").mkdir(parents=True)
    (path / "status.d").mkdir()
    (path / "DPKG-STATUS").write_text(f"{stanza}\n" if stanza else "", encoding="utf-8")
    if stanza:
        (path / "info" / "libexpat1.list").write_text(
            f"/usr\n/usr/lib\n/{LIB}\n/{LIB}/libexpat.so.1.13.0\n/{LIB}/libexpat.so.1\n",
            encoding="utf-8",
        )
        (path / "info" / "libexpat1.md5sums").write_text("new\n", encoding="utf-8")
        (path / "status.d" / "libexpat1").write_text(
            "Package: libexpat1\nVersion: 2.9.0-1~deb13u1\n", encoding="utf-8"
        )
    return path


def test_upgrade_records_the_installed_version_everywhere(tmp_path):
    """Fails if any dpkg record still names the replaced version, so a scanner would
    still report it, or if the replaced library file stays in the image."""
    root = tmp_path / "root"
    _runtime(root)
    staging = _staging(tmp_path / "staging")

    assert upgrade_module.upgrade(root, staging) == ["libexpat1:amd64 2.9.0-1~deb13u1"]

    dpkg = root / "var/lib/dpkg"
    status = (dpkg / "status").read_text(encoding="utf-8")
    assert "2.8.3" not in status
    assert NEW_STANZA in status
    assert OTHER_STANZA in status
    assert "2.9.0-1~deb13u1" in (dpkg / "status.d" / "libexpat1").read_text(encoding="utf-8")
    assert (dpkg / "info" / "libexpat1.md5sums").read_text(encoding="utf-8") == "new\n"
    assert "libexpat.so.1.13.0" in (dpkg / "info" / "libexpat1.list").read_text(encoding="utf-8")
    assert (dpkg / "info" / "libexpat1-dev.list").is_file()
    assert not (root / LIB / "libexpat.so.1.12.3").exists()
    assert (root / LIB / "libexpat.so.1.13.0").read_bytes() == b"new"
    assert (root / LIB / "libexpat.so.1").resolve().name == "libexpat.so.1.13.0"
    assert not staging.exists()


def test_upgrade_refuses_a_package_the_runtime_base_does_not_have(tmp_path):
    """Fails if the step silently adds a package instead of replacing one."""
    root = tmp_path / "root"
    _runtime(root)
    staging = _staging(tmp_path / "staging", NEW_STANZA.replace("libexpat1", "libnew1"))
    before = (root / "var/lib/dpkg/status").read_text(encoding="utf-8")

    with pytest.raises(SystemExit, match="does not record libnew1:amd64"):
        upgrade_module.upgrade(root, staging)

    assert (root / "var/lib/dpkg/status").read_text(encoding="utf-8") == before


def test_nothing_staged_leaves_the_runtime_records_unchanged(tmp_path):
    """Fails if a build with no upgrade, such as the public-base fallback, rewrites
    or drops runtime package records."""
    root = tmp_path / "root"
    _runtime(root)
    staging = _staging(tmp_path / "staging", "")
    before = (root / "var/lib/dpkg/status").read_text(encoding="utf-8")

    assert upgrade_module.upgrade(root, staging) == []

    assert (root / "var/lib/dpkg/status").read_text(encoding="utf-8") == before
    assert (root / LIB / "libexpat.so.1.12.3").exists()
    assert not staging.exists()


def test_dockerfile_pins_the_upgrade_and_stops_once_the_hardened_base_has_it():
    """Fails if the upgrade loses its exact version pin, its runtime step, or the
    build failure that forces its removal once the hardened base ships the fix."""
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "ARG LIBEXPAT_VERSION=2.9.0-1~deb13u1" in dockerfile
    assert "FROM ${BASE_IMAGE} AS runtime-base" in dockerfile
    assert 'dpkg --compare-versions "${base_version}" lt "${LIBEXPAT_VERSION}"' in dockerfile
    assert "grep -q '^Maintainer: Docker Hardened Images'" in dockerfile
    assert "remove the runtime package upgrade" in dockerfile
    assert (
        'RUN ["python", "/tmp/upgrade_runtime_packages.py", "/", "/tmp/runtime-upgrade-records"]'
        in dockerfile
    )
