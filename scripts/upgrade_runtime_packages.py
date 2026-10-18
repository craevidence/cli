"""Record newer Debian package builds staged into the runtime image.

The runtime image has no package manager. The Dockerfile copies the files of each
staged package over the runtime base and then runs this script, which brings the
dpkg records in line with those files: it removes files of the replaced version
that the new version no longer ships, and replaces the package's status stanza,
its ``status.d`` record and its ``info`` files. SBOM generators and vulnerability
scanners read those records, so they must name the version actually installed.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def _stanzas(text: str) -> list[str]:
    return [item for item in text.strip().split("\n\n") if item]


def _field(stanza: str, name: str) -> str:
    prefix = f"{name}: "
    return next(line[len(prefix) :] for line in stanza.splitlines() if line.startswith(prefix))


def _info_files(info_dir: Path, package: str, arch: str) -> list[Path]:
    return sorted(
        path
        for path in info_dir.iterdir()
        if path.name.startswith((f"{package}.", f"{package}:{arch}."))
    )


def _file_list(info_dir: Path, package: str, arch: str) -> Path:
    for name in (f"{package}:{arch}.list", f"{package}.list"):
        if (info_dir / name).is_file():
            return info_dir / name
    message = f"no dpkg file list for {package}:{arch} in {info_dir}"
    raise SystemExit(message)


def upgrade(root: Path, staging: Path) -> list[str]:
    """Apply every package staged under ``staging`` to the image rooted at ``root``.

    Returns ``package:arch version`` for each upgraded package and removes
    ``staging``. A staged package that the runtime base does not record is
    refused: this step replaces packages, it never adds them.
    """
    dpkg = root / "var" / "lib" / "dpkg"
    status_path = dpkg / "status"
    current = _stanzas(status_path.read_text(encoding="utf-8"))
    upgraded: list[str] = []
    for stanza in _stanzas((staging / "DPKG-STATUS").read_text(encoding="utf-8")):
        package, arch = _field(stanza, "Package"), _field(stanza, "Architecture")
        index = next(
            (
                position
                for position, item in enumerate(current)
                if (_field(item, "Package"), _field(item, "Architecture")) == (package, arch)
            ),
            None,
        )
        if index is None:
            message = f"the runtime base does not record {package}:{arch}"
            raise SystemExit(message)

        new_paths = set(
            _file_list(staging / "info", package, arch).read_text(encoding="utf-8").splitlines()
        )
        old_list = _file_list(dpkg / "info", package, arch)
        for line in old_list.read_text(encoding="utf-8").splitlines():
            path = root / line.lstrip("/")
            if line not in new_paths and (path.is_symlink() or path.is_file()):
                path.unlink()

        for old in _info_files(dpkg / "info", package, arch):
            old.unlink()
        for new in _info_files(staging / "info", package, arch):
            shutil.copy2(new, dpkg / "info" / new.name)

        status_d = dpkg / "status.d"
        if status_d.is_dir():
            record = staging / "status.d" / package
            if not record.is_file():
                message = f"no status.d record staged for {package}"
                raise SystemExit(message)
            shutil.copy2(record, status_d / package)

        current[index] = stanza
        upgraded.append(f"{package}:{arch} {_field(stanza, 'Version')}")

    status_path.write_text("\n\n".join(current) + "\n", encoding="utf-8")
    shutil.rmtree(staging)
    return upgraded


if __name__ == "__main__":
    for entry in upgrade(Path(sys.argv[1]), Path(sys.argv[2])):
        print(f"upgraded {entry}")
    Path(__file__).unlink()
