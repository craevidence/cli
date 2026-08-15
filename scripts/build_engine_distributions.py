"""Build platform wheels from promoted Grype and Opengrep payloads.

The engine directory must be the ``/engine`` payload extracted from the pinned
engine image. No engine is rebuilt here. Linux manylinux and musllinux wheels
are packaged separately from the same promoted static binary bytes.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

SOURCE_DATE_EPOCH = "946684800"
ENGINE_PACKAGE_PATH = Path("cra_evidence_cli/_engine")
ENGINE_BINARY_PATH = ENGINE_PACKAGE_PATH / "grype"
OPENGREP_BINARY_PATH = ENGINE_PACKAGE_PATH / "opengrep"
OPENGREP_LOCK_PATH = ENGINE_PACKAGE_PATH / "opengrep-release.json"
MANYLINUX_GLIBC_FLOOR = (2, 17)
_GLIBC_VERSION_RE = re.compile(rb"GLIBC_(\d+)\.(\d+)")


@dataclass(frozen=True)
class WheelTarget:
    engine_name: str
    opengrep_name: str
    platform_tag: str


WHEEL_TARGETS = (
    WheelTarget(
        "grype-linux-amd64",
        "opengrep_manylinux_x86",
        "manylinux_2_17_x86_64",
    ),
    WheelTarget("grype-linux-amd64", "opengrep_musllinux_x86", "musllinux_1_2_x86_64"),
    WheelTarget(
        "grype-linux-arm64",
        "opengrep_manylinux_aarch64",
        "manylinux_2_17_aarch64",
    ),
    WheelTarget(
        "grype-linux-arm64",
        "opengrep_musllinux_aarch64",
        "musllinux_1_2_aarch64",
    ),
    WheelTarget("grype-darwin-amd64", "opengrep_osx_x86", "macosx_12_0_x86_64"),
    WheelTarget("grype-darwin-arm64", "opengrep_osx_arm64", "macosx_12_0_arm64"),
)


class DistributionBuildError(Exception):
    """The promoted payload or a built distribution failed verification."""


@contextmanager
def _release_umask():
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def expected_wheel_filenames(version: str) -> tuple[str, ...]:
    tags = [target.platform_tag for target in WHEEL_TARGETS]
    return tuple(f"craevidence-{version}-py3-none-{tag}.whl" for tag in tags)


def expected_distribution_filenames(version: str) -> tuple[str, ...]:
    return (*expected_wheel_filenames(version), f"craevidence-{version}.tar.gz")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_hashes(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) != 2 or len(fields[0]) != 64:
            msg = f"invalid SHA256SUMS line: {line!r}"
            raise DistributionBuildError(msg)
        name = Path(fields[1].lstrip("*")).name
        result[name] = fields[0]
    return result


def _validate_elf(path: Path, expected_machine: int, *, require_static: bool) -> None:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        msg = f"{path.name} is not a 64-bit ELF executable"
        raise DistributionBuildError(msg)
    if data[5] == 1:
        byteorder = "little"
    elif data[5] == 2:
        byteorder = "big"
    else:
        msg = f"{path.name} has an invalid ELF byte order"
        raise DistributionBuildError(msg)
    machine = int.from_bytes(data[18:20], byteorder)
    if machine != expected_machine:
        msg = f"{path.name} has ELF machine {machine}, expected {expected_machine}"
        raise DistributionBuildError(msg)
    program_offset = int.from_bytes(data[32:40], byteorder)
    entry_size = int.from_bytes(data[54:56], byteorder)
    entry_count = int.from_bytes(data[56:58], byteorder)
    table_end = program_offset + entry_size * entry_count
    if table_end > len(data):
        msg = f"{path.name} has a truncated ELF program table"
        raise DistributionBuildError(msg)
    for index in range(entry_count):
        offset = program_offset + entry_size * index
        if entry_size < 4:
            msg = f"{path.name} has an invalid ELF program-header size"
            raise DistributionBuildError(msg)
        program_type = int.from_bytes(data[offset : offset + 4], byteorder)
        if require_static and program_type == 3:
            msg = (
                f"{path.name} is dynamically linked and cannot back both "
                "manylinux and musllinux wheels"
            )
            raise DistributionBuildError(msg)


def _validate_macho(path: Path, expected_cpu: int) -> None:
    header = path.read_bytes()[:8]
    if len(header) < 8 or header[:4] != b"\xcf\xfa\xed\xfe":
        msg = f"{path.name} is not a 64-bit Mach-O executable"
        raise DistributionBuildError(msg)
    cpu = int.from_bytes(header[4:8], "little")
    if cpu != expected_cpu:
        msg = f"{path.name} has Mach-O CPU {cpu}, expected {expected_cpu}"
        raise DistributionBuildError(msg)


def _validate_binary_shape(target: WheelTarget, path: Path) -> None:
    expected = {
        "grype-linux-amd64": ("elf", 62),
        "grype-linux-arm64": ("elf", 183),
        "grype-darwin-amd64": ("macho", 0x01000007),
        "grype-darwin-arm64": ("macho", 0x0100000C),
    }[target.engine_name]
    if expected[0] == "elf":
        _validate_elf(path, expected[1], require_static=True)
    else:
        _validate_macho(path, expected[1])


def _validate_opengrep_linux_abi(target: WheelTarget, path: Path) -> None:
    data = path.read_bytes()
    if len(data) < 64 or data[:5] != b"\x7fELF\x02":
        msg = f"{path.name} is not a 64-bit ELF executable"
        raise DistributionBuildError(msg)
    if data[5] == 1:
        byteorder = "little"
    elif data[5] == 2:
        byteorder = "big"
    else:
        msg = f"{path.name} has an invalid ELF byte order"
        raise DistributionBuildError(msg)
    section_offset = int.from_bytes(data[40:48], byteorder)
    section_size = int.from_bytes(data[58:60], byteorder)
    section_count = int.from_bytes(data[60:62], byteorder)
    names_index = int.from_bytes(data[62:64], byteorder)
    table_end = section_offset + section_size * section_count
    if (
        section_size < 64
        or section_count == 0
        or names_index >= section_count
        or table_end > len(data)
    ):
        msg = f"{path.name} has an invalid ELF section table"
        raise DistributionBuildError(msg)

    def section(index: int) -> bytes:
        header = section_offset + section_size * index
        content_offset = int.from_bytes(data[header + 24 : header + 32], byteorder)
        content_size = int.from_bytes(data[header + 32 : header + 40], byteorder)
        content_end = content_offset + content_size
        if content_end > len(data):
            msg = f"{path.name} has an ELF section outside the file"
            raise DistributionBuildError(msg)
        return data[content_offset:content_end]

    names = section(names_index)
    dynamic_strings: bytes | None = None
    for index in range(section_count):
        header = section_offset + section_size * index
        name_offset = int.from_bytes(data[header : header + 4], byteorder)
        if name_offset >= len(names):
            continue
        name = names[name_offset:].split(b"\x00", 1)[0]
        if name == b".dynstr":
            dynamic_strings = section(index)
            break
    if dynamic_strings is None:
        msg = f"{path.name} has no ELF .dynstr section"
        raise DistributionBuildError(msg)
    versions = {
        (int(match.group(1)), int(match.group(2)))
        for value in dynamic_strings.split(b"\x00")
        if (match := _GLIBC_VERSION_RE.fullmatch(value)) is not None
    }
    if target.platform_tag.startswith("manylinux"):
        if not versions:
            msg = f"{target.opengrep_name} declares no GLIBC symbol versions"
            raise DistributionBuildError(msg)
        newest = max(versions)
        if newest > MANYLINUX_GLIBC_FLOOR:
            msg = (
                f"{target.opengrep_name} requires GLIBC {newest[0]}.{newest[1]}, "
                "newer than the manylinux_2_17 floor"
            )
            raise DistributionBuildError(msg)
    elif target.platform_tag.startswith("musllinux") and versions:
        msg = f"{target.opengrep_name} carries GLIBC symbol versions in a musllinux wheel"
        raise DistributionBuildError(msg)


def validate_engine_payload(engine_dir: Path) -> None:
    required_text = {
        "LICENSE": "Apache License",
        "NOTICE": "modified build of Anchore Grype",
    }
    for name, marker in required_text.items():
        path = engine_dir / name
        if not path.is_file() or marker not in path.read_text(encoding="utf-8"):
            msg = f"engine payload {name} is missing or does not contain {marker!r}"
            raise DistributionBuildError(msg)

    manifest_path = engine_dir / "SHA256SUMS"
    if not manifest_path.is_file():
        msg = "engine payload is missing SHA256SUMS"
        raise DistributionBuildError(msg)
    manifest = _manifest_hashes(manifest_path)

    for target in WHEEL_TARGETS:
        binary = engine_dir / target.engine_name
        if not binary.is_file() or binary.is_symlink():
            msg = f"engine payload is missing regular file {target.engine_name}"
            raise DistributionBuildError(msg)
        suffix = target.engine_name.removeprefix("grype-")
        matching = [value for name, value in manifest.items() if name.endswith(suffix)]
        if len(matching) != 1:
            msg = f"SHA256SUMS has {len(matching)} entries for {target.engine_name}"
            raise DistributionBuildError(msg)
        actual = _sha256_file(binary)
        if actual != matching[0]:
            msg = f"SHA-256 mismatch for {target.engine_name}: {actual} != {matching[0]}"
            raise DistributionBuildError(msg)
        _validate_binary_shape(target, binary)


def validate_opengrep_payload(
    opengrep_dir: Path, lock_path: Path | None = None
) -> None:
    required_text = {
        "LICENSE": "GNU LESSER GENERAL PUBLIC LICENSE",
        "NOTICE": "includes Opengrep",
        "COPYRIGHT": "Copyright",
    }
    for name, marker in required_text.items():
        path = opengrep_dir / name
        if not path.is_file() or marker not in path.read_text(encoding="utf-8"):
            msg = f"Opengrep payload {name} is missing or lacks {marker!r}"
            raise DistributionBuildError(msg)

    manifest_path = opengrep_dir / "SHA256SUMS"
    if not manifest_path.is_file():
        msg = "Opengrep payload is missing SHA256SUMS"
        raise DistributionBuildError(msg)
    manifest = _manifest_hashes(manifest_path)
    for target in WHEEL_TARGETS:
        binary = opengrep_dir / target.opengrep_name
        if not binary.is_file() or binary.is_symlink():
            msg = f"Opengrep payload is missing regular file {target.opengrep_name}"
            raise DistributionBuildError(msg)
        expected_hash = manifest.get(target.opengrep_name)
        actual_hash = _sha256_file(binary)
        if expected_hash != actual_hash:
            msg = (
                f"SHA-256 mismatch for {target.opengrep_name}: "
                f"{actual_hash} != {expected_hash}"
            )
            raise DistributionBuildError(msg)
        if target.opengrep_name.startswith("opengrep_osx"):
            cpu = 0x01000007 if target.opengrep_name.endswith("x86") else 0x0100000C
            _validate_macho(binary, cpu)
        else:
            machine = 62 if target.opengrep_name.endswith("x86") else 183
            _validate_elf(binary, machine, require_static=False)

    if lock_path is None:
        return
    if not lock_path.is_file():
        msg = f"release source is missing Opengrep lock: {lock_path}"
        raise DistributionBuildError(msg)
    payload_manifest_path = opengrep_dir / "MANIFEST.json"
    if not payload_manifest_path.is_file():
        msg = "Opengrep payload is missing MANIFEST.json provenance"
        raise DistributionBuildError(msg)
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        payload_manifest = json.loads(
            payload_manifest_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        msg = f"Opengrep provenance is not valid JSON: {error}"
        raise DistributionBuildError(msg) from error
    for key in (
        "project",
        "version",
        "tag",
        "commit",
        "certificate_identity",
        "certificate_issuer",
    ):
        if payload_manifest.get(key) != lock.get(key):
            msg = f"Opengrep payload {key} does not match the release source lock"
            raise DistributionBuildError(msg)
    payload_assets = {
        asset.get("name"): asset.get("sha256")
        for asset in payload_manifest.get("assets") or []
        if asset.get("signature_verified") is True
    }
    if payload_assets != lock.get("assets"):
        msg = "Opengrep payload assets do not match the signed release lock"
        raise DistributionBuildError(msg)
    source = payload_manifest.get("source_archive") or {}
    locked_source = lock.get("source_archive") or {}
    for key in ("repository", "commit", "signature_verified", "verification"):
        if source.get(key) != locked_source.get(key):
            msg = f"Opengrep source archive {key} does not match the release source lock"
            raise DistributionBuildError(msg)
    if source.get("signature_verified") is not False:
        msg = "Opengrep source archive must not be described as signature-verified"
        raise DistributionBuildError(msg)
    source_path = opengrep_dir / str(source.get("name") or "")
    if not source_path.is_file() or _sha256_file(source_path) != source.get("sha256"):
        msg = "Opengrep build-source archive is missing or has the wrong hash"
        raise DistributionBuildError(msg)
    if (
        not isinstance(source.get("submodule_count"), int)
        or source["submodule_count"] < 1
        or not isinstance(source.get("tracked_file_count"), int)
        or source["tracked_file_count"] < 1
    ):
        msg = "Opengrep source archive lacks recursive source inventory counts"
        raise DistributionBuildError(msg)
    expected_exclusion = [
        {
            "path": "tests/semgrep-rules",
            "reason": "non-build rule test corpus excluded from redistribution",
        }
    ]
    if source.get("excluded_paths") != expected_exclusion:
        msg = "Opengrep source archive exclusions are not the reviewed set"
        raise DistributionBuildError(msg)
    try:
        with tarfile.open(source_path, "r:gz") as source_archive:
            source_names = set(source_archive.getnames())
            roots = {
                name.split("/", 1)[0] for name in source_names if "/" in name
            }
            if len(roots) != 1:
                msg = "Opengrep source archive does not have one source root"
                raise DistributionBuildError(msg)
            source_root = next(iter(roots))
            required_source = {
                f"{source_root}/SOURCE-COMMITS.json",
                (
                    f"{source_root}/cli/src/semgrep/semgrep_interfaces/"
                    "semgrep_output_v1.atd"
                ),
                (
                    f"{source_root}/languages/python/tree-sitter/"
                    "semgrep-python/lib/parser.c"
                ),
            }
            if not required_source.issubset(source_names):
                msg = "Opengrep source archive is missing pinned submodule source"
                raise DistributionBuildError(msg)
            if any(
                name.startswith(f"{source_root}/tests/semgrep-rules/")
                for name in source_names
            ):
                msg = "Opengrep source archive contains the excluded rule test corpus"
                raise DistributionBuildError(msg)
            manifest_file = source_archive.extractfile(
                f"{source_root}/SOURCE-COMMITS.json"
            )
            if manifest_file is None:
                msg = "Opengrep source commit manifest could not be read"
                raise DistributionBuildError(msg)
            source_commits = json.load(manifest_file)
    except (OSError, tarfile.TarError, json.JSONDecodeError) as error:
        msg = f"Opengrep source archive inventory is invalid: {error}"
        raise DistributionBuildError(msg) from error
    submodules = source_commits.get("submodules") or []
    if (
        source_commits.get("commit") != source.get("commit")
        or len(submodules) != source["submodule_count"]
        or any(
            not isinstance(item, dict)
            or not re.fullmatch(r"[0-9a-f]{40}", str(item.get("commit") or ""))
            or not isinstance(item.get("path"), str)
            for item in submodules
        )
    ):
        msg = "Opengrep source commit manifest does not match the payload"
        raise DistributionBuildError(msg)

    native_dependencies_path = opengrep_dir / "NATIVE-DEPENDENCIES.json"
    try:
        native_dependencies = json.loads(
            native_dependencies_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        msg = "Opengrep native dependency inventory is missing or invalid"
        raise DistributionBuildError(msg) from error
    if set(native_dependencies) != set(lock["assets"]):
        msg = "Opengrep native dependency inventory does not cover every asset"
        raise DistributionBuildError(msg)
    if any(
        not isinstance(values, list)
        or any(not isinstance(value, str) for value in values)
        for values in native_dependencies.values()
    ):
        msg = "Opengrep native dependency inventory has an invalid shape"
        raise DistributionBuildError(msg)

    for target in WHEEL_TARGETS:
        if target.platform_tag.startswith(("manylinux", "musllinux")):
            _validate_opengrep_linux_abi(
                target, opengrep_dir / target.opengrep_name
            )
    for arch in ("x86", "aarch64"):
        manylinux = opengrep_dir / f"opengrep_manylinux_{arch}"
        musllinux = opengrep_dir / f"opengrep_musllinux_{arch}"
        if _sha256_file(manylinux) == _sha256_file(musllinux):
            msg = f"Opengrep manylinux and musllinux {arch} assets are identical"
            raise DistributionBuildError(msg)


def _run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, env=env, check=False)  # noqa: S603
    if result.returncode != 0:
        msg = f"command failed with exit {result.returncode}: {' '.join(command)}"
        raise DistributionBuildError(msg)


def _copy_release_source(source: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git",
        ".venv",
        "build",
        "dist",
        "*.egg-info",
        "__pycache__",
        "*.pyc",
    )
    shutil.copytree(source, destination, ignore=ignored)
    # Normalize file modes so the built bytes do not depend on the checkout's
    # umask history: a long-lived working tree can carry group-writable files
    # while a fresh CI checkout creates 644, and the wheel records source
    # modes in its zip entries. Directories and executables become 755 and
    # regular files 644, matching a fresh checkout.
    for path in sorted(destination.rglob("*")):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o755)
        elif path.stat().st_mode & 0o111:
            path.chmod(0o755)
        else:
            path.chmod(0o644)


def _validate_engine_free_source(release_src: Path) -> None:
    for binary_path in (ENGINE_BINARY_PATH, OPENGREP_BINARY_PATH):
        engine_binary = release_src / binary_path
        if engine_binary.exists() or engine_binary.is_symlink():
            msg = (
                "source distribution input contains a bundled engine executable: "
                f"{engine_binary}"
            )
            raise DistributionBuildError(msg)


def _build_platform_wheel(
    release_src: Path,
    engine_dir: Path,
    opengrep_dir: Path,
    target: WheelTarget,
    output_dir: Path,
) -> Path:
    with tempfile.TemporaryDirectory() as temporary:
        staged_source = Path(temporary) / "source"
        build_output = Path(temporary) / "dist"
        _copy_release_source(release_src, staged_source)
        package_dir = staged_source / ENGINE_PACKAGE_PATH
        package_dir.mkdir(parents=True, exist_ok=True)
        binary = package_dir / "grype"
        shutil.copy2(engine_dir / target.engine_name, binary)
        binary.chmod(0o755)
        shutil.copy2(engine_dir / "LICENSE", package_dir / "LICENSE")
        shutil.copy2(engine_dir / "NOTICE", package_dir / "NOTICE")
        opengrep = package_dir / "opengrep"
        shutil.copy2(opengrep_dir / target.opengrep_name, opengrep)
        opengrep.chmod(0o755)
        shutil.copy2(opengrep_dir / "LICENSE", package_dir / "opengrep-LICENSE")
        shutil.copy2(opengrep_dir / "NOTICE", package_dir / "opengrep-NOTICE")
        shutil.copy2(opengrep_dir / "COPYRIGHT", package_dir / "opengrep-COPYRIGHT")
        shutil.copy2(
            opengrep_dir / "NATIVE-DEPENDENCIES.json",
            package_dir / "opengrep-NATIVE-DEPENDENCIES.json",
        )

        env = {**os.environ, "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--outdir",
                str(build_output),
                (
                    "--config-setting=--build-option="
                    f"--plat-name={target.platform_tag}"
                ),
                str(staged_source),
            ],
            env=env,
        )
        wheels = list(build_output.glob("*.whl"))
        if len(wheels) != 1:
            msg = f"expected one {target.platform_tag} wheel, found {wheels}"
            raise DistributionBuildError(msg)
        built = output_dir / wheels[0].name
        shutil.copy2(wheels[0], built)
        _normalize_wheel(built)
        return built


def _normalize_wheel(wheel: Path) -> None:
    """Rewrite a built wheel with canonical entry modes.

    Setuptools creates intermediate copies whose modes follow the build
    host's umask, so the same source can yield 644 entries on one machine
    and 664 on another. Rewriting every entry with 644 for regular files
    and 755 for executables makes the archive bytes independent of the
    host's umask and interpreter, matching the sdist normalization below.
    """
    source = wheel.with_suffix(".orig")
    wheel.replace(source)
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        with zipfile.ZipFile(
            wheel, "w", compression=zipfile.ZIP_DEFLATED
        ) as output:
            for entry in entries:
                data = archive.read(entry.filename)
                info = zipfile.ZipInfo(entry.filename, date_time=entry.date_time)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = entry.create_system
                mode = (entry.external_attr >> 16) & 0o7777
                normalized = 0o755 if mode & 0o111 else 0o644
                info.external_attr = ((0o100000 | normalized) << 16) | (
                    entry.external_attr & 0xFFFF
                )
                output.writestr(info, data)
    source.unlink()


def _binary_hash_in_wheel(wheel: Path, binary_name: str) -> str:
    with zipfile.ZipFile(wheel) as archive:
        names = [
            name for name in archive.namelist() if name.endswith(f"/_engine/{binary_name}")
        ]
        if len(names) != 1:
            msg = f"{wheel.name} contains {len(names)} bundled engine files"
            raise DistributionBuildError(msg)
        return hashlib.sha256(archive.read(names[0])).hexdigest()


def _normalize_sdist(source: Path, destination: Path) -> None:
    epoch = int(SOURCE_DATE_EPOCH)
    with tarfile.open(source, "r:gz") as input_archive:
        members = sorted(input_archive.getmembers(), key=lambda item: item.name)
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts:
                msg = f"unsafe path in built source distribution: {member.name}"
                raise DistributionBuildError(msg)

        with destination.open("wb") as output_file:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=output_file,
                mtime=epoch,
            ) as gzip_file:
                with tarfile.open(
                    fileobj=gzip_file,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as output_archive:
                    for original in members:
                        normalized = copy.copy(original)
                        normalized.mtime = epoch
                        normalized.uid = 0
                        normalized.gid = 0
                        if normalized.isdir() or normalized.mode & 0o111:
                            normalized.mode = 0o755
                        else:
                            normalized.mode = 0o644
                        normalized.uname = ""
                        normalized.gname = ""
                        normalized.pax_headers = {}
                        if original.isfile():
                            content = input_archive.extractfile(original)
                            if content is None:
                                msg = f"could not read {original.name} from source distribution"
                                raise DistributionBuildError(msg)
                            with content:
                                output_archive.addfile(normalized, content)
                        else:
                            output_archive.addfile(normalized)


def _build_sdist(release_src: Path, output_dir: Path, env: dict[str, str]) -> Path:
    with tempfile.TemporaryDirectory() as temporary:
        raw_output = Path(temporary)
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--sdist",
                "--outdir",
                str(raw_output),
                str(release_src),
            ],
            env=env,
        )
        sdists = list(raw_output.glob("*.tar.gz"))
        if len(sdists) != 1:
            msg = f"expected one source distribution, found {sdists}"
            raise DistributionBuildError(msg)
        normalized = output_dir / sdists[0].name
        _normalize_sdist(sdists[0], normalized)
        return normalized


def build_distributions(
    version: str,
    release_src: Path,
    engine_dir: Path,
    opengrep_dir: Path,
    output_dir: Path,
) -> tuple[Path, ...]:
    with _release_umask():
        return _build_distributions(
            version, release_src, engine_dir, opengrep_dir, output_dir
        )


def _build_distributions(
    version: str,
    release_src: Path,
    engine_dir: Path,
    opengrep_dir: Path,
    output_dir: Path,
) -> tuple[Path, ...]:
    validate_engine_payload(engine_dir)
    validate_opengrep_payload(opengrep_dir, release_src / OPENGREP_LOCK_PATH)
    output_dir.mkdir(parents=True, exist_ok=True)
    produced: list[Path] = []

    sdist = build_source_distribution(version, release_src, output_dir)

    for target in WHEEL_TARGETS:
        original_engine_hash = _sha256_file(engine_dir / target.engine_name)
        original_opengrep_hash = _sha256_file(opengrep_dir / target.opengrep_name)
        wheel = _build_platform_wheel(
            release_src,
            engine_dir,
            opengrep_dir,
            target,
            output_dir,
        )
        if _binary_hash_in_wheel(wheel, "grype") != original_engine_hash:
            msg = f"{wheel.name} does not contain the promoted Grype bytes"
            raise DistributionBuildError(msg)
        if _binary_hash_in_wheel(wheel, "opengrep") != original_opengrep_hash:
            msg = f"{wheel.name} does not contain the verified Opengrep bytes"
            raise DistributionBuildError(msg)
        produced.append(wheel)

    expected_sdist = output_dir / f"craevidence-{version}.tar.gz"
    if sdist != expected_sdist or not sdist.is_file():
        msg = f"build output is missing {sdist.name}"
        raise DistributionBuildError(msg)
    produced.append(sdist)

    expected = set(expected_distribution_filenames(version))
    actual = {path.name for path in produced}
    if actual != expected:
        msg = f"distribution set mismatch: expected {sorted(expected)}, got {sorted(actual)}"
        raise DistributionBuildError(msg)
    return tuple(produced)


def build_source_distribution(version: str, release_src: Path, output_dir: Path) -> Path:
    with _release_umask():
        return _build_source_distribution(version, release_src, output_dir)


def _build_source_distribution(
    version: str,
    release_src: Path,
    output_dir: Path,
) -> Path:
    _validate_engine_free_source(release_src)
    output_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}
    sdist = _build_sdist(release_src, output_dir, env)
    expected = output_dir / f"craevidence-{version}.tar.gz"
    if sdist != expected:
        msg = f"source distribution mismatch: expected {expected.name}, got {sdist.name}"
        raise DistributionBuildError(msg)
    return sdist


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build CRA Evidence platform wheels from a promoted engine payload.",
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-src", type=Path, required=True)
    parser.add_argument("--engine-dir", type=Path)
    parser.add_argument("--opengrep-dir", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--sdist-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.sdist_only:
            build_source_distribution(args.version, args.release_src, args.out_dir)
        else:
            if args.engine_dir is None or args.opengrep_dir is None:
                msg = "--engine-dir and --opengrep-dir are required for platform wheels"
                raise DistributionBuildError(msg)
            build_distributions(
                args.version,
                args.release_src,
                args.engine_dir,
                args.opengrep_dir,
                args.out_dir,
            )
    except DistributionBuildError as error:
        sys.stderr.write(f"engine distribution build failed: {error}\n")
        return 1
    names = (
        (f"craevidence-{args.version}.tar.gz",)
        if args.sdist_only
        else expected_distribution_filenames(args.version)
    )
    for name in names:
        sys.stdout.write(f"built {name}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
