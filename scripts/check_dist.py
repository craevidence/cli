"""Distribution content guard.

Builds the sdist and wheel and verifies:
  - Exactly EXPECTED_RULE_COUNT rule YAML files are present in each artifact.
  - No .py or fixture files appear under local/rules/ in either artifact.
  - No rule_fixtures path appears in either artifact.
  - The source distribution contains no bundled engine executable.

Run: python scripts/check_dist.py

Invoked by CI after the rulepack structural and engine gates pass. Implemented
as a standalone script (not a pytest test) to keep multi-second build time out
of the normal test suite.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
RULES_ROOT = REPO_ROOT / "cra_evidence_cli" / "local" / "rules"

EXPECTED_RULE_COUNT = 93
ENGINE_BINARY_SUFFIX = "cra_evidence_cli/_engine/grype"
OPENGREP_BINARY_SUFFIX = "cra_evidence_cli/_engine/opengrep"
OPENGREP_LOCK_SUFFIX = "cra_evidence_cli/_engine/opengrep-release.json"
ENGINE_PACKAGE_SUFFIX = "cra_evidence_cli/_engine"
OPENGREP_LOCK_PATH = REPO_ROOT / "cra_evidence_cli" / "_engine" / "opengrep-release.json"
# The Opengrep NOTICE is generated from a fixed template, so the released copy
# has exactly one valid form for a given pinned commit and version.
OPENGREP_NOTICE_TEMPLATE = (
    "This product includes Opengrep, licensed under the GNU Lesser General "
    "Public License version 2.1. Source commit: {commit}. The upstream "
    "repository is https://github.com/opengrep/opengrep. The matching CRA "
    "Evidence CLI GitHub release includes opengrep-{version}-source.tar.gz. "
    "Upstream copyright notices and the native dependency inventory accompany "
    "this notice.\n"
)
OPENGREP_NOTICE_COMMIT_RE = re.compile(r"Source commit: ([0-9a-fA-F]{7,40})")
MAX_WHEEL_SIZE = 80 * 1024 * 1024
PYPI_FILE_SIZE_LIMIT = 100 * 1024 * 1024
WHEEL_ENGINES = {
    "manylinux_2_17_x86_64": ("grype-linux-amd64", "opengrep_manylinux_x86"),
    "musllinux_1_2_x86_64": ("grype-linux-amd64", "opengrep_musllinux_x86"),
    "manylinux_2_17_aarch64": ("grype-linux-arm64", "opengrep_manylinux_aarch64"),
    "musllinux_1_2_aarch64": ("grype-linux-arm64", "opengrep_musllinux_aarch64"),
    "macosx_12_0_x86_64": ("grype-darwin-amd64", "opengrep_osx_x86"),
    "macosx_12_0_arm64": ("grype-darwin-arm64", "opengrep_osx_arm64"),
}


def _build_dist(dist_dir: Path) -> tuple[list[Path], Path]:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "build", "--outdir", str(dist_dir), str(REPO_ROOT)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        msg = f"build failed (exit {result.returncode})"
        raise SystemExit(msg)

    wheels = list(dist_dir.glob("*.whl"))
    sdists = list(dist_dir.glob("*.tar.gz"))
    if not wheels:
        msg = "expected at least 1 wheel"
        raise SystemExit(msg)
    if len(sdists) != 1:
        msg = f"expected 1 sdist, found {len(sdists)}: {sdists}"
        raise SystemExit(msg)
    return wheels, sdists[0]


def _names_from_wheel(whl: Path) -> list[str]:
    with zipfile.ZipFile(whl) as z:
        return z.namelist()


def _names_from_sdist(sdist: Path) -> list[str]:
    with tarfile.open(sdist, "r:gz") as t:
        return t.getnames()


def _check(artifact_label: str, names: list[str]) -> list[str]:
    errors: list[str] = []

    rule_yamls = sorted(RULES_ROOT.rglob("*.yaml"))
    if len(rule_yamls) != EXPECTED_RULE_COUNT:
        errors.append(
            f"{artifact_label}: expected {EXPECTED_RULE_COUNT} rule files on disk, "
            f"found {len(rule_yamls)}"
        )

    for rule_path in rule_yamls:
        rel = rule_path.relative_to(REPO_ROOT)
        suffix = str(rel).replace("\\", "/")
        matching = [n for n in names if n.endswith(suffix)]
        if not matching:
            errors.append(
                f"{artifact_label}: rule file missing from artifact: {suffix}"
            )

    py_in_rules = [
        n for n in names
        if "local/rules/" in n and n.endswith(".py")
    ]
    if py_in_rules:
        errors.append(
            f"{artifact_label}: .py files found under local/rules/ -- "
            f"fixtures must not ship: {py_in_rules}"
        )

    fixture_entries = [n for n in names if "rule_fixtures" in n]
    if fixture_entries:
        errors.append(
            f"{artifact_label}: rule_fixtures paths found in artifact -- "
            f"deliberately-vulnerable fixtures must not ship: {fixture_entries[:5]}"
        )

    lock_entries = [
        name
        for name in names
        if name.replace("\\", "/").endswith(OPENGREP_LOCK_SUFFIX)
    ]
    if len(lock_entries) != 1:
        errors.append(
            f"{artifact_label}: expected one Opengrep release lock, found {lock_entries}"
        )

    return errors


def _check_engine_free_sdist(names: list[str]) -> list[str]:
    engine_entries = [
        name
        for name in names
        if name.replace("\\", "/").endswith(
            (ENGINE_BINARY_SUFFIX, OPENGREP_BINARY_SUFFIX)
        )
    ]
    if not engine_entries:
        return []
    return [
        "sdist: bundled engine executable must not ship in the source "
        f"distribution: {engine_entries}"
    ]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _project_version() -> str:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(project["project"]["version"])


def _expected_release_names(version: str) -> set[str]:
    wheels = {
        f"craevidence-{version}-py3-none-{platform}.whl"
        for platform in WHEEL_ENGINES
    }
    return {*wheels, f"craevidence-{version}.tar.gz"}


def _opengrep_release_lock() -> dict:
    return json.loads(OPENGREP_LOCK_PATH.read_text(encoding="utf-8"))


def _expected_opengrep_notice() -> str:
    lock = _opengrep_release_lock()
    commit = str(lock["commit"])
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        msg = f"Opengrep release lock pins a malformed commit: {commit!r}"
        raise SystemExit(msg)
    return OPENGREP_NOTICE_TEMPLATE.format(
        commit=commit, version=str(lock["version"])
    )


def _check_opengrep_notice(label: str, notice_bytes: bytes) -> list[str]:
    """Compare the shipped Opengrep NOTICE against the generated attribution text.

    The NOTICE is written from a fixed template with the pinned commit and
    version substituted in, so any difference is either stale text or text that
    no longer states the licence and source the release actually ships.
    """
    expected = _expected_opengrep_notice()
    try:
        notice = notice_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{label}: Opengrep NOTICE is not valid UTF-8"]
    if notice == expected:
        return []
    pinned_commit = str(_opengrep_release_lock()["commit"])
    match = OPENGREP_NOTICE_COMMIT_RE.search(notice)
    stated_commit = match.group(1) if match else None
    if stated_commit is None or stated_commit.lower() != pinned_commit:
        return [
            f"{label}: Opengrep NOTICE states source commit "
            f"{stated_commit or 'none'}, release lock pins {pinned_commit}"
        ]
    return [
        f"{label}: Opengrep NOTICE does not match the generated LGPL "
        f"attribution text for commit {pinned_commit}"
    ]


def _check_wheel_size(wheel: Path) -> list[str]:
    size = wheel.stat().st_size
    size_mib = size / (1024 * 1024)
    errors = []
    if size > MAX_WHEEL_SIZE:
        errors.append(
            f"{wheel.name}: {size_mib:.1f} MiB exceeds the 80 MiB release limit"
        )
    if size > PYPI_FILE_SIZE_LIMIT:
        errors.append(
            f"{wheel.name}: {size_mib:.1f} MiB exceeds PyPI's 100 MiB file limit"
        )
    return errors


def _check_release_wheel(
    wheel: Path,
    engine_binary: Path,
    engine_dir: Path,
    opengrep_binary: Path,
    opengrep_dir: Path,
) -> list[str]:
    errors: list[str] = []
    with zipfile.ZipFile(wheel) as archive:
        engine_members = [
            name for name in archive.namelist() if name.endswith(ENGINE_BINARY_SUFFIX)
        ]
        if len(engine_members) != 1:
            return [
                f"{wheel.name}: expected one bundled engine, found {engine_members}"
            ]
        engine_member = engine_members[0]
        info = archive.getinfo(engine_member)
        mode = info.external_attr >> 16
        if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) == 0:
            errors.append(f"{wheel.name}: bundled engine is not executable")

        actual_hash = _sha256_bytes(archive.read(engine_member))
        expected_hash = _sha256_bytes(engine_binary.read_bytes())
        if actual_hash != expected_hash:
            errors.append(
                f"{wheel.name}: bundled engine hash {actual_hash} does not match "
                f"promoted payload {expected_hash}"
            )

        for name in ("LICENSE", "NOTICE"):
            members = [
                member
                for member in archive.namelist()
                if member.endswith(f"{ENGINE_PACKAGE_SUFFIX}/{name}")
            ]
            if len(members) != 1:
                errors.append(
                    f"{wheel.name}: expected one engine {name}, found {members}"
                )
                continue
            expected = (engine_dir / name).read_bytes()
            if archive.read(members[0]) != expected:
                errors.append(
                    f"{wheel.name}: engine {name} differs from the promoted payload"
                )

        opengrep_members = [
            name
            for name in archive.namelist()
            if name.endswith(OPENGREP_BINARY_SUFFIX)
        ]
        if len(opengrep_members) != 1:
            errors.append(
                f"{wheel.name}: expected one bundled Opengrep, found {opengrep_members}"
            )
        else:
            info = archive.getinfo(opengrep_members[0])
            mode = info.external_attr >> 16
            if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) == 0:
                errors.append(f"{wheel.name}: bundled Opengrep is not executable")
            if _sha256_bytes(archive.read(opengrep_members[0])) != _sha256_bytes(
                opengrep_binary.read_bytes()
            ):
                errors.append(
                    f"{wheel.name}: bundled Opengrep differs from verified payload"
                )
        for packaged_name, payload_name in (
            ("opengrep-LICENSE", "LICENSE"),
            ("opengrep-NOTICE", "NOTICE"),
            ("opengrep-COPYRIGHT", "COPYRIGHT"),
            ("opengrep-NATIVE-DEPENDENCIES.json", "NATIVE-DEPENDENCIES.json"),
        ):
            members = [
                member
                for member in archive.namelist()
                if member.endswith(f"{ENGINE_PACKAGE_SUFFIX}/{packaged_name}")
            ]
            if len(members) != 1:
                errors.append(
                    f"{wheel.name}: expected one {packaged_name}, found {members}"
                )
                continue
            packaged_bytes = archive.read(members[0])
            if packaged_bytes != (opengrep_dir / payload_name).read_bytes():
                errors.append(f"{wheel.name}: {packaged_name} differs from payload")
                continue
            if payload_name == "NOTICE":
                # The comparison above only proves the two copies agree. If the
                # payload itself carried the wrong text both copies would still
                # match, so compare it with the generated attribution text.
                errors.extend(_check_opengrep_notice(wheel.name, packaged_bytes))
    return errors


def _check_release_set(
    dist_dir: Path, engine_dir: Path, opengrep_dir: Path
) -> list[str]:
    version = _project_version()
    expected = _expected_release_names(version)
    actual = {
        path.name
        for path in dist_dir.iterdir()
        if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    }
    if actual != expected:
        return [
            "release distribution set mismatch: "
            f"expected {sorted(expected)}, found {sorted(actual)}"
        ]

    errors: list[str] = []
    for platform, (engine_name, opengrep_name) in WHEEL_ENGINES.items():
        wheel = dist_dir / f"craevidence-{version}-py3-none-{platform}.whl"
        errors.extend(_check_wheel_size(wheel))
        engine_binary = engine_dir / engine_name
        if not engine_binary.is_file() or engine_binary.is_symlink():
            errors.append(f"promoted payload is missing regular file {engine_name}")
            continue
        opengrep_binary = opengrep_dir / opengrep_name
        if not opengrep_binary.is_file() or opengrep_binary.is_symlink():
            errors.append(f"verified payload is missing regular file {opengrep_name}")
            continue
        errors.extend(
            _check_release_wheel(
                wheel,
                engine_binary,
                engine_dir,
                opengrep_binary,
                opengrep_dir,
            )
        )
    return errors


def _check_dist_dir(dist_dir: Path) -> list[str]:
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if not wheels or len(sdists) != 1:
        msg = f"expected wheels and one sdist in {dist_dir}"
        raise SystemExit(msg)
    all_errors: list[str] = []
    for wheel in wheels:
        print(f"  wheel : {wheel.name}")
        all_errors.extend(_check(f"wheel ({wheel.name})", _names_from_wheel(wheel)))
    print(f"  sdist : {sdists[0].name}")
    sdist_names = _names_from_sdist(sdists[0])
    all_errors.extend(_check(f"sdist ({sdists[0].name})", sdist_names))
    all_errors.extend(_check_engine_free_sdist(sdist_names))
    return all_errors


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Check release distribution contents.")
    parser.add_argument("--dist-dir", type=Path)
    parser.add_argument("--engine-dir", type=Path)
    parser.add_argument("--opengrep-dir", type=Path)
    args = parser.parse_args(argv)

    if args.dist_dir:
        if args.engine_dir is None or args.opengrep_dir is None:
            parser.error("--engine-dir and --opengrep-dir are required with --dist-dir")
        all_errors = _check_dist_dir(args.dist_dir)
        all_errors.extend(
            _check_release_set(args.dist_dir, args.engine_dir, args.opengrep_dir)
        )
    else:
        with tempfile.TemporaryDirectory() as tmp:
            dist_dir = Path(tmp)
            print("Building sdist and wheel...")
            _build_dist(dist_dir)
            all_errors = _check_dist_dir(dist_dir)

    if all_errors:
        print("\nDist content check FAILED:")
        for err in all_errors:
            print(f"  {err}")
        raise SystemExit(1)

    detail = ""
    if args.dist_dir:
        detail = (
            " Promoted Grype and verified Opengrep bytes, licences, and "
            "executable modes match."
        )
    print(
        f"\nDist content check passed: "
        f"{EXPECTED_RULE_COUNT} rules in every wheel and the sdist, no fixtures, "
        f"and no engine executable in the sdist.{detail}"
    )


if __name__ == "__main__":
    main()
