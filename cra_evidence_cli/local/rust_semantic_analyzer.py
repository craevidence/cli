"""Static provenance analysis for narrow Rust external-crate calls."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any, NoReturn

REQWEST_PACKAGE = "reqwest"
REQWEST_CRATE = "reqwest"
REQWEST_VERSION = "0.12.24"
REQWEST_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
REQWEST_CHECKSUM = "9d0946410b9f7b082a427e4ef5c8ff541a88b357bc6c637c40db3a68ac70a36f"
SUPPORTED_EDITIONS = frozenset({"2018", "2021", "2024"})
SUPPORTED_REQUIREMENTS = frozenset(
    {
        "0.12",
        "0.12.*",
        "0.12.x",
        "0.12.24",
        "^0.12",
        "^0.12.24",
        "~0.12",
        "~0.12.24",
        "=0.12.24",
    }
)

_CALL_PATTERN = re.compile(
    r"::\s*(?P<candidate>reqwest\s*::\s*"
    r"(?:"
    r"Client\s*::\s*builder\s*\(\s*\)"
    r"|ClientBuilder\s*::\s*new\s*\(\s*\)"
    r"|blocking\s*::\s*Client\s*::\s*builder\s*\(\s*\)"
    r"|blocking\s*::\s*ClientBuilder\s*::\s*new\s*\(\s*\)"
    r")"
    r"\s*\.\s*"
    r"(?P<method>danger_accept_invalid_(?:certs|hostnames))"
    r"\s*\(\s*true\s*\))",
    re.MULTILINE,
)
_EXTERN_ALIAS_PATTERN = re.compile(
    r"\bextern\s+crate\s+(?P<target>self|[A-Za-z_][A-Za-z0-9_]*)"
    r"\s+as\s+reqwest\s*;",
    re.MULTILINE,
)


class RustAnalysisError(ValueError):
    """The package is outside the supported fail-closed Rust profile."""


def _reject(message: str, cause: BaseException | None = None) -> NoReturn:
    if cause is None:
        raise RustAnalysisError(message)
    raise RustAnalysisError(message) from cause


def _load_toml(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        _reject(f"{label} must be a regular non-symlink file")
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        _reject(f"{label} is not valid UTF-8 TOML", exc)
    if not isinstance(document, dict):
        _reject(f"{label} must contain a TOML document")
    return document


def _dependency_requirement(manifest: dict[str, Any]) -> str:
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, dict):
        _reject("Cargo.toml has no normal dependencies table")
    specification = dependencies.get(REQWEST_CRATE)
    if isinstance(specification, str):
        requirement = specification
    elif isinstance(specification, dict):
        prohibited = {"git", "path", "registry", "workspace"}.intersection(specification)
        if prohibited:
            names = ", ".join(sorted(prohibited))
            _reject(f"reqwest dependency uses unsupported keys: {names}")
        package = specification.get("package", REQWEST_PACKAGE)
        if package != REQWEST_PACKAGE:
            _reject("reqwest dependency does not name the reqwest package")
        requirement = specification.get("version")
    else:
        _reject("Cargo.toml has no supported reqwest dependency")
    if not isinstance(requirement, str) or requirement.strip() not in SUPPORTED_REQUIREMENTS:
        _reject("reqwest version requirement is outside the pinned profile")
    return requirement.strip()


def _locked_package(lock: dict[str, Any], name: str, version: str) -> dict[str, Any]:
    packages = lock.get("package")
    if not isinstance(packages, list):
        _reject("Cargo.lock has no package records")
    matches = [
        package
        for package in packages
        if isinstance(package, dict)
        and package.get("name") == name
        and package.get("version") == version
    ]
    if len(matches) != 1:
        _reject(f"Cargo.lock must contain one {name} {version} package")
    return matches[0]


def _validate_lock(
    lock: dict[str, Any], package_name: str, package_version: str
) -> None:
    dependency = _locked_package(lock, REQWEST_PACKAGE, REQWEST_VERSION)
    if dependency.get("source") != REQWEST_SOURCE:
        _reject("locked reqwest source is not the pinned crates.io source")
    if dependency.get("checksum") != REQWEST_CHECKSUM:
        _reject("locked reqwest checksum is not the pinned package checksum")

    root_package = _locked_package(lock, package_name, package_version)
    if root_package.get("source") is not None:
        _reject("the analyzed root package must be a local package")
    dependencies = root_package.get("dependencies")
    if not isinstance(dependencies, list):
        _reject("the root lock record has no dependency graph")
    accepted = {
        REQWEST_PACKAGE,
        f"{REQWEST_PACKAGE} {REQWEST_VERSION}",
        f"{REQWEST_PACKAGE} {REQWEST_VERSION} ({REQWEST_SOURCE})",
    }
    if not any(item in accepted for item in dependencies):
        _reject("the root lock record is not bound to pinned reqwest")


def _position(text: str, offset: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, offset) + 1
    return text.count("\n", 0, offset) + 1, offset - line_start + 1


def validate_rust_ancestor_context(source_root: Path) -> None:
    """Reject Cargo inputs outside the package root supported by this profile."""
    root = source_root.resolve(strict=True)
    for ancestor in root.parents:
        if (ancestor / "Cargo.toml").exists():
            _reject("an ancestor Cargo.toml makes package resolution ambiguous")
        cargo_directory = ancestor / ".cargo"
        if any((cargo_directory / name).exists() for name in ("config", "config.toml")):
            _reject("ancestor Cargo configuration is unsupported")


def analyze_rust_package(source_root: Path) -> dict[str, Any]:
    """Return pinned reqwest occurrences for one non-workspace Cargo package."""
    root = source_root.resolve(strict=True)
    if not root.is_dir():
        _reject("Rust evidence path must be a package directory")
    validate_rust_ancestor_context(root)
    manifest_path = root / "Cargo.toml"
    lock_path = root / "Cargo.lock"
    manifest = _load_toml(manifest_path, "Cargo.toml")
    lock = _load_toml(lock_path, "Cargo.lock")

    if "workspace" in manifest or "patch" in manifest or "replace" in manifest:
        _reject("workspaces and dependency overrides are unsupported")
    cargo_directory = root / ".cargo"
    if any((cargo_directory / name).exists() for name in ("config", "config.toml")):
        _reject("project Cargo configuration is unsupported")

    package = manifest.get("package")
    if not isinstance(package, dict):
        _reject("Cargo.toml has no package table")
    package_name = package.get("name")
    package_version = package.get("version")
    edition = str(package.get("edition", "2015"))
    if not isinstance(package_name, str) or not package_name or package_name == REQWEST_CRATE:
        _reject("the root package name is invalid for this profile")
    if not isinstance(package_version, str) or not package_version:
        _reject("the root package version is missing")
    if edition not in SUPPORTED_EDITIONS:
        _reject("Rust edition must be 2018, 2021, or 2024")
    requirement = _dependency_requirement(manifest)
    _validate_lock(lock, package_name, package_version)

    rust_files = sorted(
        path for path in root.rglob("*.rs") if "target" not in path.relative_to(root).parts
    )
    if not rust_files:
        _reject("no Rust source files were found")
    application_alias = False
    source_text: dict[Path, str] = {}
    for path in rust_files:
        if path.is_symlink():
            _reject("Rust source files must not be symbolic links")
        text = path.read_text(encoding="utf-8")
        source_text[path] = text
        if _EXTERN_ALIAS_PATTERN.search(text):
            application_alias = True
            continue
        if all(re.search(rf"\b{token}\b", text) for token in ("extern", "crate", REQWEST_CRATE)):
            _reject("an ambiguous extern-crate reqwest binding is unsupported")

    occurrences: list[dict[str, Any]] = []
    for path in rust_files:
        text = source_text[path]
        relative = path.relative_to(root).as_posix()
        for match in _CALL_PATTERN.finditer(text):
            start_line, start_column = _position(text, match.start("candidate"))
            end_line, end_column = _position(text, match.end("candidate"))
            if application_alias:
                occurrence_owner = {
                    "package_name": package_name,
                    "package_version": package_version,
                    "package_source": "local-current-crate",
                    "package_checksum": "",
                    "binding": "application-extern-alias",
                }
            else:
                occurrence_owner = {
                    "package_name": REQWEST_PACKAGE,
                    "package_version": REQWEST_VERSION,
                    "package_source": REQWEST_SOURCE,
                    "package_checksum": REQWEST_CHECKSUM,
                    "binding": "absolute-extern-prelude",
                }
            occurrences.append(
                {
                    "path": relative,
                    "start_line": start_line,
                    "start_column": start_column,
                    "end_line": end_line,
                    "end_column": end_column,
                    "crate_name": REQWEST_CRATE,
                    **occurrence_owner,
                    "method": match.group("method"),
                }
            )
    return {
        "edition": edition,
        "manifest_path": "Cargo.toml",
        "lock_path": "Cargo.lock",
        "root_package_name": package_name,
        "root_package_version": package_version,
        "dependency_requirement": requirement,
        "occurrences": occurrences,
    }
