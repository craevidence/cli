"""Fail-closed verification of externally generated semantic evidence."""

from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "craevidence.semantic_evidence.v1"
JAVA_SCHEMA_VERSION = "craevidence.java_semantic_evidence.v1"
CSHARP_SCHEMA_VERSION = "craevidence.csharp_semantic_evidence.v1"
RUST_SCHEMA_VERSION = "craevidence.rust_semantic_evidence.v1"
C_SCHEMA_VERSION = "craevidence.c_semantic_evidence.v2"
CPP_SCHEMA_VERSION = "craevidence.cpp_semantic_evidence.v2"
SUPPORTED_PROFILE = "scip-dotnet-0.2.14-dotnet-8.0.423"
JAVA_SUPPORTED_PROFILE = "jdk-compiler-api-java-symbols-v1"
CSHARP_SUPPORTED_PROFILE = "roslyn-direct-framework-symbols-v1"
RUST_SUPPORTED_PROFILE = "rust-cratesio-absolute-binding-v1"
MAX_ENVELOPE_BYTES = 1024 * 1024
MAX_SCIP_BYTES = 128 * 1024 * 1024
MAX_PROTOBUF_FIELD_BYTES = 32 * 1024 * 1024
MAX_OCCURRENCES = 2_000_000

_PROFILE = {
    "package_sha512": (
        "Ss+ENj4K9k+0tV04asKNzgGcFTJRgO7p92KTHAw+4oVgcpzCiiWDiWHu9RUdzHs2AOzNPL6Pi4AZNMIQFybp2w=="
    ),
    "executable_version": ("0.2.14+3e1f671e65692f517b0d35521fd1951c63939e3c"),
    "commit": "3e1f671e65692f517b0d35521fd1951c63939e3c",
    "image_manifest": ("sha256:e2f26f26169fd10d6f1b426e01c97397717b32e9d5ab4ee4a7d5497ed9403007"),
    "sdk_version": "8.0.423",
    "framework_assembly_version": "8.0.0.0",
}

_INPUT_SUFFIXES = frozenset({".cs", ".csproj", ".sln", ".props", ".targets"})
_INPUT_NAMES = frozenset({"global.json", "packages.lock.json", "nuget.config"})
_IGNORED_PARTS = frozenset(
    {".git", ".gradle", ".hg", ".svn", "bin", "build", "node_modules", "obj", "out", "target"}
)


class SemanticEvidenceError(ValueError):
    """Evidence is absent, malformed, stale, partial, or unsupported."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True)
class SemanticOccurrence:
    path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    symbol: str


@dataclass(frozen=True)
class VerifiedSemanticEvidence:
    language: str
    adapter_profile: str
    source_tree_sha256: str
    build_profile_sha256: str
    occurrences: tuple[SemanticOccurrence, ...]

    def matching_occurrences(
        self,
        *,
        path: str,
        start_line: int,
        start_column: int,
        end_line: int,
        end_column: int,
        symbol: str | None = None,
    ) -> tuple[SemanticOccurrence, ...]:
        normalized = _normalize_relative_path(path)
        return tuple(
            occurrence
            for occurrence in self.occurrences
            if occurrence.path == normalized
            and (symbol is None or occurrence.symbol == symbol)
            and _range_contains(
                start_line,
                start_column,
                end_line,
                end_column,
                occurrence,
            )
        )


def _fail(reason_code: str, detail: str) -> None:
    raise SemanticEvidenceError(reason_code, detail)


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("invalid_envelope", f"{name} must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        _fail(
            "invalid_envelope",
            f"{name} fields differ: missing={missing}, unexpected={unexpected}",
        )


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        _fail("invalid_envelope", f"{name} must be an array")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        _fail("invalid_envelope", f"{name} must be a non-empty string")
    return value


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("invalid_envelope", f"{name} must be an integer")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_bounded(path: Path, limit: int, reason_code: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        _fail(reason_code, f"cannot stat {path.name}: {type(exc).__name__}")
    if size > limit:
        _fail(reason_code, f"{path.name} exceeds the {limit}-byte limit")
    try:
        return path.read_bytes()
    except OSError as exc:
        _fail(reason_code, f"cannot read {path.name}: {type(exc).__name__}")


def _normalize_relative_path(raw: str) -> str:
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        _fail("invalid_path", "evidence paths must be normalized relative paths")
    return path.as_posix()


def _resolve_contained(base: Path, raw: str, *, reason_code: str) -> Path:
    normalized = _normalize_relative_path(raw)
    candidate = base / PurePosixPath(normalized)
    if candidate.is_symlink():
        _fail(reason_code, f"{normalized} must not be a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(base.resolve(strict=True))
    except (OSError, ValueError) as exc:
        _fail(reason_code, f"{normalized} is unavailable or leaves its root: {type(exc).__name__}")
    if not resolved.is_file():
        _fail(reason_code, f"{normalized} is not a regular file")
    return resolved


def _source_inputs(root: Path, language: str) -> tuple[str, ...]:
    if root.is_file():
        if language == "java":
            return (root.name,) if root.suffix.lower() == ".java" else ()
        if language == "csharp-direct":
            return (root.name,) if root.suffix.lower() == ".cs" else ()
        if language == "rust-static":
            return (root.name,) if root.suffix.lower() == ".rs" else ()
        if language == "c-direct":
            return (root.name,) if root.suffix.lower() in {".c", ".h", ".inc", ".inl"} else ()
        if language == "cpp-direct":
            return (
                (root.name,)
                if root.suffix.lower()
                in {".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
                else ()
            )
        return (root.name,) if root.suffix.lower() in _INPUT_SUFFIXES else ()
    selected: list[str] = []
    for candidate in root.rglob("*"):
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            continue
        if _IGNORED_PARTS.intersection(relative.parts[:-1]):
            continue
        if candidate.is_symlink():
            _fail("source_symlink", f"{relative.as_posix()} is a symbolic link")
        if not candidate.is_file():
            continue
        if language == "java":
            selected_input = candidate.suffix.lower() == ".java"
        elif language == "csharp-direct":
            selected_input = candidate.suffix.lower() == ".cs"
        elif language == "rust-static":
            selected_input = candidate.suffix.lower() == ".rs" or candidate.name in {
                "Cargo.toml",
                "Cargo.lock",
                "config",
                "config.toml",
            }
        elif language == "c-direct":
            selected_input = candidate.suffix.lower() in {".c", ".h", ".inc", ".inl"}
        elif language == "cpp-direct":
            selected_input = candidate.suffix.lower() in {
                ".cc",
                ".cpp",
                ".cxx",
                ".h",
                ".hh",
                ".hpp",
                ".hxx",
                ".inc",
                ".inl",
            }
        else:
            selected_input = (
                candidate.suffix.lower() in _INPUT_SUFFIXES
                or candidate.name.lower() in _INPUT_NAMES
            )
        if selected_input:
            selected.append(relative.as_posix())
    return tuple(sorted(selected))


def source_tree_manifest(root: Path, language: str = "csharp") -> tuple[list[dict[str, Any]], str]:
    """Return a deterministic language-input manifest and its digest."""
    resolved_root = root.resolve(strict=True)
    base = resolved_root.parent if resolved_root.is_file() else resolved_root
    records: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for relative in _source_inputs(resolved_root, language):
        candidate = _resolve_contained(base, relative, reason_code="source_unavailable")
        file_digest = _sha256_bytes(candidate.read_bytes())
        mode = stat.S_IMODE(candidate.stat().st_mode)
        record = {"path": relative, "mode": mode, "sha256": file_digest}
        records.append(record)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(mode).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\0")
    return records, digest.hexdigest()


def _validate_source(
    source: dict[str, Any], scan_root: Path, language: str = "csharp"
) -> tuple[str, set[str]]:
    expected_records, expected_digest = source_tree_manifest(scan_root, language)
    supplied_records = _list(source.get("files"), "source.files")
    normalized_records: list[dict[str, Any]] = []
    for index, raw_record in enumerate(supplied_records):
        record = _mapping(raw_record, f"source.files[{index}]")
        normalized_records.append(
            {
                "path": _normalize_relative_path(
                    _string(record.get("path"), f"source.files[{index}].path")
                ),
                "mode": _integer(record.get("mode"), f"source.files[{index}].mode"),
                "sha256": _string(record.get("sha256"), f"source.files[{index}].sha256"),
            }
        )
    if normalized_records != expected_records:
        _fail("stale_source", "source file manifest does not match the scan root")
    supplied_digest = _string(source.get("tree_sha256"), "source.tree_sha256")
    if supplied_digest != expected_digest:
        _fail("stale_source", "source tree digest does not match the scan root")
    return expected_digest, {record["path"] for record in expected_records}


def _validate_adapter(adapter: dict[str, Any]) -> str:
    profile = _string(adapter.get("profile"), "adapter.profile")
    if profile != SUPPORTED_PROFILE:
        _fail("unsupported_adapter", f"unsupported adapter profile {profile}")
    for key, expected in _PROFILE.items():
        if key == "framework_assembly_version":
            continue
        actual = _string(adapter.get(key), f"adapter.{key}")
        if actual != expected:
            _fail("adapter_provenance_mismatch", f"adapter.{key} does not match the pinned profile")
    arguments = _list(adapter.get("arguments"), "adapter.arguments")
    if not arguments or not all(isinstance(value, str) and value for value in arguments):
        _fail("adapter_arguments_missing", "adapter.arguments must contain the full invocation")
    if "--skip-dotnet-restore" not in arguments:
        _fail("adapter_arguments_unsafe", "the pinned adapter must run with --skip-dotnet-restore")
    return profile


def _validate_isolation(isolation: dict[str, Any]) -> None:
    expected = {
        "network": "none",
        "source_read_only": True,
        "root_read_only": True,
        "capabilities_dropped": True,
        "no_new_privileges": True,
        "project_hooks": "contained",
    }
    for key, value in expected.items():
        if isolation.get(key) != value:
            _fail("isolation_not_attested", f"isolation.{key} must equal {value!r}")


def _validate_build(build: dict[str, Any], source_paths: set[str]) -> str:
    profile = _mapping(build.get("profile"), "build.profile")
    configuration = _string(profile.get("configuration"), "build.profile.configuration")
    target_framework = _string(profile.get("target_framework"), "build.profile.target_framework")
    platform = _string(profile.get("platform"), "build.profile.platform")
    constants = _list(profile.get("define_constants"), "build.profile.define_constants")
    if not all(isinstance(value, str) and value for value in constants):
        _fail("invalid_build_profile", "build profile constants must be strings")
    project_paths = [
        _normalize_relative_path(_string(value, "build.profile.project_paths[]"))
        for value in _list(profile.get("project_paths"), "build.profile.project_paths")
    ]
    if not project_paths or len(set(project_paths)) != len(project_paths):
        _fail("invalid_build_profile", "build profile project paths must be unique")
    normalized_profile = {
        "configuration": configuration,
        "target_framework": target_framework,
        "platform": platform,
        "define_constants": constants,
        "project_paths": project_paths,
    }
    computed_profile_digest = _sha256_bytes(
        json.dumps(
            normalized_profile,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    profile_digest = _string(build.get("profile_sha256"), "build.profile_sha256")
    if profile_digest != computed_profile_digest:
        _fail("stale_build_profile", "build profile digest does not match its fields")
    projects = _list(build.get("projects"), "build.projects")
    if not projects:
        _fail("build_missing", "build.projects must not be empty")
    seen: set[str] = set()
    for index, raw_project in enumerate(projects):
        project = _mapping(raw_project, f"build.projects[{index}]")
        path = _normalize_relative_path(
            _string(project.get("path"), f"build.projects[{index}].path")
        )
        if path in seen:
            _fail("build_ambiguous", f"project {path} is duplicated")
        if path not in source_paths:
            _fail("project_not_bound", f"project {path} is absent from the source manifest")
        seen.add(path)
        if _integer(project.get("restore_exit_code"), "restore_exit_code") != 0:
            _fail("restore_failed", f"restore failed for {path}")
        if _integer(project.get("build_exit_code"), "build_exit_code") != 0:
            _fail("build_failed", f"build failed for {path}")
        if _integer(project.get("workspace_failure_count"), "workspace_failure_count") != 0:
            _fail("workspace_failure", f"workspace failures were captured for {path}")
    if seen != set(project_paths):
        _fail("project_set_mismatch", "built projects do not match the build profile")
    return profile_digest


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if offset >= len(data):
            _fail("invalid_scip", "truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    _fail("invalid_scip", "protobuf varint exceeds ten bytes")


def _iter_fields(data: bytes) -> Iterable[tuple[int, int, bytes | int]]:
    offset = 0
    while offset < len(data):
        key, offset = _read_varint(data, offset)
        number = key >> 3
        wire_type = key & 0x07
        if number == 0:
            _fail("invalid_scip", "protobuf field zero is invalid")
        if wire_type == 0:
            value, offset = _read_varint(data, offset)
            yield number, wire_type, value
            continue
        if wire_type == 1:
            end = offset + 8
        elif wire_type == 2:
            length, offset = _read_varint(data, offset)
            if length > MAX_PROTOBUF_FIELD_BYTES:
                _fail("oversized_scip", "protobuf field exceeds the size limit")
            end = offset + length
        elif wire_type == 5:
            end = offset + 4
        else:
            _fail("invalid_scip", f"unsupported protobuf wire type {wire_type}")
        if end > len(data):
            _fail("invalid_scip", "truncated protobuf field")
        yield number, wire_type, data[offset:end]
        offset = end


def _utf8(value: bytes | int, name: str) -> str:
    if not isinstance(value, bytes):
        _fail("invalid_scip", f"{name} has the wrong protobuf wire type")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        _fail("invalid_scip", f"{name} is not valid UTF-8")


def _packed_varints(value: bytes | int) -> list[int]:
    if not isinstance(value, bytes):
        _fail("invalid_scip", "occurrence range has the wrong wire type")
    values: list[int] = []
    offset = 0
    while offset < len(value):
        item, offset = _read_varint(value, offset)
        values.append(item)
    return values


def _typed_range(value: bytes | int, field_count: int) -> list[int]:
    if not isinstance(value, bytes):
        _fail("invalid_scip", "typed occurrence range has the wrong wire type")
    fields: dict[int, int] = {}
    for number, wire_type, field in _iter_fields(value):
        if wire_type != 0 or not isinstance(field, int) or number not in range(1, field_count + 1):
            _fail("invalid_scip", "typed occurrence range has an invalid field")
        if number in fields:
            _fail("invalid_scip", "typed occurrence range has a duplicate field")
        fields[number] = field
    if set(fields) != set(range(1, field_count + 1)):
        _fail("invalid_scip", "typed occurrence range is incomplete")
    return [fields[number] for number in range(1, field_count + 1)]


def _decode_occurrence(value: bytes | int, path: str) -> SemanticOccurrence | None:
    if not isinstance(value, bytes):
        _fail("invalid_scip", "occurrence has the wrong wire type")
    legacy_range: list[int] = []
    typed_range: list[int] | None = None
    symbol = ""
    for number, wire_type, field in _iter_fields(value):
        if number == 1 and wire_type == 2:
            if legacy_range:
                _fail("invalid_scip", "occurrence has duplicate packed ranges")
            legacy_range.extend(_packed_varints(field))
        elif number == 1 and wire_type == 0:
            if not isinstance(field, int):
                _fail("invalid_scip", "occurrence range has an invalid value")
            legacy_range.append(field)
        elif number == 2 and wire_type == 2:
            if symbol:
                _fail("invalid_scip", "occurrence has duplicate symbols")
            symbol = _utf8(field, "occurrence symbol")
        elif number == 8 and wire_type == 2:
            if typed_range is not None:
                _fail("invalid_scip", "occurrence has multiple typed ranges")
            typed_range = _typed_range(field, 3)
        elif number == 9 and wire_type == 2:
            if typed_range is not None:
                _fail("invalid_scip", "occurrence has multiple typed ranges")
            typed_range = _typed_range(field, 4)
    if typed_range is not None and legacy_range and typed_range != legacy_range:
        _fail("ambiguous_scip_range", "typed and legacy occurrence ranges disagree")
    raw_range = typed_range or legacy_range
    if not raw_range or not symbol:
        return None
    if len(raw_range) == 3:
        start_line, start_column, end_column = raw_range
        end_line = start_line
    elif len(raw_range) == 4:
        start_line, start_column, end_line, end_column = raw_range
    else:
        _fail("unsupported_scip_range", "SCIP occurrence range must have three or four values")
    if (end_line, end_column) < (start_line, start_column):
        _fail("invalid_scip", "SCIP occurrence range is reversed")
    return SemanticOccurrence(
        path=path,
        start_line=start_line + 1,
        start_column=start_column + 1,
        end_line=end_line + 1,
        end_column=end_column + 1,
        symbol=symbol,
    )


def _decode_document(value: bytes | int) -> tuple[str, list[SemanticOccurrence]]:
    if not isinstance(value, bytes):
        _fail("invalid_scip", "document has the wrong wire type")
    path = ""
    language = ""
    position_encoding: int | None = None
    occurrence_payloads: list[bytes | int] = []
    for number, wire_type, field in _iter_fields(value):
        if number == 1 and wire_type == 2:
            if path:
                _fail("invalid_scip", "document has duplicate paths")
            path = _normalize_relative_path(_utf8(field, "document path"))
        elif number == 2 and wire_type == 2:
            occurrence_payloads.append(field)
        elif number == 4 and wire_type == 2:
            language = _utf8(field, "document language")
        elif number == 6 and wire_type == 0:
            if not isinstance(field, int):
                _fail("invalid_scip", "document position encoding is invalid")
            position_encoding = field
    if not path or language != "C#":
        _fail("invalid_scip", "SCIP document must declare a path and C# language")
    if position_encoding not in {None, 1}:
        _fail("unsupported_position_encoding", "SCIP document is not UTF-8 encoded")
    occurrences = [
        decoded
        for payload in occurrence_payloads
        if (decoded := _decode_occurrence(payload, path)) is not None
    ]
    return path, occurrences


def _decode_metadata(value: bytes | int) -> None:
    if not isinstance(value, bytes):
        _fail("invalid_scip", "metadata has the wrong wire type")
    text_encoding: int | None = None
    for number, wire_type, field in _iter_fields(value):
        if number == 4 and wire_type == 0:
            if not isinstance(field, int):
                _fail("invalid_scip", "metadata encoding is invalid")
            text_encoding = field
    if text_encoding != 1:
        _fail("unsupported_position_encoding", "SCIP metadata must declare UTF-8 encoding")


def _decode_scip(data: bytes) -> tuple[SemanticOccurrence, ...]:
    metadata_count = 0
    documents: set[str] = set()
    occurrences: list[SemanticOccurrence] = []
    for number, wire_type, value in _iter_fields(data):
        if number == 1 and wire_type == 2:
            metadata_count += 1
            _decode_metadata(value)
        elif number == 2 and wire_type == 2:
            path, decoded = _decode_document(value)
            if path in documents:
                _fail("ambiguous_scip_document", f"SCIP document {path} is duplicated")
            documents.add(path)
            occurrences.extend(decoded)
            if len(occurrences) > MAX_OCCURRENCES:
                _fail("oversized_scip", "SCIP occurrence count exceeds the limit")
    if metadata_count != 1 or not documents:
        _fail("invalid_scip", "SCIP index requires one metadata record and at least one document")
    return tuple(occurrences)


def _java_symbol(record: dict[str, Any]) -> str:
    fields = (
        "module",
        "package",
        "qualified_name",
        "binary_name",
        "nesting",
        "method",
        "first_parameter",
    )
    values: list[str] = []
    for field in fields:
        value = record.get(field)
        if not isinstance(value, str) or (field not in {"module", "package"} and not value):
            _fail("invalid_envelope", f"analysis.occurrences[].{field} is invalid")
        values.append(value)
    return "jdk-symbol " + " ".join(values)


def _load_java_evidence(
    envelope: dict[str, Any], envelope_path: Path, scan_root: Path
) -> VerifiedSemanticEvidence:
    _exact_keys(
        envelope,
        {"schema_version", "language", "adapter", "isolation", "source", "analysis"},
        "envelope",
    )
    if envelope.get("language") != "java":
        _fail("unsupported_language", "Java semantic evidence language must be java")
    adapter = _mapping(envelope.get("adapter"), "adapter")
    _exact_keys(
        adapter,
        {
            "profile",
            "analyzer_sha256",
            "java_version",
            "java_executable_sha256",
            "arguments",
        },
        "adapter",
    )
    profile = _string(adapter.get("profile"), "adapter.profile")
    if profile != JAVA_SUPPORTED_PROFILE:
        _fail("unsupported_adapter", f"unsupported adapter profile {profile}")
    analyzer = Path(__file__).with_name("java_symbol_analyzer.java")
    expected_analyzer = _sha256_bytes(analyzer.read_bytes())
    if _string(adapter.get("analyzer_sha256"), "adapter.analyzer_sha256") != expected_analyzer:
        _fail("adapter_provenance_mismatch", "the Java analyzer digest does not match")
    _string(adapter.get("java_version"), "adapter.java_version")
    _string(adapter.get("java_executable_sha256"), "adapter.java_executable_sha256")
    arguments = _list(adapter.get("arguments"), "adapter.arguments")
    if len(arguments) != 3 or not all(isinstance(value, str) and value for value in arguments):
        _fail("adapter_arguments_missing", "adapter.arguments must contain the invocation")
    isolation = _mapping(envelope.get("isolation"), "isolation")
    expected_isolation = {
        "build_scripts_executed": False,
        "annotation_processing": False,
        "class_path": "empty",
        "source_path": "empty",
        "implicit_compilation": False,
    }
    _exact_keys(isolation, set(expected_isolation), "isolation")
    for key, value in expected_isolation.items():
        if isolation.get(key) != value:
            _fail("isolation_not_attested", f"isolation.{key} must equal {value!r}")
    source = _mapping(envelope.get("source"), "source")
    _exact_keys(source, {"tree_sha256", "files"}, "source")
    for index, raw_record in enumerate(_list(source.get("files"), "source.files")):
        _exact_keys(
            _mapping(raw_record, f"source.files[{index}]"),
            {"path", "mode", "sha256"},
            f"source.files[{index}]",
        )
    source_digest, source_paths = _validate_source(source, scan_root, "java")
    analysis = _mapping(envelope.get("analysis"), "analysis")
    _exact_keys(
        analysis,
        {
            "compiler_exit_code",
            "error_count",
            "compiler_options",
            "profile_sha256",
            "occurrences",
        },
        "analysis",
    )
    if _integer(analysis.get("compiler_exit_code"), "analysis.compiler_exit_code") != 0:
        _fail("compiler_failed", "the Java compiler analysis did not succeed")
    if _integer(analysis.get("error_count"), "analysis.error_count") != 0:
        _fail("compiler_diagnostics", "the Java compiler reported errors")
    compiler_options = _list(analysis.get("compiler_options"), "analysis.compiler_options")
    expected_options = [
        "-proc:none",
        "-implicit:none",
        "empty-class-path",
        "empty-source-path",
    ]
    if compiler_options != expected_options:
        _fail("analysis_profile_mismatch", "the Java compiler options do not match")
    computed_profile = _sha256_bytes(
        json.dumps(compiler_options, separators=(",", ":")).encode("utf-8")
    )
    supplied_profile = _string(analysis.get("profile_sha256"), "analysis.profile_sha256")
    if supplied_profile != computed_profile:
        _fail("analysis_profile_mismatch", "the Java analysis profile digest does not match")
    occurrence_records = _list(analysis.get("occurrences"), "analysis.occurrences")
    if len(occurrence_records) > MAX_OCCURRENCES:
        _fail("invalid_envelope", "Java occurrence count exceeds the limit")
    occurrences: list[SemanticOccurrence] = []
    for index, raw in enumerate(occurrence_records):
        record = _mapping(raw, f"analysis.occurrences[{index}]")
        _exact_keys(
            record,
            {
                "path",
                "start_line",
                "start_column",
                "end_line",
                "end_column",
                "module",
                "package",
                "qualified_name",
                "binary_name",
                "nesting",
                "method",
                "first_parameter",
            },
            f"analysis.occurrences[{index}]",
        )
        path = _normalize_relative_path(
            _string(record.get("path"), f"analysis.occurrences[{index}].path")
        )
        if path not in source_paths:
            _fail("occurrence_not_bound", f"Java occurrence path {path} is not a source input")
        start_line = _integer(record.get("start_line"), "start_line")
        start_column = _integer(record.get("start_column"), "start_column")
        end_line = _integer(record.get("end_line"), "end_line")
        end_column = _integer(record.get("end_column"), "end_column")
        if min(start_line, start_column, end_line, end_column) < 1 or (
            end_line,
            end_column,
        ) < (start_line, start_column):
            _fail("invalid_range", "Java semantic occurrence range is invalid")
        occurrences.append(
            SemanticOccurrence(
                path=path,
                start_line=start_line,
                start_column=start_column,
                end_line=end_line,
                end_column=end_column,
                symbol=_java_symbol(record),
            )
        )
    return VerifiedSemanticEvidence(
        language="java",
        adapter_profile=profile,
        source_tree_sha256=source_digest,
        build_profile_sha256=supplied_profile,
        occurrences=tuple(occurrences),
    )


_CSHARP_OCCURRENCE_FIELDS = {
    "path",
    "start_line",
    "start_column",
    "end_line",
    "end_column",
    "left_property",
    "left_type",
    "left_assembly",
    "left_assembly_version",
    "left_public_key_token",
    "right_property",
    "right_type",
    "right_assembly",
    "right_assembly_version",
    "right_public_key_token",
}


def _csharp_symbol(record: dict[str, Any]) -> str:
    fields = (
        "left_assembly",
        "left_assembly_version",
        "left_public_key_token",
        "left_type",
        "left_property",
        "right_assembly",
        "right_assembly_version",
        "right_public_key_token",
        "right_type",
        "right_property",
    )
    values = []
    for field in fields:
        value = record.get(field)
        allow_empty = field in {
            "left_public_key_token",
            "right_public_key_token",
        }
        if not isinstance(value, str) or (not value and not allow_empty):
            _fail("invalid_envelope", f"analysis.occurrences[].{field} is invalid")
        values.append(value)
    return "dotnet-property-assignment " + " ".join(values)


def _load_csharp_direct_evidence(
    envelope: dict[str, Any], scan_root: Path
) -> VerifiedSemanticEvidence:
    _exact_keys(
        envelope,
        {"schema_version", "language", "adapter", "isolation", "source", "analysis"},
        "envelope",
    )
    if envelope.get("language") != "csharp":
        _fail("unsupported_language", "C# semantic evidence language must be csharp")
    adapter = _mapping(envelope.get("adapter"), "adapter")
    adapter_fields = {
        "profile",
        "analyzer_sha256",
        "dotnet_executable_sha256",
        "sdk_version",
        "runtime_version",
        "roslyn_version",
        "reference_pack_version",
        "reference_pack_sha256",
    }
    _exact_keys(adapter, adapter_fields, "adapter")
    profile = _string(adapter.get("profile"), "adapter.profile")
    if profile != CSHARP_SUPPORTED_PROFILE:
        _fail("unsupported_adapter", f"unsupported adapter profile {profile}")
    analyzer = Path(__file__).with_name("csharp_symbol_analyzer.cs")
    supplied_analyzer = _string(adapter.get("analyzer_sha256"), "adapter.analyzer_sha256")
    if supplied_analyzer != _sha256_bytes(analyzer.read_bytes()):
        _fail("adapter_provenance_mismatch", "the C# analyzer digest does not match")
    if _string(adapter.get("sdk_version"), "adapter.sdk_version") != "8.0.423":
        _fail("adapter_provenance_mismatch", "the C# SDK version does not match")
    if _string(adapter.get("reference_pack_version"), "adapter.reference_pack_version") != "8.0.29":
        _fail("adapter_provenance_mismatch", "the C# reference pack version does not match")
    identity_fields = adapter_fields - {
        "profile",
        "analyzer_sha256",
        "sdk_version",
        "reference_pack_version",
    }
    for field in identity_fields:
        _string(adapter.get(field), f"adapter.{field}")
    isolation = _mapping(envelope.get("isolation"), "isolation")
    expected_isolation = {
        "build_scripts_executed": False,
        "projects_loaded": False,
        "restore_executed": False,
        "msbuild_executed": False,
        "generators_loaded": False,
        "target_code_executed": False,
        "reference_source": "trusted-framework-pack-only",
    }
    _exact_keys(isolation, set(expected_isolation), "isolation")
    for field, expected in expected_isolation.items():
        if isolation.get(field) != expected:
            _fail("isolation_not_attested", f"isolation.{field} must equal {expected!r}")
    source = _mapping(envelope.get("source"), "source")
    _exact_keys(source, {"tree_sha256", "files"}, "source")
    for index, raw_record in enumerate(_list(source.get("files"), "source.files")):
        _exact_keys(
            _mapping(raw_record, f"source.files[{index}]"),
            {"path", "mode", "sha256"},
            f"source.files[{index}]",
        )
    source_digest, source_paths = _validate_source(source, scan_root, "csharp-direct")
    analysis = _mapping(envelope.get("analysis"), "analysis")
    _exact_keys(
        analysis,
        {"compiler_exit_code", "error_count", "compiler_options", "profile_sha256", "occurrences"},
        "analysis",
    )
    if _integer(analysis.get("compiler_exit_code"), "analysis.compiler_exit_code") != 0:
        _fail("compiler_failed", "the C# compiler analysis did not succeed")
    if _integer(analysis.get("error_count"), "analysis.error_count") != 0:
        _fail("compiler_diagnostics", "the C# compiler reported errors")
    expected_options = [
        "/noconfig",
        "/nostdlib+",
        "/target:exe",
        "framework-reference-pack-only",
        "no-project-inputs",
        "sanitized-dotnet-environment",
        "invariant-globalization",
    ]
    options = _list(analysis.get("compiler_options"), "analysis.compiler_options")
    if options != expected_options:
        _fail("analysis_profile_mismatch", "the C# compiler options do not match")
    profile_digest = _sha256_bytes(json.dumps(options, separators=(",", ":")).encode("utf-8"))
    if _string(analysis.get("profile_sha256"), "analysis.profile_sha256") != profile_digest:
        _fail("analysis_profile_mismatch", "the C# analysis profile digest does not match")
    records = _list(analysis.get("occurrences"), "analysis.occurrences")
    if len(records) > MAX_OCCURRENCES:
        _fail("invalid_envelope", "C# occurrence count exceeds the limit")
    occurrences = []
    for index, raw in enumerate(records):
        record = _mapping(raw, f"analysis.occurrences[{index}]")
        _exact_keys(record, _CSHARP_OCCURRENCE_FIELDS, f"analysis.occurrences[{index}]")
        path = _normalize_relative_path(_string(record.get("path"), "occurrence.path"))
        if path not in source_paths:
            _fail("occurrence_not_bound", f"C# occurrence path {path} is not a source input")
        start_line = _integer(record.get("start_line"), "start_line")
        start_column = _integer(record.get("start_column"), "start_column")
        end_line = _integer(record.get("end_line"), "end_line")
        end_column = _integer(record.get("end_column"), "end_column")
        if min(start_line, start_column, end_line, end_column) < 1 or (end_line, end_column) < (
            start_line,
            start_column,
        ):
            _fail("invalid_range", "C# semantic occurrence range is invalid")
        occurrences.append(
            SemanticOccurrence(
                path=path,
                start_line=start_line,
                start_column=start_column,
                end_line=end_line,
                end_column=end_column,
                symbol=_csharp_symbol(record),
            )
        )
    return VerifiedSemanticEvidence(
        language="csharp",
        adapter_profile=profile,
        source_tree_sha256=source_digest,
        build_profile_sha256=profile_digest,
        occurrences=tuple(occurrences),
    )


_RUST_OCCURRENCE_FIELDS = {
    "path",
    "start_line",
    "start_column",
    "end_line",
    "end_column",
    "crate_name",
    "package_name",
    "package_version",
    "package_source",
    "package_checksum",
    "binding",
    "method",
}


def _load_rust_evidence(
    envelope: dict[str, Any], scan_root: Path
) -> VerifiedSemanticEvidence:
    from cra_evidence_cli.local.rust_semantic_analyzer import (
        REQWEST_CHECKSUM,
        REQWEST_CRATE,
        REQWEST_PACKAGE,
        REQWEST_SOURCE,
        REQWEST_VERSION,
        SUPPORTED_EDITIONS,
        SUPPORTED_REQUIREMENTS,
        RustAnalysisError,
        validate_rust_ancestor_context,
    )

    _exact_keys(
        envelope,
        {"schema_version", "language", "adapter", "isolation", "source", "analysis"},
        "envelope",
    )
    if envelope.get("language") != "rust":
        _fail("unsupported_language", "Rust semantic evidence language must be rust")
    try:
        validate_rust_ancestor_context(scan_root)
    except (OSError, RustAnalysisError) as exc:
        _fail("analysis_context_mismatch", str(exc))
    adapter = _mapping(envelope.get("adapter"), "adapter")
    adapter_fields = {
        "profile",
        "analyzer_sha256",
        "package_name",
        "package_version",
        "package_source",
        "package_checksum",
    }
    _exact_keys(adapter, adapter_fields, "adapter")
    profile = _string(adapter.get("profile"), "adapter.profile")
    if profile != RUST_SUPPORTED_PROFILE:
        _fail("unsupported_adapter", f"unsupported adapter profile {profile}")
    analyzer = Path(__file__).with_name("rust_semantic_analyzer.py")
    supplied_analyzer = _string(adapter.get("analyzer_sha256"), "adapter.analyzer_sha256")
    if supplied_analyzer != _sha256_bytes(analyzer.read_bytes()):
        _fail("adapter_provenance_mismatch", "the Rust analyzer digest does not match")
    expected_package = {
        "package_name": REQWEST_PACKAGE,
        "package_version": REQWEST_VERSION,
        "package_source": REQWEST_SOURCE,
        "package_checksum": REQWEST_CHECKSUM,
    }
    for field, expected in expected_package.items():
        if _string(adapter.get(field), f"adapter.{field}") != expected:
            _fail("adapter_provenance_mismatch", f"adapter.{field} does not match")

    isolation = _mapping(envelope.get("isolation"), "isolation")
    expected_isolation = {
        "cargo_executed": False,
        "compiler_executed": False,
        "build_scripts_executed": False,
        "proc_macros_executed": False,
        "target_code_executed": False,
        "network_required": False,
        "provenance_source": "static-manifest-lock-and-pinned-checksum",
    }
    _exact_keys(isolation, set(expected_isolation), "isolation")
    for field, expected in expected_isolation.items():
        if isolation.get(field) != expected:
            _fail("isolation_not_attested", f"isolation.{field} must equal {expected!r}")

    source = _mapping(envelope.get("source"), "source")
    _exact_keys(source, {"tree_sha256", "files"}, "source")
    for index, raw_record in enumerate(_list(source.get("files"), "source.files")):
        _exact_keys(
            _mapping(raw_record, f"source.files[{index}]"),
            {"path", "mode", "sha256"},
            f"source.files[{index}]",
        )
    source_digest, source_paths = _validate_source(source, scan_root, "rust-static")

    analysis = _mapping(envelope.get("analysis"), "analysis")
    _exact_keys(analysis, {"profile", "profile_sha256", "occurrences"}, "analysis")
    analysis_profile = _mapping(analysis.get("profile"), "analysis.profile")
    profile_fields = {
        "edition",
        "manifest_path",
        "lock_path",
        "root_package_name",
        "root_package_version",
        "dependency_requirement",
    }
    _exact_keys(analysis_profile, profile_fields, "analysis.profile")
    edition = _string(analysis_profile.get("edition"), "analysis.profile.edition")
    if edition not in SUPPORTED_EDITIONS:
        _fail("analysis_profile_mismatch", "the Rust edition is unsupported")
    if _string(analysis_profile.get("manifest_path"), "manifest_path") != "Cargo.toml":
        _fail("analysis_profile_mismatch", "the Rust manifest path is unsupported")
    if _string(analysis_profile.get("lock_path"), "lock_path") != "Cargo.lock":
        _fail("analysis_profile_mismatch", "the Rust lock path is unsupported")
    root_package_name = _string(
        analysis_profile.get("root_package_name"), "root_package_name"
    )
    root_package_version = _string(
        analysis_profile.get("root_package_version"), "root_package_version"
    )
    requirement = _string(
        analysis_profile.get("dependency_requirement"), "dependency_requirement"
    )
    if requirement not in SUPPORTED_REQUIREMENTS:
        _fail("analysis_profile_mismatch", "the Rust dependency requirement is unsupported")
    profile_digest = _sha256_bytes(
        json.dumps(analysis_profile, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if _string(analysis.get("profile_sha256"), "analysis.profile_sha256") != profile_digest:
        _fail("analysis_profile_mismatch", "the Rust profile digest does not match")

    records = _list(analysis.get("occurrences"), "analysis.occurrences")
    if len(records) > MAX_OCCURRENCES:
        _fail("invalid_envelope", "Rust occurrence count exceeds the limit")
    occurrences = []
    for index, raw in enumerate(records):
        record = _mapping(raw, f"analysis.occurrences[{index}]")
        _exact_keys(record, _RUST_OCCURRENCE_FIELDS, f"analysis.occurrences[{index}]")
        path = _normalize_relative_path(_string(record.get("path"), "occurrence.path"))
        if path not in source_paths or not path.endswith(".rs"):
            _fail("occurrence_not_bound", f"Rust occurrence path {path} is not a source input")
        start_line = _integer(record.get("start_line"), "start_line")
        start_column = _integer(record.get("start_column"), "start_column")
        end_line = _integer(record.get("end_line"), "end_line")
        end_column = _integer(record.get("end_column"), "end_column")
        if min(start_line, start_column, end_line, end_column) < 1 or (
            end_line,
            end_column,
        ) < (start_line, start_column):
            _fail("invalid_range", "Rust semantic occurrence range is invalid")
        if _string(record.get("crate_name"), "occurrence.crate_name") != REQWEST_CRATE:
            _fail("occurrence_provenance_mismatch", "occurrence.crate_name does not match")
        binding = _string(record.get("binding"), "occurrence.binding")
        if binding == "absolute-extern-prelude":
            for field, expected in expected_package.items():
                if _string(record.get(field), f"occurrence.{field}") != expected:
                    _fail(
                        "occurrence_provenance_mismatch",
                        f"occurrence.{field} does not match",
                    )
            symbol = expected_symbol("rust.cratesio-reqwest-invalid-certs")
        elif binding == "application-extern-alias":
            application_owner = {
                "package_name": root_package_name,
                "package_version": root_package_version,
                "package_source": "local-current-crate",
                "package_checksum": "",
            }
            for field, expected in application_owner.items():
                value = record.get(field)
                if not isinstance(value, str) or value != expected:
                    _fail(
                        "occurrence_provenance_mismatch",
                        f"occurrence.{field} does not match",
                    )
            symbol = (
                f"rust-application-binding {root_package_name} "
                f"{root_package_version} reqwest"
            )
        else:
            _fail("occurrence_provenance_mismatch", "the Rust binding is unsupported")
        method = _string(record.get("method"), "occurrence.method")
        if method not in {
            "danger_accept_invalid_certs",
            "danger_accept_invalid_hostnames",
        }:
            _fail("occurrence_provenance_mismatch", "the Rust method is unsupported")
        occurrences.append(
            SemanticOccurrence(
                path=path,
                start_line=start_line,
                start_column=start_column,
                end_line=end_line,
                end_column=end_column,
                symbol=symbol,
            )
        )
    return VerifiedSemanticEvidence(
        language="rust",
        adapter_profile=profile,
        source_tree_sha256=source_digest,
        build_profile_sha256=profile_digest,
        occurrences=tuple(occurrences),
    )


_C_OCCURRENCE_BASE_FIELDS = {
    "path",
    "start_line",
    "start_column",
    "end_line",
    "end_column",
    "classification",
}
_C_ARRAY_OCCURRENCE_FIELDS = _C_OCCURRENCE_BASE_FIELDS | {
    "index",
}
_C_FORMAT_OCCURRENCE_FIELDS = _C_OCCURRENCE_BASE_FIELDS | {
    "callee",
    "parameter",
}


def _load_c_family_evidence(
    envelope: dict[str, Any], scan_root: Path, language: str
) -> VerifiedSemanticEvidence:
    from cra_evidence_cli.local.c_semantic_analyzer import inspect_c_frontend

    _exact_keys(
        envelope,
        {"schema_version", "language", "adapter", "isolation", "source", "analysis"},
        "envelope",
    )
    if envelope.get("language") != language:
        _fail(
            "unsupported_language",
            f"{language} semantic evidence language must be {language}",
        )
    adapter = _mapping(envelope.get("adapter"), "adapter")
    adapter_fields = {
        "profile",
        "analyzer_sha256",
        "library_path",
        "library_sha256",
        "library_version",
        "resource_headers_sha256",
    }
    _exact_keys(adapter, adapter_fields, "adapter")
    profile = _string(adapter.get("profile"), "adapter.profile")
    analyzer = Path(__file__).with_name("c_semantic_analyzer.py")
    if _string(adapter.get("analyzer_sha256"), "adapter.analyzer_sha256") != (
        _sha256_bytes(analyzer.read_bytes())
    ):
        _fail("adapter_provenance_mismatch", "the C analyzer digest does not match")
    try:
        frontend = inspect_c_frontend(language)
    except (OSError, ValueError) as exc:
        _fail("adapter_provenance_mismatch", f"supported libclang is unavailable: {exc}")
    if profile != frontend["profile"]:
        _fail("unsupported_adapter", f"unsupported adapter profile {profile}")
    for field in (
        "library_path",
        "library_sha256",
        "library_version",
        "resource_headers_sha256",
    ):
        supplied = _string(adapter.get(field), f"adapter.{field}")
        if supplied != frontend[field]:
            _fail(
                "adapter_provenance_mismatch",
                f"adapter.{field} does not match the active frontend",
            )

    isolation = _mapping(envelope.get("isolation"), "isolation")
    expected_isolation = {
        "build_system_executed": False,
        "compiler_plugins_loaded": False,
        "linker_executed": False,
        "target_code_executed": False,
        "network_required": False,
        "analysis_mode": "libclang-frontend-only",
    }
    _exact_keys(isolation, set(expected_isolation), "isolation")
    for field, expected in expected_isolation.items():
        if isolation.get(field) != expected:
            _fail("isolation_not_attested", f"isolation.{field} must equal {expected!r}")

    source = _mapping(envelope.get("source"), "source")
    _exact_keys(source, {"tree_sha256", "files"}, "source")
    for index, raw_record in enumerate(_list(source.get("files"), "source.files")):
        _exact_keys(
            _mapping(raw_record, f"source.files[{index}]"),
            {"path", "mode", "sha256"},
            f"source.files[{index}]",
        )
    source_profile = "c-direct" if language == "c" else "cpp-direct"
    source_digest, source_paths = _validate_source(source, scan_root, source_profile)

    analysis = _mapping(envelope.get("analysis"), "analysis")
    _exact_keys(analysis, {"compiler_options", "profile_sha256", "occurrences"}, "analysis")
    options = _list(analysis.get("compiler_options"), "analysis.compiler_options")
    expected_arguments = frontend["compiler_options"]
    if options != list(expected_arguments):
        _fail(
            "analysis_profile_mismatch",
            f"the {language} compiler options do not match",
        )
    profile_digest = _sha256_bytes(
        json.dumps(options, separators=(",", ":")).encode("utf-8")
    )
    if _string(analysis.get("profile_sha256"), "analysis.profile_sha256") != profile_digest:
        _fail("analysis_profile_mismatch", "the C profile digest does not match")

    records = _list(analysis.get("occurrences"), "analysis.occurrences")
    if len(records) > MAX_OCCURRENCES:
        _fail("invalid_envelope", "C occurrence count exceeds the limit")
    occurrences = []
    for index, raw in enumerate(records):
        record = _mapping(raw, f"analysis.occurrences[{index}]")
        classification = _string(record.get("classification"), "occurrence.classification")
        if classification in {
            "fixed-array-out-of-bounds-write",
            "not-compiler-attested",
        }:
            occurrence_fields = _C_ARRAY_OCCURRENCE_FIELDS
        elif classification in {
            "system-printf-main-argv-format",
            "printf-main-argv-not-system-bound",
            "system-shell-main-argv-command",
            "system-main-argv-not-system-bound",
        }:
            occurrence_fields = _C_FORMAT_OCCURRENCE_FIELDS
        else:
            _fail("occurrence_provenance_mismatch", "the C classification is unsupported")
        _exact_keys(record, occurrence_fields, f"analysis.occurrences[{index}]")
        path = _normalize_relative_path(_string(record.get("path"), "occurrence.path"))
        source_suffixes = (".c",) if language == "c" else (".cc", ".cpp", ".cxx")
        if path not in source_paths or not path.endswith(source_suffixes):
            _fail(
                "occurrence_not_bound",
                f"{language} occurrence path {path} is not a source input",
            )
        start_line = _integer(record.get("start_line"), "start_line")
        start_column = _integer(record.get("start_column"), "start_column")
        end_line = _integer(record.get("end_line"), "end_line")
        end_column = _integer(record.get("end_column"), "end_column")
        if min(start_line, start_column, end_line, end_column) < 1 or (
            end_line,
            end_column,
        ) < (start_line, start_column):
            _fail("invalid_range", "C semantic occurrence range is invalid")
        if classification == "fixed-array-out-of-bounds-write":
            if _integer(record.get("index"), "occurrence.index") < 0:
                _fail("invalid_range", "the C array index must not be negative")
            policy = (
                "c.fixed-array-literal-oob-write"
                if language == "c"
                else "cpp.fixed-array-literal-oob-write"
            )
            symbol = expected_symbol(policy)
        elif classification == "not-compiler-attested":
            if _integer(record.get("index"), "occurrence.index") < 0:
                _fail("invalid_range", "the C array index must not be negative")
            frontend = "c17" if language == "c" else "cpp17"
            symbol = f"clang-{frontend} not-compiler-attested"
        elif classification == "system-printf-main-argv-format":
            if _string(record.get("callee"), "occurrence.callee") != "printf":
                _fail("occurrence_provenance_mismatch", "the C callee is unsupported")
            _string(record.get("parameter"), "occurrence.parameter")
            policy = (
                "c.printf-main-argv-format"
                if language == "c"
                else "cpp.printf-main-argv-format"
            )
            symbol = expected_symbol(policy)
        elif classification == "printf-main-argv-not-system-bound":
            if _string(record.get("callee"), "occurrence.callee") != "printf":
                _fail("occurrence_provenance_mismatch", "the C callee is unsupported")
            _string(record.get("parameter"), "occurrence.parameter")
            frontend = "c17" if language == "c" else "cpp17"
            symbol = f"clang-{frontend} printf-main-argv-not-system-bound"
        elif classification == "system-shell-main-argv-command":
            if _string(record.get("callee"), "occurrence.callee") != "system":
                _fail("occurrence_provenance_mismatch", "the C callee is unsupported")
            _string(record.get("parameter"), "occurrence.parameter")
            policy = (
                "c.system-main-argv-command"
                if language == "c"
                else "cpp.system-main-argv-command"
            )
            symbol = expected_symbol(policy)
        elif classification == "system-main-argv-not-system-bound":
            if _string(record.get("callee"), "occurrence.callee") != "system":
                _fail("occurrence_provenance_mismatch", "the C callee is unsupported")
            _string(record.get("parameter"), "occurrence.parameter")
            frontend = "c17" if language == "c" else "cpp17"
            symbol = f"clang-{frontend} system-main-argv-not-system-bound"
        else:
            _fail("occurrence_provenance_mismatch", "the C classification is unsupported")
        occurrences.append(
            SemanticOccurrence(
                path=path,
                start_line=start_line,
                start_column=start_column,
                end_line=end_line,
                end_column=end_column,
                symbol=symbol,
            )
        )
    return VerifiedSemanticEvidence(
        language=language,
        adapter_profile=profile,
        source_tree_sha256=source_digest,
        build_profile_sha256=profile_digest,
        occurrences=tuple(occurrences),
    )


def load_semantic_evidence(envelope_path: Path, scan_root: Path) -> VerifiedSemanticEvidence:
    """Load and validate one supported semantic evidence envelope."""
    raw = _read_bounded(envelope_path, MAX_ENVELOPE_BYTES, "invalid_envelope")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("invalid_envelope", "semantic evidence is not valid UTF-8 JSON")
    envelope = _mapping(document, "envelope")
    if envelope.get("schema_version") == JAVA_SCHEMA_VERSION:
        return _load_java_evidence(envelope, envelope_path, scan_root)
    if envelope.get("schema_version") == CSHARP_SCHEMA_VERSION:
        return _load_csharp_direct_evidence(envelope, scan_root)
    if envelope.get("schema_version") == RUST_SCHEMA_VERSION:
        return _load_rust_evidence(envelope, scan_root)
    if envelope.get("schema_version") == C_SCHEMA_VERSION:
        return _load_c_family_evidence(envelope, scan_root, "c")
    if envelope.get("schema_version") == CPP_SCHEMA_VERSION:
        return _load_c_family_evidence(envelope, scan_root, "cpp")
    if envelope.get("schema_version") != SCHEMA_VERSION:
        _fail("unsupported_schema", "semantic evidence schema version is unsupported")
    if envelope.get("language") != "csharp":
        _fail("unsupported_language", "semantic evidence language must be csharp")

    adapter_profile = _validate_adapter(_mapping(envelope.get("adapter"), "adapter"))
    _validate_isolation(_mapping(envelope.get("isolation"), "isolation"))
    source_digest, source_paths = _validate_source(
        _mapping(envelope.get("source"), "source"), scan_root
    )
    build_digest = _validate_build(_mapping(envelope.get("build"), "build"), source_paths)

    index_records = _list(envelope.get("indexes"), "indexes")
    if not index_records:
        _fail("index_missing", "indexes must not be empty")
    evidence_root = envelope_path.resolve(strict=True).parent
    occurrences: list[SemanticOccurrence] = []
    document_paths: set[str] = set()
    for index, raw_record in enumerate(index_records):
        record = _mapping(raw_record, f"indexes[{index}]")
        index_path = _resolve_contained(
            evidence_root,
            _string(record.get("path"), f"indexes[{index}].path"),
            reason_code="index_unavailable",
        )
        index_bytes = _read_bounded(index_path, MAX_SCIP_BYTES, "oversized_scip")
        if _sha256_bytes(index_bytes) != _string(record.get("sha256"), f"indexes[{index}].sha256"):
            _fail("stale_index", f"{index_path.name} digest does not match")
        decoded = _decode_scip(index_bytes)
        paths = {item.path for item in decoded}
        duplicate_paths = document_paths.intersection(paths)
        if duplicate_paths:
            _fail("ambiguous_scip_document", "a source document appears in multiple indexes")
        document_paths.update(paths)
        occurrences.extend(decoded)

    return VerifiedSemanticEvidence(
        language="csharp",
        adapter_profile=adapter_profile,
        source_tree_sha256=source_digest,
        build_profile_sha256=build_digest,
        occurrences=tuple(occurrences),
    )


def expected_symbol(policy: str) -> str:
    if policy == "csharp.framework-md5-create":
        version = _PROFILE["framework_assembly_version"]
        return (
            f"scip-dotnet nuget System.Security.Cryptography {version} Cryptography/MD5#Create()."
        )
    if policy == "java.jdk-message-digest-get-instance":
        return (
            "jdk-symbol java.base java.security java.security.MessageDigest "
            "java.security.MessageDigest TOP_LEVEL getInstance java.lang.String"
        )
    if policy == "csharp.framework-dangerous-certificate-validator":
        owner = "global::System.Net.Http.HttpClientHandler"
        assembly = "System.Net.Http 8.0.0.0 b03f5f7f11d50a3a"
        return (
            f"dotnet-property-assignment {assembly} {owner} "
            "ServerCertificateCustomValidationCallback "
            f"{assembly} {owner} DangerousAcceptAnyServerCertificateValidator"
        )
    if policy == "rust.cratesio-reqwest-invalid-certs":
        return (
            "rust-crate-binding reqwest reqwest 0.12.24 "
            "registry+https://github.com/rust-lang/crates.io-index "
            "9d0946410b9f7b082a427e4ef5c8ff541a88b357bc6c637c40db3a68ac70a36f "
            "absolute-extern-prelude tls-invalid-acceptance"
        )
    if policy == "c.fixed-array-literal-oob-write":
        return "clang-c17 fixed-array-out-of-bounds-write"
    if policy == "c.printf-main-argv-format":
        return "clang-c17 system-printf-main-argv-format"
    if policy == "c.system-main-argv-command":
        return "clang-c17 system-shell-main-argv-command"
    if policy == "cpp.fixed-array-literal-oob-write":
        return "clang-cpp17 fixed-array-out-of-bounds-write"
    if policy == "cpp.printf-main-argv-format":
        return "clang-cpp17 system-printf-main-argv-format"
    if policy == "cpp.system-main-argv-command":
        return "clang-cpp17 system-shell-main-argv-command"
    _fail("unsupported_policy", f"unsupported semantic policy {policy}")


def _range_contains(
    start_line: int,
    start_column: int,
    end_line: int,
    end_column: int,
    occurrence: SemanticOccurrence,
) -> bool:
    start = (start_line, start_column)
    end = (end_line, end_column)
    return (
        start <= (occurrence.start_line, occurrence.start_column)
        and (
            occurrence.end_line,
            occurrence.end_column,
        )
        <= end
    )
