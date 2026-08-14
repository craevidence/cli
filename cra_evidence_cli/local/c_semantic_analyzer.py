"""Build-free libclang evidence for focused C and C++ rules."""

from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

C_PROFILE = "libclang-18-c17-security-evidence-v2"
CPP_PROFILE = "libclang-18-cpp17-security-evidence-v2"
C_VERSION = "Ubuntu clang version 18.1.3 (1ubuntu1)"
DEBIAN_C_PROFILE = "libclang-18.1.8-debian13-c17-security-evidence-v2"
DEBIAN_CPP_PROFILE = "libclang-18.1.8-debian13-cpp17-security-evidence-v2"
DEBIAN_C_VERSION = "Debian clang version 18.1.8 (18+b1)"
_LIBRARY_CANDIDATES = (
    Path("/usr/lib/x86_64-linux-gnu/libclang-18.so.18"),
    Path("/usr/lib/aarch64-linux-gnu/libclang-18.so.18"),
    Path("/usr/lib/llvm-18/lib/libclang-18.so.18"),
    Path("/lib/x86_64-linux-gnu/libclang-18.so.18"),
    Path("/lib/aarch64-linux-gnu/libclang-18.so.18"),
)
_ASSIGNMENT = re.compile(
    r"(?P<array>\b[A-Za-z_][A-Za-z0-9_]*\b)"
    r"(?P<space1>[ \t]*)\[(?P<space2>[ \t]*)"
    r"(?P<index>0|[1-9][0-9]{0,8})(?P<space3>[ \t]*)\]"
    r"(?P<space4>[ \t]*)=(?!=)"
)
_PRINTF_ARGV = re.compile(
    r"(?P<call>(?:std[ \t]*::[ \t]*)?printf[ \t]*\([ \t]*"
    r"(?P<parameter>[A-Za-z_][A-Za-z0-9_]*)[ \t]*\[[^\]\r\n]+\][ \t]*\))"
)
_SYSTEM_ARGV = re.compile(
    r"(?P<call>(?:std[ \t]*::[ \t]*)?\bsystem[ \t]*\([ \t]*"
    r"(?P<parameter>[A-Za-z_][A-Za-z0-9_]*)[ \t]*\[[^\]\r\n]+\][ \t]*\))"
)
_INCLUDE = re.compile(r'^\s*#\s*include\s*(?P<kind>[<"])(?P<path>[^>"]+)[>"]\s*$')
_C_SOURCE_SUFFIXES = frozenset({".c"})
_CPP_SOURCE_SUFFIXES = frozenset({".cc", ".cpp", ".cxx"})
_C_INPUT_SUFFIXES = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
)
_ENVIRONMENT_KEYS = (
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH",
    "LIBCLANG_PATH",
)
_MACHINE_TRIPLES = {
    "aarch64": "aarch64-linux-gnu",
    "arm64": "aarch64-linux-gnu",
    "x86_64": "x86_64-linux-gnu",
}


@dataclass(frozen=True)
class _FrontendProfile:
    version: str
    c_profile: str
    cpp_profile: str
    resource_headers: bool
    toolchain_version: str

    def identifier(self, language: str) -> str:
        return self.c_profile if language == "c" else self.cpp_profile


_UBUNTU_PROFILE = _FrontendProfile(
    version=C_VERSION,
    c_profile=C_PROFILE,
    cpp_profile=CPP_PROFILE,
    resource_headers=False,
    toolchain_version="13",
)
_DEBIAN_PROFILE = _FrontendProfile(
    version=DEBIAN_C_VERSION,
    c_profile=DEBIAN_C_PROFILE,
    cpp_profile=DEBIAN_CPP_PROFILE,
    resource_headers=True,
    toolchain_version="14",
)
_FRONTEND_PROFILES = {
    profile.version: profile for profile in (_UBUNTU_PROFILE, _DEBIAN_PROFILE)
}


def _profile_for_version(version: str) -> _FrontendProfile:
    try:
        return _FRONTEND_PROFILES[version]
    except KeyError as exc:
        message = f"unsupported libclang version: {version}"
        raise CAnalysisError(message) from exc


def _profile_include_roots(
    language: str = "c", profile: _FrontendProfile = _UBUNTU_PROFILE
) -> tuple[Path, ...]:
    triple = _MACHINE_TRIPLES.get(platform.machine().lower())
    if triple is None:
        return ()
    compiler_root = (
        Path("/usr/lib/llvm-18/lib/clang/18/include")
        if profile.resource_headers
        else Path(f"/usr/lib/gcc/{triple}/{profile.toolchain_version}/include")
    )
    c_roots = (
        compiler_root,
        Path(f"/usr/include/{triple}"),
        Path("/usr/include"),
    )
    if language == "c":
        return c_roots
    if language == "cpp":
        return (
            Path(f"/usr/include/c++/{profile.toolchain_version}"),
            Path(f"/usr/include/{triple}/c++/{profile.toolchain_version}"),
            *c_roots,
        )
    return ()


def _include_roots(
    language: str = "c", profile: _FrontendProfile = _UBUNTU_PROFILE
) -> tuple[Path, ...]:
    roots = _profile_include_roots(language, profile)
    expected_count = 3 if language == "c" else 5 if language == "cpp" else 0
    if len(roots) != expected_count or not all(path.is_dir() for path in roots):
        message = "the supported system include directories are unavailable"
        raise CAnalysisError(message)
    return roots


def _compiler_arguments(
    language: str = "c", profile: _FrontendProfile = _UBUNTU_PROFILE
) -> tuple[str, ...]:
    if language not in {"c", "cpp"}:
        return ()
    arguments = [
        "-x",
        "c" if language == "c" else "c++",
        "-std=c17" if language == "c" else "-std=c++17",
        "-pedantic-errors",
        "-Wall",
        "-Warray-bounds",
        "-nostdinc",
    ]
    for root in _profile_include_roots(language, profile):
        arguments.extend(("-isystem", str(root)))
    return tuple(arguments)


C_ARGUMENTS = _compiler_arguments("c", _UBUNTU_PROFILE)
CPP_ARGUMENTS = _compiler_arguments("cpp", _UBUNTU_PROFILE)


class CAnalysisError(ValueError):
    """The exact libclang analysis profile could not be established."""


class _CXString(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("private_flags", ctypes.c_uint)]


class _CXSourceLocation(ctypes.Structure):
    _fields_ = [("ptr_data", ctypes.c_void_p * 2), ("int_data", ctypes.c_uint)]


class _CXSourceRange(ctypes.Structure):
    _fields_ = [
        ("ptr_data", ctypes.c_void_p * 2),
        ("begin_int_data", ctypes.c_uint),
        ("end_int_data", ctypes.c_uint),
    ]


class _CXCursor(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint),
        ("xdata", ctypes.c_int),
        ("data", ctypes.c_void_p * 3),
    ]


_CXCursorVisitor = ctypes.CFUNCTYPE(
    ctypes.c_uint, _CXCursor, _CXCursor, ctypes.c_void_p
)


@dataclass(frozen=True)
class _Candidate:
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    index: int


@dataclass(frozen=True)
class _PrintfCandidate:
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    parameter: str


@dataclass(frozen=True)
class _SystemCandidate:
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    parameter: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _include_roots_sha256(
    language: str = "c", profile: _FrontendProfile = _UBUNTU_PROFILE
) -> str:
    digest = hashlib.sha256()
    for root in _include_roots(language, profile):
        digest.update(str(root).encode("utf-8"))
        digest.update(b"\0")
        digest.update(_tree_sha256(root).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _validate_includes(root: Path) -> None:
    resolved_root = root.resolve(strict=True)
    inputs = sorted(
        item
        for item in resolved_root.rglob("*")
        if item.is_file() and item.suffix.lower() in _C_INPUT_SUFFIXES
    )
    for source_path in inputs:
        for line_number, line in enumerate(
            source_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not re.match(r"^\s*#\s*include", line):
                continue
            match = _INCLUDE.fullmatch(line)
            if match is None:
                message = (
                    f"unsupported include directive in "
                    f"{source_path.relative_to(resolved_root).as_posix()}:{line_number}"
                )
                raise CAnalysisError(message)
            include = Path(match.group("path"))
            if match.group("kind") == "<":
                if include.is_absolute() or ".." in include.parts:
                    message = "system include path must be normalized and relative"
                    raise CAnalysisError(message)
                continue
            candidate = source_path.parent / include
            if candidate.is_symlink():
                message = "local C includes must not be symbolic links"
                raise CAnalysisError(message)
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(resolved_root)
            except (OSError, ValueError) as exc:
                message = "local C include leaves the source root or is unavailable"
                raise CAnalysisError(message) from exc
            if resolved.suffix.lower() not in _C_INPUT_SUFFIXES:
                message = "local C include has an unsupported source suffix"
                raise CAnalysisError(message)


def _library_path() -> Path:
    matches = []
    for candidate in _LIBRARY_CANDIDATES:
        if not candidate.exists():
            continue
        resolved = candidate.resolve(strict=True)
        if resolved.is_file() and resolved not in matches:
            matches.append(resolved)
    if len(matches) != 1:
        message = "exactly one supported libclang 18 library is required"
        raise CAnalysisError(message)
    return matches[0]


def _configure(library: ctypes.CDLL) -> None:
    library.clang_createIndex.argtypes = [ctypes.c_int, ctypes.c_int]
    library.clang_createIndex.restype = ctypes.c_void_p
    library.clang_disposeIndex.argtypes = [ctypes.c_void_p]
    library.clang_parseTranslationUnit.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_uint,
    ]
    library.clang_parseTranslationUnit.restype = ctypes.c_void_p
    library.clang_disposeTranslationUnit.argtypes = [ctypes.c_void_p]
    library.clang_getNumDiagnostics.argtypes = [ctypes.c_void_p]
    library.clang_getNumDiagnostics.restype = ctypes.c_uint
    library.clang_getDiagnostic.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    library.clang_getDiagnostic.restype = ctypes.c_void_p
    library.clang_getDiagnosticSeverity.argtypes = [ctypes.c_void_p]
    library.clang_getDiagnosticSeverity.restype = ctypes.c_uint
    library.clang_getDiagnosticLocation.argtypes = [ctypes.c_void_p]
    library.clang_getDiagnosticLocation.restype = _CXSourceLocation
    library.clang_getDiagnosticOption.argtypes = [ctypes.c_void_p, ctypes.POINTER(_CXString)]
    library.clang_getDiagnosticOption.restype = _CXString
    library.clang_formatDiagnostic.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    library.clang_formatDiagnostic.restype = _CXString
    library.clang_defaultDiagnosticDisplayOptions.restype = ctypes.c_uint
    library.clang_disposeDiagnostic.argtypes = [ctypes.c_void_p]
    library.clang_getExpansionLocation.argtypes = [
        _CXSourceLocation,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
    ]
    library.clang_getFileName.argtypes = [ctypes.c_void_p]
    library.clang_getFileName.restype = _CXString
    library.clang_getClangVersion.restype = _CXString
    library.clang_getCString.argtypes = [_CXString]
    library.clang_getCString.restype = ctypes.c_char_p
    library.clang_disposeString.argtypes = [_CXString]
    library.clang_getTranslationUnitCursor.argtypes = [ctypes.c_void_p]
    library.clang_getTranslationUnitCursor.restype = _CXCursor
    library.clang_visitChildren.argtypes = [
        _CXCursor,
        _CXCursorVisitor,
        ctypes.c_void_p,
    ]
    library.clang_visitChildren.restype = ctypes.c_uint
    library.clang_getCursorKindSpelling.argtypes = [ctypes.c_uint]
    library.clang_getCursorKindSpelling.restype = _CXString
    library.clang_getCursorSpelling.argtypes = [_CXCursor]
    library.clang_getCursorSpelling.restype = _CXString
    library.clang_getCursorUSR.argtypes = [_CXCursor]
    library.clang_getCursorUSR.restype = _CXString
    library.clang_getCursorReferenced.argtypes = [_CXCursor]
    library.clang_getCursorReferenced.restype = _CXCursor
    library.clang_getCursorExtent.argtypes = [_CXCursor]
    library.clang_getCursorExtent.restype = _CXSourceRange
    library.clang_getRangeStart.argtypes = [_CXSourceRange]
    library.clang_getRangeStart.restype = _CXSourceLocation
    library.clang_getRangeEnd.argtypes = [_CXSourceRange]
    library.clang_getRangeEnd.restype = _CXSourceLocation
    library.clang_Cursor_getNumArguments.argtypes = [_CXCursor]
    library.clang_Cursor_getNumArguments.restype = ctypes.c_int
    library.clang_Cursor_getArgument.argtypes = [_CXCursor, ctypes.c_uint]
    library.clang_Cursor_getArgument.restype = _CXCursor


def _string(library: ctypes.CDLL, value: _CXString) -> str:
    raw = library.clang_getCString(value)
    result = raw.decode("utf-8", errors="strict") if raw else ""
    library.clang_disposeString(value)
    return result


def _load_frontend(
    language: str,
) -> tuple[ctypes.CDLL, Path, str, _FrontendProfile, tuple[str, ...]]:
    if language not in {"c", "cpp"}:
        message = f"unsupported C-family language: {language}"
        raise CAnalysisError(message)
    library_path = _library_path()
    try:
        library = ctypes.CDLL(str(library_path))
    except OSError as exc:
        message = f"supported libclang could not be loaded: {exc}"
        raise CAnalysisError(message) from exc
    _configure(library)
    version = _string(library, library.clang_getClangVersion())
    profile = _profile_for_version(version)
    _include_roots(language, profile)
    arguments = _compiler_arguments(language, profile)
    return library, library_path, version, profile, arguments


def inspect_c_frontend(language: str = "c") -> dict[str, Any]:
    """Return the complete identity of the active supported frontend."""
    _, library_path, version, profile, arguments = _load_frontend(language)
    return {
        "profile": profile.identifier(language),
        "library_path": str(library_path),
        "library_sha256": _sha256(library_path),
        "library_version": version,
        "resource_headers_sha256": _include_roots_sha256(language, profile),
        "compiler_options": list(arguments),
    }


def _candidate_lines(source: str) -> list[_Candidate]:
    candidates = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for match in _ASSIGNMENT.finditer(line):
            start = match.start("array")
            end = match.end("index") + len(match.group("space3")) + 1
            candidates.append(
                _Candidate(
                    start_line=line_number,
                    start_column=start + 1,
                    end_line=line_number,
                    end_column=end + 1,
                    index=int(match.group("index")),
                )
            )
    return candidates


def _printf_candidate_lines(source: str) -> list[_PrintfCandidate]:
    candidates = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for match in _PRINTF_ARGV.finditer(line):
            candidates.append(
                _PrintfCandidate(
                    start_line=line_number,
                    start_column=match.start("call") + 1,
                    end_line=line_number,
                    end_column=match.end("call") + 1,
                    parameter=match.group("parameter"),
                )
            )
    return candidates


def _system_candidate_lines(source: str) -> list[_SystemCandidate]:
    candidates = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for match in _SYSTEM_ARGV.finditer(line):
            candidates.append(
                _SystemCandidate(
                    start_line=line_number,
                    start_column=match.start("call") + 1,
                    end_line=line_number,
                    end_column=match.end("call") + 1,
                    parameter=match.group("parameter"),
                )
            )
    return candidates


def _cursor_kind(library: ctypes.CDLL, cursor: _CXCursor) -> str:
    return _string(library, library.clang_getCursorKindSpelling(cursor.kind))


def _cursor_spelling(library: ctypes.CDLL, cursor: _CXCursor) -> str:
    return _string(library, library.clang_getCursorSpelling(cursor))


def _cursor_usr(library: ctypes.CDLL, cursor: _CXCursor) -> str:
    return _string(library, library.clang_getCursorUSR(cursor))


def _cursor_children(library: ctypes.CDLL, cursor: _CXCursor) -> tuple[_CXCursor, ...]:
    children: list[_CXCursor] = []

    @_CXCursorVisitor
    def collect(child: _CXCursor, _parent: _CXCursor, _data: ctypes.c_void_p) -> int:
        children.append(child)
        return 1

    library.clang_visitChildren(cursor, collect, None)
    return tuple(children)


def _location(
    library: ctypes.CDLL, location: _CXSourceLocation
) -> tuple[Path | None, int, int]:
    location_file = ctypes.c_void_p()
    line = ctypes.c_uint()
    column = ctypes.c_uint()
    offset = ctypes.c_uint()
    library.clang_getExpansionLocation(
        location,
        ctypes.byref(location_file),
        ctypes.byref(line),
        ctypes.byref(column),
        ctypes.byref(offset),
    )
    path = None
    if location_file:
        raw_path = _string(library, library.clang_getFileName(location_file))
        if raw_path:
            path = Path(raw_path).resolve()
    return path, line.value, column.value


def _cursor_range(
    library: ctypes.CDLL, cursor: _CXCursor
) -> tuple[Path | None, int, int, Path | None, int, int]:
    extent = library.clang_getCursorExtent(cursor)
    start_path, start_line, start_column = _location(
        library, library.clang_getRangeStart(extent)
    )
    end_path, end_line, end_column = _location(
        library, library.clang_getRangeEnd(extent)
    )
    return start_path, start_line, start_column, end_path, end_line, end_column


def _unwrap_expression(library: ctypes.CDLL, cursor: _CXCursor) -> _CXCursor:
    current = cursor
    while _cursor_kind(library, current) == "UnexposedExpr":
        children = _cursor_children(library, current)
        if len(children) != 1:
            break
        current = children[0]
    return current


def _array_base_parameter_usr(library: ctypes.CDLL, cursor: _CXCursor) -> str | None:
    expression = _unwrap_expression(library, cursor)
    if _cursor_kind(library, expression) != "ArraySubscriptExpr":
        return None
    children = _cursor_children(library, expression)
    if len(children) != 2:
        return None
    base = _unwrap_expression(library, children[0])
    if _cursor_kind(library, base) != "DeclRefExpr":
        return None
    referenced = library.clang_getCursorReferenced(base)
    if _cursor_kind(library, referenced) != "ParmDecl":
        return None
    return _cursor_usr(library, referenced)


def _system_function_declaration(
    library: ctypes.CDLL,
    call: _CXCursor,
    system_roots: tuple[Path, ...],
    spelling: str,
) -> bool:
    referenced = library.clang_getCursorReferenced(call)
    if _cursor_kind(library, referenced) != "FunctionDecl":
        return False
    if _cursor_spelling(library, referenced) != spelling:
        return False
    start_path, *_ = _cursor_range(library, referenced)
    if start_path is None:
        return False
    return any(start_path.is_relative_to(root.resolve()) for root in system_roots)


def _printf_occurrences(
    library: ctypes.CDLL,
    translation_unit: ctypes.c_void_p,
    source_path: Path,
    relative: str,
    system_roots: tuple[Path, ...],
) -> list[dict[str, Any]]:
    resolved_source = source_path.resolve()
    occurrences: list[dict[str, Any]] = []
    root = library.clang_getTranslationUnitCursor(translation_unit)
    for function in _cursor_children(library, root):
        if (
            _cursor_kind(library, function) != "FunctionDecl"
            or _cursor_spelling(library, function) != "main"
        ):
            continue
        start_path, *_ = _cursor_range(library, function)
        if start_path != resolved_source:
            continue
        parameters = [
            child
            for child in _cursor_children(library, function)
            if _cursor_kind(library, child) == "ParmDecl"
        ]
        if len(parameters) < 2:
            continue
        argv = parameters[1]
        argv_usr = _cursor_usr(library, argv)
        argv_name = _cursor_spelling(library, argv)
        if not argv_usr or not argv_name:
            continue

        pending = list(_cursor_children(library, function))
        while pending:
            cursor = pending.pop()
            pending.extend(_cursor_children(library, cursor))
            if _cursor_kind(library, cursor) != "CallExpr":
                continue
            if _cursor_spelling(library, cursor) != "printf":
                continue
            start_path, start_line, start_column, end_path, end_line, end_column = (
                _cursor_range(library, cursor)
            )
            if start_path != resolved_source or end_path != resolved_source:
                continue
            if library.clang_Cursor_getNumArguments(cursor) != 1:
                continue
            argument = library.clang_Cursor_getArgument(cursor, 0)
            if _array_base_parameter_usr(library, argument) != argv_usr:
                continue
            occurrences.append(
                {
                    "path": relative,
                    "start_line": start_line,
                    "start_column": start_column,
                    "end_line": end_line,
                    "end_column": end_column,
                    "callee": _cursor_spelling(library, cursor),
                    "parameter": argv_name,
                    "classification": (
                        "system-printf-main-argv-format"
                        if _system_function_declaration(
                            library, cursor, system_roots, "printf"
                        )
                        else "printf-main-argv-not-system-bound"
                    ),
                }
            )
    return occurrences


def _system_occurrences(
    library: ctypes.CDLL,
    translation_unit: ctypes.c_void_p,
    source_path: Path,
    relative: str,
    system_roots: tuple[Path, ...],
) -> list[dict[str, Any]]:
    resolved_source = source_path.resolve()
    occurrences: list[dict[str, Any]] = []
    root = library.clang_getTranslationUnitCursor(translation_unit)
    for function in _cursor_children(library, root):
        if (
            _cursor_kind(library, function) != "FunctionDecl"
            or _cursor_spelling(library, function) != "main"
        ):
            continue
        start_path, *_ = _cursor_range(library, function)
        if start_path != resolved_source:
            continue
        parameters = [
            child
            for child in _cursor_children(library, function)
            if _cursor_kind(library, child) == "ParmDecl"
        ]
        if len(parameters) < 2:
            continue
        argv = parameters[1]
        argv_usr = _cursor_usr(library, argv)
        argv_name = _cursor_spelling(library, argv)
        if not argv_usr or not argv_name:
            continue

        pending = list(_cursor_children(library, function))
        while pending:
            cursor = pending.pop()
            pending.extend(_cursor_children(library, cursor))
            if _cursor_kind(library, cursor) != "CallExpr":
                continue
            if _cursor_spelling(library, cursor) != "system":
                continue
            start_path, start_line, start_column, end_path, end_line, end_column = (
                _cursor_range(library, cursor)
            )
            if start_path != resolved_source or end_path != resolved_source:
                continue
            if library.clang_Cursor_getNumArguments(cursor) != 1:
                continue
            argument = library.clang_Cursor_getArgument(cursor, 0)
            if _array_base_parameter_usr(library, argument) != argv_usr:
                continue
            occurrences.append(
                {
                    "path": relative,
                    "start_line": start_line,
                    "start_column": start_column,
                    "end_line": end_line,
                    "end_column": end_column,
                    "callee": _cursor_spelling(library, cursor),
                    "parameter": argv_name,
                    "classification": (
                        "system-shell-main-argv-command"
                        if _system_function_declaration(
                            library, cursor, system_roots, "system"
                        )
                        else "system-main-argv-not-system-bound"
                    ),
                }
            )
    return occurrences


def _diagnostics(
    library: ctypes.CDLL, translation_unit: ctypes.c_void_p, source_path: Path
) -> tuple[set[tuple[int, int]], list[str]]:
    bounds = set()
    errors = []
    for number in range(library.clang_getNumDiagnostics(translation_unit)):
        diagnostic = library.clang_getDiagnostic(translation_unit, number)
        try:
            severity = library.clang_getDiagnosticSeverity(diagnostic)
            disable = _CXString()
            option = _string(
                library,
                library.clang_getDiagnosticOption(diagnostic, ctypes.byref(disable)),
            )
            _string(library, disable)
            location = library.clang_getDiagnosticLocation(diagnostic)
            location_file = ctypes.c_void_p()
            line = ctypes.c_uint()
            column = ctypes.c_uint()
            offset = ctypes.c_uint()
            library.clang_getExpansionLocation(
                location,
                ctypes.byref(location_file),
                ctypes.byref(line),
                ctypes.byref(column),
                ctypes.byref(offset),
            )
            location_path = (
                Path(_string(library, library.clang_getFileName(location_file))).resolve()
                if location_file
                else None
            )
            if (
                option in {"-Warray-bounds", "-Warray-bounds="}
                and location_path == source_path.resolve()
            ):
                bounds.add((line.value, column.value))
            if severity >= 3:
                detail = _string(
                    library,
                    library.clang_formatDiagnostic(
                        diagnostic, library.clang_defaultDiagnosticDisplayOptions()
                    ),
                )
                errors.append(detail[:500])
        finally:
            library.clang_disposeDiagnostic(diagnostic)
    return bounds, errors


def analyze_c_tree(root: Path, language: str = "c") -> dict[str, Any]:
    if language == "c":
        source_suffixes = _C_SOURCE_SUFFIXES
    elif language == "cpp":
        source_suffixes = _CPP_SOURCE_SUFFIXES
    else:
        message = f"unsupported C-family language: {language}"
        raise CAnalysisError(message)
    _validate_includes(root)
    library, library_path, version, profile, compiler_arguments = _load_frontend(language)
    source_files = sorted(
        item
        for item in root.rglob("*")
        if item.is_file()
        and not item.is_symlink()
        and item.suffix.lower() in source_suffixes
    )
    if not source_files:
        message = f"no {language} source files were found"
        raise CAnalysisError(message)
    arguments = (ctypes.c_char_p * len(compiler_arguments))(
        *(item.encode("ascii") for item in compiler_arguments)
    )
    occurrences = []
    index = library.clang_createIndex(1, 1)
    if not index:
        message = "libclang index creation failed"
        raise CAnalysisError(message)
    saved_environment = {key: os.environ.get(key) for key in _ENVIRONMENT_KEYS}
    for key in _ENVIRONMENT_KEYS:
        os.environ.pop(key, None)
    try:
        for source_path in source_files:
            relative = source_path.relative_to(root).as_posix()
            source = source_path.read_text(encoding="utf-8")
            candidates = _candidate_lines(source)
            translation_unit = library.clang_parseTranslationUnit(
                index,
                str(source_path).encode("utf-8"),
                arguments,
                len(compiler_arguments),
                None,
                0,
                0,
            )
            if not translation_unit:
                message = f"libclang could not parse {relative}"
                raise CAnalysisError(message)
            try:
                bounds, errors = _diagnostics(library, translation_unit, source_path)
                ast_format_occurrences = _printf_occurrences(
                    library,
                    translation_unit,
                    source_path,
                    relative,
                    _profile_include_roots(language, profile),
                )
                ast_system_occurrences = _system_occurrences(
                    library,
                    translation_unit,
                    source_path,
                    relative,
                    _profile_include_roots(language, profile),
                )
            finally:
                library.clang_disposeTranslationUnit(translation_unit)
            if errors:
                message = f"C analysis failed for {relative}: {errors[0]}"
                raise CAnalysisError(message)
            for candidate in candidates:
                attested = any(
                    line == candidate.start_line
                    and candidate.start_column <= column < candidate.end_column
                    for line, column in bounds
                )
                occurrences.append(
                    {
                        "path": relative,
                        "start_line": candidate.start_line,
                        "start_column": candidate.start_column,
                        "end_line": candidate.end_line,
                        "end_column": candidate.end_column,
                        "index": candidate.index,
                        "classification": (
                            "fixed-array-out-of-bounds-write"
                            if attested
                            else "not-compiler-attested"
                        ),
                    }
                )
            for candidate in _printf_candidate_lines(source):
                matching = [
                    item
                    for item in ast_format_occurrences
                    if item["start_line"] == candidate.start_line
                    and item["start_column"] == candidate.start_column
                    and item["end_line"] == candidate.end_line
                    and item["end_column"] == candidate.end_column
                ]
                if len(matching) == 1:
                    occurrences.append(matching[0])
                else:
                    occurrences.append(
                        {
                            "path": relative,
                            "start_line": candidate.start_line,
                            "start_column": candidate.start_column,
                            "end_line": candidate.end_line,
                            "end_column": candidate.end_column,
                            "callee": "printf",
                            "parameter": candidate.parameter,
                            "classification": "printf-main-argv-not-system-bound",
                        }
                    )
            for candidate in _system_candidate_lines(source):
                matching = [
                    item
                    for item in ast_system_occurrences
                    if item["start_line"] == candidate.start_line
                    and item["start_column"] == candidate.start_column
                    and item["end_line"] == candidate.end_line
                    and item["end_column"] == candidate.end_column
                ]
                if len(matching) == 1:
                    occurrences.append(matching[0])
                else:
                    occurrences.append(
                        {
                            "path": relative,
                            "start_line": candidate.start_line,
                            "start_column": candidate.start_column,
                            "end_line": candidate.end_line,
                            "end_column": candidate.end_column,
                            "callee": "system",
                            "parameter": candidate.parameter,
                            "classification": "system-main-argv-not-system-bound",
                        }
                    )
    finally:
        library.clang_disposeIndex(index)
        for key, value in saved_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return {
        "profile": profile.identifier(language),
        "library_path": str(library_path),
        "library_sha256": _sha256(library_path),
        "library_version": version,
        "resource_headers_sha256": _include_roots_sha256(language, profile),
        "compiler_options": list(compiler_arguments),
        "occurrences": occurrences,
    }
