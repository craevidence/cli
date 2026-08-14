"""Generate local build-script-free semantic evidence."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import click

from cra_evidence_cli.local.c_semantic_analyzer import (
    CAnalysisError,
    analyze_c_tree,
)
from cra_evidence_cli.local.rust_semantic_analyzer import (
    REQWEST_CHECKSUM,
    REQWEST_PACKAGE,
    REQWEST_SOURCE,
    REQWEST_VERSION,
    RustAnalysisError,
    analyze_rust_package,
)
from cra_evidence_cli.local.semantic_evidence import (
    C_SCHEMA_VERSION,
    CPP_SCHEMA_VERSION,
    CSHARP_SCHEMA_VERSION,
    CSHARP_SUPPORTED_PROFILE,
    JAVA_SCHEMA_VERSION,
    JAVA_SUPPORTED_PROFILE,
    RUST_SCHEMA_VERSION,
    RUST_SUPPORTED_PROFILE,
    source_tree_manifest,
)

_ANALYZER = Path(__file__).parent.parent / "local" / "java_symbol_analyzer.java"
_CSHARP_ANALYZER = Path(__file__).parent.parent / "local" / "csharp_symbol_analyzer.cs"
_RUST_ANALYZER = Path(__file__).parent.parent / "local" / "rust_semantic_analyzer.py"
_C_ANALYZER = Path(__file__).parent.parent / "local" / "c_semantic_analyzer.py"
_MAX_ANALYZER_OUTPUT = 16 * 1024 * 1024
_COMPILER_OPTIONS = ["-proc:none", "-implicit:none", "empty-class-path", "empty-source-path"]
_CSHARP_SDK_VERSION = "8.0.423"
_CSHARP_REFERENCE_VERSION = "8.0.29"
_CSHARP_COMPILER_OPTIONS = [
    "/noconfig",
    "/nostdlib+",
    "/target:exe",
    "framework-reference-pack-only",
    "no-project-inputs",
    "sanitized-dotnet-environment",
    "invariant-globalization",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _csharp_runtime_environment(dotnet_root: Path, home: Path) -> dict[str, str]:
    return {
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_NOLOGO": "1",
        "DOTNET_ROOT": str(dotnet_root),
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT": "1",
        "HOME": str(home),
        "PATH": os.defpath,
    }


def _parse_output(raw: bytes) -> tuple[str, list[dict[str, Any]]]:
    if len(raw) > _MAX_ANALYZER_OUTPUT:
        message = "Java analyzer output exceeded the size limit"
        raise click.ClickException(message)
    try:
        lines = raw.decode("utf-8").splitlines()
        documents = [json.loads(line) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        message = "Java analyzer returned malformed output"
        raise click.ClickException(message) from exc
    if not documents or documents[0].get("schema") != "craevidence.java_symbols.v1":
        message = "Java analyzer returned an unsupported output schema"
        raise click.ClickException(message)
    java_version = documents[0].get("java_version")
    if not isinstance(java_version, str) or not java_version:
        message = "Java analyzer did not report its runtime version"
        raise click.ClickException(message)
    occurrences = documents[1:]
    if not all(isinstance(item, dict) for item in occurrences):
        message = "Java analyzer returned an invalid occurrence"
        raise click.ClickException(message)
    return java_version, occurrences


def _parse_csharp_output(raw: bytes) -> tuple[str, str, list[dict[str, Any]]]:
    if len(raw) > _MAX_ANALYZER_OUTPUT:
        message = "C# analyzer output exceeded the size limit"
        raise click.ClickException(message)
    try:
        documents = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        message = "C# analyzer returned malformed output"
        raise click.ClickException(message) from exc
    if not documents or documents[0].get("schema") != "craevidence.csharp_symbols.v1":
        message = "C# analyzer returned an unsupported output schema"
        raise click.ClickException(message)
    runtime_version = documents[0].get("runtime_version")
    roslyn_version = documents[0].get("roslyn_version")
    if not all(isinstance(value, str) and value for value in (runtime_version, roslyn_version)):
        message = "C# analyzer did not report its runtime identity"
        raise click.ClickException(message)
    return runtime_version, roslyn_version, documents[1:]


def _write_envelope(output_path: Path, envelope: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output_path.parent,
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        json.dump(envelope, handle, indent=2, sort_keys=True)
        handle.write("\n")
    try:
        os.replace(temporary, output_path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def _generate_csharp(path: Path, output_path: Path, timeout: int) -> None:
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        message = ".NET SDK 8.0.423 is required to generate C# semantic evidence"
        raise click.ClickException(message)
    dotnet_path = Path(dotnet).resolve(strict=True)
    discovery_environment = _csharp_runtime_environment(
        dotnet_path.parent, Path(tempfile.gettempdir())
    )
    try:
        sdk_result = subprocess.run(  # noqa: S603
            [str(dotnet_path), "--list-sdks"],
            capture_output=True,
            text=True,
            timeout=min(timeout, 30),
            check=False,
            env=discovery_environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        message = f"C# SDK discovery failed: {type(exc).__name__}"
        raise click.ClickException(message) from exc
    expected_prefix = f"{_CSHARP_SDK_VERSION} ["
    sdk_lines = [
        line for line in sdk_result.stdout.splitlines() if line.startswith(expected_prefix)
    ]
    if sdk_result.returncode != 0 or len(sdk_lines) != 1 or not sdk_lines[0].endswith("]"):
        message = "the required .NET SDK 8.0.423 was not found"
        raise click.ClickException(message)
    sdk_base = Path(sdk_lines[0][len(expected_prefix) : -1]).resolve(strict=True)
    sdk_root = (sdk_base / _CSHARP_SDK_VERSION).resolve(strict=True)
    dotnet_root = sdk_base.parent
    roslyn_root = sdk_root / "Roslyn" / "bincore"
    csc = roslyn_root / "csc.dll"
    csc_deps = roslyn_root / "csc.deps.json"
    code_analysis = roslyn_root / "Microsoft.CodeAnalysis.dll"
    code_analysis_csharp = roslyn_root / "Microsoft.CodeAnalysis.CSharp.dll"
    reference_root = (
        dotnet_root
        / "packs"
        / "Microsoft.NETCore.App.Ref"
        / _CSHARP_REFERENCE_VERSION
        / "ref"
        / "net8.0"
    )
    required = (csc, csc_deps, code_analysis, code_analysis_csharp, reference_root)
    if not all(item.exists() for item in required):
        message = "the required trusted Roslyn and net8.0 reference files are missing"
        raise click.ClickException(message)
    references = sorted(reference_root.glob("*.dll"))
    if not references:
        message = "the trusted net8.0 framework reference pack is empty"
        raise click.ClickException(message)
    source_root = path.resolve(strict=True)
    before_files, before_digest = source_tree_manifest(source_root, "csharp-direct")
    if not before_files:
        message = "no C# source files were found"
        raise click.ClickException(message)
    reference_digest = hashlib.sha256()
    for reference in references:
        reference_digest.update(reference.name.encode("utf-8"))
        reference_digest.update(b"\0")
        reference_digest.update(_sha256(reference).encode("ascii"))
        reference_digest.update(b"\0")
    with tempfile.TemporaryDirectory(prefix="cra-csharp-symbols-") as temporary_raw:
        temporary = Path(temporary_raw)
        runtime_environment = _csharp_runtime_environment(dotnet_root, temporary)
        analyzer_dll = temporary / "CraCSharpSymbolAnalyzer.dll"
        response = temporary / "compiler.rsp"
        runtime_config = temporary / "CraCSharpSymbolAnalyzer.runtimeconfig.json"
        response_lines = [
            "/noconfig",
            "/nostdlib+",
            "/target:exe",
            f"/out:{analyzer_dll}",
            f"/r:{code_analysis}",
            f"/r:{code_analysis_csharp}",
            *(f"/r:{item}" for item in references),
            str(_CSHARP_ANALYZER),
        ]
        response.write_text("\n".join(response_lines) + "\n", encoding="utf-8")
        runtime_config.write_text(
            json.dumps(
                {
                    "runtimeOptions": {
                        "tfm": "net8.0",
                        "framework": {"name": "Microsoft.NETCore.App", "version": "8.0.0"},
                    },
                }
            ),
            encoding="utf-8",
        )
        try:
            compile_result = subprocess.run(  # noqa: S603
                [str(dotnet_path), str(csc), f"@{response}"],
                capture_output=True,
                timeout=timeout,
                check=False,
                env=runtime_environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            message = f"C# analyzer compilation failed: {type(exc).__name__}"
            raise click.ClickException(message) from exc
        if compile_result.returncode != 0:
            diagnostic = compile_result.stderr or compile_result.stdout
            detail = diagnostic.decode("utf-8", errors="replace").strip().splitlines()
            suffix = f": {detail[0][:300]}" if detail else ""
            message = (
                f"C# analyzer compilation failed with exit {compile_result.returncode}{suffix}"
            )
            raise click.ClickException(message)
        command = [
            str(dotnet_path),
            "exec",
            "--runtimeconfig",
            str(runtime_config),
            "--depsfile",
            str(csc_deps),
            str(analyzer_dll),
            str(reference_root),
            str(source_root),
        ]
        try:
            result = subprocess.run(  # noqa: S603
                command, capture_output=True, timeout=timeout, check=False, env=runtime_environment
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            message = f"C# semantic analysis failed: {type(exc).__name__}"
            raise click.ClickException(message) from exc
    after_files, after_digest = source_tree_manifest(source_root, "csharp-direct")
    if (after_files, after_digest) != (before_files, before_digest):
        message = "C# source changed during semantic analysis"
        raise click.ClickException(message)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        suffix = f": {detail[0][:300]}" if detail else ""
        message = f"C# compiler analysis failed with exit {result.returncode}{suffix}"
        raise click.ClickException(message)
    runtime_version, roslyn_version, occurrences = _parse_csharp_output(result.stdout)
    profile_digest = hashlib.sha256(
        json.dumps(_CSHARP_COMPILER_OPTIONS, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    envelope = {
        "schema_version": CSHARP_SCHEMA_VERSION,
        "language": "csharp",
        "adapter": {
            "profile": CSHARP_SUPPORTED_PROFILE,
            "analyzer_sha256": _sha256(_CSHARP_ANALYZER),
            "dotnet_executable_sha256": _sha256(dotnet_path),
            "sdk_version": _CSHARP_SDK_VERSION,
            "runtime_version": runtime_version,
            "roslyn_version": roslyn_version,
            "reference_pack_version": _CSHARP_REFERENCE_VERSION,
            "reference_pack_sha256": reference_digest.hexdigest(),
        },
        "isolation": {
            "build_scripts_executed": False,
            "projects_loaded": False,
            "restore_executed": False,
            "msbuild_executed": False,
            "generators_loaded": False,
            "target_code_executed": False,
            "reference_source": "trusted-framework-pack-only",
        },
        "source": {"tree_sha256": before_digest, "files": before_files},
        "analysis": {
            "compiler_exit_code": 0,
            "error_count": 0,
            "compiler_options": _CSHARP_COMPILER_OPTIONS,
            "profile_sha256": profile_digest,
            "occurrences": occurrences,
        },
    }
    _write_envelope(output_path, envelope)
    click.echo(f"C# semantic evidence written to {output_path}.")


def _generate_rust(path: Path, output_path: Path) -> None:
    source_root = path.resolve(strict=True)
    before_files, before_digest = source_tree_manifest(source_root, "rust-static")
    if not before_files:
        message = "no Rust package inputs were found"
        raise click.ClickException(message)
    try:
        result = analyze_rust_package(source_root)
    except (OSError, UnicodeDecodeError, RustAnalysisError) as exc:
        message = f"Rust static analysis failed: {exc}"
        raise click.ClickException(message) from exc
    after_files, after_digest = source_tree_manifest(source_root, "rust-static")
    if (after_files, after_digest) != (before_files, before_digest):
        message = "Rust package inputs changed during static analysis"
        raise click.ClickException(message)
    occurrences = result.pop("occurrences")
    profile_digest = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    envelope = {
        "schema_version": RUST_SCHEMA_VERSION,
        "language": "rust",
        "adapter": {
            "profile": RUST_SUPPORTED_PROFILE,
            "analyzer_sha256": _sha256(_RUST_ANALYZER),
            "package_name": REQWEST_PACKAGE,
            "package_version": REQWEST_VERSION,
            "package_source": REQWEST_SOURCE,
            "package_checksum": REQWEST_CHECKSUM,
        },
        "isolation": {
            "cargo_executed": False,
            "compiler_executed": False,
            "build_scripts_executed": False,
            "proc_macros_executed": False,
            "target_code_executed": False,
            "network_required": False,
            "provenance_source": "static-manifest-lock-and-pinned-checksum",
        },
        "source": {"tree_sha256": before_digest, "files": before_files},
        "analysis": {
            "profile": result,
            "profile_sha256": profile_digest,
            "occurrences": occurrences,
        },
    }
    _write_envelope(output_path, envelope)
    click.echo(f"Rust semantic evidence written to {output_path}.")


def _generate_c(path: Path, output_path: Path, language: str = "c") -> None:
    source_root = path.resolve(strict=True)
    source_profile = "c-direct" if language == "c" else "cpp-direct"
    source_suffixes = (".c",) if language == "c" else (".cc", ".cpp", ".cxx")
    before_files, before_digest = source_tree_manifest(source_root, source_profile)
    if not any(record["path"].endswith(source_suffixes) for record in before_files):
        message = f"no {language} source files were found"
        raise click.ClickException(message)
    try:
        result = analyze_c_tree(source_root, language)
    except (OSError, UnicodeDecodeError, CAnalysisError) as exc:
        message = f"{language} semantic analysis failed: {exc}"
        raise click.ClickException(message) from exc
    after_files, after_digest = source_tree_manifest(source_root, source_profile)
    if (after_files, after_digest) != (before_files, before_digest):
        message = f"{language} source inputs changed during semantic analysis"
        raise click.ClickException(message)
    occurrences = result.pop("occurrences")
    options = result.pop("compiler_options")
    adapter_profile = result.pop("profile")
    profile_digest = hashlib.sha256(
        json.dumps(options, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    envelope = {
        "schema_version": C_SCHEMA_VERSION if language == "c" else CPP_SCHEMA_VERSION,
        "language": language,
        "adapter": {
            "profile": adapter_profile,
            "analyzer_sha256": _sha256(_C_ANALYZER),
            "library_path": result["library_path"],
            "library_sha256": result["library_sha256"],
            "library_version": result["library_version"],
            "resource_headers_sha256": result["resource_headers_sha256"],
        },
        "isolation": {
            "build_system_executed": False,
            "compiler_plugins_loaded": False,
            "linker_executed": False,
            "target_code_executed": False,
            "network_required": False,
            "analysis_mode": "libclang-frontend-only",
        },
        "source": {"tree_sha256": before_digest, "files": before_files},
        "analysis": {
            "compiler_options": options,
            "profile_sha256": profile_digest,
            "occurrences": occurrences,
        },
    }
    _write_envelope(output_path, envelope)
    click.echo(f"{language} semantic evidence written to {output_path}.")


@click.command("code-evidence")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--language",
    type=click.Choice(["java", "csharp", "rust", "c", "cpp"], case_sensitive=False),
    required=True,
    help="Language evidence profile to run.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Write the versioned semantic evidence envelope to this file.",
)
@click.option(
    "--timeout",
    type=click.IntRange(min=1, max=1800),
    default=300,
    show_default=True,
    help="Maximum seconds for compiler analysis.",
)
def code_evidence(path: Path, language: str, output_path: Path, timeout: int) -> None:
    """Generate semantic evidence without running project build scripts."""
    if language.lower() == "csharp":
        _generate_csharp(path, output_path, timeout)
        return
    if language.lower() == "rust":
        _generate_rust(path, output_path)
        return
    if language.lower() == "c":
        _generate_c(path, output_path)
        return
    if language.lower() == "cpp":
        _generate_c(path, output_path, "cpp")
        return
    java = shutil.which("java")
    if java is None:
        message = "Java is required to generate Java semantic evidence"
        raise click.ClickException(message)
    java_path = Path(java).resolve(strict=True)
    source_root = path.resolve(strict=True)
    before_files, before_digest = source_tree_manifest(source_root, "java")
    if not before_files:
        message = "no Java source files were found"
        raise click.ClickException(message)
    command = [str(java_path), str(_ANALYZER), str(source_root)]
    try:
        result = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        message = f"Java semantic analysis failed: {type(exc).__name__}"
        raise click.ClickException(message) from exc
    after_files, after_digest = source_tree_manifest(source_root, "java")
    if (after_files, after_digest) != (before_files, before_digest):
        message = "Java source changed during semantic analysis"
        raise click.ClickException(message)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        suffix = f": {detail[0][:300]}" if detail else ""
        message = f"Java compiler analysis failed with exit {result.returncode}{suffix}"
        raise click.ClickException(message)
    java_version, occurrences = _parse_output(result.stdout)
    profile_digest = hashlib.sha256(
        json.dumps(_COMPILER_OPTIONS, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    envelope = {
        "schema_version": JAVA_SCHEMA_VERSION,
        "language": "java",
        "adapter": {
            "profile": JAVA_SUPPORTED_PROFILE,
            "analyzer_sha256": _sha256(_ANALYZER),
            "java_version": java_version,
            "java_executable_sha256": _sha256(java_path),
            "arguments": command,
        },
        "isolation": {
            "build_scripts_executed": False,
            "annotation_processing": False,
            "class_path": "empty",
            "source_path": "empty",
            "implicit_compilation": False,
        },
        "source": {"tree_sha256": before_digest, "files": before_files},
        "analysis": {
            "compiler_exit_code": 0,
            "error_count": 0,
            "compiler_options": _COMPILER_OPTIONS,
            "profile_sha256": profile_digest,
            "occurrences": occurrences,
        },
    }
    _write_envelope(output_path, envelope)
    click.echo(f"Java semantic evidence written to {output_path}.")
