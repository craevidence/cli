from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from cra_evidence_cli.commands.code_evidence import (
    _csharp_runtime_environment,
    code_evidence,
)
from cra_evidence_cli.local.semantic_evidence import (
    SemanticEvidenceError,
    expected_symbol,
    load_semantic_evidence,
)


def _java_available() -> bool:
    return shutil.which("java") is not None


def _csharp_sdk_available() -> bool:
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        return False
    result = subprocess.run(  # noqa: S603
        [dotnet, "--list-sdks"], capture_output=True, text=True, check=False
    )
    return any(line.startswith("8.0.423 [") for line in result.stdout.splitlines())


def _c_semantic_profile_available() -> bool:
    try:
        from cra_evidence_cli.local.c_semantic_analyzer import _library_path

        _library_path()
    except (OSError, ValueError):
        return False
    return True


def test_debian_c_family_frontend_profiles_are_distinct_and_fixed() -> None:
    from cra_evidence_cli.local.c_semantic_analyzer import (
        DEBIAN_C_PROFILE,
        DEBIAN_C_VERSION,
        DEBIAN_CPP_PROFILE,
        _compiler_arguments,
        _profile_for_version,
        _profile_include_roots,
    )

    profile = _profile_for_version(DEBIAN_C_VERSION)

    assert profile.identifier("c") == DEBIAN_C_PROFILE
    assert profile.identifier("cpp") == DEBIAN_CPP_PROFILE
    c_roots = _profile_include_roots("c", profile)
    cpp_roots = _profile_include_roots("cpp", profile)
    assert c_roots[0] == Path("/usr/lib/llvm-18/lib/clang/18/include")
    assert cpp_roots[0] == Path("/usr/include/c++/14")
    assert cpp_roots[2:] == c_roots
    assert _compiler_arguments("c", profile)[:6] == (
        "-x",
        "c",
        "-std=c17",
        "-pedantic-errors",
        "-Wall",
        "-Warray-bounds",
    )
    assert _compiler_arguments("cpp", profile)[:3] == (
        "-x",
        "c++",
        "-std=c++17",
    )


@pytest.mark.skipif(not _c_semantic_profile_available(), reason="exact libclang is unavailable")
def test_c_evidence_attests_bounds_and_rejects_macro_redirect(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fixture = Path(__file__).parent / "semantic" / "c_array_bounds_binding.c"
    (source / "main.c").write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
    output = tmp_path / "c-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "c", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("c.fixed-array-literal-oob-write")
    assert [item.start_line for item in evidence.occurrences] == [5, 6, 13, 15]
    assert [item.symbol == expected for item in evidence.occurrences] == [
        False,
        True,
        False,
        True,
    ]
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["adapter"]["library_version"] == ("Ubuntu clang version 18.1.3 (1ubuntu1)")
    assert document["isolation"]["build_system_executed"] is False
    assert document["isolation"]["target_code_executed"] is False


@pytest.mark.skipif(not _c_semantic_profile_available(), reason="exact libclang is unavailable")
def test_cpp_evidence_attests_bounds_and_rejects_preprocessor_decoys(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fixture_root = Path(__file__).parent / "semantic"
    for name in ("cpp_array_bounds_binding.cpp", "cpp_array_application_type.cpp"):
        (source / name).write_text(
            (fixture_root / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    output = tmp_path / "cpp-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "cpp", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("cpp.fixed-array-literal-oob-write")
    by_path = {}
    for occurrence in evidence.occurrences:
        by_path.setdefault(occurrence.path, []).append(occurrence)
    binding = by_path["cpp_array_bounds_binding.cpp"]
    assert [item.start_line for item in binding] == [5, 6, 13, 15, 21]
    assert [item.symbol == expected for item in binding] == [
        False,
        True,
        False,
        True,
        False,
    ]
    application = by_path["cpp_array_application_type.cpp"]
    assert len(application) == 1
    assert application[0].symbol == expected
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["language"] == "cpp"
    assert document["adapter"]["profile"] == (
        "libclang-18-cpp17-security-evidence-v2"
    )
    wrong_schema = tmp_path / "cpp-as-c.json"
    document["schema_version"] = "craevidence.c_semantic_evidence.v2"
    wrong_schema.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(wrong_schema, source)
    assert error.value.reason_code == "unsupported_language"


@pytest.mark.skipif(not _c_semantic_profile_available(), reason="exact libclang is unavailable")
def test_c_evidence_attests_system_printf_and_rejects_homonyms(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fixture_root = Path(__file__).parent / "semantic"
    names = (
        "c_printf_argv_binding.c",
        "c_printf_application_homonym.c",
        "c_printf_wrong_scope.c",
    )
    for name in names:
        (source / name).write_text(
            (fixture_root / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    output = tmp_path / "c-format-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "c", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("c.printf-main-argv-format")
    binding = [
        item for item in evidence.occurrences if item.path == "c_printf_argv_binding.c"
    ]
    assert len(binding) == 3
    assert sum(item.symbol == expected for item in binding) == 1
    assert all(
        item.symbol != expected
        for item in evidence.occurrences
        if item.path in {
            "c_printf_application_homonym.c",
            "c_printf_wrong_scope.c",
        }
    )
    document = json.loads(output.read_text(encoding="utf-8"))
    format_records = [
        item
        for item in document["analysis"]["occurrences"]
        if "printf" in item["classification"]
    ]
    assert [item["classification"] for item in format_records].count(
        "system-printf-main-argv-format"
    ) == 1
    assert [item["classification"] for item in format_records].count(
        "printf-main-argv-not-system-bound"
    ) == 4
    attested_record = next(
        item
        for item in document["analysis"]["occurrences"]
        if item["classification"] == "system-printf-main-argv-format"
    )
    attested_record["callee"] = "puts"
    mutated = tmp_path / "c-format-mutated.json"
    mutated.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(mutated, source)
    assert error.value.reason_code == "occurrence_provenance_mismatch"


@pytest.mark.skipif(not _c_semantic_profile_available(), reason="exact libclang is unavailable")
def test_cpp_evidence_attests_both_system_printf_spellings(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fixture_root = Path(__file__).parent / "semantic"
    names = (
        "cpp_printf_argv_binding.cpp",
        "cpp_printf_application_homonym.cpp",
        "cpp_printf_shadowed_parameter.cpp",
    )
    for name in names:
        (source / name).write_text(
            (fixture_root / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    output = tmp_path / "cpp-format-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "cpp", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("cpp.printf-main-argv-format")
    binding = [
        item for item in evidence.occurrences if item.path == "cpp_printf_argv_binding.cpp"
    ]
    assert len(binding) == 4
    assert sum(item.symbol == expected for item in binding) == 2
    homonym = [
        item
        for item in evidence.occurrences
        if item.path == "cpp_printf_application_homonym.cpp"
    ]
    assert len(homonym) == 1
    assert homonym[0].symbol != expected
    shadow = [
        item
        for item in evidence.occurrences
        if item.path == "cpp_printf_shadowed_parameter.cpp"
    ]
    assert len(shadow) == 1
    assert shadow[0].symbol != expected


@pytest.mark.skipif(not _c_semantic_profile_available(), reason="exact libclang is unavailable")
def test_c_evidence_attests_system_shell_and_rejects_homonyms(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fixture_root = Path(__file__).parent / "semantic"
    names = (
        "c_system_argv_binding.c",
        "c_system_application_homonym.c",
        "c_system_wrong_scope.c",
    )
    for name in names:
        (source / name).write_text(
            (fixture_root / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    output = tmp_path / "c-system-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "c", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("c.system-main-argv-command")
    assert sum(item.symbol == expected for item in evidence.occurrences) == 1
    document = json.loads(output.read_text(encoding="utf-8"))
    records = [
        item
        for item in document["analysis"]["occurrences"]
        if item["classification"].startswith("system-")
        and "printf" not in item["classification"]
    ]
    assert [item["classification"] for item in records].count(
        "system-shell-main-argv-command"
    ) == 1
    assert [item["classification"] for item in records].count(
        "system-main-argv-not-system-bound"
    ) == 4


@pytest.mark.skipif(not _c_semantic_profile_available(), reason="exact libclang is unavailable")
def test_cpp_evidence_attests_both_system_shell_spellings(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fixture_root = Path(__file__).parent / "semantic"
    names = (
        "cpp_system_argv_binding.cpp",
        "cpp_system_application_homonym.cpp",
        "cpp_system_shadowed_parameter.cpp",
    )
    for name in names:
        (source / name).write_text(
            (fixture_root / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    output = tmp_path / "cpp-system-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "cpp", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("cpp.system-main-argv-command")
    assert sum(item.symbol == expected for item in evidence.occurrences) == 2
    document = json.loads(output.read_text(encoding="utf-8"))
    records = [
        item
        for item in document["analysis"]["occurrences"]
        if item["classification"].startswith("system-")
        and "printf" not in item["classification"]
    ]
    assert [item["classification"] for item in records].count(
        "system-shell-main-argv-command"
    ) == 2
    assert [item["classification"] for item in records].count(
        "system-main-argv-not-system-bound"
    ) == 4


@pytest.mark.skipif(not _c_semantic_profile_available(), reason="exact libclang is unavailable")
def test_c_evidence_rejects_syntax_errors_and_inherited_include_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    injected = tmp_path / "injected"
    injected.mkdir()
    (injected / "target_header.h").write_text("typedef int injected_type;\n", encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text(
        "#include <target_header.h>\nvoid run(void) { char value[4]; value[4] = 1; }\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CPATH", str(injected))
    output = tmp_path / "c-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "c", "--output", str(output)],
    )

    assert result.exit_code != 0
    assert "file not found" in result.output
    assert not output.exists()


@pytest.mark.skipif(not _c_semantic_profile_available(), reason="exact libclang is unavailable")
def test_c_evidence_does_not_attribute_header_diagnostic_to_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "bounds.h").write_text(
        "#include <stdint.h>\n"
        "static inline void header_write(int value) {\n"
        "    uint8_t buffer[4];\n"
        "    buffer[4] = (uint8_t)value;\n"
        "}\n",
        encoding="utf-8",
    )
    (source / "main.c").write_text(
        '#include "bounds.h"\n'
        "void source_write(int value) {\n"
        "    uint8_t buffer[4];\n"
        "    buffer[3] = (uint8_t)value;\n"
        "}\n",
        encoding="utf-8",
    )
    output = tmp_path / "c-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "c", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    assert len(evidence.occurrences) == 1
    assert evidence.occurrences[0].start_line == 4
    assert evidence.occurrences[0].symbol == "clang-c17 not-compiler-attested"


@pytest.mark.skipif(not _c_semantic_profile_available(), reason="exact libclang is unavailable")
def test_cpp_evidence_does_not_attribute_header_diagnostic_to_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "bounds.hpp").write_text(
        "#include <cstdint>\n"
        "static inline void header_write(int value) {\n"
        "    uint8_t buffer[4];\n"
        "    buffer[4] = static_cast<uint8_t>(value);\n"
        "}\n",
        encoding="utf-8",
    )
    (source / "main.cpp").write_text(
        '#include "bounds.hpp"\n'
        "void source_write(int value) {\n"
        "    uint8_t buffer[4];\n"
        "    buffer[3] = static_cast<uint8_t>(value);\n"
        "}\n",
        encoding="utf-8",
    )
    output = tmp_path / "cpp-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "cpp", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    assert len(evidence.occurrences) == 1
    assert evidence.occurrences[0].start_line == 4
    assert evidence.occurrences[0].symbol == "clang-cpp17 not-compiler-attested"


def _write_rust_package(root: Path, source: str) -> None:
    (root / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname = "rust-proof"\nversion = "0.1.0"\nedition = "2021"\n\n'
        '[dependencies]\nreqwest = "0.12"\n',
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text(
        "version = 4\n\n"
        "[[package]]\n"
        'name = "rust-proof"\n'
        'version = "0.1.0"\n'
        'dependencies = ["reqwest"]\n\n'
        "[[package]]\n"
        'name = "reqwest"\n'
        'version = "0.12.24"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "9d0946410b9f7b082a427e4ef5c8ff541a88b357bc6c637c40db3a68ac70a36f"\n',
        encoding="utf-8",
    )
    (root / "src" / "lib.rs").write_text(source, encoding="utf-8")


def test_csharp_runtime_environment_drops_inherited_code_loading_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DOTNET_STARTUP_HOOKS", str(tmp_path / "untrusted.dll"))
    monkeypatch.setenv("CORECLR_PROFILER_PATH", str(tmp_path / "untrusted.so"))
    monkeypatch.setenv("DOTNET_ADDITIONAL_DEPS", str(tmp_path / "untrusted.deps.json"))

    environment = _csharp_runtime_environment(Path("/trusted/dotnet"), tmp_path)

    assert environment == {
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_NOLOGO": "1",
        "DOTNET_ROOT": "/trusted/dotnet",
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT": "1",
        "HOME": str(tmp_path),
        "PATH": os.defpath,
    }


def test_rust_evidence_attests_only_absolute_pinned_reqwest_calls(tmp_path: Path) -> None:
    source = tmp_path / "rust-source"
    _write_rust_package(
        source,
        "pub fn run() {\n"
        "    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(true);\n"
        "    let _ = ::reqwest::blocking::ClientBuilder::new()\n"
        "        .danger_accept_invalid_hostnames(true);\n"
        "    let _ = reqwest::Client::builder().danger_accept_invalid_certs(true);\n"
        "}\n",
    )
    output = tmp_path / "rust-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "rust", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("rust.cratesio-reqwest-invalid-certs")
    assert evidence.language == "rust"
    assert [item.symbol for item in evidence.occurrences] == [expected, expected]
    assert [(item.start_line, item.end_line) for item in evidence.occurrences] == [
        (2, 2),
        (3, 4),
    ]
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["isolation"] == {
        "build_scripts_executed": False,
        "cargo_executed": False,
        "compiler_executed": False,
        "network_required": False,
        "proc_macros_executed": False,
        "provenance_source": "static-manifest-lock-and-pinned-checksum",
        "target_code_executed": False,
    }


@pytest.mark.parametrize(
    ("mutation", "expected_message"),
    [
        ("path-dependency", "unsupported keys: path"),
        ("checksum", "checksum is not the pinned package checksum"),
        ("workspace", "workspaces and dependency overrides"),
        ("cargo-config", "project Cargo configuration"),
        ("ancestor-manifest", "ancestor Cargo.toml"),
    ],
)
def test_rust_evidence_rejects_untrusted_binding_inputs(
    tmp_path: Path, mutation: str, expected_message: str
) -> None:
    source = tmp_path / "rust-source"
    rust_text = (
        "pub fn run() {\n"
        "    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(true);\n"
        "}\n"
    )
    _write_rust_package(source, rust_text)
    if mutation == "path-dependency":
        manifest = (source / "Cargo.toml").read_text(encoding="utf-8")
        (source / "Cargo.toml").write_text(
            manifest.replace('reqwest = "0.12"', 'reqwest = { version = "0.12", path = "x" }'),
            encoding="utf-8",
        )
    elif mutation == "checksum":
        lock = (source / "Cargo.lock").read_text(encoding="utf-8")
        (source / "Cargo.lock").write_text(
            lock.replace("9d0946410b9f", "0d0946410b9f"), encoding="utf-8"
        )
    elif mutation == "workspace":
        with (source / "Cargo.toml").open("a", encoding="utf-8") as handle:
            handle.write("\n[workspace]\n")
    elif mutation == "cargo-config":
        (source / ".cargo").mkdir()
        (source / ".cargo" / "config.toml").write_text(
            'paths = ["../replacement"]\n', encoding="utf-8"
        )
    else:
        (tmp_path / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    output = tmp_path / "rust-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "rust", "--output", str(output)],
    )

    assert result.exit_code != 0
    assert expected_message in result.output
    assert not output.exists()


def test_rust_evidence_records_compiling_current_crate_alias(tmp_path: Path) -> None:
    source = tmp_path / "rust-source"
    _write_rust_package(
        source,
        "extern crate self as reqwest;\n"
        "pub struct Client;\n"
        "pub struct Builder;\n"
        "impl Client { pub fn builder() -> Builder { Builder } }\n"
        "impl Builder { pub fn danger_accept_invalid_certs(self, _: bool) -> Self { self } }\n"
        "pub fn run() {\n"
        "    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(true);\n"
        "}\n",
    )
    output = tmp_path / "rust-evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "rust", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("rust.cratesio-reqwest-invalid-certs")
    assert len(evidence.occurrences) == 1
    assert evidence.occurrences[0].symbol != expected
    document = json.loads(output.read_text(encoding="utf-8"))
    occurrence = document["analysis"]["occurrences"][0]
    assert occurrence["binding"] == "application-extern-alias"
    assert occurrence["package_source"] == "local-current-crate"


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("analyzer", "adapter_provenance_mismatch"),
        ("isolation", "isolation_not_attested"),
        ("profile", "analysis_profile_mismatch"),
        ("occurrence", "occurrence_provenance_mismatch"),
    ],
)
def test_rust_evidence_envelope_mutations_fail_closed(
    tmp_path: Path, mutation: str, reason: str
) -> None:
    source = tmp_path / "rust-source"
    _write_rust_package(
        source,
        "pub fn run() {\n"
        "    let _ = ::reqwest::Client::builder().danger_accept_invalid_certs(true);\n"
        "}\n",
    )
    output = tmp_path / "rust-evidence.json"
    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "rust", "--output", str(output)],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(output.read_text(encoding="utf-8"))
    if mutation == "analyzer":
        document["adapter"]["analyzer_sha256"] = "0" * 64
    elif mutation == "isolation":
        document["isolation"]["cargo_executed"] = True
    elif mutation == "profile":
        profile = document["analysis"]["profile"]
        profile["edition"] = "2015"
        document["analysis"]["profile_sha256"] = hashlib.sha256(
            json.dumps(profile, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    else:
        document["analysis"]["occurrences"][0]["package_checksum"] = "0" * 64
    output.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(output, source)

    assert error.value.reason_code == reason


@pytest.mark.skipif(not _csharp_sdk_available(), reason="exact .NET SDK is unavailable")
def test_csharp_evidence_resolves_framework_and_application_owners(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fixture = Path(__file__).parent / "semantic" / "csharp_dangerous_validator_binding.cs"
    (source / "Program.cs").write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
    sentinel = tmp_path / "project-hook-ran"
    (source / "Directory.Build.targets").write_text(
        '<Project><Target Name="Run" BeforeTargets="Build">'
        f'<WriteLinesToFile File="{sentinel}" Lines="executed" />'
        "</Target></Project>\n",
        encoding="utf-8",
    )
    output = tmp_path / "evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "csharp", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    assert not sentinel.exists()
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("csharp.framework-dangerous-certificate-validator")
    assert sum(item.symbol == expected for item in evidence.occurrences) == 1
    assert sum(item.symbol != expected for item in evidence.occurrences) == 1


@pytest.mark.skipif(not _csharp_sdk_available(), reason="exact .NET SDK is unavailable")
def test_csharp_compiler_error_never_writes_evidence(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Program.cs").write_text(
        "class Program { object Run() { return new object() } }\n", encoding="utf-8"
    )
    output = tmp_path / "evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "csharp", "--output", str(output)],
    )

    assert result.exit_code != 0
    assert "compiler analysis failed" in result.output
    assert not output.exists()


@pytest.mark.skipif(not _csharp_sdk_available(), reason="exact .NET SDK is unavailable")
@pytest.mark.parametrize(
    ("fixture_name", "occurrence_count", "framework_count"),
    [
        ("csharp_dangerous_validator_cross_owners.cs", 2, 0),
        ("csharp_dangerous_validator_namespace_shadow.cs", 1, 0),
        ("csharp_dangerous_validator_inherited.cs", 1, 1),
        ("csharp_dangerous_validator_multiple.cs", 2, 2),
        ("csharp_dangerous_validator_conditional.cs", 0, 0),
    ],
)
def test_csharp_evidence_adversarial_owner_matrix(
    tmp_path: Path,
    fixture_name: str,
    occurrence_count: int,
    framework_count: int,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fixture = Path(__file__).parent / "semantic" / fixture_name
    (source / "Program.cs").write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
    output = tmp_path / "evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "csharp", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("csharp.framework-dangerous-certificate-validator")
    assert len(evidence.occurrences) == occurrence_count
    assert sum(item.symbol == expected for item in evidence.occurrences) == framework_count


@pytest.mark.skipif(not _java_available(), reason="Java runtime is unavailable")
def test_java_evidence_attests_jdk_owner_without_build_execution(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Program.java").write_text(
        "import java.security.MessageDigest;\n"
        "class Program { Object run() throws Exception {\n"
        'return MessageDigest.getInstance("MD5"); } }\n',
        encoding="utf-8",
    )
    sentinel = tmp_path / "build-script-ran"
    (source / "build.gradle").write_text(
        f'file("{sentinel}").text = "executed"\n', encoding="utf-8"
    )
    output = tmp_path / "evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "java", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    assert not sentinel.exists()
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("java.jdk-message-digest-get-instance")
    assert evidence.language == "java"
    assert [item.symbol for item in evidence.occurrences] == [expected]


@pytest.mark.skipif(not _java_available(), reason="Java runtime is unavailable")
def test_java_evidence_records_compiling_application_shadow(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Program.java").write_text(
        "import java.security.*;\n"
        "class MessageDigest { static Object getInstance(String value) { return value; } }\n"
        'class Program { Object run() { return MessageDigest.getInstance("MD5"); } }\n',
        encoding="utf-8",
    )
    output = tmp_path / "evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "java", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("java.jdk-message-digest-get-instance")
    assert all(item.symbol != expected for item in evidence.occurrences)
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["isolation"]["build_scripts_executed"] is False


@pytest.mark.skipif(not _java_available(), reason="Java runtime is unavailable")
def test_java_evidence_rejects_nested_dotted_name_lookalike(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Program.java").write_text(
        "class java { static class security { static class MessageDigest {\n"
        "static Object getInstance(String value) { return value; } } } }\n"
        "class Program { Object run() {\n"
        'return java.security.MessageDigest.getInstance("MD5"); } }\n',
        encoding="utf-8",
    )
    output = tmp_path / "evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "java", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    evidence = load_semantic_evidence(output, source)
    expected = expected_symbol("java.jdk-message-digest-get-instance")
    assert all(item.symbol != expected for item in evidence.occurrences)
    occurrence = json.loads(output.read_text(encoding="utf-8"))["analysis"]["occurrences"][0]
    assert occurrence["qualified_name"] == "java.security.MessageDigest"
    assert occurrence["binary_name"] == "java$security$MessageDigest"
    assert occurrence["nesting"] == "MEMBER"


@pytest.mark.skipif(not _java_available(), reason="Java runtime is unavailable")
def test_java_compiler_error_never_writes_evidence(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Program.java").write_text(
        'class Program { Object run() { return "broken" } }\n', encoding="utf-8"
    )
    output = tmp_path / "evidence.json"

    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "java", "--output", str(output)],
    )

    assert result.exit_code != 0
    assert "compiler analysis failed" in result.output
    assert not output.exists()


@pytest.mark.skipif(not _java_available(), reason="Java runtime is unavailable")
def test_java_evidence_rejects_unknown_occurrence_fields(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Program.java").write_text(
        "import java.security.MessageDigest;\n"
        "class Program { Object run() throws Exception {\n"
        'return MessageDigest.getInstance("MD5"); } }\n',
        encoding="utf-8",
    )
    output = tmp_path / "evidence.json"
    result = CliRunner().invoke(
        code_evidence,
        [str(source), "--language", "java", "--output", str(output)],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(output.read_text(encoding="utf-8"))
    document["analysis"]["occurrences"][0]["unreviewed"] = True
    output.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SemanticEvidenceError, match="unexpected=.*unreviewed"):
        load_semantic_evidence(output, source)


def test_java_analyzer_hard_disables_extensible_compiler_inputs() -> None:
    analyzer = (
        Path(__file__).parent.parent / "cra_evidence_cli" / "local" / "java_symbol_analyzer.java"
    ).read_text(encoding="utf-8")

    assert '"-proc:none"' in analyzer
    assert '"-implicit:none"' in analyzer
    assert "StandardLocation.CLASS_PATH, List.of()" in analyzer
    assert "StandardLocation.SOURCE_PATH, List.of()" in analyzer
    assert "ProcessBuilder" not in analyzer
