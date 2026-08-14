from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cra_evidence_cli.commands.code_check import _apply_semantic_evidence
from cra_evidence_cli.local.rules_pack import inspect_rule_pack
from cra_evidence_cli.local.sast_scanner import SASTFinding, SASTReport
from cra_evidence_cli.local.semantic_evidence import (
    SemanticEvidenceError,
    expected_symbol,
    load_semantic_evidence,
    source_tree_manifest,
)

_PACKAGE_SHA512 = (
    "Ss+ENj4K9k+0tV04asKNzgGcFTJRgO7p92KTHAw+4oVgcpzCiiWDiWHu9RUdzHs2AOzNPL6Pi4AZNMIQFybp2w=="
)
_REPO_ROOT = Path(__file__).parent.parent
_RULE_ID = "cra-csharp-framework-md5-create"
_CSHARP_TLS_RULE_ID = "cra-csharp-framework-dangerous-certificate-validator"
_CSHARP_OPTIONS = [
    "/noconfig",
    "/nostdlib+",
    "/target:exe",
    "framework-reference-pack-only",
    "no-project-inputs",
    "sanitized-dotnet-environment",
    "invariant-globalization",
]


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _field(number: int, wire_type: int, value: bytes | int) -> bytes:
    key = _varint((number << 3) | wire_type)
    if wire_type == 0:
        assert isinstance(value, int)
        return key + _varint(value)
    assert wire_type == 2
    assert isinstance(value, bytes)
    return key + _varint(len(value)) + value


def _scip_index(
    *,
    path: str = "Program.cs",
    symbols: tuple[str, ...] = (),
    ranges: tuple[tuple[int, ...], ...] = (),
    typed_ranges: bool = False,
) -> bytes:
    metadata = _field(4, 0, 1)
    document = _field(1, 2, path.encode()) + _field(4, 2, b"C#") + _field(6, 0, 1)
    for symbol, occurrence_range in zip(symbols, ranges, strict=True):
        if typed_ranges:
            assert len(occurrence_range) in {3, 4}
            typed = b"".join(
                _field(index, 0, value) for index, value in enumerate(occurrence_range, start=1)
            )
            range_field = _field(8 if len(occurrence_range) == 3 else 9, 2, typed)
        else:
            packed_range = b"".join(_varint(value) for value in occurrence_range)
            range_field = _field(1, 2, packed_range)
        occurrence = range_field + _field(2, 2, symbol.encode())
        document += _field(2, 2, occurrence)
    return _field(1, 2, metadata) + _field(2, 2, document)


def _write_valid_evidence(
    tmp_path: Path,
    *,
    symbols: tuple[str, ...] | None = None,
    ranges: tuple[tuple[int, ...], ...] | None = None,
) -> tuple[Path, Path, dict]:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "Program.cs").write_text(
        "using System.Security.Cryptography;\nclass Program { object Run() => MD5.Create(); }\n",
        encoding="utf-8",
    )
    (source_root / "Program.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk" />\n', encoding="utf-8"
    )
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    symbol_values = (
        symbols if symbols is not None else (expected_symbol("csharp.framework-md5-create"),)
    )
    range_values = ranges if ranges is not None else ((1, 36, 42),)
    index = _scip_index(symbols=symbol_values, ranges=range_values)
    index_path = evidence_root / "index.scip"
    index_path.write_bytes(index)
    files, tree_digest = source_tree_manifest(source_root)
    build_profile = {
        "configuration": "Debug",
        "target_framework": "net8.0",
        "platform": "AnyCPU",
        "define_constants": ["TRACE", "DEBUG"],
        "project_paths": ["Program.csproj"],
    }
    build_profile_digest = hashlib.sha256(
        json.dumps(
            build_profile,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    envelope = {
        "schema_version": "craevidence.semantic_evidence.v1",
        "language": "csharp",
        "adapter": {
            "profile": "scip-dotnet-0.2.14-dotnet-8.0.423",
            "package_sha512": _PACKAGE_SHA512,
            "executable_version": "0.2.14+3e1f671e65692f517b0d35521fd1951c63939e3c",
            "commit": "3e1f671e65692f517b0d35521fd1951c63939e3c",
            "image_manifest": (
                "sha256:e2f26f26169fd10d6f1b426e01c97397717b32e9d5ab4ee4a7d5497ed9403007"
            ),
            "sdk_version": "8.0.423",
            "arguments": [
                "index",
                "--skip-dotnet-restore",
                "--project",
                "/src/Program.csproj",
            ],
        },
        "isolation": {
            "network": "none",
            "source_read_only": True,
            "root_read_only": True,
            "capabilities_dropped": True,
            "no_new_privileges": True,
            "project_hooks": "contained",
        },
        "source": {"tree_sha256": tree_digest, "files": files},
        "build": {
            "profile": build_profile,
            "profile_sha256": build_profile_digest,
            "projects": [
                {
                    "path": "Program.csproj",
                    "restore_exit_code": 0,
                    "build_exit_code": 0,
                    "workspace_failure_count": 0,
                }
            ],
        },
        "indexes": [{"path": "index.scip", "sha256": hashlib.sha256(index).hexdigest()}],
    }
    envelope_path = evidence_root / "evidence.json"
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
    return envelope_path, source_root, envelope


def _rewrite(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def _write_csharp_direct_evidence(
    tmp_path: Path,
    *,
    framework_owner: bool = True,
    duplicate: bool = False,
) -> tuple[Path, Path, dict]:
    source_root = tmp_path / "direct-source"
    source_root.mkdir()
    (source_root / "Program.cs").write_text(
        "using System.Net.Http;\n"
        "class Program\n"
        "{\n"
        "    void Configure(HttpClientHandler handler)\n"
        "    {\n"
        "        handler.ServerCertificateCustomValidationCallback = "
        "HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    files, tree_digest = source_tree_manifest(source_root, "csharp-direct")
    if framework_owner:
        owner = {
            "assembly": "System.Net.Http",
            "version": "8.0.0.0",
            "token": "b03f5f7f11d50a3a",
            "type": "global::System.Net.Http.HttpClientHandler",
        }
    else:
        owner = {
            "assembly": "CraEvidenceAnalysis",
            "version": "0.0.0.0",  # noqa: S104
            "token": "",
            "type": "global::Application.HttpClientHandler",
        }
    occurrence = {
        "path": "Program.cs",
        "start_line": 6,
        "start_column": 9,
        "end_line": 6,
        "end_column": 123,
        "left_property": "ServerCertificateCustomValidationCallback",
        "left_type": owner["type"],
        "left_assembly": owner["assembly"],
        "left_assembly_version": owner["version"],
        "left_public_key_token": owner["token"],
        "right_property": "DangerousAcceptAnyServerCertificateValidator",
        "right_type": owner["type"],
        "right_assembly": owner["assembly"],
        "right_assembly_version": owner["version"],
        "right_public_key_token": owner["token"],
    }
    analyzer = _REPO_ROOT / "cra_evidence_cli" / "local" / "csharp_symbol_analyzer.cs"
    profile_digest = hashlib.sha256(
        json.dumps(_CSHARP_OPTIONS, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    envelope = {
        "schema_version": "craevidence.csharp_semantic_evidence.v1",
        "language": "csharp",
        "adapter": {
            "profile": "roslyn-direct-framework-symbols-v1",
            "analyzer_sha256": hashlib.sha256(analyzer.read_bytes()).hexdigest(),
            "dotnet_executable_sha256": "1" * 64,
            "sdk_version": "8.0.423",
            "runtime_version": "8.0.29",
            "roslyn_version": "4.11.0.0",
            "reference_pack_version": "8.0.29",
            "reference_pack_sha256": "2" * 64,
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
        "source": {"tree_sha256": tree_digest, "files": files},
        "analysis": {
            "compiler_exit_code": 0,
            "error_count": 0,
            "compiler_options": _CSHARP_OPTIONS.copy(),
            "profile_sha256": profile_digest,
            "occurrences": [occurrence, occurrence.copy()] if duplicate else [occurrence],
        },
    }
    envelope_path = tmp_path / "direct-evidence.json"
    _rewrite(envelope_path, envelope)
    return envelope_path, source_root, envelope


def _candidate_report(source_root: Path) -> SASTReport:
    source = str(source_root / "Program.cs")
    finding = SASTFinding(
        rule_id=_RULE_ID,
        severity="warning",
        file=source,
        line=2,
        start_column=33,
        end_line=2,
        end_column=45,
        message="MD5 candidate",
    )
    sarif_result = {
        "ruleId": _RULE_ID,
        "message": {"text": "MD5 candidate"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": source},
                    "region": {
                        "startLine": 2,
                        "startColumn": 33,
                        "endLine": 2,
                        "endColumn": 45,
                    },
                }
            }
        ],
    }
    return SASTReport(
        engine_version="1.26.0",
        rules_path="bundled",
        rule_count=1,
        findings=[finding],
        scan_failed=False,
        failure_reason=None,
        sarif_raw={"version": "2.1.0", "runs": [{"results": [sarif_result]}]},
        scan_root=str(source_root),
    )


def _csharp_tls_candidate_report(source_root: Path) -> SASTReport:
    source = str(source_root / "Program.cs")
    finding = SASTFinding(
        rule_id=_CSHARP_TLS_RULE_ID,
        severity="error",
        file=source,
        line=6,
        start_column=9,
        end_line=6,
        end_column=123,
        message="TLS candidate",
    )
    sarif_result = {
        "ruleId": _CSHARP_TLS_RULE_ID,
        "message": {"text": "TLS candidate"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": source},
                    "region": {
                        "startLine": 6,
                        "startColumn": 9,
                        "endLine": 6,
                        "endColumn": 123,
                    },
                }
            }
        ],
    }
    return SASTReport(
        engine_version="1.26.0",
        rules_path="bundled",
        rule_count=1,
        findings=[finding],
        scan_failed=False,
        failure_reason=None,
        sarif_raw={"version": "2.1.0", "runs": [{"results": [sarif_result]}]},
        scan_root=str(source_root),
    )


def _inventory():
    return inspect_rule_pack(_REPO_ROOT / "cra_evidence_cli" / "local" / "rules")


def test_csharp_direct_framework_assignment_attests_exact_signed_owners(
    tmp_path: Path,
) -> None:
    envelope_path, source_root, _ = _write_csharp_direct_evidence(tmp_path)
    evidence = load_semantic_evidence(envelope_path, source_root)

    matches = evidence.matching_occurrences(
        path="Program.cs",
        start_line=6,
        start_column=9,
        end_line=6,
        end_column=123,
        symbol=expected_symbol("csharp.framework-dangerous-certificate-validator"),
    )

    assert len(matches) == 1
    assert evidence.adapter_profile == "roslyn-direct-framework-symbols-v1"


def test_csharp_direct_application_assignment_cannot_attest_framework_policy(
    tmp_path: Path,
) -> None:
    envelope_path, source_root, _ = _write_csharp_direct_evidence(tmp_path, framework_owner=False)
    evidence = load_semantic_evidence(envelope_path, source_root)

    assert (
        evidence.matching_occurrences(
            path="Program.cs",
            start_line=6,
            start_column=9,
            end_line=6,
            end_column=123,
            symbol=expected_symbol("csharp.framework-dangerous-certificate-validator"),
        )
        == ()
    )


def test_csharp_direct_command_keeps_exact_framework_owner(tmp_path: Path) -> None:
    envelope_path, source_root, _ = _write_csharp_direct_evidence(tmp_path)
    report = _csharp_tls_candidate_report(source_root)

    _apply_semantic_evidence(report, _inventory(), (envelope_path,), source_root)

    assert len(report.findings) == 1
    assert report.semantic_evidence_summary["attested"] == 1
    assert report.semantic_evidence_summary["unanalysed"] == 0


def test_csharp_direct_command_rejects_recorded_application_owner(
    tmp_path: Path,
) -> None:
    envelope_path, source_root, _ = _write_csharp_direct_evidence(tmp_path, framework_owner=False)
    report = _csharp_tls_candidate_report(source_root)

    _apply_semantic_evidence(report, _inventory(), (envelope_path,), source_root)

    assert report.findings == []
    assert report.unanalysed_files == []
    assert report.semantic_evidence_summary["rejected"] == 1


def test_csharp_direct_command_missing_range_degrades_coverage(tmp_path: Path) -> None:
    envelope_path, source_root, envelope = _write_csharp_direct_evidence(tmp_path)
    envelope["analysis"]["occurrences"] = []
    _rewrite(envelope_path, envelope)
    report = _csharp_tls_candidate_report(source_root)

    _apply_semantic_evidence(report, _inventory(), (envelope_path,), source_root)

    assert report.findings == []
    assert report.unanalysed_files == [
        {
            "path": "Program.cs",
            "language": "C#",
            "reason": "semantic_occurrence_missing",
        }
    ]
    assert report.semantic_evidence_summary["unanalysed"] == 1


def test_csharp_direct_command_duplicate_range_degrades_coverage(tmp_path: Path) -> None:
    envelope_path, source_root, _ = _write_csharp_direct_evidence(tmp_path, duplicate=True)
    report = _csharp_tls_candidate_report(source_root)

    _apply_semantic_evidence(report, _inventory(), (envelope_path,), source_root)

    assert report.findings == []
    assert report.unanalysed_files[0]["reason"] == "semantic_occurrence_ambiguous"
    assert report.semantic_evidence_summary["unanalysed"] == 1


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda envelope: envelope["adapter"].update(analyzer_sha256="0" * 64),
            "adapter_provenance_mismatch",
        ),
        (
            lambda envelope: envelope["isolation"].update(projects_loaded=True),
            "isolation_not_attested",
        ),
        (lambda envelope: envelope["analysis"].update(error_count=1), "compiler_diagnostics"),
        (
            lambda envelope: envelope["analysis"]["compiler_options"].pop(),
            "analysis_profile_mismatch",
        ),
    ],
)
def test_csharp_direct_provenance_and_isolation_mutations_fail_closed(
    tmp_path: Path, mutate, reason: str
) -> None:
    envelope_path, source_root, envelope = _write_csharp_direct_evidence(tmp_path)
    mutate(envelope)
    _rewrite(envelope_path, envelope)

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(envelope_path, source_root)

    assert error.value.reason_code == reason


def test_csharp_direct_duplicate_occurrence_remains_ambiguous(tmp_path: Path) -> None:
    envelope_path, source_root, _ = _write_csharp_direct_evidence(tmp_path, duplicate=True)
    evidence = load_semantic_evidence(envelope_path, source_root)

    matches = evidence.matching_occurrences(
        path="Program.cs",
        start_line=6,
        start_column=9,
        end_line=6,
        end_column=123,
        symbol=expected_symbol("csharp.framework-dangerous-certificate-validator"),
    )

    assert len(matches) == 2


def test_csharp_direct_schema_and_consumer_require_the_same_profile() -> None:
    schema = json.loads(
        (
            _REPO_ROOT / "cra_evidence_cli" / "local" / "csharp_semantic_evidence.schema.json"
        ).read_text(encoding="utf-8")
    )

    assert (
        schema["properties"]["analysis"]["properties"]["compiler_options"]["const"]
        == _CSHARP_OPTIONS
    )


def test_csharp_analyzer_has_no_project_or_code_execution_inputs() -> None:
    analyzer = (_REPO_ROOT / "cra_evidence_cli" / "local" / "csharp_symbol_analyzer.cs").read_text(
        encoding="utf-8"
    )

    assert "CSharpCompilation.Create(" in analyzer
    assert "compilation.GetDiagnostics()" in analyzer
    assert "model.GetSymbolInfo(assignment.Left)" in analyzer
    assert "model.GetSymbolInfo(assignment.Right)" in analyzer
    for forbidden in (
        ".csproj",
        "Assembly.Load",
        "CSharpGeneratorDriver",
        "Emit(",
        "MSBuild",
        "Process.Start",
    ):
        assert forbidden not in analyzer


def test_genuine_framework_occurrence_is_bound_to_candidate_range(tmp_path: Path) -> None:
    envelope_path, source_root, _ = _write_valid_evidence(tmp_path)
    evidence = load_semantic_evidence(envelope_path, source_root)

    matches = evidence.matching_occurrences(
        path="Program.cs",
        start_line=2,
        start_column=33,
        end_line=2,
        end_column=45,
        symbol=expected_symbol("csharp.framework-md5-create"),
    )

    assert len(matches) == 1
    assert matches[0].start_column == 37
    assert evidence.adapter_profile == "scip-dotnet-0.2.14-dotnet-8.0.423"


def test_application_shadow_does_not_attest_framework_policy(tmp_path: Path) -> None:
    shadow = "scip-dotnet nuget . . Cryptography/MD5#Create()."
    envelope_path, source_root, _ = _write_valid_evidence(
        tmp_path, symbols=(shadow,), ranges=((1, 36, 42),)
    )
    evidence = load_semantic_evidence(envelope_path, source_root)

    matches = evidence.matching_occurrences(
        path="Program.cs",
        start_line=2,
        start_column=33,
        end_line=2,
        end_column=45,
        symbol=expected_symbol("csharp.framework-md5-create"),
    )

    assert matches == ()


def test_typed_scip_range_is_accepted(tmp_path: Path) -> None:
    envelope_path, source_root, envelope = _write_valid_evidence(tmp_path)
    index = _scip_index(
        symbols=(expected_symbol("csharp.framework-md5-create"),),
        ranges=((1, 36, 42),),
        typed_ranges=True,
    )
    (envelope_path.parent / "index.scip").write_bytes(index)
    envelope["indexes"][0]["sha256"] = hashlib.sha256(index).hexdigest()
    _rewrite(envelope_path, envelope)

    evidence = load_semantic_evidence(envelope_path, source_root)

    assert evidence.occurrences[0].start_column == 37


def test_duplicate_framework_occurrences_are_visible_as_ambiguous(tmp_path: Path) -> None:
    symbol = expected_symbol("csharp.framework-md5-create")
    envelope_path, source_root, _ = _write_valid_evidence(
        tmp_path,
        symbols=(symbol, symbol),
        ranges=((1, 36, 42), (1, 37, 42)),
    )
    evidence = load_semantic_evidence(envelope_path, source_root)

    matches = evidence.matching_occurrences(
        path="Program.cs",
        start_line=2,
        start_column=33,
        end_line=2,
        end_column=45,
        symbol=symbol,
    )

    assert len(matches) == 2


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("schema_version", "future", "unsupported_schema"),
        ("language", "java", "unsupported_language"),
    ],
)
def test_envelope_identity_fails_closed(
    tmp_path: Path, field: str, value: str, reason: str
) -> None:
    envelope_path, source_root, envelope = _write_valid_evidence(tmp_path)
    envelope[field] = value
    _rewrite(envelope_path, envelope)

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(envelope_path, source_root)

    assert error.value.reason_code == reason


def test_adapter_version_drift_fails_closed(tmp_path: Path) -> None:
    envelope_path, source_root, envelope = _write_valid_evidence(tmp_path)
    envelope["adapter"]["executable_version"] = "0.2.15"
    _rewrite(envelope_path, envelope)

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(envelope_path, source_root)

    assert error.value.reason_code == "adapter_provenance_mismatch"


def test_missing_skip_restore_argument_fails_closed(tmp_path: Path) -> None:
    envelope_path, source_root, envelope = _write_valid_evidence(tmp_path)
    envelope["adapter"]["arguments"].remove("--skip-dotnet-restore")
    _rewrite(envelope_path, envelope)

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(envelope_path, source_root)

    assert error.value.reason_code == "adapter_arguments_unsafe"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("restore_exit_code", 1, "restore_failed"),
        ("build_exit_code", 1, "build_failed"),
        ("workspace_failure_count", 1, "workspace_failure"),
    ],
)
def test_failed_build_evidence_is_never_accepted(
    tmp_path: Path, field: str, value: int, reason: str
) -> None:
    envelope_path, source_root, envelope = _write_valid_evidence(tmp_path)
    envelope["build"]["projects"][0][field] = value
    _rewrite(envelope_path, envelope)

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(envelope_path, source_root)

    assert error.value.reason_code == reason


def test_source_change_invalidates_evidence(tmp_path: Path) -> None:
    envelope_path, source_root, _ = _write_valid_evidence(tmp_path)
    (source_root / "Program.cs").write_text("class Changed {}\n", encoding="utf-8")

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(envelope_path, source_root)

    assert error.value.reason_code == "stale_source"


def test_index_digest_change_invalidates_evidence(tmp_path: Path) -> None:
    envelope_path, source_root, _ = _write_valid_evidence(tmp_path)
    (envelope_path.parent / "index.scip").write_bytes(b"changed")

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(envelope_path, source_root)

    assert error.value.reason_code == "stale_index"


def test_truncated_scip_fails_closed(tmp_path: Path) -> None:
    envelope_path, source_root, envelope = _write_valid_evidence(tmp_path)
    index_path = envelope_path.parent / "index.scip"
    index_path.write_bytes(b"\x0a\x80")
    envelope["indexes"][0]["sha256"] = hashlib.sha256(b"\x0a\x80").hexdigest()
    _rewrite(envelope_path, envelope)

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(envelope_path, source_root)

    assert error.value.reason_code == "invalid_scip"


def test_index_symlink_is_rejected(tmp_path: Path) -> None:
    envelope_path, source_root, envelope = _write_valid_evidence(tmp_path)
    original = envelope_path.parent / "index.scip"
    target = tmp_path / "outside.scip"
    original.replace(target)
    original.symlink_to(target)
    envelope["indexes"][0]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    _rewrite(envelope_path, envelope)

    with pytest.raises(SemanticEvidenceError) as error:
        load_semantic_evidence(envelope_path, source_root)

    assert error.value.reason_code == "index_unavailable"


def test_command_filter_keeps_only_attested_framework_candidate(tmp_path: Path) -> None:
    envelope_path, source_root, _ = _write_valid_evidence(tmp_path)
    report = _candidate_report(source_root)

    _apply_semantic_evidence(report, _inventory(), (envelope_path,), source_root)

    assert len(report.findings) == 1
    assert report.findings[0].semantic_evidence == {
        "status": "attested",
        "reason_code": "semantic_symbol_attested",
        "policy": "csharp.framework-md5-create",
        "adapter_profile": "scip-dotnet-0.2.14-dotnet-8.0.423",
        "source_tree_sha256": report.findings[0].semantic_evidence["source_tree_sha256"],
        "build_profile_sha256": report.findings[0].semantic_evidence["build_profile_sha256"],
    }
    assert report.semantic_evidence_summary["attested"] == 1
    result = report.sarif_raw["runs"][0]["results"][0]
    assert result["properties"]["craEvidenceSemanticEvidence"]["status"] == ("attested")


def test_command_filter_rejects_application_shadow_without_degrading(tmp_path: Path) -> None:
    shadow = "scip-dotnet nuget . . Cryptography/MD5#Create()."
    envelope_path, source_root, _ = _write_valid_evidence(
        tmp_path, symbols=(shadow,), ranges=((1, 36, 42),)
    )
    report = _candidate_report(source_root)

    _apply_semantic_evidence(report, _inventory(), (envelope_path,), source_root)

    assert report.findings == []
    assert report.unanalysed_files == []
    assert report.semantic_evidence_summary == {
        "schema_version": "craevidence.semantic_summary.v1",
        "candidate_count": 1,
        "attested": 0,
        "rejected": 1,
        "unanalysed": 0,
        "reason_counts": {"semantic_symbol_not_attested": 1},
    }
    assert report.sarif_raw["runs"][0]["results"] == []


def test_command_filter_missing_evidence_degrades_coverage(tmp_path: Path) -> None:
    _, source_root, _ = _write_valid_evidence(tmp_path)
    report = _candidate_report(source_root)

    _apply_semantic_evidence(report, _inventory(), (), source_root)

    assert report.findings == []
    assert report.unanalysed_files == [
        {
            "path": "Program.cs",
            "language": "C#",
            "reason": "semantic_evidence_missing",
        }
    ]
    assert report.semantic_evidence_summary["unanalysed"] == 1


def test_command_filter_workspace_failure_degrades_coverage(tmp_path: Path) -> None:
    envelope_path, source_root, envelope = _write_valid_evidence(tmp_path)
    envelope["build"]["projects"][0]["workspace_failure_count"] = 1
    _rewrite(envelope_path, envelope)
    report = _candidate_report(source_root)

    _apply_semantic_evidence(report, _inventory(), (envelope_path,), source_root)

    assert report.findings == []
    assert report.unanalysed_files[0]["reason"] == "workspace_failure"
    assert report.semantic_evidence_summary["reason_counts"] == {"workspace_failure": 1}
