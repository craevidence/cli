from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
from pathlib import Path
from zipfile import ZipFile

import pytest

from scripts import check_rulepack_batch as batch
from scripts import check_rulepack_real_projects as real_projects
from scripts import fetch_rulepack_corpora as fetch_corpora
from scripts import score_rulepack_benchmarks as benchmarks
from scripts.rulepack_engine import EngineIdentityError, verify_engine

REPO_ROOT = Path(__file__).parent.parent
REAL_PROJECTS = Path(__file__).parent / "rulepack_real_projects.json"
BENCHMARKS = Path(__file__).parent / "rulepack_benchmarks.json"


def test_non_python_default_rules_have_fail_closed_evidence() -> None:
    from cra_evidence_cli.local.rules_pack import PACK_VERSION, inspect_rule_pack

    manifest = json.loads(BENCHMARKS.read_text(encoding="utf-8"))
    real_manifest = json.loads(REAL_PROJECTS.read_text(encoding="utf-8"))
    inventory = inspect_rule_pack(REPO_ROOT / "cra_evidence_cli" / "local" / "rules")
    entries = manifest["default_tier_evidence"]
    benchmarks_by_name = {benchmark["name"]: benchmark for benchmark in manifest["benchmarks"]}

    expected = {
        rule_id
        for rule_id, tier in inventory.rule_tiers.items()
        if tier == "default" and inventory.rule_languages[rule_id] != "python"
    }
    recorded = {entry["rule_id"] for entry in entries}
    assert recorded == expected
    assert len(recorded) == len(entries)

    real_projects = {project["name"] for project in real_manifest["projects"]}
    for entry in entries:
        assert entry["pack_version"] == PACK_VERSION
        assert entry["terminal_decision"] == "default"
        assert entry["evidence_route"] in {"A", "B"}
        assert entry["real_project_lane"] in real_projects
        assert entry["real_project_evidence"]

        if entry["evidence_route"] == "A":
            assert entry["precision"] >= 0.9
            assert entry["detected_positive_count"] > 0
            assert entry["safe_case_count"] > 0
            intrinsic = entry.get("ownership_model") == "language-intrinsic"
            if intrinsic:
                assert entry["compiling_homonym_status"] == (
                    "not applicable: no identifier or API binding"
                )
                assert entry["compiling_homonym_fixtures"] == []
            else:
                assert entry["compiling_homonym_status"] == "no findings"
            assert entry["benchmark_lanes"]
            for lane in entry["benchmark_lanes"]:
                assert lane in benchmarks_by_name
            assert entry["semantic_benchmark"]
            fixtures = entry["compiling_homonym_fixtures"]
            for fixture in fixtures:
                assert (REPO_ROOT / fixture).is_file()
            for semantic_test in entry["semantic_tests"]:
                test_path, test_name = semantic_test.split("::", maxsplit=1)
                semantic_source = (REPO_ROOT / test_path).read_text(encoding="utf-8")
                assert f"def {test_name}(" in semantic_source
            companion = entry.get("companion_rule")
            if companion is not None:
                assert inventory.rule_tiers[companion] == "experimental"
            continue

        fixtures = entry["compiling_homonym_fixtures"]
        assert fixtures
        assert entry["binding_basis"]
        for fixture in fixtures:
            assert (REPO_ROOT / fixture).is_file()
        test_path, test_name = entry["semantic_test"].split("::", maxsplit=1)
        semantic_source = (REPO_ROOT / test_path).read_text(encoding="utf-8")
        assert f"def {test_name}(" in semantic_source
        if entry["rule_id"] == "cra-csharp-framework-dangerous-certificate-validator":
            assert entry["semantic_producer"] == "code-evidence --language csharp"
            assert entry["sdk_version"] == "8.0.423"
            assert entry["reference_pack_version"] == "8.0.29"
            assert "PublicKeyToken=b03f5f7f11d50a3a" in entry["framework_assembly"]
            assert entry["binding_references"] == [
                "https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.dangerousacceptanyservercertificatevalidator",
                "https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.servercertificatecustomvalidationcallback",
            ]
            assert (REPO_ROOT / entry["analyzer_asset"]).is_file()
            assert (REPO_ROOT / entry["schema_asset"]).is_file()
        if entry["rule_id"] == "cra-rust-cratesio-reqwest-invalid-certs":
            assert entry["semantic_producer"] == "code-evidence --language rust"
            assert entry["compiler_version"] == "rustc 1.88.0 (6b00bc388 2025-06-23)"
            assert re.fullmatch(r"rust@sha256:[0-9a-f]{64}", entry["compiler_image"])
            assert entry["package_name"] == "reqwest"
            assert entry["package_version"] == "0.12.24"
            assert entry["package_source"] == (
                "registry+https://github.com/rust-lang/crates.io-index"
            )
            assert re.fullmatch(r"[0-9a-f]{64}", entry["package_checksum"])
            assert entry["broad_benchmark_lane"] == "codeql-rust-cwe295"
            assert entry["broad_benchmark_rule"] == "cra-rust-reqwest-invalid-certs"
            assert entry["narrow_benchmark_findings"] == 0
            assert "no locations are credited" in entry["benchmark_attribution"]
            for field in (
                "analyzer_asset",
                "schema_asset",
                "compiling_positive_fixture",
                "compiler_dependency_fixture",
            ):
                assert (REPO_ROOT / entry[field]).is_file()
        if entry["rule_id"] == "cra-c-fixed-array-literal-oob-write":
            assert entry["semantic_producer"] == "code-evidence --language c"
            assert entry["compiler_frontend"] == (
                "Ubuntu clang version 18.1.3 (1ubuntu1)"
            )
            assert re.fullmatch(r"[0-9a-f]{64}", entry["compiler_library_sha256"])
            assert entry["compiler_profile"] == (
                "libclang-18-c17-security-evidence-v2"
            )
            assert entry["container_compiler_frontend"] == (
                "Debian clang version 18.1.8 (18+b1)"
            )
            assert entry["container_compiler_library_sha256_by_arch"] == {
                "amd64": "4b9b5073e3dad198b23589a81ce317b0224b36cfa5776305b48d138a53bf2e1d",
                "arm64": "939adf9a6d00fd3ed53c7cecace983f885431d4e9c61a9dc01999517c64b27dd",
            }
            assert entry["container_resource_headers_sha256_by_arch"] == {
                "amd64": "9ecfc31a5e9b723c6ad8e62fce9839907cc0cdaf44b68a37ece1dc9a55ab51c8",
                "arm64": "8343b19f446ea7d62767fa342753ba8c1b535ec6973ee8b17182822bba656b67",
            }
            assert entry["container_compiler_profile"] == (
                "libclang-18.1.8-debian13-c17-security-evidence-v2"
            )
            origin_path, origin_test = entry["diagnostic_origin_test"].split(
                "::", maxsplit=1
            )
            origin_source = (REPO_ROOT / origin_path).read_text(encoding="utf-8")
            assert f"def {origin_test}(" in origin_source
            assert (REPO_ROOT / entry["analyzer_asset"]).is_file()
            assert (REPO_ROOT / entry["schema_asset"]).is_file()
        if entry["rule_id"] == "cra-cpp-fixed-array-literal-oob-write":
            assert entry["semantic_producer"] == "code-evidence --language cpp"
            assert entry["compiler_frontend"] == (
                "Ubuntu clang version 18.1.3 (1ubuntu1)"
            )
            assert re.fullmatch(r"[0-9a-f]{64}", entry["compiler_library_sha256"])
            assert entry["compiler_profile"] == (
                "libclang-18-cpp17-security-evidence-v2"
            )
            assert entry["container_compiler_frontend"] == (
                "Debian clang version 18.1.8 (18+b1)"
            )
            assert entry["container_compiler_library_sha256_by_arch"] == {
                "amd64": "4b9b5073e3dad198b23589a81ce317b0224b36cfa5776305b48d138a53bf2e1d",
                "arm64": "939adf9a6d00fd3ed53c7cecace983f885431d4e9c61a9dc01999517c64b27dd",
            }
            assert entry["container_resource_headers_sha256_by_arch"] == {
                "amd64": "02371ccb4f079176c8f92152e50769067facb335bca9381b1662c9f9d0f71985",
                "arm64": "264f66375eebe65d080ac48c5931c59841e9c06eaa504b5abd0ce7ceb4de43ce",
            }
            assert entry["container_compiler_profile"] == (
                "libclang-18.1.8-debian13-cpp17-security-evidence-v2"
            )
            origin_path, origin_test = entry["diagnostic_origin_test"].split(
                "::", maxsplit=1
            )
            origin_source = (REPO_ROOT / origin_path).read_text(encoding="utf-8")
            assert f"def {origin_test}(" in origin_source
            assert (REPO_ROOT / entry["analyzer_asset"]).is_file()
            assert (REPO_ROOT / entry["schema_asset"]).is_file()
        if entry["rule_id"] in {
            "cra-c-printf-argv-format",
            "cra-c-system-argv",
            "cra-cpp-printf-argv-format",
            "cra-cpp-system-argv",
        }:
            language = "c" if entry["rule_id"].startswith("cra-c-") else "cpp"
            standard = "c17" if language == "c" else "cpp17"
            assert entry["semantic_producer"] == f"code-evidence --language {language}"
            assert entry["compiler_frontend"] == (
                "Ubuntu clang version 18.1.3 (1ubuntu1)"
            )
            assert re.fullmatch(r"[0-9a-f]{64}", entry["compiler_library_sha256"])
            assert entry["compiler_profile"] == (
                f"libclang-18-{standard}-security-evidence-v2"
            )
            assert entry["container_compiler_frontend"] == (
                "Debian clang version 18.1.8 (18+b1)"
            )
            assert entry["container_compiler_profile"] == (
                f"libclang-18.1.8-debian13-{standard}-security-evidence-v2"
            )
            for field in (
                "analyzer_asset",
                "schema_asset",
                "compiling_positive_fixture",
            ):
                assert (REPO_ROOT / entry[field]).is_file()
            end_to_end_path, end_to_end_test = entry["end_to_end_test"].split(
                "::", maxsplit=1
            )
            end_to_end_source = (REPO_ROOT / end_to_end_path).read_text(
                encoding="utf-8"
            )
            assert f"def {end_to_end_test}(" in end_to_end_source
        runtime_probes = entry.get("runtime_probe_files", [])
        for runtime_probe in runtime_probes:
            assert (REPO_ROOT / runtime_probe).is_file()
        if runtime_probes:
            assert re.fullmatch(r"php@sha256:[0-9a-f]{64}", entry["runtime_image"])
        companion = entry.get("companion_rule")
        if companion is not None:
            assert inventory.rule_tiers[companion] == "experimental"


def test_real_project_manifest_pins_unique_licensed_revisions() -> None:
    manifest = json.loads(REAL_PROJECTS.read_text(encoding="utf-8"))
    projects = manifest["projects"]
    assert {project["language"] for project in projects} == {
        "python",
        "javascript",
        "go",
        "java",
        "c",
        "cpp",
        "rust",
        "php",
        "csharp",
    }
    assert len({project["name"] for project in projects}) == len(projects)
    for project in projects:
        assert re.fullmatch(r"[0-9a-f]{40}", project["commit"])
        assert project["repository"].startswith("https://github.com/")
        assert project["license_file"]
        assert project["tracked_source_files"] >= project["expected"]["files_scanned"]
        assert project["known_engine_exclusions"]
        assert project["capability_overlap"]
        assert project["expected"]["files_scanned"] > 0
        errors = sum(project["expected"]["engine_errors_by_kind"].values())
        assert project["parse_coverage_complete"] is (errors == 0)


def test_real_project_error_kind_handles_pinned_engine_shapes() -> None:
    assert real_projects._error_kind({"type": "Syntax error"}) == "Syntax error"
    assert real_projects._error_kind({"type": ["PartialParsing", []]}) == ("PartialParsing")
    assert real_projects._error_kind({"type": []}) == "Unknown"


def test_real_project_result_path_must_stay_inside_target(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    inside = target / "src" / "app.java"
    inside.parent.mkdir()
    inside.touch()
    result = real_projects._relative_result(
        {
            "check_id": "cra-example",
            "path": str(inside),
            "start": {"line": 4, "col": 2},
        },
        target,
    )
    assert result == {
        "rule_id": "cra-example",
        "path": "src/app.java",
        "line": 4,
        "column": 2,
    }
    outside = tmp_path / "outside.java"
    outside.touch()
    with pytest.raises(real_projects.CorpusGateError, match="escapes corpus"):
        real_projects._relative_result({"path": str(outside)}, target)


def test_tracked_source_count_uses_declared_scope_and_language(tmp_path: Path) -> None:
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True)  # noqa: S603
    (tmp_path / "src").mkdir()
    (tmp_path / "test").mkdir()
    (tmp_path / "src" / "main.cpp").touch()
    (tmp_path / "src" / "compat.c").touch()
    (tmp_path / "test" / "main.cpp").touch()
    (tmp_path / "README.md").touch()
    subprocess.run(  # noqa: S603
        [git, "-C", str(tmp_path), "add", "."], check=True
    )

    assert real_projects._tracked_source_count(tmp_path, ".", "cpp") == 3
    assert real_projects._tracked_source_count(tmp_path, "src", "cpp") == 2


def test_benchmark_score_counts_true_and_false_results() -> None:
    document = {
        "paths": {"scanned": ["BenchmarkTest00001.java", "BenchmarkTest00002.java"]},
        "errors": [],
        "results": [
            {
                "check_id": "cra-cwe-89",
                "path": "/corpus/BenchmarkTest00001.java",
                "start": {"line": 10, "col": 3},
            },
            {
                "check_id": "cra-cwe-89",
                "path": "/corpus/BenchmarkTest00002.java",
                "start": {"line": 20, "col": 3},
            },
        ],
    }
    cases = {
        "BenchmarkTest00001": (89, True),
        "BenchmarkTest00002": (89, False),
        "BenchmarkTest00003": (89, True),
        "BenchmarkTest00004": (89, False),
    }
    score = benchmarks._score(document, cases, {"cra-cwe-89": {89}})
    assert score == {
        "files_scanned": 2,
        "engine_errors": 0,
        "metrics_by_cwe": {
            "89": {"tp": 1, "fp": 1, "fn": 1, "tn": 1},
        },
        "metrics_by_rule": {
            "cra-cwe-89": {
                "89": {"tp": 1, "fp": 1, "fn": 1, "tn": 1},
            }
        },
    }


def test_juliet_score_records_case_recall_and_location_corroboration(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.xml"
    manifest.write_text(
        "<container>"
        "<testcase><file path='CWE328_one.java'>"
        "<flaw line='10' name='CWE-328'/></file></testcase>"
        "<testcase><file path='CWE328_two.java'>"
        "<flaw line='20' name='CWE-328'/></file></testcase>"
        "</container>",
        encoding="utf-8",
    )
    document = {
        "paths": {"scanned": ["CWE328_one.java", "CWE328_two.java"]},
        "errors": [],
        "results": [
            {
                "check_id": "cra-java-weak-message-digest",
                "path": str(tmp_path / "CWE328_one.java"),
                "start": {"line": 10, "col": 3},
            }
        ],
    }

    assert benchmarks._score_juliet(
        document,
        manifest,
        {"cra-java-weak-message-digest": 328},
    ) == {
        "files_scanned": 2,
        "engine_errors": 0,
        "metrics_by_rule": {
            "cra-java-weak-message-digest": {
                "cwe": 328,
                "cases_total": 2,
                "cases_detected": 1,
                "cases_missed": 1,
                "files_with_findings": 1,
                "finding_count": 1,
                "findings_at_manifest_flaws": 1,
                "findings_outside_manifest_flaws": 0,
            }
        },
    }


def test_benchmark_score_rejects_empty_cwe_intersection() -> None:
    with pytest.raises(benchmarks.BenchmarkGateError, match="no CWE intersection"):
        benchmarks._score(
            {"paths": {"scanned": ["BenchmarkTest00001.java"]}},
            {"BenchmarkTest00001": (89, True)},
            {"cra-unrelated": {9999}},
        )


def test_benchmark_score_rejects_zero_selected_files() -> None:
    with pytest.raises(benchmarks.BenchmarkGateError, match="evaluated zero files"):
        benchmarks._score(
            {"paths": {"scanned": []}, "results": []},
            {"BenchmarkTest00001": (89, True)},
            {"cra-cwe-89": {89}},
        )


def test_benchmark_score_rejects_cross_category_finding() -> None:
    document = {
        "paths": {"scanned": ["BenchmarkTest00001.java"]},
        "results": [
            {
                "check_id": "cra-cwe-78",
                "path": "/corpus/BenchmarkTest00001.java",
                "start": {"line": 10, "col": 3},
            }
        ],
    }
    with pytest.raises(benchmarks.BenchmarkGateError, match="cannot be scored safely"):
        benchmarks._score(
            document,
            {"BenchmarkTest00001": (89, False)},
            {"cra-cwe-78": {78}, "cra-cwe-89": {89}},
        )


def test_benchmark_cwe_aliases_are_bound_to_reviewed_corpus_pairs() -> None:
    assert benchmarks._reviewed_cwe_aliases("owasp-benchmark-python", {"94": 95}) == {94: 95}
    with pytest.raises(benchmarks.BenchmarkGateError, match="unreviewed CWE aliases"):
        benchmarks._reviewed_cwe_aliases("another-corpus", {"94": 95})


def test_juliet_method_score_ignores_findings_from_other_rules(tmp_path: Path) -> None:
    source = tmp_path / "Case.cs"
    source.write_text(
        "public void Bad()\n{\n    Sink();\n}\npublic void Good()\n{\n    Sink();\n}\n",
        encoding="utf-8",
    )
    document = {
        "results": [
            {
                "check_id": "measured-rule",
                "path": str(source),
                "start": {"line": 3},
            },
            {
                "check_id": "unrelated-rule",
                "path": str(source),
                "start": {"line": 7},
            },
        ]
    }

    assert benchmarks._score_juliet_methods(
        document, benchmarks.CSHARP_METHOD_RE, "measured-rule"
    ) == {
        "files_with_bad_finding": 1,
        "findings_in_good_methods": 0,
        "findings_not_attributed": 0,
    }


def test_preprocessed_juliet_score_ignores_other_rules(tmp_path: Path) -> None:
    source = tmp_path / "case.c"
    source.write_text(
        "void case_bad()\n{\n    mktemp(buffer);\n}\nvoid good_case()\n{\n    mktemp(buffer);\n}\n",
        encoding="utf-8",
    )
    document = {
        "results": [
            {
                "check_id": "measured-rule",
                "path": str(source),
                "start": {"line": 3},
            },
            {
                "check_id": "unrelated-rule",
                "path": str(source),
                "start": {"line": 7},
            },
        ]
    }

    assert benchmarks._score_juliet_preprocessed(document, 1, 0, "measured-rule") == {
        "preprocessed_files": 1,
        "skipped_files": 0,
        "files_with_bad_finding": 1,
        "findings_in_good_on_insecure_call": 0,
        "findings_in_good_on_secure_call": 0,
    }


def test_codeql_score_enforces_rule_ownership_and_one_to_one_spans(
    tmp_path: Path,
) -> None:
    source = tmp_path / "query"
    source.mkdir()
    case = source / "Case.java"
    case.write_text(
        "first(); // $ hasQuery\nsecond(); // $ hasQuery\nsafe(); // GOOD\n",
        encoding="utf-8",
    )
    document = {
        "results": [
            {
                "check_id": "measured-rule",
                "path": str(case),
                "start": {"line": 1},
                "end": {"line": 3},
            },
            {
                "check_id": "unrelated-rule",
                "path": str(case),
                "start": {"line": 2},
                "end": {"line": 2},
            },
        ]
    }

    assert benchmarks._score_codeql_markers(document, source, "hasQuery", "measured-rule") == {
        "alert_lines": 2,
        "alert_lines_covered": 1,
        "good_lines": 1,
        "good_lines_reported": 1,
        "findings_scored": 1,
    }


def test_codeql_score_does_not_merge_duplicate_basenames(tmp_path: Path) -> None:
    source = tmp_path / "query"
    first = source / "first" / "Case.java"
    second = source / "second" / "Case.java"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("first(); // $ hasQuery\n", encoding="utf-8")
    second.write_text("second(); // $ hasQuery\n", encoding="utf-8")
    document = {
        "results": [
            {
                "check_id": "measured-rule",
                "path": str(first),
                "start": {"line": 1},
                "end": {"line": 1},
            }
        ]
    }

    score = benchmarks._score_codeql_markers(document, source, "hasQuery", "measured-rule")

    assert score["alert_lines"] == 2
    assert score["alert_lines_covered"] == 1


def test_sard_truth_uses_exact_variables_and_plain_assignment(tmp_path: Path) -> None:
    safe = tmp_path / "safe" / "case.php"
    safe.parent.mkdir()
    safe.write_text("MODIFICATIONS.*/\n$tained_suffix = $tainted;\n", encoding="utf-8")
    assert benchmarks._sard_truth(safe, "$tained", "$sanitized") == "safe"

    comparison = tmp_path / "unsafe" / "comparison.php"
    comparison.parent.mkdir()
    comparison.write_text(
        "MODIFICATIONS.*/\nif ($sanitized == 'allowed') {}\n$tainted = $sanitized;\n",
        encoding="utf-8",
    )
    assert benchmarks._sard_truth(comparison, "$tained", "$sanitized") == "safe"

    assigned = comparison.with_name("assigned.php")
    assigned.write_text(
        "MODIFICATIONS.*/\n$sanitized = clean($tainted);\n$tainted = $sanitized;\n",
        encoding="utf-8",
    )
    assert benchmarks._sard_truth(assigned, "$tained", "$sanitized") == "vulnerable"


def test_gosec_score_credits_only_the_declared_rule(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(benchmarks, "_gosec_cases", lambda path: [(["package p"], 1)])
    monkeypatch.setattr(benchmarks, "_rule_cwes", lambda rules: {"measured-rule": {109}})

    def scan_other_rule(binary: Path, rules: Path, target: Path) -> dict:
        source = target / "G109" / "case000" / "f0.go"
        return {
            "paths": {"scanned": [str(source)]},
            "results": [
                {
                    "check_id": "other-rule",
                    "path": str(source),
                    "start": {"line": 1, "col": 1},
                }
            ],
            "errors": [],
        }

    monkeypatch.setattr(
        benchmarks,
        "_scan",
        scan_other_rule,
    )

    score, findings, scan_seconds = benchmarks._score_gosec(
        Path("opengrep"),
        Path("rules"),
        tmp_path,
        {"G109": "sample.go"},
        {"G109": "measured-rule"},
        tmp_path / "work",
    )
    assert score == {
        "cases_total": 1,
        "by_rule": {"G109": {"cases": 1, "vulnerable": 1, "detected": 0, "fp_on_safe": 0}},
    }
    assert findings == [("G109/case000/f0.go", "other-rule", 1, 1)]
    assert scan_seconds >= 0

    with pytest.raises(benchmarks.BenchmarkGateError, match="ownership differ"):
        benchmarks._score_gosec(
            Path("opengrep"),
            Path("rules"),
            tmp_path,
            {"G109": "sample.go"},
            {},
            tmp_path / "other-work",
        )

    monkeypatch.setattr(benchmarks, "_rule_cwes", lambda rules: {})
    with pytest.raises(benchmarks.BenchmarkGateError, match="not present"):
        benchmarks._score_gosec(
            Path("opengrep"),
            Path("rules"),
            tmp_path,
            {"G109": "sample.go"},
            {"G109": "missing-rule"},
            tmp_path / "missing-work",
        )


def test_gosec_score_batches_all_cases_in_one_scan(tmp_path: Path, monkeypatch) -> None:
    def cases(path: Path) -> list[tuple[list[str], int]]:
        if path.name == "g109.go":
            return [(["package p", "package p"], 1), (["package p"], 0)]
        return [(["package p"], 1)]

    monkeypatch.setattr(benchmarks, "_gosec_cases", cases)
    monkeypatch.setattr(
        benchmarks,
        "_rule_cwes",
        lambda rules: {"parse-rule": {109}, "shell-rule": {78}},
    )
    scan_targets = []

    def scan(binary: Path, rules: Path, target: Path) -> dict:
        scan_targets.append(target)
        files = sorted(target.rglob("*.go"))
        return {
            "paths": {"scanned": [str(path) for path in files]},
            "results": [
                {
                    "check_id": "parse-rule",
                    "path": str(target / "G109" / "case000" / "f1.go"),
                    "start": {"line": 3, "col": 4},
                },
                {
                    "check_id": "other-rule",
                    "path": str(target / "G109" / "case001" / "f0.go"),
                    "start": {"line": 5, "col": 6},
                },
                {
                    "check_id": "shell-rule",
                    "path": str(target / "G204" / "case000" / "f0.go"),
                    "start": {"line": 7, "col": 8},
                },
            ],
            "errors": [],
        }

    monkeypatch.setattr(benchmarks, "_scan", scan)
    workdir = tmp_path / "work"
    score, findings, _ = benchmarks._score_gosec(
        Path("opengrep"),
        Path("rules"),
        tmp_path,
        {"G109": "g109.go", "G204": "g204.go"},
        {"G109": "parse-rule", "G204": "shell-rule"},
        workdir,
    )

    assert scan_targets == [workdir]
    assert sorted(path.relative_to(workdir).as_posix() for path in workdir.rglob("*.go")) == [
        "G109/case000/f0.go",
        "G109/case000/f1.go",
        "G109/case001/f0.go",
        "G204/case000/f0.go",
    ]
    assert score == {
        "cases_total": 3,
        "by_rule": {
            "G109": {"cases": 2, "vulnerable": 1, "detected": 1, "fp_on_safe": 0},
            "G204": {"cases": 1, "vulnerable": 1, "detected": 1, "fp_on_safe": 0},
        },
    }
    assert findings == [
        ("G109/case000/f1.go", "parse-rule", 3, 4),
        ("G109/case001/f0.go", "other-rule", 5, 6),
        ("G204/case000/f0.go", "shell-rule", 7, 8),
    ]


def test_gosec_score_rejects_engine_errors(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(benchmarks, "_gosec_cases", lambda path: [(["package p"], 1)])
    monkeypatch.setattr(benchmarks, "_rule_cwes", lambda rules: {"measured-rule": {109}})
    monkeypatch.setattr(
        benchmarks,
        "_scan",
        lambda binary, rules, target: {
            "paths": {"scanned": [str(target / "G109" / "case000" / "f0.go")]},
            "results": [],
            "errors": [{"message": "parse failure"}],
        },
    )

    with pytest.raises(benchmarks.BenchmarkGateError, match="engine errors"):
        benchmarks._score_gosec(
            Path("opengrep"),
            Path("rules"),
            tmp_path,
            {"G109": "sample.go"},
            {"G109": "measured-rule"},
            tmp_path / "work",
        )


def test_gosec_score_rejects_empty_materialization(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(benchmarks, "_gosec_cases", lambda path: [])
    monkeypatch.setattr(benchmarks, "_rule_cwes", lambda rules: {"measured-rule": {109}})
    monkeypatch.setattr(
        benchmarks,
        "_scan",
        lambda binary, rules, target: pytest.fail("scan must not run"),
    )

    with pytest.raises(benchmarks.BenchmarkGateError, match="materialized zero files"):
        benchmarks._score_gosec(
            Path("opengrep"),
            Path("rules"),
            tmp_path,
            {"G109": "sample.go"},
            {"G109": "measured-rule"},
            tmp_path / "work",
        )


@pytest.mark.parametrize(
    ("scanned", "message"),
    [
        ("missing", "coverage differs"),
        ("duplicate", "duplicate scanned paths"),
        ("unknown", "unknown materialized file"),
        ("outside", "outside the materialized root"),
        ("traversal", "contains traversal"),
        ("symlink", "symbolic path"),
    ],
)
def test_gosec_score_requires_exact_scan_coverage(
    tmp_path: Path, monkeypatch, scanned: str, message: str
) -> None:
    monkeypatch.setattr(benchmarks, "_gosec_cases", lambda path: [(["package p"], 1)])
    monkeypatch.setattr(benchmarks, "_rule_cwes", lambda rules: {"measured-rule": {109}})

    def scan(binary: Path, rules: Path, target: Path) -> dict:
        expected = target / "G109" / "case000" / "f0.go"
        symlink = target / "linked.go"
        if scanned == "symlink":
            symlink.symlink_to(expected)
        paths = {
            "missing": [],
            "duplicate": [str(expected), str(expected)],
            "unknown": [str(target / "G109" / "case999" / "f0.go")],
            "outside": [str(tmp_path / "outside.go")],
            "traversal": [str(target / "G109" / "case999" / ".." / "case000" / "f0.go")],
            "symlink": [str(symlink)],
        }[scanned]
        return {"paths": {"scanned": paths}, "results": [], "errors": []}

    monkeypatch.setattr(benchmarks, "_scan", scan)
    with pytest.raises(benchmarks.BenchmarkGateError, match=message):
        benchmarks._score_gosec(
            Path("opengrep"),
            Path("rules"),
            tmp_path,
            {"G109": "sample.go"},
            {"G109": "measured-rule"},
            tmp_path / "work",
        )


def test_gosec_score_rejects_unknown_finding_path(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(benchmarks, "_gosec_cases", lambda path: [(["package p"], 1)])
    monkeypatch.setattr(benchmarks, "_rule_cwes", lambda rules: {"measured-rule": {109}})

    def scan(binary: Path, rules: Path, target: Path) -> dict:
        expected = target / "G109" / "case000" / "f0.go"
        return {
            "paths": {"scanned": [str(expected)]},
            "results": [
                {
                    "check_id": "measured-rule",
                    "path": str(target / "G109" / "case999" / "f0.go"),
                    "start": {"line": 1, "col": 1},
                }
            ],
            "errors": [],
        }

    monkeypatch.setattr(benchmarks, "_scan", scan)
    with pytest.raises(benchmarks.BenchmarkGateError, match="unknown materialized file"):
        benchmarks._score_gosec(
            Path("opengrep"),
            Path("rules"),
            tmp_path,
            {"G109": "sample.go"},
            {"G109": "measured-rule"},
            tmp_path / "work",
        )


def test_gosec_repeat_compares_finding_identity() -> None:
    score = {"cases_total": 1, "by_rule": {}}
    first = [("G109/case000/f0.go", "rule", 1, 1)]
    second = [("G109/case000/f0.go", "rule", 2, 1)]

    assert benchmarks._gosec_repeat_differences(score, first, score, first) == []
    assert benchmarks._gosec_repeat_differences(score, first, score, second) == [
        "repeated findings differ"
    ]
    assert benchmarks._gosec_repeat_differences(score, first, {}, first) == [
        "repeated scoring differs"
    ]


def test_benchmark_rejects_unidentified_finding_path() -> None:
    with pytest.raises(benchmarks.BenchmarkGateError, match="no BenchmarkTest"):
        benchmarks._normalized_findings(
            {"results": [{"check_id": "cra-example", "path": "unknown.java"}]}
        )


def test_cross_rule_annotations_cover_multiline_and_ignore_ruleid_laundering(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture.py"
    fixture.write_text(
        "# ok: safe-rule\n# ruleid: unrelated-positive\ndangerous_call(\n    user_input,\n)\n",
        encoding="utf-8",
    )

    ok_ids, rule_ids, marker_line = batch._annotations_for_line(fixture, 4)

    assert ok_ids == {"safe-rule"}
    assert rule_ids == {"unrelated-positive"}
    assert marker_line == 1
    with pytest.raises(batch.BatchGateError, match="untriaged cross-rule"):
        batch._check_cross_rule_ok(
            [
                {
                    "rule_id": "unexpected-rule",
                    "path": "fixture.py",
                    "start": [4, 5],
                    "end": [4, 15],
                    "severity": "ERROR",
                }
            ],
            tmp_path,
        )


def test_cross_rule_annotations_are_bounded_and_canonical(tmp_path: Path) -> None:
    fixture = tmp_path / "other-rule.py"
    fixture.write_text(
        "# ok: unexpected-rule\n"
        "safe_call()\n" + "\n" * batch.MAX_ANNOTATION_DISTANCE + "dangerous_call()\n",
        encoding="utf-8",
    )
    ok_ids, _, marker_line = batch._annotations_for_line(fixture, batch.MAX_ANNOTATION_DISTANCE + 3)
    assert ok_ids == set()
    assert marker_line is None

    close_fixture = tmp_path / "other-rule.py"
    close_fixture.write_text(
        "# ok: unexpected-rule\ndangerous_call()\n",
        encoding="utf-8",
    )
    with pytest.raises(batch.BatchGateError, match="untriaged cross-rule"):
        batch._check_cross_rule_ok(
            [
                {
                    "rule_id": "unexpected-rule",
                    "path": "other-rule.py",
                    "start": [2, 1],
                    "end": [2, 17],
                    "severity": "ERROR",
                }
            ],
            tmp_path,
        )


def test_engine_identity_rejects_wrong_version(tmp_path: Path, monkeypatch) -> None:
    # A real executable at an explicit path keeps this hermetic: the strict
    # resolution step must succeed on any host, including one with no
    # opengrep on PATH, so the version comparison is what fails.
    binary = tmp_path / "opengrep"
    binary.write_text("#!/bin/sh\necho 1.25.0\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setattr("scripts.rulepack_engine._verified_asset", lambda binary: "test-asset")

    with pytest.raises(EngineIdentityError, match="expected Opengrep 1.26.0"):
        verify_engine(binary)


def test_engine_identity_resolves_default_binary_from_path(
    tmp_path: Path, monkeypatch
) -> None:
    binary = tmp_path / "opengrep"
    binary.write_text("#!/bin/sh\necho 1.26.0\n", encoding="utf-8")
    binary.chmod(0o755)
    verified = []
    executed = []
    completed = type(
        "Completed",
        (),
        {"returncode": 0, "stdout": "1.26.0\n", "stderr": ""},
    )()
    monkeypatch.setattr("scripts.rulepack_engine.shutil.which", lambda command: str(binary))
    monkeypatch.setattr(
        "scripts.rulepack_engine._verified_asset", lambda path: verified.append(path)
    )
    monkeypatch.setattr(
        "scripts.rulepack_engine.subprocess.run",
        lambda command, **kwargs: executed.append(command) or completed,
    )

    assert verify_engine(Path("opengrep")) == "1.26.0"
    assert verified == [binary]
    assert executed == [[str(binary), "--version"]]


def test_engine_identity_rejects_version_spoofing_wrapper(tmp_path: Path, monkeypatch) -> None:
    wrapper = tmp_path / "opengrep"
    wrapper.write_text("#!/bin/sh\necho 1.26.0\n", encoding="utf-8")
    wrapper.chmod(0o755)
    completed = type(
        "Completed",
        (),
        {"returncode": 0, "stdout": "1.26.0\n", "stderr": ""},
    )()
    monkeypatch.setattr("scripts.rulepack_engine.subprocess.run", lambda *args, **kwargs: completed)

    with pytest.raises(EngineIdentityError, match="SHA-256"):
        verify_engine(wrapper)


def test_benchmark_manifest_records_denominators_and_blocker() -> None:
    manifest = json.loads(BENCHMARKS.read_text(encoding="utf-8"))
    for entry in manifest["benchmarks"]:
        assert isinstance(entry["promotion_ready"], bool)
        if not entry["promotion_ready"]:
            assert entry["promotion_blocker"]
    benchmark = manifest["benchmarks"][0]
    assert re.fullmatch(r"[0-9a-f]{40}", benchmark["commit"])
    assert benchmark["directory"] == "owasp-java"
    assert benchmark["promotion_ready"] is False
    assert benchmark["promotion_blocker"]
    metrics = benchmark["expected"]["metrics_by_cwe"]
    assert set(metrics) == {"22", "78", "89", "328"}
    assert sum(item["tp"] + item["fn"] for item in metrics.values()) == 660
    assert sum(item["fp"] for item in metrics.values()) == 24
    denominator = benchmark["full_denominator"]
    assert denominator["cases"] == 2740
    assert denominator["vulnerable_cases"] == 1415
    assert denominator["scored_cases"] + denominator["excluded_cases"] == 2740
    assert denominator["scored_vulnerable_cases"] + denominator["excluded_vulnerable_cases"] == 1415
    assert sum(denominator["excluded_categories"].values()) == 755


def test_eslint_rule_tester_parser_preserves_official_labels(tmp_path: Path) -> None:
    source = tmp_path / "no-loss-of-precision.js"
    source.write_text(
        "ruleTester.run(\"no-loss-of-precision\", rule, {\n"
        "  valid: [\n"
        "    \"const safe = 1;\",\n"
        "    { code: \"const exact = 2;\" },\n"
        "  ],\n"
        "  invalid: [\n"
        "    { code: \"const unsafe = 9007199254740993;\" },\n"
        "  ],\n"
        "});\n"
        "ruleTester.run(\"no-loss-of-precision\", rule, {\n"
        "  valid: [\n"
        "    \"const typed: number = 1;\",\n"
        "  ],\n"
        "  invalid: [\n"
        "    { code: \"const typed: number = 9007199254740993;\" },\n"
        "  ],\n"
        "});\n",
        encoding="utf-8",
    )

    assert benchmarks._eslint_rule_tester_cases(source) == [
        ("const safe = 1;", False, "js"),
        ("const exact = 2;", False, "js"),
        ("const unsafe = 9007199254740993;", True, "js"),
        ("const typed: number = 1;", False, "ts"),
        ("const typed: number = 9007199254740993;", True, "ts"),
    ]


def test_benchmark_denominator_records_excluded_categories() -> None:
    cases = {
        "one": (89, True),
        "two": (89, False),
        "three": (79, True),
        "four": (79, False),
    }

    assert benchmarks._denominator(cases, {89}) == {
        "cases": 4,
        "vulnerable_cases": 2,
        "scored_cases": 2,
        "scored_vulnerable_cases": 1,
        "excluded_cases": 2,
        "excluded_vulnerable_cases": 1,
        "excluded_categories": {"79": 1},
    }


def test_corpus_fetch_rejects_conflicting_duplicate_directories(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    benchmark = tmp_path / "benchmark.json"
    real.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "directory": "same",
                        "repository": "https://example.test/one.git",
                        "commit": "a" * 40,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    benchmark.write_text(
        json.dumps(
            {
                "benchmarks": [
                    {
                        "directory": "same",
                        "repository": "https://example.test/two.git",
                        "commit": "b" * 40,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(fetch_corpora.CorpusFetchError, match="conflicting corpus sources"):
        fetch_corpora._entries(real, benchmark)


def test_corpus_fetch_deduplicates_matching_sources(tmp_path: Path) -> None:
    source = {
        "directory": "shared",
        "repository": "https://example.test/shared.git",
        "commit": "a" * 40,
    }
    real = tmp_path / "real.json"
    benchmark = tmp_path / "benchmark.json"
    real.write_text(json.dumps({"projects": [source]}), encoding="utf-8")
    benchmark.write_text(
        json.dumps({"benchmarks": [{**source, "name": "second-scorecard"}]}),
        encoding="utf-8",
    )

    assert fetch_corpora._entries(real, benchmark) == [source]


def test_corpus_fetch_rejects_parent_traversal_in_archive(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("../outside.txt", "unsafe")

    with pytest.raises(fetch_corpora.CorpusFetchError, match="unsafe ZIP entry"):
        fetch_corpora._validate_zip(archive, expected_entries=1)


def test_corpus_download_identifies_client(tmp_path: Path, monkeypatch) -> None:
    requests = []

    def open_response(request, *, timeout):
        requests.append((request, timeout))
        return io.BytesIO(b"corpus bytes")

    monkeypatch.setattr(fetch_corpora.urllib.request, "urlopen", open_response)
    target = tmp_path / "corpus.zip"

    fetch_corpora._download("https://example.test/corpus.zip", target)

    assert target.read_bytes() == b"corpus bytes"
    assert len(requests) == 1
    request, timeout = requests[0]
    assert request.full_url == "https://example.test/corpus.zip"
    assert request.get_header("User-agent") == fetch_corpora.DOWNLOAD_USER_AGENT
    assert timeout == 60


def test_corpus_download_rejects_non_https_url(tmp_path: Path) -> None:
    with pytest.raises(fetch_corpora.CorpusFetchError, match="must use HTTPS"):
        fetch_corpora._download("file:///tmp/corpus.zip", tmp_path / "corpus.zip")


def test_corpus_fetch_repairs_only_pinned_manifest_line(tmp_path: Path) -> None:
    source = tmp_path / "manifest.xml"
    source.write_text(
        "<container>\n  <testcase></testcase>\n  </testcase>\n</container>\n",
        encoding="utf-8",
    )
    repaired = "<container>\n  <testcase></testcase>\n</container>\n"
    entry = {
        "manifest_repair": {
            "source": "manifest.xml",
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "remove_lines": [3],
            "expected_testcases": 1,
            "destination": "manifest.repaired.xml",
            "destination_sha256": hashlib.sha256(repaired.encode()).hexdigest(),
        }
    }

    fetch_corpora._repair_manifest(entry, tmp_path)

    assert (tmp_path / "manifest.repaired.xml").read_text() == repaired


def test_benchmark_manifest_pins_juliet_archive_and_repair() -> None:
    manifest = json.loads(BENCHMARKS.read_text(encoding="utf-8"))
    juliet = next(item for item in manifest["benchmarks"] if item["name"] == "nist-juliet-java-1.3")
    assert juliet["source_type"] == "archive"
    assert re.fullmatch(r"[0-9a-f]{64}", juliet["archive_sha256"])
    assert juliet["archive_bytes"] == 76798417
    assert juliet["manifest_repair"]["remove_lines"] == [50084, 66737]
    assert juliet["manifest_repair"]["expected_testcases"] == 28881
    assert juliet["license_file"] == "CC0-1.0.txt"


def test_evidence_manifests_match_pinned_engine_version() -> None:
    from cra_evidence_cli.local.rules_pack import TESTED_OPENGREP_VERSION

    real_manifest = json.loads(REAL_PROJECTS.read_text(encoding="utf-8"))
    benchmark_manifest = json.loads(BENCHMARKS.read_text(encoding="utf-8"))
    assert real_manifest["engine_version"] == TESTED_OPENGREP_VERSION
    assert benchmark_manifest["engine_version"] == TESTED_OPENGREP_VERSION
