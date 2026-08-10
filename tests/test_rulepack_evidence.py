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
    assert real_projects._error_kind({"type": ["PartialParsing", []]}) == (
        "PartialParsing"
    )
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
        "# ok: safe-rule\n"
        "# ruleid: unrelated-positive\n"
        "dangerous_call(\n"
        "    user_input,\n"
        ")\n",
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
        "safe_call()\n"
        + "\n" * batch.MAX_ANNOTATION_DISTANCE
        + "dangerous_call()\n",
        encoding="utf-8",
    )
    ok_ids, _, marker_line = batch._annotations_for_line(
        fixture, batch.MAX_ANNOTATION_DISTANCE + 3
    )
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


def test_engine_identity_rejects_wrong_version(monkeypatch) -> None:
    completed = type(
        "Completed",
        (),
        {"returncode": 0, "stdout": "1.25.0\n", "stderr": ""},
    )()
    monkeypatch.setattr(
        "scripts.rulepack_engine.subprocess.run", lambda *args, **kwargs: completed
    )
    monkeypatch.setattr(
        "scripts.rulepack_engine._verified_asset", lambda binary: "test-asset"
    )

    with pytest.raises(EngineIdentityError, match="expected Opengrep 1.26.0"):
        verify_engine(Path("opengrep"))


def test_engine_identity_rejects_version_spoofing_wrapper(tmp_path: Path, monkeypatch) -> None:
    wrapper = tmp_path / "opengrep"
    wrapper.write_text("#!/bin/sh\necho 1.26.0\n", encoding="utf-8")
    wrapper.chmod(0o755)
    completed = type(
        "Completed",
        (),
        {"returncode": 0, "stdout": "1.26.0\n", "stderr": ""},
    )()
    monkeypatch.setattr(
        "scripts.rulepack_engine.subprocess.run", lambda *args, **kwargs: completed
    )

    with pytest.raises(EngineIdentityError, match="SHA-256"):
        verify_engine(wrapper)


def test_benchmark_manifest_records_denominators_and_blocker() -> None:
    manifest = json.loads(BENCHMARKS.read_text(encoding="utf-8"))
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
    assert (
        denominator["scored_vulnerable_cases"]
        + denominator["excluded_vulnerable_cases"]
        == 1415
    )
    assert sum(denominator["excluded_categories"].values()) == 755


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


def test_corpus_fetch_rejects_duplicate_directories(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    benchmark = tmp_path / "benchmark.json"
    real.write_text(
        json.dumps({"projects": [{"directory": "same"}]}), encoding="utf-8"
    )
    benchmark.write_text(
        json.dumps({"benchmarks": [{"directory": "same"}]}), encoding="utf-8"
    )

    with pytest.raises(fetch_corpora.CorpusFetchError, match="must be unique"):
        fetch_corpora._entries(real, benchmark)


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
        "<container>\n"
        "  <testcase></testcase>\n"
        "  </testcase>\n"
        "</container>\n",
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
    juliet = next(
        item for item in manifest["benchmarks"] if item["name"] == "nist-juliet-java-1.3"
    )
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
