#!/usr/bin/env python3
"""Score applicable CRA Evidence rules against pinned known-answer benchmarks."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

try:
    from scripts.rulepack_engine import verify_engine
except ModuleNotFoundError:  # Direct execution: python scripts/score_rulepack_benchmarks.py
    from rulepack_engine import verify_engine

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "rulepack_benchmarks.json"
DEFAULT_RULES = REPO_ROOT / "cra_evidence_cli" / "local" / "rules"
TEST_ID_RE = re.compile(r"(BenchmarkTest\d+)")
CWE_RE = re.compile(r"^CWE-(\d+)")


class BenchmarkGateError(RuntimeError):
    pass


def _git_head(checkout: Path) -> str:
    git = shutil.which("git")
    if git is None:
        message = "git is required to verify benchmark revisions"
        raise BenchmarkGateError(message)
    result = subprocess.run(  # noqa: S603
        [git, "-C", str(checkout), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        message = f"cannot read Git commit for {checkout}: {result.stderr.strip()}"
        raise BenchmarkGateError(message)
    return result.stdout.strip()


def _rule_cwes(rules: Path) -> dict[str, set[int]]:
    mapping: dict[str, set[int]] = {}
    for rule_file in sorted(rules.rglob("*.yaml")):
        document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        rule = document["rules"][0]
        values: set[int] = set()
        for entry in rule["metadata"]["cwe"]:
            match = CWE_RE.match(str(entry))
            if match:
                values.add(int(match.group(1)))
        mapping[str(rule["id"])] = values
    return mapping


def _expected_cases(path: Path) -> dict[str, tuple[int, bool]]:
    cases: dict[str, tuple[int, bool]] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        rows = csv.reader(line for line in handle if not line.startswith("#"))
        for row in rows:
            if len(row) != 4:
                message = f"invalid expected-results row: {row}"
                raise BenchmarkGateError(message)
            cases[row[0]] = (int(row[3]), row[2].lower() == "true")
    if not cases:
        message = f"benchmark contains no expected cases: {path}"
        raise BenchmarkGateError(message)
    return cases


def _scan(binary: Path, rules: Path, source: Path | list[Path]) -> dict:
    sources = [source] if isinstance(source, Path) else source
    command = [
        str(binary),
        "scan",
        "-f",
        str(rules),
        "--no-rewrite-rule-ids",
        "--taint-intrafile",
        "--disable-version-check",
        "--timeout=20",
        "--timeout-threshold=3",
        "--quiet",
        "--json",
        *(str(item) for item in sources),
    ]
    result = subprocess.run(  # noqa: S603
        command,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        message = (
            f"Opengrep exited {result.returncode}: "
            f"{result.stderr.strip()[:600]}"
        )
        raise BenchmarkGateError(message)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        message = "Opengrep benchmark output was not valid JSON"
        raise BenchmarkGateError(message) from exc


def _normalized_findings(document: dict) -> list[tuple[str, str, int, int]]:
    findings: list[tuple[str, str, int, int]] = []
    for result in document.get("results") or []:
        match = TEST_ID_RE.search(str(result.get("path") or ""))
        if not match:
            message = (
                "benchmark finding path has no BenchmarkTest identifier: "
                f"{result.get('path')}"
            )
            raise BenchmarkGateError(message)
        start = result.get("start") or {}
        findings.append(
            (
                str(result.get("check_id") or ""),
                match.group(1),
                int(start.get("line") or 0),
                int(start.get("col") or 0),
            )
        )
    return sorted(findings)


def _score(
    document: dict,
    cases: dict[str, tuple[int, bool]],
    rule_cwes: dict[str, set[int]],
    cwe_aliases: dict[int, int] | None = None,
) -> dict:
    """Score an OWASP-style corpus.

    cwe_aliases maps a benchmark CWE onto the rule CWE that covers it, for the
    case where a corpus labels a case with a class-level weakness while the rule
    declares the precise child MITRE prefers for mapping. The relationship is
    declared per benchmark so it stays visible rather than being hidden by
    widening a rule's own CWE list.
    """
    scanned = document.get("paths", {}).get("scanned") or []
    if not scanned:
        message = "benchmark scan evaluated zero files"
        raise BenchmarkGateError(message)
    applicable_cwes = sorted(
        {cwe for values in rule_cwes.values() for cwe in values}
        & {cwe for cwe, _ in cases.values()}
    )
    if not applicable_cwes:
        message = "benchmark has no CWE intersection with the selected rules"
        raise BenchmarkGateError(message)
    detected: dict[int, set[str]] = {cwe: set() for cwe in applicable_cwes}
    detected_by_rule: dict[str, dict[int, set[str]]] = {
        rule_id: {cwe: set() for cwe in cwes if cwe in applicable_cwes}
        for rule_id, cwes in rule_cwes.items()
        if cwes & set(applicable_cwes)
    }
    aliases = cwe_aliases or {}
    for rule_id, test_id, _, _ in _normalized_findings(document):
        if test_id not in cases:
            message = f"finding references unknown benchmark case: {test_id}"
            raise BenchmarkGateError(message)
        expected_cwe, _ = cases[test_id]
        expected_cwe = aliases.get(expected_cwe, expected_cwe)
        finding_cwes = rule_cwes.get(rule_id, set())
        if expected_cwe not in finding_cwes:
            message = (
                f"{rule_id} fired on {test_id} (CWE-{expected_cwe}) without a "
                "matching rule CWE; the result cannot be scored safely"
            )
            raise BenchmarkGateError(message)
        for cwe in finding_cwes:
            if cwe == expected_cwe and cwe in detected:
                detected[cwe].add(test_id)
                detected_by_rule[rule_id][cwe].add(test_id)

    metrics: dict[str, dict[str, int]] = {}
    for cwe in applicable_cwes:
        relevant = {
            test_id: vulnerable
            for test_id, (case_cwe, vulnerable) in cases.items()
            if case_cwe == cwe
        }
        hits = detected[cwe]
        metrics[str(cwe)] = {
            "tp": sum(test_id in hits and value for test_id, value in relevant.items()),
            "fp": sum(test_id in hits and not value for test_id, value in relevant.items()),
            "fn": sum(test_id not in hits and value for test_id, value in relevant.items()),
            "tn": sum(test_id not in hits and not value for test_id, value in relevant.items()),
        }
    metrics_by_rule: dict[str, dict[str, dict[str, int]]] = {}
    for rule_id, cwe_hits in sorted(detected_by_rule.items()):
        metrics_by_rule[rule_id] = {}
        for cwe, hits in sorted(cwe_hits.items()):
            relevant = {
                test_id: vulnerable
                for test_id, (case_cwe, vulnerable) in cases.items()
                if case_cwe == cwe
            }
            metrics_by_rule[rule_id][str(cwe)] = {
                "tp": sum(
                    test_id in hits and value for test_id, value in relevant.items()
                ),
                "fp": sum(
                    test_id in hits and not value for test_id, value in relevant.items()
                ),
                "fn": sum(
                    test_id not in hits and value for test_id, value in relevant.items()
                ),
                "tn": sum(
                    test_id not in hits and not value
                    for test_id, value in relevant.items()
                ),
            }
    return {
        "files_scanned": len(scanned),
        "engine_errors": len(document.get("errors") or []),
        "metrics_by_cwe": metrics,
        "metrics_by_rule": metrics_by_rule,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exact_findings(document: dict, root: Path) -> list[tuple[str, str, int, int]]:
    findings: list[tuple[str, str, int, int]] = []
    resolved_root = root.resolve()
    for result in document.get("results") or []:
        path = Path(str(result.get("path") or "")).resolve()
        try:
            relative = path.relative_to(resolved_root).as_posix()
        except ValueError as exc:
            message = f"benchmark finding path escapes corpus: {path}"
            raise BenchmarkGateError(message) from exc
        start = result.get("start") or {}
        findings.append(
            (
                str(result.get("check_id") or ""),
                relative,
                int(start.get("line") or 0),
                int(start.get("col") or 0),
            )
        )
    return sorted(findings)


def _juliet_ground_truth(
    manifest: Path, rule_cwes: dict[str, int]
) -> tuple[dict[str, int], dict[int, set[int]], dict[str, set[int]]]:
    try:
        content = manifest.read_text(encoding="utf-8")
    except (OSError, ET.ParseError) as exc:
        message = f"cannot parse Juliet manifest: {manifest}"
        raise BenchmarkGateError(message) from exc
    if "<!DOCTYPE" in content or "<!ENTITY" in content:
        message = f"Juliet manifest contains a forbidden XML declaration: {manifest}"
        raise BenchmarkGateError(message)
    try:
        root = ET.fromstring(content)  # noqa: S314 - declarations rejected above
    except ET.ParseError as exc:
        message = f"cannot parse Juliet manifest: {manifest}"
        raise BenchmarkGateError(message) from exc
    case_by_file: dict[str, int] = {}
    cases_by_cwe: dict[int, set[int]] = {
        cwe: set() for cwe in set(rule_cwes.values())
    }
    flaws_by_file: dict[str, set[int]] = {}
    for case_number, testcase in enumerate(root.findall("testcase")):
        for file_node in testcase.findall("file"):
            path = str(file_node.get("path") or "")
            if not path.endswith(".java"):
                continue
            if path in case_by_file:
                message = f"duplicate Juliet Java filename in manifest: {path}"
                raise BenchmarkGateError(message)
            case_by_file[path] = case_number
            for cwe in cases_by_cwe:
                if path.startswith(f"CWE{cwe}_"):
                    cases_by_cwe[cwe].add(case_number)
            flaws_by_file[path] = {
                int(flaw.get("line") or 0) for flaw in file_node.findall("flaw")
            }
    for cwe, cases in cases_by_cwe.items():
        if not cases:
            message = f"Juliet manifest has no testcases for CWE-{cwe}"
            raise BenchmarkGateError(message)
    return case_by_file, cases_by_cwe, flaws_by_file


def _score_juliet(
    document: dict,
    manifest: Path,
    rule_cwes: dict[str, int],
) -> dict:
    scanned = document.get("paths", {}).get("scanned") or []
    if not scanned:
        message = "benchmark scan evaluated zero files"
        raise BenchmarkGateError(message)
    case_by_file, cases_by_cwe, flaws_by_file = _juliet_ground_truth(
        manifest, rule_cwes
    )
    cases_detected: dict[str, set[int]] = {rule_id: set() for rule_id in rule_cwes}
    files_detected: dict[str, set[str]] = {rule_id: set() for rule_id in rule_cwes}
    finding_counts = dict.fromkeys(rule_cwes, 0)
    at_flaw_counts = dict.fromkeys(rule_cwes, 0)
    outside_flaw_counts = dict.fromkeys(rule_cwes, 0)
    for result in document.get("results") or []:
        rule_id = str(result.get("check_id") or "")
        if rule_id not in rule_cwes:
            message = f"unexpected rule in Juliet result: {rule_id}"
            raise BenchmarkGateError(message)
        filename = Path(str(result.get("path") or "")).name
        if filename not in case_by_file:
            message = f"Juliet finding references unknown file: {filename}"
            raise BenchmarkGateError(message)
        cwe = rule_cwes[rule_id]
        if not filename.startswith(f"CWE{cwe}_"):
            message = f"{rule_id} fired outside its declared CWE: {filename}"
            raise BenchmarkGateError(message)
        line = int((result.get("start") or {}).get("line") or 0)
        cases_detected[rule_id].add(case_by_file[filename])
        files_detected[rule_id].add(filename)
        finding_counts[rule_id] += 1
        if line in flaws_by_file.get(filename, set()):
            at_flaw_counts[rule_id] += 1
        else:
            outside_flaw_counts[rule_id] += 1
    metrics_by_rule: dict[str, dict[str, int]] = {}
    for rule_id, cwe in sorted(rule_cwes.items()):
        total = len(cases_by_cwe[cwe])
        detected = len(cases_detected[rule_id])
        metrics_by_rule[rule_id] = {
            "cwe": cwe,
            "cases_total": total,
            "cases_detected": detected,
            "cases_missed": total - detected,
            "files_with_findings": len(files_detected[rule_id]),
            "finding_count": finding_counts[rule_id],
            "findings_at_manifest_flaws": at_flaw_counts[rule_id],
            "findings_outside_manifest_flaws": outside_flaw_counts[rule_id],
        }
    return {
        "files_scanned": len(scanned),
        "engine_errors": len(document.get("errors") or []),
        "metrics_by_rule": metrics_by_rule,
    }


GOSEC_SAMPLE_RE = re.compile(r"\{\[\]string\{(.*?)\},\s*(\d+),", re.S)
GOSEC_CODE_RE = re.compile(r"`(.*?)`", re.S)


def _gosec_cases(sample_file: Path) -> list[tuple[list[str], int]]:
    """Extract (sources, expected_issue_count) pairs from a gosec sample file.

    gosec stores its labelled samples as Go source: each CodeSample carries the
    program text in raw string literals and the number of issues the sample is
    expected to produce.
    """
    text = sample_file.read_text(encoding="utf-8")
    cases = []
    for block, expected in GOSEC_SAMPLE_RE.findall(text):
        sources = GOSEC_CODE_RE.findall(block)
        if sources:
            cases.append((sources, int(expected)))
    return cases


JULIET_FUNC_RE = re.compile(
    r"^(?:static\s+)?(?:void|int|char\s*\*)\s+(\w+)\s*\(", re.MULTILINE
)
JULIET_INSECURE_CALL_RE = re.compile(r"\b(mktemp|tmpnam|tempnam)\s*\(")


def _enclosing_function(lines: list[str], line: int) -> str:
    """Name of the function a 1-indexed source line sits in, or an empty string."""
    for index in range(min(line, len(lines)) - 1, -1, -1):
        match = JULIET_FUNC_RE.match(lines[index])
        if match:
            return match.group(1)
    return ""


def _preprocess_juliet(
    source_dir: Path, support_dir: Path, out_dir: Path, pattern: str
) -> tuple[int, int]:
    """Expand macros so aliased sink calls become matchable.

    Juliet routes its sinks through identity macros such as `#define MKTEMP
    mktemp`, which no syntactic rule can match as shipped. Windows-only variants
    fail to preprocess on Linux and are counted separately rather than hidden.
    """
    compiler = shutil.which("gcc")
    if compiler is None:
        message = "gcc is required to preprocess this benchmark"
        raise BenchmarkGateError(message)
    out_dir.mkdir(parents=True, exist_ok=True)
    done = 0
    skipped = 0
    for source in sorted(source_dir.glob(pattern)):
        target = out_dir / source.name
        result = subprocess.run(  # noqa: S603
            [compiler, "-E", "-P", "-I", str(support_dir), str(source), "-o", str(target)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 and target.is_file():
            done += 1
        else:
            target.unlink(missing_ok=True)
            skipped += 1
    return done, skipped


def _score_juliet_preprocessed(document: dict, preprocessed: int, skipped: int) -> dict:
    """Score by Juliet's bad/good function naming, not by manifest line numbers.

    Preprocessing shifts every line, so the shipped manifest offsets no longer
    apply. The function name is stable across preprocessing and carries the same
    ground truth.
    """
    files_with_bad_finding = set()
    in_good_on_insecure_call = 0
    in_good_on_secure_call = 0
    cache: dict[str, list[str]] = {}
    for result in document.get("results") or []:
        path = str(result["path"])
        if path not in cache:
            cache[path] = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        lines = cache[path]
        line = int(result["start"]["line"])
        name = _enclosing_function(lines, line)
        text = lines[line - 1] if 0 < line <= len(lines) else ""
        if "_bad" in name:
            files_with_bad_finding.add(Path(path).name)
        elif "good" in name.lower():
            if JULIET_INSECURE_CALL_RE.search(text):
                in_good_on_insecure_call += 1
            else:
                in_good_on_secure_call += 1
    return {
        "preprocessed_files": preprocessed,
        "skipped_files": skipped,
        "files_with_bad_finding": len(files_with_bad_finding),
        "findings_in_good_on_insecure_call": in_good_on_insecure_call,
        "findings_in_good_on_secure_call": in_good_on_secure_call,
    }


CSHARP_METHOD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|internal|static|override|virtual|sealed|new|async)\s+)+"
    r"[\w\[\]<>,\.]+\s+(\w+)\s*\(",
    re.MULTILINE,
)


def _score_juliet_methods(document: dict, method_re: re.Pattern[str]) -> dict:
    """Score against Juliet's Bad and Good method naming.

    Juliet C# ships no manifest. Its ground truth is the method name: a finding
    inside a Bad method is a true positive and one inside a Good method is a
    false positive.
    """
    files_with_bad_finding: set[str] = set()
    in_good = 0
    unattributed = 0
    cache: dict[str, list[str]] = {}
    for result in document.get("results") or []:
        path = str(result["path"])
        if path not in cache:
            cache[path] = Path(path).read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines()
        lines = cache[path]
        line = int(result["start"]["line"])
        name = ""
        for index in range(min(line, len(lines)) - 1, -1, -1):
            match = method_re.match(lines[index])
            if match:
                name = match.group(1)
                break
        lowered = name.lower()
        if lowered.startswith("bad"):
            files_with_bad_finding.add(Path(path).name)
        elif lowered.startswith("good"):
            in_good += 1
        else:
            unattributed += 1
    return {
        "files_with_bad_finding": len(files_with_bad_finding),
        "findings_in_good_methods": in_good,
        "findings_not_attributed": unattributed,
    }


CODEQL_GOOD_RE = re.compile(r"//\s*good\b", re.IGNORECASE)
# CodeQL marks its own known false negatives with MISSING. Those lines are not
# alerts the corpus asserts, so they are not counted as expected detections.
CODEQL_MISSING_RE = re.compile(r"\$\s*MISSING")


def _score_codeql_markers(document: dict, source: Path, alert_query: str) -> dict:
    """Score against CodeQL's inline alert and good markers.

    A finding is credited to an alert when the alert line falls inside the
    finding's own start..end source range. Proximity windows were rejected: our
    rules often anchor at the start of a call chain while CodeQL anchors at the
    method call, and a window either credits a neighbouring construct or lets one
    finding absorb every remaining alert.
    """
    spans: dict[str, list[tuple[int, int]]] = {}
    for result in document.get("results") or []:
        name = Path(str(result["path"])).name
        spans.setdefault(name, []).append(
            (int(result["start"]["line"]), int(result["end"]["line"]))
        )
    alerts = covered = good_lines = good_hit = 0
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.name.endswith(".expected"):
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        file_spans = spans.get(path.name, [])
        for index, text in enumerate(lines, start=1):
            if alert_query in text and not CODEQL_MISSING_RE.search(text):
                alerts += 1
                if any(start <= index <= end for start, end in file_spans):
                    covered += 1
            elif CODEQL_GOOD_RE.search(text):
                good_lines += 1
                if any(start <= index <= end for start, end in file_spans):
                    good_hit += 1
    return {
        "alert_lines": alerts,
        "alert_lines_covered": covered,
        "good_lines": good_lines,
        "good_lines_reported": good_hit,
    }


def _score_gosec(
    binary: Path,
    rules: Path,
    checkout: Path,
    sample_files: dict[str, str],
    workdir: Path,
) -> dict:
    """Score our rules against gosec's labelled samples, per gosec rule id."""
    actual: dict[str, dict[str, int]] = {}
    total_cases = 0
    for gosec_rule, relative in sorted(sample_files.items()):
        cases = _gosec_cases(checkout / relative)
        detected = 0
        vulnerable = 0
        fp_on_safe = 0
        for index, (sources, expected) in enumerate(cases):
            case_dir = workdir / gosec_rule / f"case{index:03d}"
            case_dir.mkdir(parents=True, exist_ok=True)
            for position, source in enumerate(sources):
                (case_dir / f"f{position}.go").write_text(source, encoding="utf-8")
            document = _scan(binary, rules, case_dir)
            found = len(document.get("results") or [])
            if expected > 0:
                vulnerable += 1
                if found:
                    detected += 1
            elif found:
                fp_on_safe += 1
        total_cases += len(cases)
        actual[gosec_rule] = {
            "cases": len(cases),
            "vulnerable": vulnerable,
            "detected": detected,
            "fp_on_safe": fp_on_safe,
        }
    return {"cases_total": total_cases, "by_rule": actual}


def _ratio(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "n/a"
    return f"{numerator / denominator:.1%}"


def _denominator(cases: dict[str, tuple[int, bool]], applicable: set[int]) -> dict:
    scored = {key: value for key, value in cases.items() if value[0] in applicable}
    excluded = {key: value for key, value in cases.items() if value[0] not in applicable}
    excluded_categories = {
        str(cwe): sum(case_cwe == cwe and vulnerable for case_cwe, vulnerable in excluded.values())
        for cwe in sorted({case_cwe for case_cwe, _ in excluded.values()})
    }
    return {
        "cases": len(cases),
        "vulnerable_cases": sum(vulnerable for _, vulnerable in cases.values()),
        "scored_cases": len(scored),
        "scored_vulnerable_cases": sum(vulnerable for _, vulnerable in scored.values()),
        "excluded_cases": len(excluded),
        "excluded_vulnerable_cases": sum(
            vulnerable for _, vulnerable in excluded.values()
        ),
        "excluded_categories": excluded_categories,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--opengrep", type=Path, default=Path("opengrep"))
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES / "java")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--benchmark",
        action="append",
        default=[],
        help="Run only the named benchmark. Repeatable.",
    )
    parser.add_argument("--require-promotion-ready", action="store_true")
    args = parser.parse_args()

    engine_version = verify_engine(args.opengrep)

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    benchmarks = manifest["benchmarks"]
    if args.benchmark:
        requested = set(args.benchmark)
        known = {str(benchmark["name"]) for benchmark in benchmarks}
        unknown = requested - known
        if unknown:
            message = f"unknown benchmark name(s): {sorted(unknown)}"
            raise BenchmarkGateError(message)
        benchmarks = [
            benchmark for benchmark in benchmarks if benchmark["name"] in requested
        ]
    failures: list[str] = []
    for benchmark in benchmarks:
        checkout = args.benchmark_root / str(benchmark["directory"])
        if not checkout.is_dir():
            failures.append(f"{benchmark['name']}: checkout is missing: {checkout}")
            continue
        license_file = benchmark.get("license_file")
        if license_file and not (checkout / str(license_file)).is_file():
            failures.append(f"{benchmark['name']}: licence file is missing")
            continue
        if not license_file and not benchmark.get("license_note"):
            failures.append(f"{benchmark['name']}: no licence file or licence note")
            continue
        source_type = benchmark.get("source_type", "git")
        if source_type == "git" and benchmark.get("benchmark_type") == "codeql-markers":
            # Fixture text is vendored rather than cloned: the CodeQL repository
            # is far too large to check out for a handful of test files. The
            # pinned commit records the provenance of that text.
            pass
        elif source_type == "git":
            actual_commit = _git_head(checkout)
            if actual_commit != benchmark["commit"]:
                failures.append(
                    f"{benchmark['name']}: expected commit {benchmark['commit']}, "
                    f"found {actual_commit}"
                )
                continue
        elif source_type == "archive-preprocessed":
            archive = checkout / str(benchmark["archive_file"])
            if not archive.is_file() or _sha256(archive) != benchmark["archive_sha256"]:
                failures.append(f"{benchmark['name']}: archive identity mismatch")
                continue
        elif source_type == "archive":
            archive = checkout / str(benchmark["archive_file"])
            if (
                not archive.is_file()
                or archive.stat().st_size != benchmark["archive_bytes"]
                or _sha256(archive) != benchmark["archive_sha256"]
            ):
                failures.append(f"{benchmark['name']}: archive identity mismatch")
                continue
            repair = benchmark["manifest_repair"]
            source_manifest = checkout / str(repair["source"])
            repaired_manifest = checkout / str(repair["destination"])
            if (
                not source_manifest.is_file()
                or _sha256(source_manifest) != repair["source_sha256"]
                or not repaired_manifest.is_file()
                or _sha256(repaired_manifest) != repair["destination_sha256"]
            ):
                failures.append(f"{benchmark['name']}: manifest identity mismatch")
                continue
        else:
            failures.append(
                f"{benchmark['name']}: unsupported source type {source_type}"
            )
            continue

        benchmark_type = benchmark["benchmark_type"]
        if benchmark_type == "owasp-csv":
            source = checkout / benchmark["source_path"]
            cases = _expected_cases(checkout / benchmark["expected_results"])
            cwe_aliases = {
                int(source): int(target)
                for source, target in (benchmark.get("cwe_aliases") or {}).items()
            }
            if cwe_aliases:
                cases = {
                    name: (cwe_aliases.get(cwe, cwe), vulnerable)
                    for name, (cwe, vulnerable) in cases.items()
                }
            # A benchmark states the rule subtree it is scored against. The
            # --rules default targets the Java corpora, so a benchmark for
            # another language that relied on it would silently score zero.
            benchmark_rules = (
                DEFAULT_RULES / str(benchmark["rules_subdir"])
                if benchmark.get("rules_subdir")
                else args.rules
            )
            rule_cwes = _rule_cwes(benchmark_rules)
            selected_cwes = sorted(
                {cwe for values in rule_cwes.values() for cwe in values}
            )
            benchmark_cwes = sorted({cwe for cwe, _ in cases.values()})
            applicable_cwes = sorted(set(selected_cwes) & set(benchmark_cwes))
            excluded_cwes = sorted(set(benchmark_cwes) - set(applicable_cwes))
            actual_denominator = _denominator(cases, set(applicable_cwes))
            if actual_denominator != benchmark["full_denominator"]:
                failures.append(
                    f"{benchmark['name']}: denominator changed from "
                    f"{benchmark['full_denominator']} to {actual_denominator}"
                )
            print(f"  applicable CWEs: {applicable_cwes}")
            print(f"  excluded benchmark CWEs: {excluded_cwes}")
            first_document = _scan(args.opengrep, benchmark_rules, source)
            second_document = _scan(args.opengrep, benchmark_rules, source)
            if _normalized_findings(first_document) != _normalized_findings(
                second_document
            ):
                failures.append(f"{benchmark['name']}: repeated findings differ")
            actual = _score(first_document, cases, rule_cwes, cwe_aliases)
        elif benchmark_type == "juliet-xml":
            source_root = checkout / str(benchmark["source_root"])
            sources = [source_root / path for path in benchmark["source_paths"]]
            if not all(path.is_dir() for path in sources):
                failures.append(f"{benchmark['name']}: source path is missing")
                continue
            rule_cwes = {
                str(rule_id): int(cwe)
                for rule_id, cwe in benchmark["rule_cwes"].items()
            }
            actual_rule_cwes = _rule_cwes(args.rules)
            invalid_rules = {
                rule_id: cwe
                for rule_id, cwe in rule_cwes.items()
                if cwe not in actual_rule_cwes.get(rule_id, set())
            }
            if invalid_rules:
                failures.append(
                    f"{benchmark['name']}: rule CWE mapping changed: {invalid_rules}"
                )
                continue
            first_document = _scan(args.opengrep, args.rules, sources)
            second_document = _scan(args.opengrep, args.rules, sources)
            if _exact_findings(first_document, source_root) != _exact_findings(
                second_document, source_root
            ):
                failures.append(f"{benchmark['name']}: repeated findings differ")
            actual = _score_juliet(
                first_document,
                source_root / str(benchmark["manifest_file"]),
                rule_cwes,
            )
        elif benchmark_type == "juliet-preprocessed":
            benchmark_rules = DEFAULT_RULES / str(benchmark["rules_subdir"])
            source = checkout / str(benchmark["source_path"])
            support = checkout / str(benchmark["support_path"])
            if not source.is_dir() or not support.is_dir():
                failures.append(f"{benchmark['name']}: source or support path missing")
                continue
            with tempfile.TemporaryDirectory() as work:
                out = Path(work) / "preprocessed"
                done, skipped = _preprocess_juliet(
                    source, support, out, str(benchmark["file_glob"])
                )
                first = _scan(args.opengrep, benchmark_rules, out)
                second = _scan(args.opengrep, benchmark_rules, out)
                if _exact_findings(first, out) != _exact_findings(second, out):
                    failures.append(f"{benchmark['name']}: repeated findings differ")
                actual = _score_juliet_preprocessed(first, done, skipped)
        elif benchmark_type == "codeql-markers":
            benchmark_rules = DEFAULT_RULES / str(benchmark["rules_subdir"])
            source = checkout / str(benchmark["source_path"])
            if not source.is_dir():
                failures.append(f"{benchmark['name']}: source path missing: {source}")
                continue
            with tempfile.TemporaryDirectory() as neutral_root:
                # Opengrep's built-in exclusions drop paths with a component
                # named test or tests, which every CodeQL query-test path has.
                neutral = Path(neutral_root) / "corpus"
                shutil.copytree(source, neutral)
                first = _scan(args.opengrep, benchmark_rules, neutral)
                second = _scan(args.opengrep, benchmark_rules, neutral)
                if _exact_findings(first, neutral) != _exact_findings(second, neutral):
                    failures.append(f"{benchmark['name']}: repeated findings differ")
                actual = _score_codeql_markers(
                    first, neutral, str(benchmark["alert_query"])
                )
        elif benchmark_type == "juliet-methods":
            benchmark_rules = DEFAULT_RULES / str(benchmark["rules_subdir"])
            source = checkout / str(benchmark["source_path"])
            if not source.is_dir():
                failures.append(f"{benchmark['name']}: source path missing: {source}")
                continue
            first = _scan(args.opengrep, benchmark_rules, source)
            second = _scan(args.opengrep, benchmark_rules, source)
            if _exact_findings(first, source) != _exact_findings(second, source):
                failures.append(f"{benchmark['name']}: repeated findings differ")
            actual = _score_juliet_methods(first, CSHARP_METHOD_RE)
        elif benchmark_type == "gosec-samples":
            # Each benchmark states the rule subtree it is scored against. The
            # --rules default targets the Java corpora, so a Go benchmark that
            # relied on it would silently score zero.
            benchmark_rules = DEFAULT_RULES / str(benchmark["rules_subdir"])
            if not benchmark_rules.is_dir():
                failures.append(
                    f"{benchmark['name']}: rules subtree missing: {benchmark_rules}"
                )
                continue
            sample_files = {
                str(rule_id): str(relative)
                for rule_id, relative in benchmark["sample_files"].items()
            }
            missing = [
                relative
                for relative in sample_files.values()
                if not (checkout / relative).is_file()
            ]
            if missing:
                failures.append(f"{benchmark['name']}: sample file missing: {missing}")
                continue
            with tempfile.TemporaryDirectory() as first_dir:
                actual = _score_gosec(
                    args.opengrep,
                    benchmark_rules,
                    checkout,
                    sample_files,
                    Path(first_dir),
                )
            with tempfile.TemporaryDirectory() as second_dir:
                repeat = _score_gosec(
                    args.opengrep,
                    benchmark_rules,
                    checkout,
                    sample_files,
                    Path(second_dir),
                )
            if actual != repeat:
                failures.append(f"{benchmark['name']}: repeated scoring differs")
        else:
            failures.append(
                f"{benchmark['name']}: unsupported benchmark type {benchmark_type}"
            )
            continue

        if actual != benchmark["expected"]:
            failures.append(
                f"{benchmark['name']}: expected {benchmark['expected']}, found {actual}"
            )
        if args.require_promotion_ready and not benchmark["promotion_ready"]:
            failures.append(
                f"{benchmark['name']}: "
                f"{benchmark.get('promotion_blocker', 'not ready')}"
            )
        if benchmark_type == "codeql-markers":
            print(
                f"{benchmark['name']}: "
                f"{actual['alert_lines_covered']} of {actual['alert_lines']} alert lines covered, "
                f"{actual['good_lines_reported']} of {actual['good_lines']} good lines reported"
            )
            continue
        if benchmark_type == "juliet-methods":
            print(
                f"{benchmark['name']}: "
                f"{actual['files_with_bad_finding']} files with a finding in a Bad method, "
                f"{actual['findings_in_good_methods']} findings in Good methods, "
                f"{actual['findings_not_attributed']} unattributed"
            )
            continue
        if benchmark_type == "juliet-preprocessed":
            print(
                f"{benchmark['name']}: {actual['preprocessed_files']} preprocessed, "
                f"{actual['skipped_files']} skipped"
            )
            print(
                f"  files with a finding in the vulnerable function: "
                f"{actual['files_with_bad_finding']}"
            )
            print(
                f"  findings in non-vulnerable functions: "
                f"{actual['findings_in_good_on_insecure_call']} on an insecure call, "
                f"{actual['findings_in_good_on_secure_call']} on a secure call"
            )
            continue
        if benchmark_type == "gosec-samples":
            print(f"{benchmark['name']}: {actual['cases_total']} cases")
            for gosec_rule, values in sorted(actual["by_rule"].items()):
                print(
                    f"  {gosec_rule}: cases={values['cases']} "
                    f"vulnerable={values['vulnerable']} "
                    f"detected={values['detected']} "
                    f"fp_on_safe={values['fp_on_safe']}"
                )
            continue
        print(f"{benchmark['name']}: {actual['files_scanned']} files")
        if benchmark_type == "owasp-csv":
            for cwe, values in actual["metrics_by_cwe"].items():
                precision = _ratio(values["tp"], values["tp"] + values["fp"])
                recall = _ratio(values["tp"], values["tp"] + values["fn"])
                print(
                    f"  CWE-{cwe}: TP={values['tp']} FP={values['fp']} "
                    f"FN={values['fn']} TN={values['tn']} "
                    f"precision={precision} recall={recall}"
                )
        else:
            for rule_id, values in actual["metrics_by_rule"].items():
                recall = _ratio(values["cases_detected"], values["cases_total"])
                print(
                    f"  {rule_id}: cases={values['cases_detected']}/"
                    f"{values['cases_total']} recall={recall}, "
                    f"findings={values['finding_count']}, "
                    f"manifest-locations={values['findings_at_manifest_flaws']}"
                )

    if failures:
        raise BenchmarkGateError("benchmark gate failed:\n" + "\n".join(failures))
    print(f"benchmark result matches reviewed baseline with Opengrep {engine_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
