#!/usr/bin/env python3
"""Score applicable CRA Evidence rules against pinned known-answer benchmarks."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
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

# Corpus CWEs may differ from the precise mappable child used by a rule. An
# alias changes benchmark ground truth before scoring, so every accepted pair is
# bound to the benchmark where that relationship was reviewed.
REVIEWED_CWE_ALIASES = {("owasp-benchmark-python", 94, 95)}
TEST_ID_RE = re.compile(r"(BenchmarkTest\d+)")
CWE_RE = re.compile(r"^CWE-(\d+)")
JAVA_STRONG_DIGEST_RE = re.compile(
    r'MessageDigest\s*\.\s*getInstance\s*\(\s*"(?:SHA-256|SHA-384|SHA-512)"\s*\)'
)


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


def _rule_cwes(rules: Path, tier: str | None = None) -> dict[str, set[int]]:
    """Map rule id to declared CWEs, optionally restricted to one tier.

    A benchmark that measures what ships by default has to score the default
    tier only. Including an opt-in rule would credit or blame the default tier
    for a finding a user never sees without a flag.
    """
    mapping: dict[str, set[int]] = {}
    for rule_file in sorted(rules.rglob("*.yaml")):
        document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        rule = document["rules"][0]
        if tier is not None and rule["metadata"].get("tier") != tier:
            continue
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
) -> dict:
    """Score an OWASP-style corpus."""
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
    for rule_id, test_id, _, _ in _normalized_findings(document):
        if test_id not in cases:
            message = f"finding references unknown benchmark case: {test_id}"
            raise BenchmarkGateError(message)
        expected_cwe, _ = cases[test_id]
        if rule_id not in rule_cwes:
            # A rule outside the scored tier. Not part of this measurement.
            continue
        finding_cwes = rule_cwes[rule_id]
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


def _run_local_cli(arguments: list[str], *, opengrep: Path | None = None) -> str:
    environment = os.environ.copy()
    if opengrep is not None:
        environment["CRA_EVIDENCE_OPENGREP"] = str(opengrep.resolve(strict=True))
    command = [sys.executable, "-m", "cra_evidence_cli.cli", *arguments]
    result = subprocess.run(  # noqa: S603
        command,
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        message = f"local CLI failed with exit {result.returncode}: {detail[:500]}"
        raise BenchmarkGateError(message)
    return result.stdout


def _java_semantic_metrics(
    evidence: dict,
    report: dict,
    source_files: list[Path],
    rule_id: str,
) -> dict[str, int]:
    occurrences = evidence.get("analysis", {}).get("occurrences") or []
    exact_owner = {
        "module": "java.base",
        "package": "java.security",
        "qualified_name": "java.security.MessageDigest",
        "binary_name": "java.security.MessageDigest",
        "nesting": "TOP_LEVEL",
        "method": "getInstance",
        "first_parameter": "java.lang.String",
    }
    owned = sum(
        all(occurrence.get(key) == value for key, value in exact_owner.items())
        for occurrence in occurrences
    )
    findings = report.get("findings") or []
    wrong_rules = sorted(
        {str(finding.get("rule_id") or "") for finding in findings}
        - {rule_id}
    )
    if wrong_rules:
        message = f"semantic subset produced findings from other rules: {wrong_rules}"
        raise BenchmarkGateError(message)
    if any(
        (finding.get("semantic_evidence") or {}).get("status") != "attested"
        for finding in findings
    ):
        message = "semantic subset retained a finding without attestation"
        raise BenchmarkGateError(message)
    summary = report.get("semantic_evidence") or {}
    safe_controls = sum(
        len(JAVA_STRONG_DIGEST_RE.findall(path.read_text(encoding="utf-8")))
        for path in source_files
    )
    return {
        "source_files": len(evidence.get("source", {}).get("files") or []),
        "compiler_errors": int(evidence.get("analysis", {}).get("error_count", -1)),
        "resolved_invocations": len(occurrences),
        "jdk_owned_invocations": owned,
        "safe_literal_controls": safe_controls,
        "candidate_count": int(summary.get("candidate_count", -1)),
        "attested": int(summary.get("attested", -1)),
        "rejected": int(summary.get("rejected", -1)),
        "unanalysed": int(summary.get("unanalysed", -1)),
        "finding_count": len(findings),
        "engine_errors": len(report.get("engine_errors") or []),
        "unanalysed_files": len(report.get("unanalysed_files") or []),
    }


def _score_java_semantic_juliet(
    source_root: Path,
    specification: dict,
    opengrep: Path,
) -> dict[str, int]:
    source_directory = source_root / str(specification["source_directory"])
    if not source_directory.is_dir() or source_directory.is_symlink():
        message = f"semantic source directory is invalid: {source_directory}"
        raise BenchmarkGateError(message)
    selected = sorted(source_directory.glob(str(specification["file_glob"])))
    support = [source_root / str(path) for path in specification["support_files"]]
    source_files = [*selected, *support]
    if not selected or any(not path.is_file() or path.is_symlink() for path in source_files):
        message = "semantic subset contains a missing, non-file, or symlink source"
        raise BenchmarkGateError(message)
    relative_files = [path.relative_to(source_root) for path in source_files]
    if len(set(relative_files)) != len(relative_files):
        message = "semantic subset contains duplicate source paths"
        raise BenchmarkGateError(message)

    with tempfile.TemporaryDirectory(prefix="cra-java-semantic-benchmark-") as work:
        subset = Path(work) / "source"
        copied: list[Path] = []
        for source, relative in zip(source_files, relative_files, strict=True):
            destination = subset / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            if _sha256(source) != _sha256(destination):
                message = f"semantic source copy changed content: {relative}"
                raise BenchmarkGateError(message)
            copied.append(destination)

        first_evidence = Path(work) / "evidence-one.json"
        second_evidence = Path(work) / "evidence-two.json"
        for output in (first_evidence, second_evidence):
            _run_local_cli(
                [
                    "code-evidence",
                    str(subset),
                    "--language",
                    "java",
                    "--output",
                    str(output),
                ]
            )
        if first_evidence.read_bytes() != second_evidence.read_bytes():
            message = "repeated Java semantic evidence differs"
            raise BenchmarkGateError(message)

        reports = []
        for _ in range(2):
            raw_report = _run_local_cli(
                [
                    "--output",
                    "json",
                    "code-check",
                    str(subset),
                    "--include-experimental",
                    "--semantic-evidence",
                    str(first_evidence),
                ],
                opengrep=opengrep,
            )
            try:
                reports.append(json.loads(raw_report))
            except json.JSONDecodeError as exc:
                message = "semantic benchmark returned invalid JSON"
                raise BenchmarkGateError(message) from exc
        evidence = json.loads(first_evidence.read_text(encoding="utf-8"))
        first_metrics = _java_semantic_metrics(
            evidence, reports[0], copied, str(specification["rule_id"])
        )
        second_metrics = _java_semantic_metrics(
            evidence, reports[1], copied, str(specification["rule_id"])
        )
        if first_metrics != second_metrics:
            message = "repeated Java semantic benchmark results differ"
            raise BenchmarkGateError(message)
        return first_metrics


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


def _score_juliet_preprocessed(
    document: dict, preprocessed: int, skipped: int, scored_rule: str
) -> dict:
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
        if str(result.get("check_id") or "") != scored_rule:
            continue
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


SARD_SAFE_DIR = "safe"


def _sard_truth(path: Path, typo_var: str, unassigned_var: str) -> str:
    """Classify a SARD PHP case, correcting two defects in the generator.

    The corpus splits cases into safe/ and unsafe/ directories, but two
    generated shapes carry the wrong label and both are mechanically
    detectable:

    * a safe case that applies its sanitizer to a misspelled variable leaves
      the tainted value reaching the sink, so it is vulnerable;
    * an unsafe case that reassigns the tainted variable from a variable that
      is never assigned kills the taint, so it is not vulnerable.

    Scoring against the raw directory names would penalise correct behavior on
    both shapes.
    """
    body = path.read_text(encoding="utf-8", errors="replace")
    marker = body.rfind("MODIFICATIONS.*/")
    code = body[marker + len("MODIFICATIONS.*/") :] if marker >= 0 else body
    typo_token = re.escape(typo_var)
    unassigned_token = re.escape(unassigned_var)
    if f"/{SARD_SAFE_DIR}/" in path.as_posix():
        return "vulnerable" if re.search(rf"{typo_token}\b", code) else "safe"
    uses = re.search(rf"{unassigned_token}\b", code) is not None
    assigned = re.search(rf"{unassigned_token}\s*=(?![=>])", code) is not None
    return "safe" if (uses and not assigned) else "vulnerable"


def _score_sard_folders(
    document: dict,
    root: Path,  # noqa: ARG001
    typo_var: str,
    unassigned_var: str,
    scored_rule: str,
) -> dict:
    scanned = [Path(entry) for entry in document.get("paths", {}).get("scanned", [])]
    if not scanned:
        message = "the SARD scan reported no scanned files"
        raise BenchmarkGateError(message)
    # One CWE directory measures one rule. A finding from a different rule is
    # about a different weakness and would otherwise be charged to this one.
    reported = {
        Path(result["path"])
        for result in document["results"]
        if str(result["check_id"]) == scored_rule
    }
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for path in scanned:
        truth = _sard_truth(path, typo_var, unassigned_var)
        hit = path in reported
        if truth == "vulnerable":
            counts["tp" if hit else "fn"] += 1
        else:
            counts["fp" if hit else "tn"] += 1
    return {"files_scanned": len(scanned), **counts}


def _score_juliet_methods(
    document: dict, method_re: re.Pattern[str], scored_rule: str
) -> dict:
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
        if str(result.get("check_id") or "") != scored_rule:
            continue
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
ESLINT_RULE_TESTER_RE = re.compile(
    r'\.run\("no-loss-of-precision",\s*rule,\s*\{\s*'
    r"valid:\s*\[(?P<valid>.*?)\],\s*"
    r"invalid:\s*\[(?P<invalid>.*?)\],?\s*\}\);",
    re.DOTALL,
)
ESLINT_BARE_CODE_RE = re.compile(
    r'^\s*(?P<quoted>"(?:\\.|[^"\\])*")\s*,?\s*$', re.MULTILINE
)
ESLINT_OBJECT_CODE_RE = re.compile(
    r'\bcode:\s*(?P<quoted>"(?:\\.|[^"\\])*")'
)


def _score_codeql_markers(
    document: dict, source: Path, alert_query: str, scored_rule: str
) -> dict:
    """Score against CodeQL's inline alert and good markers.

    A finding is credited to at most one alert when the alert line falls inside
    the finding's own start..end source range. Proximity windows were rejected:
    our rules often anchor at the start of a call chain while CodeQL anchors at
    the method call, and a window either credits a neighbouring construct or
    lets one finding absorb every remaining alert.
    """
    spans: dict[str, list[tuple[int, int]]] = {}
    resolved_source = source.resolve()
    for result in document.get("results") or []:
        if str(result.get("check_id") or "") != scored_rule:
            continue
        result_path = Path(str(result["path"])).resolve()
        try:
            relative = result_path.relative_to(resolved_source).as_posix()
        except ValueError as error:
            message = f"CodeQL finding escapes corpus root: {result_path}"
            raise BenchmarkGateError(message) from error
        spans.setdefault(relative, []).append(
            (int(result["start"]["line"]), int(result["end"]["line"]))
        )
    alerts = covered = good_lines = good_hit = 0
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.name.endswith(".expected"):
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        relative = path.resolve().relative_to(resolved_source).as_posix()
        file_spans = spans.get(relative, [])
        unused_spans = set(range(len(file_spans)))
        for index, text in enumerate(lines, start=1):
            if alert_query in text and not CODEQL_MISSING_RE.search(text):
                alerts += 1
                candidates = [
                    position
                    for position in unused_spans
                    if file_spans[position][0] <= index <= file_spans[position][1]
                ]
                if candidates:
                    selected = min(
                        candidates,
                        key=lambda position: (
                            file_spans[position][1] - file_spans[position][0],
                            file_spans[position][0],
                        ),
                    )
                    unused_spans.remove(selected)
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
        "findings_scored": sum(len(values) for values in spans.values()),
    }


def _eslint_rule_tester_cases(source: Path) -> list[tuple[str, bool, str]]:
    """Extract official valid and invalid no-loss-of-precision cases."""
    text = source.read_text(encoding="utf-8")
    runs = list(ESLINT_RULE_TESTER_RE.finditer(text))
    if len(runs) != 2:
        message = f"expected two ESLint RuleTester runs, found {len(runs)}"
        raise BenchmarkGateError(message)

    cases: list[tuple[str, bool, str]] = []
    for run_index, run in enumerate(runs):
        suffix = "js" if run_index == 0 else "ts"
        valid_block = run.group("valid")
        invalid_block = run.group("invalid")
        valid_literals = [
            match.group("quoted")
            for match in ESLINT_BARE_CODE_RE.finditer(valid_block)
        ]
        valid_literals.extend(
            match.group("quoted")
            for match in ESLINT_OBJECT_CODE_RE.finditer(valid_block)
        )
        invalid_literals = [
            match.group("quoted")
            for match in ESLINT_OBJECT_CODE_RE.finditer(invalid_block)
        ]
        if not valid_literals or not invalid_literals:
            message = "ESLint RuleTester extraction produced an empty label set"
            raise BenchmarkGateError(message)
        try:
            cases.extend((json.loads(value), False, suffix) for value in valid_literals)
            cases.extend((json.loads(value), True, suffix) for value in invalid_literals)
        except json.JSONDecodeError as exc:
            message = "ESLint RuleTester contains an unsupported code literal"
            raise BenchmarkGateError(message) from exc
    return cases


def _score_eslint_rule_tester(
    binary: Path,
    rule: Path,
    source: Path,
    scored_rule: str,
    workdir: Path,
) -> dict:
    cases = _eslint_rule_tester_cases(source)
    corpus = workdir / "corpus"
    corpus.mkdir()
    truth: dict[str, bool] = {}
    for index, (code, vulnerable, suffix) in enumerate(cases):
        name = f"case-{index:03d}.{suffix}"
        (corpus / name).write_text(f"{code}\n", encoding="utf-8")
        truth[name] = vulnerable

    document = _scan(binary, rule, corpus)
    if document.get("errors"):
        message = "ESLint RuleTester benchmark produced engine errors"
        raise BenchmarkGateError(message)
    scanned = {Path(path).name for path in document.get("paths", {}).get("scanned") or []}
    if scanned != set(truth):
        message = "ESLint RuleTester benchmark did not scan the exact extracted cases"
        raise BenchmarkGateError(message)

    reported: dict[str, int] = {}
    for result in document.get("results") or []:
        rule_id = str(result.get("check_id") or "")
        if rule_id != scored_rule:
            message = f"unexpected rule in ESLint benchmark result: {rule_id}"
            raise BenchmarkGateError(message)
        name = Path(str(result.get("path") or "")).name
        if name not in truth:
            message = f"ESLint finding references unknown case: {name}"
            raise BenchmarkGateError(message)
        reported[name] = reported.get(name, 0) + 1
    duplicates = sorted(name for name, count in reported.items() if count != 1)
    if duplicates:
        message = f"ESLint cases produced duplicate findings: {duplicates}"
        raise BenchmarkGateError(message)

    tp = sum(vulnerable and name in reported for name, vulnerable in truth.items())
    fp = sum(not vulnerable and name in reported for name, vulnerable in truth.items())
    fn = sum(vulnerable and name not in reported for name, vulnerable in truth.items())
    tn = sum(not vulnerable and name not in reported for name, vulnerable in truth.items())
    return {
        "cases_total": len(truth),
        "vulnerable_cases": sum(truth.values()),
        "safe_cases": sum(not value for value in truth.values()),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "engine_errors": 0,
    }


def _score_gosec(
    binary: Path,
    rules: Path,
    checkout: Path,
    sample_files: dict[str, str],
    scored_rules: dict[str, str],
    workdir: Path,
) -> dict:
    """Score our rules against gosec's labelled samples, per gosec rule id."""
    actual: dict[str, dict[str, int]] = {}
    if set(sample_files) != set(scored_rules):
        message = "gosec sample files and scored-rule ownership differ"
        raise BenchmarkGateError(message)
    available_rules = set(_rule_cwes(rules))
    missing_rules = set(scored_rules.values()) - available_rules
    if missing_rules:
        message = f"gosec scored rules are not present: {sorted(missing_rules)}"
        raise BenchmarkGateError(message)
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
            found = sum(
                str(result.get("check_id") or "") == scored_rules[gosec_rule]
                for result in document.get("results") or []
            )
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


def _reviewed_cwe_aliases(name: str, raw_aliases: dict[str, int]) -> dict[int, int]:
    aliases = {int(source): int(target) for source, target in raw_aliases.items()}
    unexpected = {
        (name, source, target) for source, target in aliases.items()
    } - REVIEWED_CWE_ALIASES
    if unexpected:
        message = f"unreviewed CWE aliases: {sorted(unexpected)}"
        raise BenchmarkGateError(message)
    return aliases


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
    for benchmark in benchmarks:
        name = benchmark.get("name", "<unnamed>")
        if not isinstance(benchmark.get("promotion_ready"), bool):
            message = f"{name}: promotion_ready must be a boolean"
            raise BenchmarkGateError(message)
        if not benchmark["promotion_ready"] and not benchmark.get("promotion_blocker"):
            message = f"{name}: a non-ready benchmark requires promotion_blocker"
            raise BenchmarkGateError(message)
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
            try:
                cwe_aliases = _reviewed_cwe_aliases(
                    str(benchmark["name"]), benchmark.get("cwe_aliases") or {}
                )
            except BenchmarkGateError as error:
                failures.append(f"{benchmark['name']}: {error}")
                continue
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
            rule_cwes = _rule_cwes(benchmark_rules, benchmark.get("score_tier"))
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
            actual = _score(first_document, cases, rule_cwes)
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
            semantic_specification = benchmark.get("semantic_evidence")
            if semantic_specification is not None:
                actual["semantic_evidence"] = _score_java_semantic_juliet(
                    source_root,
                    semantic_specification,
                    args.opengrep,
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
                actual = _score_juliet_preprocessed(
                    first, done, skipped, str(benchmark["scored_rule"])
                )
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
                    first,
                    neutral,
                    str(benchmark["alert_query"]),
                    str(benchmark["scored_rule"]),
                )
        elif benchmark_type == "eslint-rule-tester":
            benchmark_rule = REPO_ROOT / str(benchmark["rule_path"])
            source = checkout / str(benchmark["source_file"])
            if not benchmark_rule.is_file():
                failures.append(
                    f"{benchmark['name']}: rule file missing: {benchmark_rule}"
                )
                continue
            if not source.is_file() or source.is_symlink():
                failures.append(f"{benchmark['name']}: source file missing: {source}")
                continue
            with tempfile.TemporaryDirectory() as first_dir:
                actual = _score_eslint_rule_tester(
                    args.opengrep,
                    benchmark_rule,
                    source,
                    str(benchmark["scored_rule"]),
                    Path(first_dir),
                )
            with tempfile.TemporaryDirectory() as second_dir:
                repeat = _score_eslint_rule_tester(
                    args.opengrep,
                    benchmark_rule,
                    source,
                    str(benchmark["scored_rule"]),
                    Path(second_dir),
                )
            if actual != repeat:
                failures.append(f"{benchmark['name']}: repeated scoring differs")
        elif benchmark_type == "sard-folders":
            benchmark_rules = DEFAULT_RULES / str(benchmark["rules_subdir"])
            source = checkout / str(benchmark["source_path"])
            if not source.is_dir():
                failures.append(f"{benchmark['name']}: source path missing: {source}")
                continue
            first = _scan(args.opengrep, benchmark_rules, source)
            second = _scan(args.opengrep, benchmark_rules, source)
            if _exact_findings(first, source) != _exact_findings(second, source):
                failures.append(f"{benchmark['name']}: repeated findings differ")
            actual = _score_sard_folders(
                first,
                source,
                str(benchmark["typo_variable"]),
                str(benchmark["unassigned_variable"]),
                str(benchmark["scored_rule"]),
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
            actual = _score_juliet_methods(
                first, CSHARP_METHOD_RE, str(benchmark["scored_rule"])
            )
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
                    benchmark["scored_rules"],
                    Path(first_dir),
                )
            with tempfile.TemporaryDirectory() as second_dir:
                repeat = _score_gosec(
                    args.opengrep,
                    benchmark_rules,
                    checkout,
                    sample_files,
                    benchmark["scored_rules"],
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
        if benchmark_type == "eslint-rule-tester":
            print(f"{benchmark['name']}: {actual['cases_total']} cases")
            print(
                f"  TP={actual['tp']} FP={actual['fp']} FN={actual['fn']} "
                f"TN={actual['tn']} precision={actual['precision']:.1%} "
                f"recall={actual['recall']:.1%}"
            )
            continue
        print(f"{benchmark['name']}: {actual['files_scanned']} files")
        if benchmark_type == "sard-folders":
            precision = _ratio(actual["tp"], actual["tp"] + actual["fp"])
            recall = _ratio(actual["tp"], actual["tp"] + actual["fn"])
            print(
                f"  TP={actual['tp']} FP={actual['fp']} FN={actual['fn']} "
                f"TN={actual['tn']} precision={precision} recall={recall}"
            )
            continue
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
            semantic = actual.get("semantic_evidence")
            if semantic is not None:
                print(
                    "  semantic evidence: "
                    f"{semantic['attested']}/{semantic['candidate_count']} attested, "
                    f"{semantic['jdk_owned_invocations']} JDK-owned calls, "
                    f"{semantic['safe_literal_controls']} strong controls, "
                    f"{semantic['compiler_errors']} compiler errors"
                )

    if failures:
        raise BenchmarkGateError("benchmark gate failed:\n" + "\n".join(failures))
    print(f"benchmark result matches reviewed baseline with Opengrep {engine_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
