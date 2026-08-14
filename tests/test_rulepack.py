"""Structural gate for the bundled SAST rule pack.

Checks run on raw YAML using pyyaml only -- no engine required. The engine
gate (opengrep per-rule execution) lives in scripts/rulepack_gate.sh.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
RULES_ROOT = REPO_ROOT / "cra_evidence_cli" / "local" / "rules"
FIXTURES_ROOT = REPO_ROOT / "tests" / "rule_fixtures"
VERSIONS_FILE = Path(__file__).parent / "rulepack_versions.json"
CWE_POLICY_FILE = Path(__file__).parent / "cwe_mapping_policy.json"

LANG_EXT = {
    "python": "py",
    "javascript": "js",
    "go": "go",
    "java": "java",
    "c": "c",
    "cpp": "cpp",
    "rust": "rs",
    "php": "php",
    "csharp": "cs",
}

EXPECTED_LANGUAGE_GROUPS = {
    "python": {"python"},
    "javascript": {"javascript", "typescript"},
    "go": {"go"},
    "java": {"java"},
    "c": {"c"},
    "cpp": {"cpp"},
    "rust": {"rust"},
    "php": {"php"},
    "csharp": {"csharp"},
}

DETECTION_KEYS = frozenset(
    {
        "pattern",
        "patterns",
        "pattern-either",
        "pattern-regex",
        "pattern-sources",
        "pattern-sinks",
        "pattern-sanitizers",
        "pattern-not",
        "pattern-not-inside",
        "pattern-inside",
    }
)

VALID_SEVERITIES = {"ERROR", "WARNING", "INFO"}
VALID_CONFIDENCES = {"LOW", "MEDIUM", "HIGH", "VERY HIGH"}
VALID_TIERS = {"default", "experimental"}

CWE_RE = re.compile(r"^CWE-(\d+)")
OWASP_RE = re.compile(r"^A\d{2}:\d{4}")
URL_RE = re.compile(r"^https?://")


def _all_rule_files() -> list[Path]:
    return sorted(RULES_ROOT.rglob("*.yaml"))


def _load_rule(path: Path) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def _rule_id_from_file(path: Path) -> str:
    return path.stem


def _fixture_path(rule_path: Path) -> Path | None:
    rel = rule_path.relative_to(RULES_ROOT)
    lang_dir = rel.parts[0]
    ext = LANG_EXT.get(lang_dir)
    if ext is None:
        return None
    stem = rule_path.stem
    return FIXTURES_ROOT / rel.parent / f"{stem}.{ext}"


def _annotation_re(rule_id: str) -> tuple[re.Pattern, re.Pattern]:
    escaped = re.escape(rule_id)
    hit = re.compile(rf"(?:#|//)\s+ruleid:\s+{escaped}")
    ok = re.compile(rf"(?:#|//)\s+ok:\s+{escaped}")
    return hit, ok


def _python_import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                bound = item.asname or item.name.split(".", 1)[0]
                aliases[bound] = item.name if item.asname else bound
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name == "*":
                    continue
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _python_call_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    parts.reverse()
    parts[0] = aliases.get(parts[0], parts[0])
    return ".".join(parts)


def _python_calls_in_ok_functions(fixture: Path, rule_id: str) -> set[str]:
    source = fixture.read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source, filename=str(fixture))
    aliases = _python_import_aliases(tree)
    calls: set[str] = set()
    marker = f"ok: {rule_id}"

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        function_lines = lines[node.lineno - 1 : node.end_lineno]
        if not any(marker in line for line in function_lines):
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = _python_call_name(child.func, aliases)
                if name:
                    calls.add(name)
    return calls


def _nested_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _nested_strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _nested_strings(child)]
    return []


def _callable_sanitizers(rule: dict) -> set[str]:
    callables: set[str] = set()
    for value in _nested_strings(rule.get("pattern-sanitizers", [])):
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_.]*)\(", value.strip())
        if match:
            callables.add(match.group(1))
    return callables


_METHOD_CALL_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_NAMESPACED_CALL_RE = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*::)+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _method_sanitizers(rule: dict) -> set[str]:
    """Sanitizer names written as a method on a metavariable or a namespaced call.

    _callable_sanitizers only matches a bare callable at the start of a pattern,
    so it returns nothing for shapes such as ``$PATH.StartsWith(...)`` or
    ``std::fs::canonicalize(...)``. Those rules would otherwise be exempt from
    the fixture coverage checks below.
    """
    names: set[str] = set()
    for value in _nested_strings(rule.get("pattern-sanitizers", [])):
        names.update(_METHOD_CALL_RE.findall(value))
        names.update(_NAMESPACED_CALL_RE.findall(value))
    return names


# ---------------------------------------------------------------------------
# Parametrize over every yaml file in the rules tree
# ---------------------------------------------------------------------------

_rule_files = _all_rule_files()
_rule_ids = [f.stem for f in _rule_files]


@pytest.mark.parametrize("rule_path", _rule_files, ids=_rule_ids)
def test_rule_structure(rule_path: Path) -> None:
    """Each YAML file must contain exactly one valid rule whose id matches the filename."""
    data = _load_rule(rule_path)
    assert isinstance(data, dict), f"{rule_path}: top-level value must be a mapping"
    assert "rules" in data, (
        f"{rule_path}: missing top-level 'rules' key -- not a valid rule file"
    )
    rules = data["rules"]
    assert isinstance(rules, list), f"{rule_path}: 'rules' must be a list"
    assert len(rules) == 1, f"{rule_path}: expected exactly 1 rule, found {len(rules)}"
    r = rules[0]

    # id matches filename
    expected_id = _rule_id_from_file(rule_path)
    assert r.get("id") == expected_id, (
        f"{rule_path}: rule 'id' is '{r.get('id')}', expected '{expected_id}'"
    )

    # id prefix
    assert str(r["id"]).startswith("cra-"), (
        f"{rule_path}: rule id '{r['id']}' must start with 'cra-'"
    )

    # severity
    assert r.get("severity") in VALID_SEVERITIES, (
        f"{rule_path}: 'severity' must be one of {VALID_SEVERITIES}, "
        f"got '{r.get('severity')}'"
    )

    # languages
    langs = r.get("languages")
    assert isinstance(langs, list), f"{rule_path}: 'languages' must be a list"
    assert langs, f"{rule_path}: 'languages' must be non-empty"

    # detection body
    detection = {k for k in r if k in DETECTION_KEYS}
    assert detection, (
        f"{rule_path}: no detection key found; expected one of {DETECTION_KEYS}"
    )

    # metadata
    meta = r.get("metadata")
    assert isinstance(meta, dict), f"{rule_path}: 'metadata' must be a mapping"

    # cwe
    cwe = meta.get("cwe")
    assert isinstance(cwe, list), f"{rule_path}: metadata.cwe must be a list"
    assert cwe, f"{rule_path}: metadata.cwe must be non-empty"
    for entry in cwe:
        assert CWE_RE.match(str(entry)), (
            f"{rule_path}: cwe entry '{entry}' must match ^CWE-\\d+"
        )

        cwe_id = CWE_RE.match(str(entry)).group(1)
        policy = json.loads(CWE_POLICY_FILE.read_text(encoding="utf-8"))
        known = policy["known_mapping_ids"]
        assert cwe_id in known, (
            f"{rule_path}: CWE-{cwe_id} is absent from {policy['source']}"
        )
        assert known[cwe_id]["kind"] == "weakness", (
            f"{rule_path}: CWE-{cwe_id} is a {known[cwe_id]['kind']}, not a Weakness"
        )
        disallowed = policy["disallowed_mapping_ids"]
        assert cwe_id not in disallowed, (
            f"{rule_path}: CWE-{cwe_id} mapping is {disallowed.get(cwe_id)} "
            f"in {policy['source']}"
        )
        review_entries = policy["allowed_with_review_mapping_ids"]
        if review_entries.get(cwe_id) == "class":
            assert cwe_id in policy["reviewed_current_mappings"], (
                f"{rule_path}: CWE-{cwe_id} is a Class-level "
                "Allowed-with-Review mapping without a recorded review"
            )

    # owasp
    owasp = meta.get("owasp")
    assert isinstance(owasp, list), f"{rule_path}: metadata.owasp must be a list"
    assert owasp, f"{rule_path}: metadata.owasp must be non-empty"
    for entry in owasp:
        assert OWASP_RE.match(str(entry)), (
            f"{rule_path}: owasp entry '{entry}' must match ^A\\d{{2}}:\\d{{4}}"
        )

    # references
    refs = meta.get("references")
    assert isinstance(refs, list), f"{rule_path}: metadata.references must be a list"
    assert refs, f"{rule_path}: metadata.references must be non-empty"
    for ref in refs:
        assert URL_RE.match(str(ref)), (
            f"{rule_path}: reference '{ref}' must be an http(s) URL"
        )

    # category
    assert meta.get("category") == "security", (
        f"{rule_path}: metadata.category must be 'security'"
    )

    # technology
    tech = meta.get("technology")
    assert isinstance(tech, list), f"{rule_path}: metadata.technology must be a list"
    assert tech, f"{rule_path}: metadata.technology must be non-empty"

    # confidence
    assert meta.get("confidence") in VALID_CONFIDENCES, (
        f"{rule_path}: metadata.confidence must be one of {VALID_CONFIDENCES}, "
        f"got '{meta.get('confidence')}'"
    )

    assert meta.get("tier") in VALID_TIERS, (
        f"{rule_path}: metadata.tier must be one of {VALID_TIERS}, "
        f"got '{meta.get('tier')}'"
    )

    # license
    assert meta.get("license") == "MIT", (
        f"{rule_path}: metadata.license must be 'MIT', got '{meta.get('license')}'"
    )

    # author or origin
    assert "author" in meta or "origin" in meta, (
        f"{rule_path}: metadata must have 'author' or 'origin'"
    )


@pytest.mark.parametrize("rule_path", _rule_files, ids=_rule_ids)
def test_taint_rule_has_sources_and_sinks(rule_path: Path) -> None:
    """A mode: taint rule must declare both pattern-sources and pattern-sinks."""
    r = _load_rule(rule_path)["rules"][0]
    if r.get("mode") != "taint":
        pytest.skip("not a taint rule")
    assert r.get("pattern-sources"), f"{rule_path}: taint rule missing pattern-sources"
    assert r.get("pattern-sinks"), f"{rule_path}: taint rule missing pattern-sinks"
    if not r.get("pattern-sanitizers"):
        analysis = (r.get("metadata") or {}).get("sanitizer_analysis")
        assert isinstance(analysis, dict), (
            f"{rule_path}: taint rule without sanitizers must declare "
            "metadata.sanitizer_analysis"
        )
        assert analysis.get("status") == "not-modeled"
        reason = str(analysis.get("reason") or "").strip()
        assert len(reason) >= 40, (
            f"{rule_path}: sanitizer_analysis.reason must explain the concrete "
            "boundary, sink replacement, or required control flow"
        )
        assert len(reason.split()) >= 6


def test_cwe_mapping_policy_is_pinned_and_complete() -> None:
    policy = json.loads(CWE_POLICY_FILE.read_text(encoding="utf-8"))
    assert policy["source"] == "MITRE CWE 4.20"
    assert policy["catalog_date"] == "2026-04-30"
    assert len(policy["known_mapping_ids"]) == 1450
    disallowed = policy["disallowed_mapping_ids"]
    assert len(disallowed) == 608
    assert len(policy["allowed_with_review_mapping_ids"]) == 93
    assert disallowed["16"] == "prohibited"
    assert disallowed["200"] == "discouraged"
    assert "99999" not in policy["known_mapping_ids"]


# Go rules adapted from dgryski/semgrep-go (MIT). Each MUST carry provenance.
_DGRYSKI_DERIVED_RULE_IDS = {
    "cra-go-hmac-timing",
    "cra-go-hmac-reused-hash",
    "cra-go-parseint-downcast",
    "cra-go-wrong-lock-unlock",
}


def test_dgryski_derived_rules_carry_origin_metadata() -> None:
    """Every dgryski-derived rule must declare its MIT origin (release gate)."""
    by_id = {f.stem: _load_rule(f)["rules"][0] for f in _rule_files}
    missing = _DGRYSKI_DERIVED_RULE_IDS - set(by_id)
    assert not missing, f"expected dgryski-derived rules not in the pack: {missing}"
    for rule_id in _DGRYSKI_DERIVED_RULE_IDS:
        origin = (by_id[rule_id].get("metadata") or {}).get("origin", "")
        assert "dgryski/semgrep-go" in origin, (
            f"rule {rule_id!r} origin {origin!r} must reference dgryski/semgrep-go"
        )
        assert "MIT" in origin, f"rule {rule_id!r} origin {origin!r} must declare MIT"


def test_every_supported_language_group_has_an_executable_rule() -> None:
    counts = dict.fromkeys(EXPECTED_LANGUAGE_GROUPS, 0)
    for rule_file in _rule_files:
        language = rule_file.relative_to(RULES_ROOT).parts[0]
        assert language in counts, f"unregistered language directory: {language}"
        counts[language] += 1
        declared = set(_load_rule(rule_file)["rules"][0]["languages"])
        assert declared & EXPECTED_LANGUAGE_GROUPS[language], (
            f"{rule_file}: languages {sorted(declared)} do not match directory {language}"
        )

    assert all(count >= 1 for count in counts.values()), counts


def test_runtime_inventory_matches_rules_on_disk() -> None:
    from cra_evidence_cli.local.rules_pack import inspect_rule_pack

    inventory = inspect_rule_pack(RULES_ROOT)
    assert set(inventory.rule_tiers) == set(_rule_ids)
    assert len(inventory.rule_tiers) == len(_rule_files)

    expected_default = sum(tier == "default" for tier in inventory.rule_tiers.values())
    expected_experimental = sum(
        tier == "experimental" for tier in inventory.rule_tiers.values()
    )

    default_count, experimental_count, language_counts = inventory.selection(
        include_experimental=False
    )
    assert default_count == expected_default
    assert experimental_count == 0
    assert sum(language_counts.values()) == expected_default

    default_count, experimental_count, language_counts = inventory.selection(
        include_experimental=True
    )
    assert default_count == expected_default
    assert experimental_count == expected_experimental
    assert sum(language_counts.values()) == len(_rule_files)


def test_runtime_inventory_supports_mixed_tiers_within_one_language(tmp_path) -> None:
    from cra_evidence_cli.local.rules_pack import inspect_rule_pack

    rules = tmp_path / "java" / "crypto"
    rules.mkdir(parents=True)
    for rule_id, tier in (("default-rule", "default"), ("experimental-rule", "experimental")):
        (rules / f"{rule_id}.yaml").write_text(
            "rules:\n"
            f"  - id: {rule_id}\n"
            "    languages: [java]\n"
            "    metadata:\n"
            f"      tier: {tier}\n",
            encoding="utf-8",
        )

    inventory = inspect_rule_pack(tmp_path)
    assert inventory.selection(include_experimental=False) == (1, 0, {"java": 1})
    assert inventory.selection(include_experimental=True) == (1, 1, {"java": 2})


def test_runtime_inventory_exposes_only_declared_semantic_policies() -> None:
    from cra_evidence_cli.local.rules_pack import SemanticRulePolicy, inspect_rule_pack

    inventory = inspect_rule_pack(RULES_ROOT)

    assert inventory.semantic_policies == {
        "cra-c-fixed-array-literal-oob-write": SemanticRulePolicy(
            language="c",
            policy="c.fixed-array-literal-oob-write",
            candidate_range="result",
        ),
        "cra-c-printf-argv-format": SemanticRulePolicy(
            language="c",
            policy="c.printf-main-argv-format",
            candidate_range="result",
        ),
        "cra-c-system-argv": SemanticRulePolicy(
            language="c",
            policy="c.system-main-argv-command",
            candidate_range="result",
        ),
        "cra-cpp-fixed-array-literal-oob-write": SemanticRulePolicy(
            language="cpp",
            policy="cpp.fixed-array-literal-oob-write",
            candidate_range="result",
        ),
        "cra-cpp-printf-argv-format": SemanticRulePolicy(
            language="cpp",
            policy="cpp.printf-main-argv-format",
            candidate_range="result",
        ),
        "cra-cpp-system-argv": SemanticRulePolicy(
            language="cpp",
            policy="cpp.system-main-argv-command",
            candidate_range="result",
        ),
        "cra-csharp-framework-dangerous-certificate-validator": SemanticRulePolicy(
            language="csharp",
            policy="csharp.framework-dangerous-certificate-validator",
            candidate_range="result",
        ),
        "cra-csharp-framework-md5-create": SemanticRulePolicy(
            language="csharp",
            policy="csharp.framework-md5-create",
            candidate_range="result",
        ),
        "cra-java-jdk-weak-message-digest-literal": SemanticRulePolicy(
            language="java",
            policy="java.jdk-message-digest-get-instance",
            candidate_range="result",
        ),
        "cra-rust-cratesio-reqwest-invalid-certs": SemanticRulePolicy(
            language="rust",
            policy="rust.cratesio-reqwest-invalid-certs",
            candidate_range="result",
        ),
    }


def test_runtime_inventory_rejects_semantic_language_mismatch(tmp_path) -> None:
    from cra_evidence_cli.local.rules_pack import inspect_rule_pack

    rule = tmp_path / "csharp" / "crypto" / "invalid.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "rules:\n"
        "  - id: invalid\n"
        "    languages: [csharp]\n"
        "    metadata:\n"
        "      tier: experimental\n"
        "      semantic_evidence:\n"
        "        required: true\n"
        "        language: java\n"
        "        policy: csharp.framework-md5-create\n"
        "        candidate_range: result\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid bundled semantic evidence policy"):
        inspect_rule_pack(tmp_path)


def test_java_rules_publish_scope_and_limitations() -> None:
    java_rules = [
        _load_rule(path)["rules"][0]
        for path in _rule_files
        if path.relative_to(RULES_ROOT).parts[0] == "java"
    ]
    assert len(java_rules) == 9
    for rule in java_rules:
        metadata = rule["metadata"]
        assert len(str(metadata.get("scope") or "").split()) >= 10, rule["id"]
        assert len(str(metadata.get("limitations") or "").split()) >= 8, rule["id"]


@pytest.mark.parametrize("rule_path", _rule_files, ids=_rule_ids)
def test_rule_fixture_exists(rule_path: Path) -> None:
    """Each rule must have a matching fixture with ruleid and ok annotations."""
    fixture = _fixture_path(rule_path)
    rule_id = _rule_id_from_file(rule_path)

    if fixture is None:
        lang_dir = rule_path.relative_to(RULES_ROOT).parts[0]
        pytest.fail(
            f"{rule_path}: cannot determine fixture path -- "
            f"language dir '{lang_dir}' not in LANG_EXT map"
        )

    assert fixture.exists(), (
        f"Missing fixture for rule '{rule_id}': expected {fixture}"
    )

    content = fixture.read_text()
    hit_re, ok_re = _annotation_re(rule_id)

    assert hit_re.search(content), (
        f"{fixture}: no 'ruleid: {rule_id}' annotation found"
    )
    assert ok_re.search(content), (
        f"{fixture}: no 'ok: {rule_id}' annotation found"
    )


def test_default_python_callable_sanitizers_have_safe_fixtures() -> None:
    missing: list[str] = []
    for rule_path in _rule_files:
        if rule_path.relative_to(RULES_ROOT).parts[0] != "python":
            continue
        rule = _load_rule(rule_path)["rules"][0]
        if (rule.get("metadata") or {}).get("tier") != "default":
            continue
        sanitizers = _callable_sanitizers(rule)
        if not sanitizers:
            continue
        fixture = _fixture_path(rule_path)
        assert fixture is not None
        assert fixture.exists()
        calls = _python_calls_in_ok_functions(fixture, rule["id"])
        for sanitizer in sorted(sanitizers - calls):
            missing.append(f"{rule['id']}: {sanitizer}")

    assert not missing, "sanitizers without an annotated safe fixture:\n" + "\n".join(
        missing
    )


def test_callable_sanitizers_have_nearby_safe_annotations() -> None:
    missing: list[str] = []
    for rule_path in _rule_files:
        rule = _load_rule(rule_path)["rules"][0]
        sanitizers = _callable_sanitizers(rule) | _method_sanitizers(rule)
        if not sanitizers:
            continue
        fixture = _fixture_path(rule_path)
        assert fixture is not None
        assert fixture.exists()
        lines = fixture.read_text(encoding="utf-8").splitlines()
        marker = f"ok: {rule['id']}"
        for sanitizer in sorted(sanitizers):
            call_lines = [
                index
                for index, line in enumerate(lines)
                if f"{sanitizer}(" in line
            ]
            covered = any(
                any(marker in line for line in lines[max(0, index - 8) : index + 9])
                for index in call_lines
            )
            if not covered:
                missing.append(f"{rule['id']}: {sanitizer}")

    assert not missing, "sanitizers without nearby safe annotations:\n" + "\n".join(
        missing
    )


# ---------------------------------------------------------------------------
# Pack-wide uniqueness check
# ---------------------------------------------------------------------------

def test_rule_ids_unique() -> None:
    """Rule ids must be unique across the entire pack."""
    ids = [_load_rule(f)["rules"][0]["id"] for f in _rule_files]
    seen: set[str] = set()
    duplicates: list[str] = []
    for rule_id in ids:
        if rule_id in seen:
            duplicates.append(rule_id)
        seen.add(rule_id)
    assert not duplicates, f"Duplicate rule ids found: {duplicates}"


# ---------------------------------------------------------------------------
# Pack version bump guard
# ---------------------------------------------------------------------------

def _compute_pack_hash() -> str:
    """Stable hash over sorted rule ids + full rule bodies.

    The whole rule dict is hashed (not just the detection keys), so any
    user-visible change -- message, severity, confidence, metadata, references,
    or detection logic -- changes the hash and therefore requires a
    PACK_VERSION bump plus a new ledger entry.
    """
    entries: list[tuple[str, str]] = []
    for f in _rule_files:
        data = _load_rule(f)
        r = data["rules"][0]
        rule_id = r["id"]
        body_str = json.dumps(r, sort_keys=True)
        entries.append((rule_id, body_str))
    entries.sort(key=lambda x: x[0])
    h = hashlib.sha256()
    for rule_id, body_str in entries:
        h.update(rule_id.encode())
        h.update(b"\x00")
        h.update(body_str.encode())
        h.update(b"\x00")
    return h.hexdigest()


def _compute_fixture_hash() -> str:
    """Stable hash over every rule fixture path and byte body."""
    h = hashlib.sha256()
    for fixture in sorted(path for path in FIXTURES_ROOT.rglob("*") if path.is_file()):
        relative = fixture.relative_to(FIXTURES_ROOT).as_posix()
        h.update(relative.encode())
        h.update(b"\x00")
        h.update(fixture.read_bytes())
        h.update(b"\x00")
    return h.hexdigest()


def test_pack_version_bump() -> None:
    """A change to the rule set must be released under a new PACK_VERSION.

    Enforcement (ledger in tests/rulepack_versions.json maps every released
    PACK_VERSION to the hash of the rule set at that version):
      - the current PACK_VERSION must map to the current rule-set hash, and
      - no OTHER version may map to the current hash.
    So changing a rule body changes the hash, which no longer matches the
    current version's recorded hash: the only way to pass is to bump
    PACK_VERSION and add a new ledger entry (reusing an existing version for a
    different rule set is rejected by the uniqueness check).
    """
    from cra_evidence_cli.local.rules_pack import PACK_VERSION

    ledger = json.loads(VERSIONS_FILE.read_text())
    computed = _compute_pack_hash()
    computed_fixtures = _compute_fixture_hash()

    fix = (
        "\n\nTo fix: bump PACK_VERSION in cra_evidence_cli/local/rules_pack.py"
        " and add an entry to tests/rulepack_versions.json:"
        f'\n    "<new PACK_VERSION>": {{"rules": "{computed}", '
        f'"fixtures": "{computed_fixtures}"}}\n'
    )

    assert PACK_VERSION in ledger, (
        f"PACK_VERSION {PACK_VERSION!r} has no entry in {VERSIONS_FILE.name}." + fix
    )
    current_entry = ledger[PACK_VERSION]
    assert isinstance(current_entry, dict), (
        f"PACK_VERSION {PACK_VERSION!r} must record both rules and fixtures"
    )
    assert current_entry.get("rules") == computed, (
        f"\n  Version {PACK_VERSION} recorded hash: {current_entry.get('rules')}"
        f"\n  Current rule-set hash            : {computed}"
        "\n  The rule set changed under an unchanged PACK_VERSION." + fix
    )
    assert current_entry.get("fixtures") == computed_fixtures, (
        f"\n  Version {PACK_VERSION} recorded fixture hash: "
        f"{current_entry.get('fixtures')}"
        f"\n  Current fixture hash                  : {computed_fixtures}"
        "\n  Rule evidence changed under an unchanged PACK_VERSION." + fix
    )
    reused = [
        version
        for version, entry in ledger.items()
        if version != PACK_VERSION
        and (
            entry == computed
            or (isinstance(entry, dict) and entry.get("rules") == computed)
        )
    ]
    assert not reused, (
        f"The current rule set is already recorded under version(s) {reused}; "
        f"do not assign it a second version ({PACK_VERSION})."
    )


# ---------------------------------------------------------------------------
# generate_rule_docs.py smoke test
# ---------------------------------------------------------------------------

def test_generate_rule_docs_produces_one_row_per_rule() -> None:
    """scripts/generate_rule_docs.py must run and emit one table row per rule."""
    script = REPO_ROOT / "scripts" / "generate_rule_docs.py"
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"generate_rule_docs.py exited {result.returncode}:\n{result.stderr}"
    )
    output = result.stdout
    expected_count = len(_rule_files)
    data_rows = [
        line for line in output.splitlines()
        if line.startswith("|")
        and not re.match(r"^\|[-| :]+\|$", line)
        and not line.startswith("| id")
    ]
    assert len(data_rows) == expected_count, (
        f"generate_rule_docs.py produced {len(data_rows)} data rows, "
        f"expected {expected_count}"
    )
