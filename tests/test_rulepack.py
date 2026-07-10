"""Structural gate for the bundled SAST rule pack.

Checks run on raw YAML using pyyaml only -- no engine required. The engine
gate (opengrep per-rule execution) lives in scripts/rulepack_gate.sh.
"""

from __future__ import annotations

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

LANG_EXT = {
    "python": "py",
    "javascript": "js",
    "go": "go",
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

CWE_RE = re.compile(r"^CWE-\d+")
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

    fix = (
        "\n\nTo fix: bump PACK_VERSION in cra_evidence_cli/local/rules_pack.py"
        " and add an entry to tests/rulepack_versions.json:"
        f'\n    "<new PACK_VERSION>": "{computed}"\n'
    )

    assert PACK_VERSION in ledger, (
        f"PACK_VERSION {PACK_VERSION!r} has no entry in {VERSIONS_FILE.name}." + fix
    )
    assert ledger[PACK_VERSION] == computed, (
        f"\n  Version {PACK_VERSION} recorded hash: {ledger[PACK_VERSION]}"
        f"\n  Current rule-set hash            : {computed}"
        "\n  The rule set changed under an unchanged PACK_VERSION." + fix
    )
    reused = [v for v, h in ledger.items() if h == computed and v != PACK_VERSION]
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
