"""Tests for the draft command group (no API key required)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from cra_evidence_cli.commands.draft import draft
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.local.disclaimer import DISCLAIMER_MARKER, DRAFT_WATERMARK
from cra_evidence_cli.local.models import Finding, LocalCheckResult
from cra_evidence_cli.local.vex import apply_vex, load_vex

# Helpers


def _obj() -> dict:
    """Minimal context object that draft commands read from ctx.obj."""
    return {
        "config": CRAEvidenceConfig(
            url="https://api.craevidence.com",
            output_format="text",
        ),
        "verbose": False,
    }


def _make_result(findings: list[Finding]) -> LocalCheckResult:
    """Build a minimal LocalCheckResult with the given findings."""
    return LocalCheckResult(
        target="x",
        target_type="sbom",
        sbom_path=None,
        components=[],
        findings=findings,
        dimensions=[],
        coverage=[],
        provenance={},
        attributions=[],
        sources_consulted=[],
    )


def _finding_with_purl(vid: str = "CVE-2024-0001") -> Finding:
    return Finding(
        id=vid,
        package="openssl",
        version="3.0.0",
        purl="pkg:deb/debian/openssl@3.0.0-1",
        aliases={"GHSA-aaaa-0001-0001"},
    )


def _finding_no_purl(vid: str = "CVE-2024-0002") -> Finding:
    return Finding(
        id=vid,
        package="zlib",
        version="1.2.11",
        purl=None,
        aliases=set(),
    )


# Test 1: draft security.txt produces required fields


def test_security_txt_stdout_contains_required_fields():
    runner = CliRunner()
    result = runner.invoke(draft, ["security.txt"], obj=_obj())

    assert result.exit_code == 0, result.output
    assert "Contact:" in result.output
    assert "Expires:" in result.output
    assert "Policy:" in result.output
    assert "RFC 9116" in result.output
    assert DISCLAIMER_MARKER in result.output


# Test 2: draft security.txt -o writes to file with required fields


def test_security_txt_output_file(tmp_path: Path):
    out = tmp_path / "security.txt"
    runner = CliRunner()
    result = runner.invoke(draft, ["security.txt", "-o", str(out)], obj=_obj())

    assert result.exit_code == 0, result.output
    assert out.exists()

    content = out.read_text(encoding="utf-8")
    assert "Contact:" in content
    assert "Expires:" in content
    assert "Policy:" in content
    assert "RFC 9116" in content
    # Disclaimer must appear as a comment inside the file itself.
    assert DISCLAIMER_MARKER in content.lower()


# Test 3: draft vex round-trip


def test_vex_round_trip(tmp_path: Path):
    """Monkeypatch run_local_check, capture output JSON, then feed through load_vex + apply_vex."""
    findings = [_finding_with_purl(), _finding_no_purl()]
    fake_result = _make_result(findings)

    # click's exists=True check runs before the command body; the file must exist.
    dummy = tmp_path / "dummy.json"
    dummy.write_text("{}", encoding="utf-8")

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["vex", "--sbom", str(dummy)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    # stdout and stderr are mixed; extract the JSON by parsing up to the first
    # non-JSON line. The JSON block starts at the first '{'.
    combined = result.output
    json_start = combined.index("{")
    # Find the matching closing brace using a quick scan.
    depth = 0
    json_end = json_start
    for i, ch in enumerate(combined[json_start:], start=json_start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                json_end = i
                break
    json_text = combined[json_start : json_end + 1]

    doc = json.loads(json_text)
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert len(doc["statements"]) == 2

    # Write to a temp file and parse through load_vex.
    vex_path = tmp_path / "out.vex.json"
    vex_path.write_text(json_text, encoding="utf-8")
    vex_doc = load_vex(vex_path)
    assert vex_doc.format == "openvex"

    # All parsed statements must be under_investigation.
    for stmt in vex_doc.statements:
        assert stmt.status == "under_investigation"

    # apply_vex with under_investigation suppresses nothing.
    kept, suppressions = apply_vex(findings, vex_doc)
    assert kept == findings
    assert suppressions == []


# Test 4: emitted vex never contains forbidden status values


def test_vex_no_forbidden_status_values(tmp_path: Path):
    findings = [_finding_with_purl("CVE-2024-9999"), _finding_no_purl("GHSA-bbbb-cccc-dddd")]
    fake_result = _make_result(findings)

    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["vex", "--sbom", str(dummy)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    combined = result.output

    assert "not_affected" not in combined
    assert '"fixed"' not in combined
    assert "justification" not in combined

    # Extract the JSON block and verify all statement statuses.
    json_start = combined.index("{")
    depth = 0
    json_end = json_start
    for i, ch in enumerate(combined[json_start:], start=json_start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                json_end = i
                break
    doc = json.loads(combined[json_start : json_end + 1])
    for stmt in doc["statements"]:
        assert stmt["status"] == "under_investigation"


# Test 5: disclaimer appears in machine output (JSON) and human stderr


def test_vex_disclaimer_in_both_outputs(tmp_path: Path):
    findings = [_finding_with_purl()]
    fake_result = _make_result(findings)

    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["vex", "--sbom", str(dummy)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    combined = result.output

    assert combined.lower().count(DISCLAIMER_MARKER) >= 2
    # Watermark must also be present.
    assert DRAFT_WATERMARK in combined, "watermark missing from output"


def test_security_txt_disclaimer_in_both_outputs():
    runner = CliRunner()
    result = runner.invoke(draft, ["security.txt"], obj=_obj())

    assert result.exit_code == 0
    combined = result.output
    assert combined.lower().count(DISCLAIMER_MARKER) >= 2
    assert DRAFT_WATERMARK in combined, "watermark missing from output"


# Test 6: purl present in statement when finding has purl, absent when not


def test_vex_products_field_only_when_purl_present(tmp_path: Path):
    with_purl = _finding_with_purl("CVE-2024-1111")
    without_purl = _finding_no_purl("CVE-2024-2222")
    fake_result = _make_result([with_purl, without_purl])

    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")

    # Use -o so the JSON goes cleanly to a file, avoiding stream-mixing issues.
    out = tmp_path / "out.vex.json"
    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["vex", "--sbom", str(dummy), "-o", str(out)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    stmts = {s["vulnerability"]["name"]: s for s in doc["statements"]}

    assert "products" in stmts["CVE-2024-1111"]
    assert stmts["CVE-2024-1111"]["products"] == [{"@id": with_purl.purl}]
    assert "products" not in stmts["CVE-2024-2222"]


# Test 7: usage errors for conflicting input modes


def test_vex_rejects_image_and_sbom_together(tmp_path: Path):
    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        draft,
        ["vex", "--image", "ubuntu:22.04", "--sbom", str(dummy)],
        obj=_obj(),
    )
    assert result.exit_code != 0


# Test 8: zero-findings case emits empty statements list and a warning


def test_vex_zero_findings_produces_empty_statements(tmp_path: Path):
    fake_result = _make_result([])

    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")

    out = tmp_path / "out.vex.json"
    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["vex", "--sbom", str(dummy), "-o", str(out)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["statements"] == []
    # A note about the empty skeleton must appear in the console output.
    assert "empty" in result.output.lower() or "no finding" in result.output.lower()


# Test: draft vex --format csaf


def test_vex_csaf_round_trip(tmp_path: Path):
    """--format csaf emits a CSAF 2.0 VEX doc that our own parser accepts."""
    findings = [_finding_with_purl("CVE-2024-0001"), _finding_no_purl("GHSA-bbbb-cccc-dddd")]
    fake_result = _make_result(findings)
    dummy = tmp_path / "dummy.json"
    dummy.write_text("{}", encoding="utf-8")
    out = tmp_path / "out.csaf.json"

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["vex", "--sbom", str(dummy), "--format", "csaf", "-o", str(out)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    assert "Wrote 2 CSAF VEX statement(s)" in result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["document"]["csaf_version"] == "2.0"

    cve_entries = [v for v in doc["vulnerabilities"] if v.get("cve") == "CVE-2024-0001"]
    assert cve_entries
    assert cve_entries[0]["product_status"]["under_investigation"] == [
        "pkg:deb/debian/openssl@3.0.0-1"
    ]
    ghsa_ids = [i["text"] for v in doc["vulnerabilities"] for i in v.get("ids", [])]
    assert "GHSA-bbbb-cccc-dddd" in ghsa_ids
    purl = "pkg:deb/debian/openssl@3.0.0-1"
    assert {"product_id": purl, "name": purl} in doc["product_tree"]["full_product_names"]
    assert DISCLAIMER_MARKER in out.read_text(encoding="utf-8").lower()

    # Round-trips through our parser as CSAF, suppressing nothing (under_investigation).
    vex_doc = load_vex(out)
    assert vex_doc.format == "csaf"
    kept, suppressions = apply_vex(findings, vex_doc)
    assert kept == findings
    assert suppressions == []


def test_vex_csaf_only_under_investigation(tmp_path: Path):
    """The CSAF skeleton must never pre-set a suppressing product_status."""
    findings = [_finding_with_purl("CVE-2024-7777")]
    fake_result = _make_result(findings)
    dummy = tmp_path / "dummy.json"
    dummy.write_text("{}", encoding="utf-8")
    out = tmp_path / "out.csaf.json"

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["vex", "--sbom", str(dummy), "--format", "csaf", "-o", str(out)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    for vuln in doc["vulnerabilities"]:
        assert list(vuln["product_status"].keys()) == ["under_investigation"]


# Tests: draft advisory


def test_advisory_structurally_valid(tmp_path: Path):
    """The advisory is a CSAF 2.0 security advisory, one vuln entry per finding."""
    findings = [_finding_with_purl("CVE-2021-44228"), _finding_no_purl("GHSA-aaaa-bbbb-cccc")]
    fake_result = _make_result(findings)
    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")
    out = tmp_path / "advisory.json"

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["advisory", "--sbom", str(dummy), "-o", str(out)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    document = doc["document"]
    assert document["category"] == "csaf_security_advisory"
    assert document["csaf_version"] == "2.0"
    assert document["tracking"]["status"] == "draft"
    assert len(doc["vulnerabilities"]) == 2

    purl = "pkg:deb/debian/openssl@3.0.0-1"
    cve_entry = next(v for v in doc["vulnerabilities"] if v.get("cve") == "CVE-2021-44228")
    assert cve_entry["product_status"]["known_affected"] == [purl]
    remediation = cve_entry["remediations"][0]
    assert remediation["category"] == "vendor_fix"
    # The placeholder url must be a valid CSAF uri (scheme, no spaces) yet clearly a stub.
    assert remediation["url"].startswith("https://")
    assert " " not in remediation["url"]
    assert "replace" in remediation["url"].lower()
    assert "REPLACE" in remediation["details"]
    assert remediation["product_ids"] == [purl]
    assert {"product_id": purl, "name": purl} in doc["product_tree"]["full_product_names"]

    # Both placeholder notes must survive: description (these findings carry no title,
    # so it falls back to the placeholder) and the impact summary.
    description_note = next(n for n in cve_entry["notes"] if n["category"] == "description")
    assert "REPLACE WITH A DESCRIPTION" in description_note["text"]
    summary_note = next(n for n in cve_entry["notes"] if n["category"] == "summary")
    assert "REPLACE WITH THE IMPACT" in summary_note["text"]
    # Finding aliases are carried into ids alongside the cve.
    assert {"system_name": "alias", "text": "GHSA-aaaa-0001-0001"} in cve_entry["ids"]

    # A non-CVE id is carried in ids, not cve, and a no-purl finding has empty status.
    ghsa_entry = next(v for v in doc["vulnerabilities"] if v.get("cve") is None)
    assert any(i["text"] == "GHSA-aaaa-bbbb-cccc" for i in ghsa_entry["ids"])
    # A finding with no purl falls back to its package name as the product reference.
    assert ghsa_entry["product_status"]["known_affected"] == ["zlib"]
    assert ghsa_entry["remediations"][0]["product_ids"] == ["zlib"]
    assert {"product_id": "zlib", "name": "zlib"} in doc["product_tree"]["full_product_names"]

    # The review marker survives into the file.
    assert DISCLAIMER_MARKER in out.read_text(encoding="utf-8").lower()


def test_advisory_includes_title_and_references(tmp_path: Path):
    finding = Finding(
        id="CVE-2024-5555",
        package="acme",
        version="1.0.0",
        purl="pkg:pypi/acme@1.0.0",
        title="Acme buffer overflow",
        references=["https://example.org/advisories/acme-1"],
    )
    fake_result = _make_result([finding])
    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")
    out = tmp_path / "advisory.json"

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["advisory", "--sbom", str(dummy), "-o", str(out)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    entry = json.loads(out.read_text(encoding="utf-8"))["vulnerabilities"][0]
    assert entry["title"] == "Acme buffer overflow"
    assert entry["references"] == [
        {"summary": "Reference", "url": "https://example.org/advisories/acme-1"}
    ]
    description = next(n for n in entry["notes"] if n["category"] == "description")
    assert description["text"] == "Acme buffer overflow"


def test_advisory_review_marker_and_watermark(tmp_path: Path):
    findings = [_finding_with_purl()]
    fake_result = _make_result(findings)
    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["advisory", "--sbom", str(dummy)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    combined = result.output
    assert DISCLAIMER_MARKER in combined.lower()
    assert DRAFT_WATERMARK in combined


def test_advisory_zero_findings_writes_nothing(tmp_path: Path):
    # A CSAF advisory requires at least one vulnerability, so with no findings the
    # command writes nothing rather than a schema-invalid empty document.
    fake_result = _make_result([])
    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")
    out = tmp_path / "advisory.json"

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["advisory", "--sbom", str(dummy), "-o", str(out)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    assert not out.exists()
    assert "no findings" in result.output.lower()
    assert "nothing to write" in result.output.lower()


def test_vex_csaf_zero_findings_writes_nothing(tmp_path: Path):
    fake_result = _make_result([])
    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")
    out = tmp_path / "vex.json"

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["vex", "--sbom", str(dummy), "--format", "csaf", "-o", str(out)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    assert not out.exists()
    assert "nothing to write" in result.output.lower()


def test_advisory_rejects_image_and_sbom_together(tmp_path: Path):
    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        draft,
        ["advisory", "--image", "ubuntu:22.04", "--sbom", str(dummy)],
        obj=_obj(),
    )
    assert result.exit_code != 0
    assert "Use only one input mode" in result.output


def test_advisory_round_trips_as_csaf_suppressing_nothing(tmp_path: Path):
    """known_affected is non-suppressing, so feeding the advisory to check --vex is a no-op."""
    findings = [_finding_with_purl("CVE-2024-0001")]
    fake_result = _make_result(findings)
    dummy = tmp_path / "sbom.json"
    dummy.write_text("{}", encoding="utf-8")
    out = tmp_path / "advisory.json"

    runner = CliRunner()
    with patch("cra_evidence_cli.commands.draft.run_local_check", return_value=fake_result):
        result = runner.invoke(
            draft,
            ["advisory", "--sbom", str(dummy), "-o", str(out)],
            obj=_obj(),
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    vex_doc = load_vex(out)
    assert vex_doc.format == "csaf"
    kept, suppressions = apply_vex(findings, vex_doc)
    assert kept == findings
    assert suppressions == []


# Tests: draft security.txt --validate


def test_vex_help_stays_neutral():
    result = CliRunner().invoke(draft, ["vex", "--help"], obj=_obj())

    assert result.exit_code == 0, result.output
    assert "VEX skeleton" in result.output


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_security_txt_validate_valid_file(tmp_path: Path):
    path = _write(
        tmp_path,
        "security.txt",
        "Contact: mailto:security@acme.test\nExpires: 2099-01-01T00:00:00Z\n",
    )
    runner = CliRunner()
    result = runner.invoke(draft, ["security.txt", "--validate", str(path)], obj=_obj())
    assert result.exit_code == 0, result.output
    assert "0 error(s)" in result.output
    assert "OK: no issues found" in result.output


def test_security_txt_validate_missing_contact_reports_error_but_exit0(tmp_path: Path):
    path = _write(tmp_path, "security.txt", "Expires: 2099-01-01T00:00:00Z\n")
    runner = CliRunner()
    result = runner.invoke(draft, ["security.txt", "--validate", str(path)], obj=_obj())
    # Advisory by default: an error is reported but the command still exits 0.
    assert result.exit_code == 0, result.output
    assert "ERROR: Contact field is missing" in result.output
    assert "1 error(s)" in result.output


def test_security_txt_validate_fail_on_invalid_exits_7(tmp_path: Path):
    path = _write(tmp_path, "security.txt", "Expires: 2099-01-01T00:00:00Z\n")
    runner = CliRunner()
    result = runner.invoke(
        draft,
        ["security.txt", "--validate", str(path), "--fail-on-invalid"],
        obj=_obj(),
    )
    assert result.exit_code == 7, result.output


def test_security_txt_validate_fail_on_invalid_exits_7_on_unparseable_expires(tmp_path: Path):
    # A distinct error type (malformed Expires) must also drive exit 7 through the command.
    path = _write(
        tmp_path,
        "security.txt",
        "Contact: mailto:security@acme.test\nExpires: not-a-date\n",
    )
    runner = CliRunner()
    result = runner.invoke(
        draft,
        ["security.txt", "--validate", str(path), "--fail-on-invalid"],
        obj=_obj(),
    )
    assert result.exit_code == 7, result.output
    assert "not a valid RFC 3339 timestamp" in result.output


def test_security_txt_validate_expired_expires_fails_on_invalid(tmp_path: Path):
    # Expired Expires makes the file stale, so --fail-on-invalid exits 7.
    path = _write(
        tmp_path,
        "security.txt",
        "Contact: mailto:security@acme.test\nExpires: 2020-01-01T00:00:00Z\n",
    )
    runner = CliRunner()
    result = runner.invoke(
        draft,
        ["security.txt", "--validate", str(path), "--fail-on-invalid"],
        obj=_obj(),
    )
    assert result.exit_code == 7, result.output
    assert "in the past" in result.output


def test_security_txt_validate_non_uri_contact_fails_on_invalid(tmp_path: Path):
    # A non-URI Contact is an RFC 9116 MUST violation, so --fail-on-invalid exits 7.
    path = _write(
        tmp_path,
        "security.txt",
        "Contact: security@acme.test\nExpires: 2099-01-01T00:00:00Z\n",
    )
    runner = CliRunner()
    result = runner.invoke(
        draft,
        ["security.txt", "--validate", str(path), "--fail-on-invalid"],
        obj=_obj(),
    )
    assert result.exit_code == 7, result.output
    assert "is not a URI" in result.output


def test_security_txt_validate_flags_placeholders(tmp_path: Path):
    path = _write(
        tmp_path,
        "security.txt",
        "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\n",
    )
    runner = CliRunner()
    result = runner.invoke(draft, ["security.txt", "--validate", str(path)], obj=_obj())
    assert result.exit_code == 0, result.output
    assert "placeholder value" in result.output


def test_security_txt_validate_reads_stdin():
    runner = CliRunner()
    result = runner.invoke(
        draft,
        ["security.txt", "--validate", "-"],
        obj=_obj(),
        input="Contact: mailto:security@acme.test\nExpires: 2099-01-01T00:00:00Z\n",
    )
    assert result.exit_code == 0, result.output
    assert "<stdin>" in result.output
    assert "OK: no issues found" in result.output


def test_security_txt_validate_rejects_output_file(tmp_path: Path):
    path = _write(tmp_path, "security.txt", "Contact: mailto:security@acme.test\n")
    out = tmp_path / "out.txt"
    runner = CliRunner()
    result = runner.invoke(
        draft,
        ["security.txt", "--validate", str(path), "-o", str(out)],
        obj=_obj(),
    )
    assert result.exit_code != 0
    assert not out.exists()


def test_security_txt_fail_on_invalid_without_validate_is_usage_error():
    runner = CliRunner()
    result = runner.invoke(draft, ["security.txt", "--fail-on-invalid"], obj=_obj())
    assert result.exit_code != 0
    assert "only applies" in result.output


def test_security_txt_emit_still_works_without_validate():
    # The default template emitter is unchanged by the new options.
    runner = CliRunner()
    result = runner.invoke(draft, ["security.txt"], obj=_obj())
    assert result.exit_code == 0, result.output
    assert "Contact: mailto:security@example.com" in result.output
    assert "validation:" not in result.output
