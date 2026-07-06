import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import check as check_module
from cra_evidence_cli.exceptions import (
    LicensePolicyExceeded,
    SbomqsThresholdExceeded,
    ScanEngineUnavailable,
    VulnerabilityThresholdExceeded,
)
from cra_evidence_cli.local.enrich import apply_cve_alias_enrichment
from cra_evidence_cli.local.models import Component, CoverageSource, Finding, LocalCheckResult
from cra_evidence_cli.local.osv import OSVClient, OSVClientError
from cra_evidence_cli.local.scanner import parse_grype_output
from cra_evidence_cli.local.signal import build_dimensions, mark_stale_sources


def _write_sbom(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "jinja2",
                        "version": "3.1.3",
                        "purl": "pkg:pypi/jinja2@3.1.3",
                    }
                ],
            }
        )
    )


def test_check_without_api_key_tolerates_malformed_config(monkeypatch, tmp_path):
    home = tmp_path / "home"
    config_dir = home / ".cra-evidence"
    config_dir.mkdir(parents=True)
    (config_dir / "config.yaml").write_text(":\n")
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    result_obj = check_module.LocalCheckResult(
        target=str(sbom_path),
        target_type="sbom",
        sbom_path=sbom_path,
        components=[],
        findings=[],
        dimensions=[],
        coverage=[],
        provenance={"engine": "test"},
        attributions=[],
        sources_consulted=[],
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    monkeypatch.setattr(check_module, "run_local_check", lambda **kwargs: result_obj)

    runner = CliRunner()
    result = runner.invoke(cli, ["--output", "json", "check", "--sbom", str(sbom_path)])

    assert result.exit_code == 0
    assert "API key is required" not in result.output
    assert '"engine": "test"' in result.output
    assert json.loads(result.output)["provenance"]["engine"] == "test"


def test_check_json_gate_error_goes_to_stderr(monkeypatch, tmp_path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)
    result_obj = check_module.LocalCheckResult(
        target=str(sbom_path),
        target_type="sbom",
        sbom_path=sbom_path,
        components=[],
        findings=[
            Finding(
                id="CVE-2021-44228",
                package="log4j-core",
                version="2.14.1",
                severity="critical",
                known_exploited=True,
            )
        ],
        dimensions=[],
        coverage=[],
        provenance={"engine": "test"},
        attributions=[],
        sources_consulted=[],
    )
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    monkeypatch.setattr(check_module, "run_local_check", lambda **kwargs: result_obj)

    emitted = []

    def fake_echo(message="", *args, **kwargs):
        emitted.append((message, kwargs.get("err", False)))

    monkeypatch.setattr(check_module.click, "echo", fake_echo)
    ctx = check_module.click.Context(
        check_module.check,
        obj={"config": SimpleNamespace(output_format="json"), "verbose": False},
    )

    with pytest.raises(SystemExit) as exc_info, ctx:
        check_module.check.callback(
            path=Path("."),
            image=None,
            sbom_file=sbom_path,
            baseline=None,
            fail_on="known-exploited",
            fail_on_new=None,
            deny_license="",
            sbom_quality=False,
            fail_on_score=None,
            strict=False,
            vex_file=None,
            policy_file=None,
            annotations=None,
            annotations_file=None,
            sbom_output=None,
            output_file=None,
            json_output=None,
            sarif_output=None,
            markdown_output=None,
        )
    assert exc_info.value.code == 17

    stdout = [message for message, is_err in emitted if not is_err]
    stderr = [message for message, is_err in emitted if is_err]
    assert json.loads(stdout[0])["schema_version"] == "craevidence.local_check.v1"
    assert stderr[0].startswith("Error: Found 1 known-exploited vulnerabilities")


def test_check_scan_engine_unavailable_goes_to_stderr(monkeypatch, tmp_path):
    sbom_path = tmp_path / "sbom.json"
    _write_sbom(sbom_path)

    def raise_unavailable(**kwargs):
        msg = "missing local DB"
        raise ScanEngineUnavailable(msg)

    emitted = []

    def fake_echo(message="", *args, **kwargs):
        emitted.append((message, kwargs.get("err", False)))

    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    monkeypatch.setattr(check_module, "run_local_check", raise_unavailable)
    monkeypatch.setattr(check_module.click, "echo", fake_echo)
    ctx = check_module.click.Context(
        check_module.check,
        obj={"config": SimpleNamespace(output_format="json"), "verbose": False},
    )

    with pytest.raises(SystemExit) as exc_info, ctx:
        check_module.check.callback(
            path=Path("."),
            image=None,
            sbom_file=sbom_path,
            baseline=None,
            fail_on=None,
            fail_on_new=None,
            deny_license="",
            sbom_quality=False,
            fail_on_score=None,
            strict=False,
            vex_file=None,
            policy_file=None,
            annotations=None,
            annotations_file=None,
            sbom_output=None,
            output_file=None,
            json_output=None,
            sarif_output=None,
            markdown_output=None,
        )
    assert exc_info.value.code == 15

    assert emitted == [("Error: missing local DB", True)]


def test_cra_dimensions_never_passed():
    dimensions = build_dimensions(
        components=[],
        findings=[],
        coverage=[CoverageSource("osv.dev", "present")],
    )

    assert all(
        item["result"] != "Passed"
        for item in dimensions
        if item["entry_id"].startswith("cra:")
    )


def test_cve_alias_join_sets_known_exploited_before_kev_lookup():
    finding = Finding(
        id="GHSA-test",
        package="pkg",
        version="1.0",
        severity="high",
        aliases={"CVE-2024-1234"},
    )

    apply_cve_alias_enrichment(
        [finding], kev_cves={"CVE-2024-1234"}, epss_scores={"CVE-2024-1234": 0.7}
    )

    assert finding.known_exploited is True
    assert finding.epss_probability == 0.7


def test_cve_less_finding_keeps_unknown_kev_state():
    finding = Finding(id="GHSA-only", package="pkg", version="1.0", severity="high")

    apply_cve_alias_enrichment([finding], kev_cves={"CVE-2024-1234"})

    assert finding.known_exploited is None


def test_grype_cve_less_finding_keeps_unknown_kev_state():
    findings = parse_grype_output(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "GHSA-only",
                            "severity": "High",
                            "aliases": [],
                            "knownExploited": [],
                        },
                        "artifact": {"name": "pkg", "version": "1.0"},
                    }
                ]
            }
        )
    )

    assert findings[0].cve_aliases == set()
    assert findings[0].known_exploited is None


def test_stale_source_downgrades_vulnerability_dimension():
    coverage = [CoverageSource("cisa-kev", "present", as_of="2000-01-01")]
    mark_stale_sources(coverage)

    dimensions = build_dimensions(
        components=[],
        findings=[],
        coverage=coverage,
    )

    assert coverage[0].status == "stale"
    assert any(item["result"].startswith("Unknown - stale") for item in dimensions)


def test_osv_batches_under_size_limit():
    client = OSVClient(max_batch_bytes=150)
    queries = [
        {"package": {"purl": f"pkg:pypi/package-{index}@1.0.0"}, "version": "1.0.0"}
        for index in range(10)
    ]

    batches = client._batches(queries)

    assert len(batches) > 1
    assert sum(len(batch) for batch in batches) == len(queries)


def test_osv_truncation_fails_loud(monkeypatch):
    class Response:
        status_code = 200
        content = b"{}"
        headers = {}

        def raise_for_status(self):
            return None

        def json(self):
            return {"next_page_token": "more", "results": []}

    class Client:
        def post(self, *args, **kwargs):
            return Response()

    client = OSVClient()

    try:
        client._post_with_retries(Client(), {"queries": []})
    except OSVClientError:
        return
    msg = "Expected truncated OSV response to fail"
    raise AssertionError(msg)


def test_attribution_gated_to_sources():
    lines = check_module._attributions({"osv.dev"})

    assert any("OSV.dev" in line for line in lines)
    assert not any("CISA" in line for line in lines)


def _result(*, findings=None, components=None, baseline=None, provenance=None):
    return LocalCheckResult(
        target="x",
        target_type="sbom",
        sbom_path=None,
        components=components or [],
        findings=findings or [],
        dimensions=[],
        coverage=[],
        provenance=provenance or {},
        attributions=[],
        sources_consulted=[],
        baseline=baseline,
    )


def test_license_deny_gate_exits_16():
    res = _result(components=[Component(name="reqs", version="1", licenses=["AGPL-3.0-only"])])
    with pytest.raises(LicensePolicyExceeded) as exc:
        check_module._enforce_gate(res, None, False, deny_license=["agpl-3.0-only"])
    assert exc.value.exit_code == 16
    # A non-denied license does not trip the gate.
    ok = _result(components=[Component(name="reqs", version="1", licenses=["MIT"])])
    check_module._enforce_gate(ok, None, False, deny_license=["agpl-3.0-only"])


def test_fail_on_new_gates_only_new_findings():
    finding = Finding(id="CVE-2025-0001", package="p", version="1", severity="high")
    new = _result(
        findings=[finding],
        baseline={"new_vulnerabilities": ["CVE-2025-0001"], "removed_vulnerabilities": []},
    )
    with pytest.raises(VulnerabilityThresholdExceeded) as exc:
        check_module._enforce_gate(new, None, False, fail_on_new="any")
    assert exc.value.exit_code == 12
    # Same finding present in the baseline is not "new" -> no failure.
    unchanged = _result(
        findings=[finding],
        baseline={"new_vulnerabilities": [], "removed_vulnerabilities": []},
    )
    check_module._enforce_gate(unchanged, None, False, fail_on_new="any")


def test_fail_on_score_only_gates_when_sbomqs_ran():
    below = _result(provenance={"sbom_quality": {"score": 42.0}})
    with pytest.raises(SbomqsThresholdExceeded) as exc:
        check_module._enforce_gate(below, None, False, fail_on_score=60)
    assert exc.value.exit_code == 14
    # No sbomqs result -> the gate is skipped, never a silent pass/fail.
    missing = _result(provenance={})
    check_module._enforce_gate(missing, None, False, fail_on_score=60)


def test_sbomqs_dimension_is_never_passed():
    dims = build_dimensions(
        components=[], findings=[], coverage=[], sbom_quality={"score": 42.0, "weakest": ["x 0/1"]}
    )
    quality = [d for d in dims if d["entry_id"].endswith("quality")]
    assert quality
    assert quality[0]["result"] != "Passed"


def test_output_file_writes_machine_output_and_text_summary(monkeypatch, tmp_path):
    res = _result(provenance={"engine": "test"})
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    monkeypatch.setattr(check_module, "run_local_check", lambda **kwargs: res)
    emitted = []
    monkeypatch.setattr(
        check_module.click,
        "echo",
        lambda message="", *a, **k: emitted.append((message, k.get("err", False))),
    )
    out = tmp_path / "report.json"
    ctx = check_module.click.Context(
        check_module.check,
        obj={"config": SimpleNamespace(output_format="json"), "verbose": False},
    )
    with ctx:
        check_module.check.callback(
            path=Path("."),
            image=None,
            sbom_file=None,
            baseline=None,
            fail_on=None,
            fail_on_new=None,
            deny_license="",
            sbom_quality=False,
            fail_on_score=None,
            strict=False,
            vex_file=None,
            policy_file=None,
            annotations=None,
            annotations_file=None,
            sbom_output=None,
            output_file=out,
            json_output=None,
            sarif_output=None,
            markdown_output=None,
        )
    assert json.loads(out.read_text())["schema_version"] == "craevidence.local_check.v1"
    stdout = [message for message, is_err in emitted if not is_err]
    assert any("Local SBOM Check" in message for message in stdout)


# Integration tests for the check enhancements (wired end-to-end via the
# CliRunner). The scanner is faked so no Grype binary or DB is required, and
# the KEV/EPSS fetches are stubbed to stay offline in tests.
from cra_evidence_cli.local.models import CoverageSource as _Cov  # noqa: E402


class _FakeScanner:
    """Stand-in for GrypeLocalScanner returning canned findings, no subprocess."""

    findings: list = []

    def __init__(self, *args, **kwargs):
        pass

    def is_available(self):
        return True

    def scan_sbom(self, sbom_path):
        return list(type(self).findings), _cov_recent()


def _cov_recent():
    return _Cov("grype-db", "present", as_of="2026-06-10", detail="test")


def _install_fake_scanner(monkeypatch, findings):
    _FakeScanner.findings = findings
    monkeypatch.setattr(check_module, "GrypeLocalScanner", _FakeScanner)
    # Keep KEV/EPSS enrichment from touching the network during integration tests.
    monkeypatch.setattr(
        check_module,
        "fetch_kev_catalog",
        lambda: (set(), _Cov("cisa-kev", "present", as_of="2026-06-10")),
    )
    monkeypatch.setattr(
        check_module,
        "fetch_epss_scores",
        lambda cves: ({}, _Cov("first-epss", "present", as_of="2026-06-10")),
    )


def _critical_finding(cve="CVE-2025-9999", known_exploited=None):
    return Finding(
        id=cve,
        package="acme",
        version="1.0.0",
        severity="critical",
        purl="pkg:pypi/acme@1.0.0",
        known_exploited=known_exploited,
    )


def _run_check(args):
    runner = CliRunner()
    return runner.invoke(cli, ["--output", "json", "check", *args])


def test_vex_not_affected_with_justification_suppresses(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [_critical_finding()])
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    vex = tmp_path / "vex.json"
    vex.write_text(
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2025-9999"},
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                    }
                ],
            }
        )
    )
    # Without VEX, --fail-on critical must fail (exit 10).
    res_no_vex = _run_check(["--sbom", str(sbom), "--fail-on", "critical"])
    assert res_no_vex.exit_code == 10
    # With VEX suppression, the finding is gone -> exit 0 and recorded as suppressed.
    res = _run_check(["--sbom", str(sbom), "--fail-on", "critical", "--vex", str(vex)])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.stdout)
    assert payload["suppressions"][0]["vuln_id"] == "CVE-2025-9999"
    assert payload["summary"]["total"] == 0


def test_vex_not_affected_without_justification_does_not_suppress(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [_critical_finding()])
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    vex = tmp_path / "vex.json"
    vex.write_text(
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [
                    {"vulnerability": {"name": "CVE-2025-9999"}, "status": "not_affected"}
                ],
            }
        )
    )
    res = _run_check(["--sbom", str(sbom), "--fail-on", "critical", "--vex", str(vex)])
    assert res.exit_code == 10  # not suppressed -> gate still fires
    payload = json.loads(res.stdout)
    assert payload["suppressions"] == []


def test_vex_kev_suppression_is_surfaced(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [_critical_finding(known_exploited=True)])
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    vex = tmp_path / "vex.json"
    vex.write_text(
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2025-9999"},
                        "status": "not_affected",
                        "justification": "component_not_present",
                    }
                ],
            }
        )
    )
    res = _run_check(["--sbom", str(sbom), "--vex", str(vex)])
    assert res.exit_code == 0
    # KEV conflict surfaced on stderr, never silently hidden.
    assert "known-exploited" in res.stderr
    payload = json.loads(res.stdout)
    assert payload["suppressions"][0]["kev_conflict"] is True


def test_policy_file_supplies_defaults_and_ignored_cve_is_shown(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [_critical_finding()])
    runner = CliRunner()
    with runner.isolated_filesystem() as cwd:
        sbom = Path(cwd) / "sbom.json"
        _write_sbom(sbom)
        policy_dir = Path(cwd) / ".cra"
        policy_dir.mkdir()
        (policy_dir / "check.yaml").write_text("fail_on: critical\nignore:\n  - cve-2025-9999\n")
        # Policy fail_on=critical applies, but the CVE is ignored -> gate passes (exit 0),
        # and the finding is still shown + marked ignored.
        res = runner.invoke(cli, ["--output", "json", "check", "--sbom", str(sbom)])
        assert res.exit_code == 0, res.output
        payload = json.loads(res.stdout)
        assert payload["findings"][0]["ignored_by_policy"] is True
        assert payload["summary"]["total"] == 1  # shown, not dropped


def test_policy_file_fail_on_gates_when_not_ignored(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [_critical_finding()])
    runner = CliRunner()
    with runner.isolated_filesystem() as cwd:
        sbom = Path(cwd) / "sbom.json"
        _write_sbom(sbom)
        policy_dir = Path(cwd) / ".cra"
        policy_dir.mkdir()
        (policy_dir / "check.yaml").write_text("fail_on: critical\n")
        res = runner.invoke(cli, ["--output", "json", "check", "--sbom", str(sbom)])
        assert res.exit_code == 10  # policy default fail_on=critical fires


def test_explicit_flag_overrides_policy(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [_critical_finding()])
    runner = CliRunner()
    with runner.isolated_filesystem() as cwd:
        sbom = Path(cwd) / "sbom.json"
        _write_sbom(sbom)
        policy_dir = Path(cwd) / ".cra"
        policy_dir.mkdir()
        # Policy says fail_on critical, but explicit --fail-on medium also fires on a
        # critical finding; to prove override, set policy known-exploited (no KEV here -> pass)
        # and explicit critical (fires). If override works, exit is 10, not 0.
        (policy_dir / "check.yaml").write_text("fail_on: known-exploited\n")
        res = runner.invoke(
            cli,
            [
                "--output", "json", "check",
                "--sbom", str(sbom), "--fail-on", "critical",
            ],
        )
        assert res.exit_code == 10  # explicit critical overrode policy known-exploited


def test_sbom_output_copies_generated_sbom(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [])
    # Fake Syft directory generation -> a real SBOM file in its own directory,
    # mirroring the private temp dir the real generator creates.
    gen_dir = tmp_path / "sbom_gen"
    gen_dir.mkdir()
    generated = gen_dir / "sbom.json"
    _write_sbom(generated)
    from cra_evidence_cli.sbom_generator import SBOMGenerationResult

    monkeypatch.setattr(
        check_module,
        "generate_sbom_from_directory",
        lambda *a, **k: SBOMGenerationResult(generated, 1, "cyclonedx", "syft"),
    )
    src = tmp_path / "src"
    src.mkdir()
    out_sbom = tmp_path / "artifact_sbom.json"
    res = _run_check([str(src), "--sbom-output", str(out_sbom)])
    assert res.exit_code == 0, res.output
    assert out_sbom.exists()
    assert json.loads(out_sbom.read_text())["bomFormat"] == "CycloneDX"
    # The generated SBOM's temp directory is removed after a successful run.
    assert not gen_dir.exists()


def test_directory_without_manifests_gives_clear_error(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [])
    # Syft finds nothing in the directory -> an SBOM without a components list.
    gen_dir = tmp_path / "sbom_gen"
    gen_dir.mkdir()
    empty = gen_dir / "sbom.json"
    empty.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5"}))
    from cra_evidence_cli.sbom_generator import SBOMGenerationResult

    monkeypatch.setattr(
        check_module,
        "generate_sbom_from_directory",
        lambda *a, **k: SBOMGenerationResult(empty, 0, "cyclonedx", "syft"),
    )
    src = tmp_path / "src"
    src.mkdir()
    res = _run_check([str(src)])
    assert res.exit_code == 1
    assert "No dependency manifests or SBOM found under" in res.stderr
    assert "requirements.txt" in res.stderr  # the hint lists what check looks for
    assert "Unsupported SBOM format" not in res.stderr
    assert not gen_dir.exists()  # the temp dir is cleaned up on this failure too


def test_malformed_sbom_keeps_unsupported_format_error(monkeypatch, tmp_path):
    from cra_evidence_cli.local.sbom import SBOMParseError, load_sbom

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "not-an-sbom"}))
    with pytest.raises(SBOMParseError, match="Unsupported SBOM format"):
        load_sbom(bad)
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    res = _run_check(["--sbom", str(bad)])
    assert res.exit_code == 1
    assert "Unsupported SBOM format" in res.stderr


def test_output_flag_on_check_subcommand(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [])
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    runner = CliRunner()
    # Subcommand-level flag alone.
    res = runner.invoke(cli, ["check", "--sbom", str(sbom), "--output", "json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["schema_version"] == "craevidence.local_check.v1"
    # Subcommand-level flag overrides the group-level flag.
    res = runner.invoke(
        cli, ["--output", "text", "check", "--sbom", str(sbom), "--output", "json"]
    )
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["schema_version"] == "craevidence.local_check.v1"
    # Group-level flag still applies when the subcommand flag is absent.
    res = runner.invoke(cli, ["--output", "json", "check", "--sbom", str(sbom)])
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["schema_version"] == "craevidence.local_check.v1"
    # The subcommand flag can switch back to text over a json group default.
    res = runner.invoke(
        cli, ["--output", "json", "check", "--sbom", str(sbom), "--output", "text"]
    )
    assert res.exit_code == 0, res.output
    assert "Local SBOM Check" in res.stdout


def test_scan_env_respects_explicit_grype_db_auto_update(monkeypatch, tmp_path):
    from cra_evidence_cli.local import scanner as scanner_module

    envs = []

    def fake_run(cmd, **kwargs):
        envs.append(kwargs.get("env") or {})
        return SimpleNamespace(returncode=0, stdout=json.dumps({"matches": []}), stderr="")

    monkeypatch.setattr(scanner_module.subprocess, "run", fake_run)
    scanner = scanner_module.GrypeLocalScanner()
    scanner._path = "/usr/bin/grype"
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)

    # An explicit user value is never clobbered.
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "false")
    scanner.scan_sbom(sbom)
    assert envs[0]["GRYPE_DB_AUTO_UPDATE"] == "false"

    # Without an explicit value, auto-update defaults on.
    envs.clear()
    monkeypatch.delenv("GRYPE_DB_AUTO_UPDATE")
    scanner.scan_sbom(sbom)
    assert envs[0]["GRYPE_DB_AUTO_UPDATE"] == "true"


def test_sbom_output_noop_when_sbom_supplied(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [])
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    out_sbom = tmp_path / "artifact_sbom.json"
    res = _run_check(["--sbom", str(sbom), "--sbom-output", str(out_sbom)])
    assert res.exit_code == 0
    assert not out_sbom.exists()
    assert "--sbom-output ignored" in res.stderr


def test_grype_failure_falls_back_to_osv(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)

    class FailingScanner:
        def is_available(self):
            return True

        def scan_sbom(self, sbom_path):
            msg = "local database unavailable"
            raise ScanEngineUnavailable(msg)

    class FakeOSVClient:
        def query_components(self, components):
            return [], _Cov("osv.dev", "present")

    monkeypatch.setattr(check_module, "GrypeLocalScanner", FailingScanner)
    monkeypatch.setattr(check_module, "OSVClient", FakeOSVClient)
    monkeypatch.setattr(
        check_module,
        "fetch_kev_catalog",
        lambda: (set(), _Cov("cisa-kev", "present", as_of="2026-06-10")),
    )
    monkeypatch.setattr(
        check_module,
        "fetch_epss_scores",
        lambda cves: ({}, _Cov("first-epss", "present", as_of="2026-06-10")),
    )

    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    res = _run_check(["--sbom", str(sbom)])

    assert res.exit_code == 0, res.output
    payload = json.loads(res.stdout)
    assert payload["provenance"]["engine"] == "osv-online"
    assert payload["provenance"]["osv.dev"]["status"] == "present"
    assert payload["provenance"]["grype-db"]["status"] == "unavailable"
    assert any(
        source["source"] == "grype-db" and source["status"] == "unavailable"
        for source in payload["coverage"]
    )
    assert any(
        source["source"] == "osv.dev" and source["status"] == "present"
        for source in payload["coverage"]
    )
    # The switch to the network fallback is announced on stderr with the reason.
    assert "Local matcher failed (local database unavailable)" in res.stderr
    assert "querying OSV.dev over the network instead" in res.stderr


def test_no_fallback_notice_when_grype_absent(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)

    class NoGrype:
        def is_available(self):
            return False

    class FakeOSVClient:
        def query_components(self, components):
            return [], _Cov("osv.dev", "present")

    monkeypatch.setattr(check_module, "GrypeLocalScanner", NoGrype)
    monkeypatch.setattr(check_module, "OSVClient", FakeOSVClient)
    monkeypatch.setattr(
        check_module,
        "fetch_kev_catalog",
        lambda: (set(), _Cov("cisa-kev", "present", as_of="2026-06-10")),
    )
    monkeypatch.setattr(
        check_module,
        "fetch_epss_scores",
        lambda cves: ({}, _Cov("first-epss", "present", as_of="2026-06-10")),
    )

    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    res = _run_check(["--sbom", str(sbom)])

    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["provenance"]["engine"] == "osv-online"
    assert "Local matcher failed" not in res.stderr


def test_annotations_github_emits_workflow_commands(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [_critical_finding()])
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    res = _run_check(["--sbom", str(sbom), "--annotations", "github"])
    assert res.exit_code == 0
    assert "::error" in res.output
    assert "title=CVE-2025-9999" in res.output


def test_annotations_gitlab_writes_report(monkeypatch, tmp_path):
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [_critical_finding()])
    runner = CliRunner()
    with runner.isolated_filesystem() as cwd:
        sbom = Path(cwd) / "sbom.json"
        _write_sbom(sbom)
        res = runner.invoke(
            cli,
            [
                "--output", "json", "check",
                "--sbom", str(sbom), "--annotations", "gitlab",
            ],
        )
        assert res.exit_code == 0, res.output
        report = Path(cwd) / "gl-code-quality-report.json"
        assert report.exists()
        entries = json.loads(report.read_text())
        assert entries[0]["severity"] == "blocker"  # critical -> blocker


def test_vex_product_scope_is_precise(tmp_path):
    """A product-scoped VEX statement must not match a different package by prefix."""
    from cra_evidence_cli.local import vex as vex_mod

    def _doc(product):
        path = tmp_path / "v.json"
        path.write_text(
            json.dumps(
                {
                    "@context": "openvex",
                    "statements": [
                        {
                            "vulnerability": {"name": "CVE-1"},
                            "status": "not_affected",
                            "justification": "x",
                            "products": [{"@id": product}],
                        }
                    ],
                }
            )
        )
        return vex_mod.load_vex(path)

    def _suppressed(product, purl):
        f = Finding(id="CVE-1", package="p", version="1", severity="high", purl=purl)
        return len(vex_mod.apply_vex([f], _doc(product))[1]) == 1

    assert _suppressed("pkg:pypi/acme", "pkg:pypi/acme-evil@1") is False
    assert _suppressed("pkg:pypi/acme", "pkg:pypi/acme@1.0.0") is True  # versionless -> any version
    assert _suppressed("pkg:pypi/acme@1.0.0", "pkg:pypi/acme@2.0.0") is False  # version-specific
    assert _suppressed("pkg:pypi/acme@1.0.0", "pkg:pypi/acme@1.0.0") is True


def test_annotation_failure_does_not_mask_gate(monkeypatch, tmp_path):
    """A failing annotation write must not change the exit code or hide the gate."""
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    _install_fake_scanner(monkeypatch, [_critical_finding()])
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    res = _run_check(
        [
            "--sbom",
            str(sbom),
            "--fail-on",
            "critical",
            "--annotations",
            "gitlab",
            "--annotations-file",
            str(tmp_path / "missing_dir" / "r.json"),
        ]
    )
    assert res.exit_code == 10  # the gate wins, not the IO error (exit 1)
    assert "failed to emit gitlab annotations" in res.stderr
