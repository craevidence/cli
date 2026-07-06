"""OSV.dev fallback: query construction, detail enrichment, and network notices."""

from __future__ import annotations

import json

import httpx
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import check as check_module
from cra_evidence_cli.commands.draft import draft
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.local.models import Component, CoverageSource, Finding, LocalCheckResult
from cra_evidence_cli.local.osv import (
    OSV_QUERYBATCH_URL,
    OSVClient,
    _severity_from_osv,
)


def test_api_query_versioned_purl_omits_separate_version() -> None:
    # OSV returns 400 when a version is given both in the purl and separately,
    # so a versioned purl must NOT carry a version field. Internal '_' keys must
    # never reach the API.
    client = OSVClient()
    query = client._query_for(
        Component(name="urllib3", version="1.0", purl="pkg:pypi/urllib3@1.0")
    )
    api = client._api_query(query)
    assert api == {"package": {"purl": "pkg:pypi/urllib3@1.0"}}
    assert "version" not in api
    assert not any(key.startswith("_") for key in api)


def test_api_query_unversioned_purl_keeps_version() -> None:
    client = OSVClient()
    query = client._query_for(
        Component(name="urllib3", version="1.0", purl="pkg:pypi/urllib3")
    )
    api = client._api_query(query)
    assert api == {"package": {"purl": "pkg:pypi/urllib3"}, "version": "1.0"}


def test_query_batch_skips_a_single_bad_purl(monkeypatch) -> None:
    # OSV 400s a whole batch if any identifier is malformed. One bad purl must
    # not drop the others: the good ones still resolve, the bad one is skipped
    # and counted, and coverage is reported as partial (not a silent pass).
    client = OSVClient()

    def fake_post(self, http_client, payload):
        purls = [q["package"]["purl"] for q in payload["queries"]]
        if any("bad" in purl for purl in purls):
            request = httpx.Request("POST", OSV_QUERYBATCH_URL)
            response = httpx.Response(400, request=request)
            msg = "bad request"
            raise httpx.HTTPStatusError(msg, request=request, response=response)
        return {"results": [{"vulns": [{"id": f"OSV-{purl}"}]} for purl in purls]}

    monkeypatch.setattr(OSVClient, "_post_with_retries", fake_post)
    monkeypatch.setattr(OSVClient, "_get_with_retries", lambda self, http_client, url: {})
    components = [
        Component(name="good1", version="1", purl="pkg:pypi/good1@1"),
        Component(name="bad", version="1", purl="pkg:generic/bad@1"),
        Component(name="good2", version="1", purl="pkg:pypi/good2@1"),
    ]
    findings, coverage = client.query_components(components)
    found = {finding.id for finding in findings}
    assert any("good1" in fid for fid in found)
    assert any("good2" in fid for fid in found)
    assert not any("bad" in fid for fid in found)
    assert coverage.status == "partial"
    assert "1 component" in (coverage.detail or "")


_DETAILS = {
    "GHSA-aaaa": {
        "id": "GHSA-aaaa",
        "aliases": ["CVE-2024-0001"],
        "database_specific": {"severity": "HIGH"},
        "summary": "test advisory",
        "references": [{"type": "WEB", "url": "https://example.com/adv"}],
        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
    },
    "PYSEC-2024-1": {
        "id": "PYSEC-2024-1",
        "aliases": ["CVE-2024-0002"],
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
    },
}


def _fake_get(calls: list[str]):
    def fake_get(self, http_client, url):
        vuln_id = url.rsplit("/", 1)[1]
        calls.append(vuln_id)
        return _DETAILS[vuln_id]

    return fake_get


def test_osv_detail_lookup_fills_severity_and_aliases(monkeypatch) -> None:
    # querybatch returns only {id, modified}; severity, aliases and fix data
    # must come from the per-vulnerability detail lookup.
    monkeypatch.setattr(
        OSVClient,
        "_post_with_retries",
        lambda self, http_client, payload: {
            "results": [{"vulns": [{"id": "GHSA-aaaa"}, {"id": "PYSEC-2024-1"}]}]
        },
    )
    calls: list[str] = []
    monkeypatch.setattr(OSVClient, "_get_with_retries", _fake_get(calls))
    findings, coverage = OSVClient().query_components(
        [Component(name="acme", version="1.0", purl="pkg:pypi/acme@1.0")]
    )
    by_id = {finding.id: finding for finding in findings}
    assert by_id["GHSA-aaaa"].severity == "high"
    assert by_id["GHSA-aaaa"].aliases == {"CVE-2024-0001"}
    assert by_id["GHSA-aaaa"].cve_aliases == {"CVE-2024-0001"}
    assert by_id["GHSA-aaaa"].fixed_versions == ["2.0.0"]
    assert by_id["GHSA-aaaa"].title == "test advisory"
    assert by_id["GHSA-aaaa"].references == ["https://example.com/adv"]
    # No qualitative label -> rating derived from the CVSS v3 vector (9.8).
    assert by_id["PYSEC-2024-1"].severity == "critical"
    assert by_id["PYSEC-2024-1"].cve_aliases == {"CVE-2024-0002"}
    assert coverage.status == "present"


def test_osv_detail_lookup_dedupes_ids(monkeypatch) -> None:
    # The same vulnerability id across several components is fetched once.
    monkeypatch.setattr(
        OSVClient,
        "_post_with_retries",
        lambda self, http_client, payload: {
            "results": [{"vulns": [{"id": "GHSA-aaaa"}]} for _ in payload["queries"]]
        },
    )
    calls: list[str] = []
    monkeypatch.setattr(OSVClient, "_get_with_retries", _fake_get(calls))
    findings, _coverage = OSVClient().query_components(
        [
            Component(name="one", version="1", purl="pkg:pypi/one@1"),
            Component(name="two", version="1", purl="pkg:pypi/two@1"),
        ]
    )
    assert calls == ["GHSA-aaaa"]
    assert [finding.severity for finding in findings] == ["high", "high"]


def test_osv_detail_lookup_404_keeps_unknown_severity(monkeypatch) -> None:
    monkeypatch.setattr(
        OSVClient,
        "_post_with_retries",
        lambda self, http_client, payload: {"results": [{"vulns": [{"id": "GHSA-gone"}]}]},
    )

    def fake_get(self, http_client, url):
        request = httpx.Request("GET", url)
        response = httpx.Response(404, request=request)
        msg = "not found"
        raise httpx.HTTPStatusError(msg, request=request, response=response)

    monkeypatch.setattr(OSVClient, "_get_with_retries", fake_get)
    findings, coverage = OSVClient().query_components(
        [Component(name="acme", version="1.0", purl="pkg:pypi/acme@1.0")]
    )
    assert findings[0].id == "GHSA-gone"
    assert findings[0].severity == "unknown"
    assert coverage.status == "present"


def test_severity_from_osv_cvss_vector_buckets() -> None:
    def vec(vector: str) -> dict:
        return {"severity": [{"type": "CVSS_V3", "score": vector}]}

    assert _severity_from_osv(vec("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")) == "critical"
    assert _severity_from_osv(vec("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")) == "high"
    assert _severity_from_osv(vec("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N")) == "medium"
    assert _severity_from_osv(vec("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")) == "low"
    # Numeric scores map directly; CVSS v4 vectors have no derivable base score.
    assert _severity_from_osv({"severity": [{"type": "CVSS_V4", "score": "7.3"}]}) == "high"
    assert _severity_from_osv(vec("not-a-vector")) == "unknown"
    # The qualitative GHSA-style label wins over any CVSS entry.
    assert (
        _severity_from_osv(
            {
                "database_specific": {"severity": "MODERATE"},
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                ],
            }
        )
        == "medium"
    )


def test_fail_on_high_gate_trips_via_osv_path(monkeypatch, tmp_path) -> None:
    # With Grype absent, the OSV path must yield real severities so that
    # --fail-on high exits 11 instead of silently passing on "unknown".
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)

    class NoGrype:
        def __init__(self, *args, **kwargs):
            pass

        def is_available(self):
            return False

    monkeypatch.setattr(check_module, "GrypeLocalScanner", NoGrype)
    monkeypatch.setattr(
        OSVClient,
        "_post_with_retries",
        lambda self, http_client, payload: {"results": [{"vulns": [{"id": "GHSA-aaaa"}]}]},
    )
    monkeypatch.setattr(OSVClient, "_get_with_retries", _fake_get([]))
    monkeypatch.setattr(
        check_module,
        "fetch_kev_catalog",
        lambda: (set(), CoverageSource("cisa-kev", "present", as_of="2026-06-10")),
    )
    monkeypatch.setattr(
        check_module,
        "fetch_epss_scores",
        lambda cves: ({}, CoverageSource("first-epss", "present", as_of="2026-06-10")),
    )
    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "acme",
                        "version": "1.0",
                        "purl": "pkg:pypi/acme@1.0",
                    }
                ],
            }
        )
    )
    result = CliRunner().invoke(
        cli, ["--output", "json", "check", "--sbom", str(sbom), "--fail-on", "high"]
    )
    assert result.exit_code == 11
    payload = json.loads(result.stdout)
    assert payload["findings"][0]["severity"] == "high"
    assert payload["findings"][0]["cve_aliases"] == ["CVE-2024-0001"]


def _obj() -> dict:
    return {
        "config": CRAEvidenceConfig(url="https://api.craevidence.com", output_format="text"),
        "verbose": False,
    }


def _result(engine: str) -> LocalCheckResult:
    return LocalCheckResult(
        target="x",
        target_type="sbom",
        sbom_path=None,
        components=[],
        findings=[Finding(id="CVE-2000-0001", package="p", version="1", purl="pkg:pypi/p@1")],
        dimensions=[],
        coverage=[],
        provenance={"engine": engine},
        attributions=[],
        sources_consulted=[],
    )


def test_draft_vex_warns_when_osv_fallback_used(monkeypatch) -> None:
    monkeypatch.setattr(
        "cra_evidence_cli.commands.draft.run_local_check", lambda **kwargs: _result("osv-online")
    )
    result = CliRunner().invoke(draft, ["vex"], obj=_obj())
    assert result.exit_code == 0, result.output
    assert "OSV.dev over the network" in result.output


def test_draft_vex_no_notice_when_grype_used(monkeypatch) -> None:
    monkeypatch.setattr(
        "cra_evidence_cli.commands.draft.run_local_check", lambda **kwargs: _result("grype-local")
    )
    result = CliRunner().invoke(draft, ["vex"], obj=_obj())
    assert result.exit_code == 0, result.output
    assert "OSV.dev over the network" not in result.output
