"""OSV.dev fallback: query construction, detail enrichment, and network notices."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import check as check_module
from cra_evidence_cli.commands.draft import draft
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.local.models import Component, CoverageSource, Finding, LocalCheckResult
from cra_evidence_cli.local.osv import (
    OSV_QUERYBATCH_URL,
    OSVClient,
    OSVClientError,
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


@pytest.mark.parametrize("version", ["1", "2"])
def test_query_batch_skips_a_single_bad_purl(monkeypatch, version) -> None:
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
        Component(name="good1", version=version, purl="pkg:pypi/good1@1"),
        Component(name="bad", version=version, purl="pkg:generic/bad@1"),
        Component(name="good2", version=version, purl="pkg:pypi/good2@1"),
    ]
    findings, coverage = client.query_components(components)
    found = {finding.id for finding in findings}
    assert any("good1" in fid for fid in found)
    assert any("good2" in fid for fid in found)
    assert not any("bad" in fid for fid in found)
    assert coverage.status == "partial"
    rejection = "1 component(s) skipped: OSV.dev rejected the identifier"
    expected = rejection
    if version == "2":
        expected = (
            "3 component occurrence(s) have conflicting explicit and PURL versions; "
            "PURL-query candidates, if any, are indicative; " + rejection
        )
    assert coverage.detail == expected
    assert [finding.is_indicative for finding in findings] == [version == "2"] * 2


def _run_osv_with_mock_transport(
    monkeypatch,
    *,
    query_payload=None,
    query_content: bytes | None = None,
    detail_payload=None,
):
    client_type = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            if query_content is not None:
                return httpx.Response(200, content=query_content, request=request)
            return httpx.Response(200, json=query_payload, request=request)
        if request.url.path.startswith("/v1/vulns/"):
            if detail_payload is not None:
                return httpx.Response(200, json=detail_payload, request=request)
            return httpx.Response(404, request=request)
        return httpx.Response(404, request=request)

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda *args, **kwargs: client_type(
            *args, transport=httpx.MockTransport(handler), **kwargs
        ),
    )
    return OSVClient().query_components(
        [Component(name="acme", version="1.0", purl="pkg:pypi/acme@1.0")]
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"results": None},
        {"results": {}},
        {"results": []},
        {"results": [{}, {}]},
        {"results": [None]},
        {"results": [{"vulns": None}]},
        {"results": [{"vulns": "invalid"}]},
        {"results": [{"vulns": [None]}]},
        {"results": [{"vulns": [{}]}]},
        {"results": [{"vulns": [{"id": "  "}]}]},
        {"results": [{"vulns": [{"id": 12}]}]},
        {"results": [{"next_page_token": "page-2"}]},
        {"results": [{"next_page_token": ""}]},
        {"results": [{"truncated": True}]},
    ],
    ids=[
        "missing-results-is-not-empty-success",
        "null-results-is-not-empty-success",
        "non-list-results",
        "short-result-list-does-not-disappear-through-zip",
        "extra-result-is-not-ignored-through-zip",
        "non-object-result",
        "null-vulns-is-not-empty-success",
        "non-list-vulns",
        "non-object-vulnerability",
        "missing-vulnerability-id",
        "blank-vulnerability-id",
        "non-string-vulnerability-id",
        "per-result-pagination-token-is-incomplete",
        "present-empty-pagination-token-is-not-assumed-complete",
        "per-result-truncated-is-incomplete",
    ],
)
def test_querybatch_rejects_incomplete_or_malformed_results(monkeypatch, payload) -> None:
    # Catch short zip acceptance, malformed consumed fields, and treating an
    # unconsumed continuation page as a complete local assessment.
    with pytest.raises(OSVClientError):
        _run_osv_with_mock_transport(monkeypatch, query_payload=payload)


def test_querybatch_empty_object_is_a_valid_empty_result(monkeypatch) -> None:
    findings, coverage = _run_osv_with_mock_transport(monkeypatch, query_payload={"results": [{}]})

    assert findings == []
    assert coverage.status == "present"


def test_parse_results_accepts_empty_list_only_for_zero_queries() -> None:
    client = OSVClient()

    assert client._parse_results([], []) == []
    with pytest.raises(OSVClientError):
        client._parse_results([{"_component_name": "acme"}], [])


@pytest.mark.parametrize(
    "query_content",
    [b"{", b"\xff"],
    ids=["invalid-json", "invalid-utf8"],
)
def test_querybatch_invalid_json_is_an_osv_client_error(monkeypatch, query_content) -> None:
    with pytest.raises(OSVClientError, match="valid JSON"):
        _run_osv_with_mock_transport(monkeypatch, query_content=query_content)


def test_detail_response_must_be_a_json_object(monkeypatch) -> None:
    with pytest.raises(OSVClientError, match="JSON object"):
        _run_osv_with_mock_transport(
            monkeypatch,
            query_payload={"results": [{"vulns": [{"id": "GHSA-example"}]}]},
            detail_payload=[],
        )


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


@pytest.mark.parametrize(
    ("versions", "empty", "exit_code", "confirmed", "indicative"),
    [
        (["1.0"], False, 11, 1, 0),
        (["2.0"], False, 0, 0, 1),
        (["2.0", "1.0"], False, 11, 1, 1),
        (["2.0"], True, 0, 0, 0),
    ],
)
def test_osv_applicability_controls_high_gate(
    monkeypatch, tmp_path, versions, empty, exit_code, confirmed, indicative
) -> None:
    """Catch candidate enrichment/gating, global demotion and OSV-partial strict failure."""
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    monkeypatch.setattr(check_module, "get_embedded_syft_version", lambda: None)

    class NoGrype:
        def __init__(self, *args, **kwargs):
            pass

        def is_available(self):
            return False

        def unavailable_reason(self):
            return "the CRA Evidence engine is not installed"

    monkeypatch.setattr(check_module, "GrypeLocalScanner", NoGrype)
    monkeypatch.setattr(
        OSVClient,
        "_post_with_retries",
        lambda self, http_client, payload: {
            "results": [
                {"vulns": [] if empty else [{"id": "GHSA-aaaa"}]}
                for query in payload["queries"]
            ]
        },
    )
    monkeypatch.setattr(OSVClient, "_get_with_retries", _fake_get([]))
    today = datetime.now(UTC).date().isoformat()
    monkeypatch.setattr(
        check_module,
        "fetch_kev_catalog",
        lambda: ({"CVE-2024-0001"}, CoverageSource("cisa-kev", "present", as_of=today)),
    )
    epss_queries = []

    def fake_epss(cves):
        epss_queries.append(cves)
        return {"CVE-2024-0001": 0.9}, CoverageSource("first-epss", "present", as_of=today)

    monkeypatch.setattr(check_module, "fetch_epss_scores", fake_epss)
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
                        "version": version,
                        "purl": "pkg:pypi/acme@1.0",
                    }
                    for version in versions
                ],
            }
        )
    )
    result = CliRunner().invoke(
        cli, ["--output", "json", "check", "--sbom", str(sbom), "--fail-on", "high", "--strict"]
    )
    assert result.exit_code == exit_code, result.output
    payload = json.loads(result.stdout)
    assert payload["summary"]["total"] == confirmed
    assert payload["summary"]["known_exploited"] == confirmed
    assert [f["severity"] for f in payload["findings"]] == ["high"] * confirmed
    assert [f["cve_aliases"] for f in payload["findings"]] == [["CVE-2024-0001"]] * confirmed
    assert epss_queries == [{"CVE-2024-0001"} if confirmed else set()]
    candidates = payload["indicative_findings"]
    assert [f["quality_reason"] for f in candidates] == ["version_conflict"] * indicative
    assert [f["version"] for f in candidates] == ["2.0"] * indicative
    assert all("known_exploited" not in f and "epss_probability" not in f for f in candidates)
    osv = next(source for source in payload["coverage"] if source["source"] == "osv.dev")
    assert osv["status"] == ("partial" if "2.0" in versions else "present")


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


@pytest.mark.parametrize(
    ("purl", "has_version"),
    [
        ("pkg:pypi/a?origin=user@host", False),
        ("pkg:pypi/a#path/@release", False),
        ("pkg:npm/%40scope/name", False),
        ("pkg:npm/@scope/name", False),
        ("pkg:generic/a@release/1", True),
        ("pkg:npm/@scope/name@release/1", True),
        ("pkg:npm/%40scope/name@1", True),
        ("pkg:npm/@scope/name@1?origin=a@b#c@d", True),
        ("pkg:pypi/a@", True),
        ("pkg:pypi/a@unknown", True),
        ("pkg:pypi/a@*", True),
    ],
)
def test_api_query_uses_structural_version_presence(purl, has_version):
    """Catch any-@ detection and a second carrier for empty or placeholder tokens."""
    client = OSVClient()
    query = client._query_for(Component(name="a", version="1", purl=purl))
    expected = {"package": {"purl": purl}}
    if not has_version:
        expected["version"] = "1"
    assert client._api_query(query) == expected


@pytest.mark.parametrize(
    ("version", "purl", "conflict"),
    [
        (" 1 ", "pkg:pypi/a@1", False),
        ("1", "pkg:pypi/a@1?epoch=2", False),
        ("0:1", "pkg:pypi/a@1", True),
        ("1.0", "pkg:pypi/a@1.0.0", True),
        ("v1", "pkg:pypi/a@1", True),
        ("1", "pkg:generic/a@release/1", True),
        ("1+fix", "pkg:deb/a@1%2Bfix", False),
        ("1+fix", "pkg:deb/a@1%252Bfix", True),
        ("2:1-1", "pkg:rpm/a@1-1?epoch=0002", False),
        ("0002:1-1", "pkg:rpm/a@2%3A1-1", False),
        ("0:1-1", "pkg:rpm/a@1-1?epoch=000", False),
        ("1-1", "pkg:rpm/a@1-1?epoch=2", True),
        ("unknown", "pkg:pypi/a@1", False),
        ("1", "pkg:pypi/a@unknown", False),
        ("1", "pkg:pypi/a@*", False),
        ("1", "pkg:pypi/a@", False),
        (None, "pkg:pypi/a@1", False),
    ],
)
def test_osv_conflict_comparison_is_opaque_except_rpm_epochs(version, purl, conflict):
    """Catch generic epoch stripping, SemVer equivalence and repeated decoding."""
    client = OSVClient()
    query = client._query_for(Component(name="a", version=version, purl=purl))
    finding = client._parse_results([query], [{"vulns": [{"id": "OSV-a"}]}])[0]
    assert finding.indicative_reason == ("version_conflict" if conflict else None)
    assert finding.version == (version or "")
    assert client._api_query(query) == {"package": {"purl": purl}}


def test_osv_rpm_conflict_preserves_both_version_declarations():
    """Catch evidence that silently substitutes an effective epoch for the original release."""
    client = OSVClient()
    purl = "pkg:rpm/a@1-1?epoch=2"
    query = client._query_for(Component(name="a", version="1-1", purl=purl))
    finding = client._parse_results([query], [{"vulns": [{"id": "OSV-a"}]}])[0]
    assert finding.applicability_evidence == {
        "component_version": "1-1",
        "purl": purl,
        "purl_version": "1-1",
        "effective_purl_version": "2:1-1",
        "concrete_versions": ["1-1", "2:1-1"],
    }


@pytest.mark.parametrize("ids", [[], ["GHSA-aaaa", "PYSEC-2024-1"]])
def test_osv_conflict_is_per_occurrence_even_without_results(monkeypatch, ids):
    """Catch global PURL/ID demotion and counting advisories instead of occurrences."""
    purl = "pkg:pypi/acme@1.0"
    requests = []

    def fake_post(self, http_client, payload):
        requests.append(payload)
        return {"results": [{"vulns": [{"id": value} for value in ids]}] * 2}

    monkeypatch.setattr(OSVClient, "_post_with_retries", fake_post)
    details = []
    monkeypatch.setattr(OSVClient, "_get_with_retries", _fake_get(details))
    findings, coverage = OSVClient().query_components(
        [
            Component(name="conflict", version="2.0", purl=purl),
            Component(name="agrees", version="1.0", purl=purl),
        ]
    )
    assert requests == [{"queries": [{"package": {"purl": purl}}] * 2}]
    assert [f.is_indicative for f in findings] == [True] * len(ids) + [False] * len(ids)
    assert [f.version for f in findings] == ["2.0"] * len(ids) + ["1.0"] * len(ids)
    assert [f.applicability_evidence for f in findings[: len(ids)]] == [
        {
            "component_version": "2.0",
            "purl": purl,
            "purl_version": "1.0",
            "concrete_versions": ["1.0", "2.0"],
        }
    ] * len(ids)
    assert [f.severity for f in findings] == ["high", "critical"] * (2 if ids else 0)
    assert details == ids
    assert coverage.status == "partial"
    assert coverage.detail == (
        "1 component occurrence(s) have conflicting explicit and PURL versions; "
        "PURL-query candidates, if any, are indicative"
    )


@pytest.mark.parametrize("include_valid", [False, True])
def test_invalid_rpm_epochs_are_local_skips_without_losing_siblings(monkeypatch, include_valid):
    """Catch whole-batch abort, server-rejection mislabeling and HTTP for all-invalid input."""
    requests = []

    def fake_post(self, http_client, payload):
        requests.append(payload)
        return {"results": [{"vulns": [{"id": "GHSA-aaaa"}]}]}

    monkeypatch.setattr(OSVClient, "_post_with_retries", fake_post)
    monkeypatch.setattr(OSVClient, "_get_with_retries", _fake_get([]))
    components = [
        Component(name="a", version="1", purl="pkg:rpm/a@1?epoch="),
        Component(name="b", version="1", purl="pkg:rpm/b@1?epoch=1&epoch=1"),
        Component(name="c", version="1", purl="pkg:rpm/c@2%3A1?epoch=3"),
    ]
    if include_valid:
        components.append(Component(name="valid", version="1", purl="pkg:pypi/valid@1"))
    findings, coverage = OSVClient().query_components(components)
    assert [f.id for f in findings] == (["GHSA-aaaa"] if include_valid else [])
    assert requests == (
        [{"queries": [{"package": {"purl": "pkg:pypi/valid@1"}}]}] if include_valid else []
    )
    assert coverage.status == "partial"
    assert coverage.detail == (
        "3 component occurrence(s) skipped locally: invalid or ambiguous RPM PURL epoch"
    )
