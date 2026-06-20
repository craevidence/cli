"""OSV.dev fallback: query construction and the draft-vex network notice."""

from __future__ import annotations

import httpx
from click.testing import CliRunner

from cra_evidence_cli.commands.draft import draft
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.local.models import Component, Finding, LocalCheckResult
from cra_evidence_cli.local.osv import OSV_QUERYBATCH_URL, OSVClient


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
