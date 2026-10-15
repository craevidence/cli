from __future__ import annotations

import json

import httpx
import pytest

from cra_evidence_cli.local import enrich


def _install_response(monkeypatch, payload: object, *, raw: bytes | None = None) -> None:
    original_client = httpx.Client
    content = raw if raw is not None else json.dumps(payload, allow_nan=True).encode()

    def client_factory(*, timeout, follow_redirects=False):
        return original_client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=content)),
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    monkeypatch.setattr(enrich.httpx, "Client", client_factory)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": [None]},
        {"vulnerabilities": [{"cveID": "  "}]},
    ],
    ids=["missing-list", "non-list", "non-object-row", "empty-cve-id"],
)
def test_invalid_kev_shapes_are_rejected(monkeypatch, payload):
    _install_response(monkeypatch, payload)

    with pytest.raises(ValueError, match="CISA KEV"):
        enrich.fetch_kev_catalog()


def test_explicit_empty_kev_catalog_remains_valid(monkeypatch):
    _install_response(monkeypatch, {"vulnerabilities": []})

    cves, source = enrich.fetch_kev_catalog()

    assert cves == set()
    assert source.status == "present"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"data": None},
        {"data": [None]},
        {"data": [{"cve": "CVE-2026-0001"}]},
        {"data": [{"epss": 0.25}]},
        {"data": [{"cve": " ", "epss": 0.25}]},
        {"data": [{"cve": "CVE-2026-0001", "epss": float("nan")}]},
        {"data": [{"cve": "CVE-2026-0001", "epss": float("inf")}]},
        {"data": [{"cve": "CVE-2026-0001", "epss": -0.01}]},
        {"data": [{"cve": "CVE-2026-0001", "epss": 1.01}]},
        {"data": [{"cve": "CVE-2026-0001", "epss": True}]},
    ],
    ids=[
        "missing-data",
        "non-list-data",
        "non-object-row",
        "missing-score",
        "missing-cve",
        "empty-cve",
        "nan-score",
        "infinite-score",
        "negative-score",
        "over-one-score",
        "boolean-score",
    ],
)
def test_invalid_epss_shapes_and_scores_are_rejected(monkeypatch, payload):
    _install_response(monkeypatch, payload)

    with pytest.raises(ValueError, match="FIRST EPSS"):
        enrich.fetch_epss_scores({"CVE-2026-0001"})


def test_explicit_empty_epss_data_remains_valid(monkeypatch):
    _install_response(monkeypatch, {"data": []})

    scores, source = enrich.fetch_epss_scores({"CVE-2026-0001"})

    assert scores == {}
    assert source.status == "present"


@pytest.mark.parametrize("score", [0, 1, "0.5"])
def test_valid_epss_probability_is_preserved(monkeypatch, score):
    _install_response(
        monkeypatch,
        {"data": [{"cve": "CVE-2026-0001", "epss": score}]},
    )

    scores, source = enrich.fetch_epss_scores({"CVE-2026-0001"})

    assert scores == {"CVE-2026-0001": float(score)}
    assert source.status == "present"
