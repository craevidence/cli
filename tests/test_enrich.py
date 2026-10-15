from __future__ import annotations

import json
from datetime import UTC, datetime

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
    "metadata",
    [
        {},
        {"dateReleased": "not-a-date"},
        {"dateReleased": "2026-1-5"},
        {"dateReleased": "2026-10-15T12:00:00Z junk"},
        {"catalogVersion": "2026-10-15"},
    ],
    ids=[
        "missing-date",
        "malformed-date",
        "noncanonical-date",
        "junk-after-date-time",
        "catalog-version-is-not-date",
    ],
)
def test_kev_publication_date_remains_unknown_without_valid_date(monkeypatch, metadata):
    _install_response(monkeypatch, {"vulnerabilities": [], **metadata})

    cves, source = enrich.fetch_kev_catalog()

    assert cves == set()
    assert source.status == "present"
    assert source.as_of is None


def test_kev_publication_date_is_used_as_as_of(monkeypatch):
    _install_response(
        monkeypatch,
        {"dateReleased": "2026-10-15", "vulnerabilities": []},
    )

    _, source = enrich.fetch_kev_catalog()

    assert source.as_of == "2026-10-15"


@pytest.mark.parametrize(
    "publication_date",
    ["2026-10-15T12:34:56.789Z", "2026-10-15T14:34:56.789+02:00"],
    ids=["fractional-utc", "fractional-offset"],
)
def test_kev_rfc3339_publication_datetime_is_used_as_as_of(monkeypatch, publication_date):
    _install_response(monkeypatch, {"dateReleased": publication_date, "vulnerabilities": []})

    _, source = enrich.fetch_kev_catalog()

    assert source.as_of == publication_date


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
    assert source.as_of is None


@pytest.mark.parametrize("score", [0, 1, "0.5"])
def test_valid_epss_probability_is_preserved(monkeypatch, score):
    _install_response(
        monkeypatch,
        {"data": [{"cve": "CVE-2026-0001", "epss": score, "date": "2026-10-15"}]},
    )

    scores, source = enrich.fetch_epss_scores({"CVE-2026-0001"})

    assert scores == {"CVE-2026-0001": float(score)}
    assert source.status == "present"
    assert source.as_of == "2026-10-15"


@pytest.mark.parametrize("date", [None, "not-a-date"], ids=["missing", "malformed"])
def test_epss_publication_date_remains_unknown_without_valid_date(monkeypatch, date):
    row = {"cve": "CVE-2026-0001", "epss": "0.25"}
    if date is not None:
        row["date"] = date
    _install_response(monkeypatch, {"data": [row]})

    scores, source = enrich.fetch_epss_scores({"CVE-2026-0001"})

    assert scores == {"CVE-2026-0001": 0.25}
    assert source.status == "present"
    assert source.as_of is None


def test_epss_uses_oldest_returned_publication_date(monkeypatch):
    _install_response(
        monkeypatch,
        {
            "data": [
                {"cve": "CVE-2026-0001", "epss": 0.25, "date": "2026-10-15"},
                {"cve": "CVE-2026-0002", "epss": 0.5, "date": "2026-10-14"},
            ]
        },
    )

    _, source = enrich.fetch_epss_scores({"CVE-2026-0001", "CVE-2026-0002"})

    assert source.as_of == "2026-10-14"


def test_feed_freshness_status_preserves_seven_day_boundary():
    today = datetime(2026, 10, 15, tzinfo=UTC)

    assert enrich.feed_freshness_status("2026-10-08", 7, today) == "fresh"
    assert enrich.feed_freshness_status("2026-10-07", 7, today) == "stale"
    assert enrich.feed_freshness_status(None, 7, today) == "unknown"
    assert enrich.feed_freshness_status("2026-10-16", 7, today) == "unknown"


def test_feed_freshness_status_parses_aware_rfc3339_datetime():
    today = datetime(2026, 10, 15, 12, 34, 56, 789000, tzinfo=UTC)

    assert (
        enrich.feed_freshness_status("2026-10-15T14:34:56.789+02:00", 7, today) == "fresh"
    )
    assert enrich.feed_freshness_status("2026-10-15T12:34:56.789", 7, today) == "unknown"
    assert (
        enrich.feed_freshness_status("2026-10-15T12:34:56.789Z junk", 7, today) == "unknown"
    )
