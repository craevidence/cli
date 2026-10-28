"""Vulnerability enrichment for local no-key checks."""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime

import httpx

from cra_evidence_cli.local.models import CoverageSource, Finding

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
_RFC3339_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def apply_cve_alias_enrichment(
    findings: list[Finding],
    kev_cves: set[str] | None = None,
    epss_scores: dict[str, tuple[float, str | None]] | None = None,
) -> None:
    kev_cves = {item.upper() for item in (kev_cves or set())}
    epss_scores = {key.upper(): value for key, value in (epss_scores or {}).items()}
    for finding in findings:
        cves = finding.cve_aliases
        if kev_cves and cves:
            finding.known_exploited = bool(cves & kev_cves)
        elif finding.known_exploited is None and not cves:
            finding.known_exploited = None

        for cve in sorted(cves):
            if cve in epss_scores:
                finding.epss_probability, finding.epss_date = epss_scores[cve]
                finding.epss_cve = cve
                finding.epss_source = "first-epss"
                break


def fetch_kev_catalog(timeout: float = 20.0) -> tuple[set[str], CoverageSource]:
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(CISA_KEV_URL)
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict):
        msg = "CISA KEV response must be an object"
        raise ValueError(msg)
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        msg = "CISA KEV response must contain a vulnerabilities list"
        raise ValueError(msg)

    cves: set[str] = set()
    for item in vulnerabilities:
        cve_id = item.get("cveID") if isinstance(item, dict) else None
        if not isinstance(cve_id, str) or not cve_id.strip():
            msg = "CISA KEV vulnerability must contain a CVE ID"
            raise ValueError(msg)
        cves.add(cve_id.strip().upper())
    as_of = data.get("dateReleased")
    return cves, CoverageSource("cisa-kev", "present", as_of=_date_text(as_of))


def fetch_epss_scores(
    cves: set[str], timeout: float = 20.0
) -> tuple[dict[str, tuple[float, str | None]], CoverageSource]:
    if not cves:
        return {}, CoverageSource("first-epss", "skipped", detail="No CVE aliases found")
    scores: dict[str, tuple[float, str | None]] = {}
    publication_dates: list[str | None] = []
    with httpx.Client(timeout=timeout) as client:
        for batch in _chunks(sorted(cves), 100):
            response = client.get(FIRST_EPSS_URL, params={"cve": ",".join(batch)})
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                msg = "FIRST EPSS response must be an object"
                raise ValueError(msg)
            rows = data.get("data")
            if not isinstance(rows, list):
                msg = "FIRST EPSS response must contain a data list"
                raise ValueError(msg)
            for item in rows:
                cve = item.get("cve") if isinstance(item, dict) else None
                if not isinstance(cve, str) or not cve.strip():
                    msg = "FIRST EPSS row must contain a CVE ID"
                    raise ValueError(msg)
                try:
                    raw_score = item["epss"]
                    if isinstance(raw_score, bool):
                        raise TypeError
                    score = float(raw_score)
                except (KeyError, OverflowError, TypeError, ValueError) as exc:
                    msg = "FIRST EPSS row must contain a numeric score"
                    raise ValueError(msg) from exc
                if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                    msg = "FIRST EPSS score must be finite and within [0, 1]"
                    raise ValueError(msg)
                publication_date = _date_text(item.get("date"))
                scores[cve.strip().upper()] = (score, publication_date)
                publication_dates.append(publication_date)
    as_of = (
        min((date for date in publication_dates if date is not None), default=None)
        if all(date is not None for date in publication_dates)
        else None
    )
    return scores, CoverageSource("first-epss", "present", as_of=as_of)


def stale_status(as_of: str | None, max_age_days: int, today: datetime | None = None) -> bool:
    return grype_freshness_status(as_of, max_age_days, today) == "stale"


def feed_freshness_status(
    as_of: str | None, max_age_days: int, today: datetime | None = None
) -> str:
    if not as_of:
        return "unknown"
    today = today or datetime.now(UTC)
    parsed = _parse_date(as_of)
    if parsed is None or parsed > today:
        return "unknown"
    return "stale" if (today - parsed).days > max_age_days else "fresh"


def _parse_date(value: str) -> datetime | None:
    try:
        parsed_date = datetime.fromisoformat(f"{value}T00:00:00+00:00")
        if parsed_date.date().isoformat() == value:
            return parsed_date
    except ValueError:
        pass
    if not _RFC3339_DATE_TIME.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def grype_freshness_status(
    as_of: str | None, max_age_days: int, today: datetime | None = None
) -> str:
    if not as_of:
        return "unknown"
    today = today or datetime.now(UTC)
    parsed = _parse_date(as_of)
    if parsed is None:
        try:
            legacy_date = datetime.strptime(as_of, "%Y.%m.%d").replace(tzinfo=UTC)
            parsed = legacy_date if legacy_date.strftime("%Y.%m.%d") == as_of else None
        except ValueError:
            parsed = None
    if parsed is None or parsed > today:
        return "unknown"
    return "stale" if (today - parsed).days > max_age_days else "fresh"


def _date_text(value: object) -> str | None:
    if not isinstance(value, str) or _parse_date(value) is None:
        return None
    return value


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[index : index + size] for index in range(0, len(items), size)]
