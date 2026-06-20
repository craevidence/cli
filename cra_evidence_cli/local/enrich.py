"""Vulnerability enrichment for local no-key checks."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from cra_evidence_cli.local.models import CoverageSource, Finding

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"


def apply_cve_alias_enrichment(
    findings: list[Finding],
    kev_cves: set[str] | None = None,
    epss_scores: dict[str, float] | None = None,
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
                finding.epss_probability = epss_scores[cve]
                break


def fetch_kev_catalog(timeout: float = 20.0) -> tuple[set[str], CoverageSource]:
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(CISA_KEV_URL)
        response.raise_for_status()
        data = response.json()
    cves = {
        str(item.get("cveID")).upper()
        for item in data.get("vulnerabilities", [])
        if item.get("cveID")
    }
    as_of = data.get("dateReleased") or data.get("catalogVersion") or _today()
    return cves, CoverageSource("cisa-kev", "present", as_of=str(as_of))


def fetch_epss_scores(
    cves: set[str], timeout: float = 20.0
) -> tuple[dict[str, float], CoverageSource]:
    if not cves:
        return {}, CoverageSource("first-epss", "skipped", detail="No CVE aliases found")
    scores: dict[str, float] = {}
    with httpx.Client(timeout=timeout) as client:
        for batch in _chunks(sorted(cves), 100):
            response = client.get(FIRST_EPSS_URL, params={"cve": ",".join(batch)})
            response.raise_for_status()
            data = response.json()
            for item in data.get("data", []):
                cve = str(item.get("cve", "")).upper()
                try:
                    scores[cve] = float(item["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
    return scores, CoverageSource("first-epss", "present", as_of=_today())


def stale_status(as_of: str | None, max_age_days: int, today: datetime | None = None) -> bool:
    if not as_of:
        return False
    today = today or datetime.now(UTC)
    parsed = _parse_date(as_of)
    if not parsed:
        return False
    return (today - parsed).days > max_age_days


def _parse_date(value: str) -> datetime | None:
    for fmt, width in (("%Y-%m-%d", 10), ("%Y.%m.%d", 10), ("%Y-%m-%dT%H:%M:%SZ", 20)):
        try:
            parsed = datetime.strptime(value[:width], fmt).replace(tzinfo=UTC)
            return parsed
        except ValueError:
            continue
    return None


def _today() -> str:
    return datetime.now(UTC).date().isoformat()


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[index : index + size] for index in range(0, len(items), size)]
