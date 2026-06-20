"""End-of-life checks against the endoflife.date public API.

Parses components from an SBOM and flags those whose name matches a product
tracked by endoflife.date and whose version falls past the recorded end-of-life
date for that cycle.

Results are advisory only. Being past end-of-life is not the same as being
vulnerable. Most SBOM components will not appear in endoflife.date; that
outcome is expected and is counted honestly as "no endoflife.date data", not
as "no EOL concern".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import unquote

import httpx

from cra_evidence_cli.local.models import Component

ENDOFLIFE_ALL_URL = "https://endoflife.date/api/all.json"
ENDOFLIFE_PRODUCT_URL = "https://endoflife.date/api/{product}.json"

_COMMON_SUFFIXES = (
    "-core",
    "-client",
    "-server",
    "-api",
    "-sdk",
    "-lib",
    "-common",
)

_PURL_NAMESPACE_SLUGS = {
    ("maven", "org.apache.logging.log4j"): "log4j",
    ("maven", "org.springframework.boot"): "spring-boot",
    ("maven", "org.springframework"): "spring-framework",
    ("maven", "org.apache.tomcat"): "tomcat",
    ("maven", "org.postgresql"): "postgresql",
    ("maven", "com.mysql"): "mysql",
    ("maven", "org.eclipse.jetty"): "jetty",
    ("npm", "@angular"): "angular",
    ("npm", "@vue"): "vue",
    ("npm", "@nestjs"): "nestjs",
    ("npm", "@aws-sdk"): "aws-sdk",
}


@dataclass
class EolFinding:
    """A component that was recognized by endoflife.date."""

    component: str
    version: str | None
    product: str
    cycle: str | None
    eol_date: str | None
    is_eol: bool
    support_date: str | None = None
    is_supported: bool | None = None
    lts: bool | str | None = None
    status: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "version": self.version,
            "product": self.product,
            "cycle": self.cycle,
            "eol_date": self.eol_date,
            "is_eol": self.is_eol,
            "support_date": self.support_date,
            "is_supported": self.is_supported,
            "lts": self.lts,
            "status": self.status,
        }


@dataclass
class EolReport:
    """Aggregated end-of-life check results."""

    findings: list[EolFinding] = field(default_factory=list)
    total_components: int = 0
    recognized: int = 0
    eol_count: int = 0
    active_count: int = 0
    security_only_count: int = 0
    unknown_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_components": self.total_components,
            "recognized": self.recognized,
            "eol_count": self.eol_count,
            "active_count": self.active_count,
            "security_only_count": self.security_only_count,
            "unknown_count": self.unknown_count,
            "findings": [f.to_dict() for f in self.findings],
        }


def fetch_products(timeout: float = 20.0) -> set[str]:
    """Fetch the list of product slugs tracked by endoflife.date."""
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(ENDOFLIFE_ALL_URL)
        response.raise_for_status()
        data = response.json()
    return set(data)


def fetch_cycles(product: str, timeout: float = 20.0) -> list[dict]:
    """Fetch the cycle list for a single endoflife.date product slug."""
    url = ENDOFLIFE_PRODUCT_URL.format(product=product)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        data = response.json()
    return list(data)


def _parse_date(value: Any) -> date | None:
    """Parse an endoflife.date field value into a date, or None if not parseable."""
    if not isinstance(value, str):
        return None
    try:
        # Date-only comparison; no timezone is involved.
        return datetime.strptime(value[:10], "%Y-%m-%d").date()  # noqa: DTZ007
    except ValueError:
        return None


def _determine_eol(eol_value: Any, today: date) -> tuple[bool, str | None]:
    """Return (is_eol, eol_date_string) from a raw cycle eol field."""
    if eol_value is True:
        return True, None
    if eol_value is False:
        return False, None
    parsed = _parse_date(eol_value)
    if parsed is not None:
        eol_str = str(eol_value)[:10]
        return parsed < today, eol_str
    return False, None


def _determine_support(
    support_value: Any, eoas_value: Any, today: date
) -> tuple[bool | None, str | None]:
    """Return (is_in_active_support, active_support_end_date) for a cycle.

    endoflife.date records the end of active support as ``support`` (legacy) or
    ``eoas`` (newer schema); a value may be a date, a bool, or absent. Returns
    is_in_active_support=None when no support information is available, so the
    caller can report "unknown" honestly instead of implying active support.
    """
    raw = eoas_value if eoas_value is not None else support_value
    if raw is True:
        return True, None
    if raw is False:
        return False, None
    parsed = _parse_date(raw)
    if parsed is not None:
        return parsed >= today, str(raw)[:10]
    return None, None


def _classify(is_eol: bool, is_supported: bool | None) -> str:
    """Map EOL and active-support state to a support-period status label.

    Uses the vocabulary the CRA expects manufacturers to determine and disclose
    for the support period (Article 13(8), Annex II point 7): "active" full
    support, "security-only" maintenance after active support ends, "eol" past
    end of life, or "unknown" when endoflife.date has no support data.
    """
    if is_eol:
        return "eol"
    if is_supported is False:
        return "security-only"
    if is_supported is True:
        return "active"
    return "unknown"


def _match_cycle(version: str, cycles: list[dict]) -> dict | None:
    """Find the first cycle entry matching the given version string."""
    for cycle in cycles:
        cycle_str = str(cycle.get("cycle", ""))
        if not cycle_str:
            continue
        if version == cycle_str or version.startswith(cycle_str + "."):
            return cycle
    return None


def _strip_common_suffix(slug: str) -> str | None:
    for suffix in _COMMON_SUFFIXES:
        if slug.endswith(suffix) and len(slug) > len(suffix):
            return slug[: -len(suffix)]
    return None


def _normalise_slug(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def _purl_parts(purl: str | None) -> tuple[str | None, str | None, str | None]:
    if not purl or not purl.startswith("pkg:"):
        return None, None, None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    before_version = body.rsplit("@", 1)[0]
    pieces = [unquote(part) for part in before_version.split("/") if part]
    if not pieces:
        return None, None, None
    ecosystem = _normalise_slug(pieces[0])
    if len(pieces) == 1:
        return ecosystem, None, None
    name = _normalise_slug(pieces[-1])
    namespace = "/".join(_normalise_slug(part) for part in pieces[1:-1]) or None
    return ecosystem, namespace, name


def slug_candidates(component: Component) -> list[str]:
    """Return possible endoflife.date product slugs for an SBOM component."""
    candidates: list[str] = []

    def add(value: str | None) -> None:
        if not value:
            return
        slug = _normalise_slug(value)
        if slug and slug not in candidates:
            candidates.append(slug)

    add(component.name)
    ecosystem, namespace, purl_name = _purl_parts(component.purl)
    add(purl_name)
    if ecosystem and namespace:
        add(_PURL_NAMESPACE_SLUGS.get((ecosystem, namespace)))
        for (mapped_ecosystem, mapped_namespace), mapped_slug in _PURL_NAMESPACE_SLUGS.items():
            if ecosystem == mapped_ecosystem and namespace.startswith(mapped_namespace + "."):
                add(mapped_slug)

    for candidate in list(candidates):
        add(_strip_common_suffix(candidate))

    return candidates


def evaluate_components(
    components: list[Component],
    today: date | None = None,
) -> EolReport:
    """Evaluate components against endoflife.date.

    Returns an EolReport describing which components were recognized,
    which cycles matched, and which are past end-of-life.
    """
    if today is None:
        today = datetime.now(UTC).date()

    total = len(components)

    product_set = fetch_products()

    findings: list[EolFinding] = []
    recognized = 0
    cycle_cache: dict[str, list[dict]] = {}

    for comp in components:
        slug = next(
            (candidate for candidate in slug_candidates(comp) if candidate in product_set),
            None,
        )
        if slug is None:
            continue

        recognized += 1

        if slug not in cycle_cache:
            try:
                cycle_cache[slug] = fetch_cycles(slug)
            except Exception:  # noqa: BLE001
                # Network error for a single product: treat as no cycle data
                # rather than crashing the whole run.
                cycle_cache[slug] = []

        cycles = cycle_cache[slug]
        version_str = comp.version or ""

        matched_cycle = _match_cycle(version_str, cycles) if version_str else None

        if matched_cycle is not None:
            is_eol, eol_date = _determine_eol(matched_cycle.get("eol"), today)
            is_supported, support_date = _determine_support(
                matched_cycle.get("support"), matched_cycle.get("eoas"), today
            )
            findings.append(
                EolFinding(
                    component=comp.name,
                    version=comp.version,
                    product=slug,
                    cycle=str(matched_cycle.get("cycle", "")),
                    eol_date=eol_date,
                    is_eol=is_eol,
                    support_date=support_date,
                    is_supported=is_supported,
                    lts=matched_cycle.get("lts"),
                    status=_classify(is_eol, is_supported),
                )
            )
        else:
            findings.append(
                EolFinding(
                    component=comp.name,
                    version=comp.version,
                    product=slug,
                    cycle=None,
                    eol_date=None,
                    is_eol=False,
                    status="unknown",
                )
            )

    eol_count = sum(1 for f in findings if f.is_eol)
    active_count = sum(1 for f in findings if f.status == "active")
    security_only_count = sum(1 for f in findings if f.status == "security-only")
    unknown_count = sum(1 for f in findings if f.status == "unknown")

    return EolReport(
        findings=findings,
        total_components=total,
        recognized=recognized,
        eol_count=eol_count,
        active_count=active_count,
        security_only_count=security_only_count,
        unknown_count=unknown_count,
    )
