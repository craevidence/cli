"""Unit tests for cra_evidence_cli.local.eol.

All network calls are mocked. No live HTTP requests are made.
"""

from __future__ import annotations

from datetime import date

from cra_evidence_cli.local.eol import (
    evaluate_components,
    slug_candidates,
)
from cra_evidence_cli.local.models import Component

# Fixtures / helpers

PAST_DATE = "2000-01-01"
FUTURE_DATE = "2100-01-01"

# A minimal cycle list for "python": one clearly-past-EOL cycle and one
# far-future cycle.
PYTHON_CYCLES = [
    {"cycle": "3.7", "eol": PAST_DATE, "latest": "3.7.17"},
    {"cycle": "3.99", "eol": FUTURE_DATE, "latest": "3.99.0"},
]


def _make_component(
    name: str, version: str | None = None, purl: str | None = None
) -> Component:
    return Component(name=name, version=version, purl=purl)


# Core evaluation tests


def test_eol_count_and_past_eol_finding(monkeypatch):
    """A component matching a past-EOL cycle is flagged; a future-EOL is not."""
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: PYTHON_CYCLES,
    )

    components = [
        _make_component("python", "3.7.17"),   # matches cycle 3.7 -> past EOL
        _make_component("python", "3.99.0"),   # matches cycle 3.99 -> future EOL
        _make_component("leftpad", "1.0.0"),   # not in endoflife.date
    ]

    report = evaluate_components(components, today=date(2026, 1, 1))

    assert report.total_components == 3
    assert report.recognized == 2
    assert report.eol_count == 1

    eol_findings = [f for f in report.findings if f.is_eol]
    assert len(eol_findings) == 1
    assert eol_findings[0].component == "python"
    assert eol_findings[0].version == "3.7.17"
    assert eol_findings[0].is_eol is True
    assert eol_findings[0].cycle == "3.7"
    assert eol_findings[0].eol_date == PAST_DATE

    future_findings = [f for f in report.findings if f.version == "3.99.0"]
    assert len(future_findings) == 1
    assert future_findings[0].is_eol is False

    leftpad_findings = [f for f in report.findings if f.component == "leftpad"]
    assert leftpad_findings == []


def test_unrecognized_component_produces_no_finding(monkeypatch):
    """Components whose slug is not in the product set produce no findings."""
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: PYTHON_CYCLES,
    )

    components = [_make_component("leftpad", "1.0.0")]
    report = evaluate_components(components, today=date(2026, 1, 1))

    assert report.total_components == 1
    assert report.recognized == 0
    assert report.eol_count == 0
    assert report.findings == []


def test_purl_namespace_maps_to_endoflife_slug(monkeypatch):
    """A Maven namespace can map a component artifact to the product slug."""
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"log4j"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: [{"cycle": "2", "eol": FUTURE_DATE}],
    )

    component = _make_component(
        "log4j-core",
        "2.20.0",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.20.0",
    )
    report = evaluate_components([component], today=date(2026, 1, 1))

    assert report.recognized == 1
    assert report.findings[0].product == "log4j"


def test_slug_candidates_strip_common_suffix():
    component = _make_component("ignored", purl="pkg:maven/com.acme/example-core@1.0.0")

    candidates = slug_candidates(component)

    assert "example-core" in candidates
    assert "example" in candidates


def test_recognized_but_unmatched_cycle(monkeypatch):
    """A component in endoflife.date whose version does not match any cycle
    still generates a finding with cycle=None and is_eol=False."""
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: PYTHON_CYCLES,
    )

    components = [_make_component("python", "99.99.99")]
    report = evaluate_components(components, today=date(2026, 1, 1))

    assert report.recognized == 1
    assert report.eol_count == 0
    assert len(report.findings) == 1
    assert report.findings[0].cycle is None
    assert report.findings[0].is_eol is False


# Boolean eol field


def test_boolean_true_eol_yields_is_eol_true(monkeypatch):
    """A cycle with eol=True yields is_eol=True regardless of date."""
    cycles = [{"cycle": "1.0", "eol": True, "latest": "1.0.0"}]

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"mylib"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: cycles,
    )

    components = [_make_component("mylib", "1.0.5")]
    report = evaluate_components(components, today=date(2026, 1, 1))

    assert report.eol_count == 1
    assert report.findings[0].is_eol is True
    assert report.findings[0].eol_date is None


def test_boolean_false_eol_yields_is_eol_false(monkeypatch):
    """A cycle with eol=False yields is_eol=False."""
    cycles = [{"cycle": "2.0", "eol": False, "latest": "2.0.0"}]

    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"mylib"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: cycles,
    )

    components = [_make_component("mylib", "2.0.1")]
    report = evaluate_components(components, today=date(2026, 1, 1))

    assert report.eol_count == 0
    assert report.findings[0].is_eol is False


# to_dict serialization


def test_eol_report_to_dict_keys(monkeypatch):
    """EolReport.to_dict() contains all expected keys."""
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: PYTHON_CYCLES,
    )

    components = [_make_component("python", "3.7.0")]
    report = evaluate_components(components, today=date(2026, 1, 1))
    d = report.to_dict()

    assert "total_components" in d
    assert "recognized" in d
    assert "eol_count" in d
    assert "findings" in d
    assert isinstance(d["findings"], list)
    assert d["findings"][0]["is_eol"] is True


def test_eol_finding_to_dict_keys(monkeypatch):
    """EolFinding.to_dict() contains all expected keys."""
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python"},
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: PYTHON_CYCLES,
    )

    components = [_make_component("python", "3.7.1")]
    report = evaluate_components(components, today=date(2026, 1, 1))
    fd = report.findings[0].to_dict()

    for key in ("component", "version", "product", "cycle", "eol_date", "is_eol"):
        assert key in fd, f"Missing key: {key}"


# Per-product network error handling


# Support-period status (active / security-only / eol / unknown)

# Cycles exercising every support state. eol/support dates are far past/future
# so the classification holds regardless of the real "today" passed in.
_SUPPORT_CYCLES = [
    {"cycle": "10", "eol": FUTURE_DATE, "support": FUTURE_DATE, "lts": False},  # active
    {"cycle": "20", "eol": FUTURE_DATE, "support": PAST_DATE, "lts": True},     # security-only
    {"cycle": "30", "eol": PAST_DATE, "support": PAST_DATE},                    # eol
    {"cycle": "40", "eol": False, "eoas": FUTURE_DATE, "support": PAST_DATE},   # eoas -> active
    {"cycle": "50", "eol": False},                                              # unknown
]


def _eval_support(monkeypatch):
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products", lambda **kwargs: {"demo"}
    )
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_cycles",
        lambda product, **kwargs: _SUPPORT_CYCLES,
    )
    components = [_make_component("demo", f"{c}.5") for c in ("10", "20", "30", "40", "50")]
    report = evaluate_components(components, today=date(2026, 1, 1))
    return {f.cycle: f for f in report.findings}, report


def test_active_support_status(monkeypatch):
    """A cycle whose active support ends in the future is classified 'active'."""
    by_cycle, report = _eval_support(monkeypatch)
    assert by_cycle["10"].status == "active"
    assert by_cycle["10"].is_supported is True
    assert by_cycle["10"].support_date == FUTURE_DATE
    assert report.active_count == 2  # cycles 10 and 40


def test_security_only_status(monkeypatch):
    """Active support ended but not yet EOL is classified 'security-only'."""
    by_cycle, report = _eval_support(monkeypatch)
    assert by_cycle["20"].status == "security-only"
    assert by_cycle["20"].is_supported is False
    assert by_cycle["20"].support_date == PAST_DATE
    assert by_cycle["20"].is_eol is False
    assert report.security_only_count == 1


def test_eol_status_takes_precedence_over_support(monkeypatch):
    """A past-EOL cycle is classified 'eol' even though support is also past."""
    by_cycle, _ = _eval_support(monkeypatch)
    assert by_cycle["30"].status == "eol"
    assert by_cycle["30"].is_eol is True


def test_eoas_field_preferred_over_support(monkeypatch):
    """When both eoas and support are present, eoas (newer schema) wins."""
    by_cycle, _ = _eval_support(monkeypatch)
    # support is PAST_DATE but eoas is FUTURE_DATE -> still in active support.
    assert by_cycle["40"].status == "active"
    assert by_cycle["40"].is_supported is True


def test_unknown_status_when_no_support_data(monkeypatch):
    """No support/eoas field and a non-EOL cycle is classified 'unknown'."""
    by_cycle, report = _eval_support(monkeypatch)
    assert by_cycle["50"].status == "unknown"
    assert by_cycle["50"].is_supported is None
    assert by_cycle["50"].support_date is None
    assert report.unknown_count == 1


def test_lts_field_surfaced(monkeypatch):
    """The raw endoflife.date lts field is carried onto the finding."""
    by_cycle, _ = _eval_support(monkeypatch)
    assert by_cycle["20"].lts is True
    assert by_cycle["10"].lts is False


def test_to_dict_includes_support_fields(monkeypatch):
    """Finding and report serialization expose the new support-period fields."""
    by_cycle, report = _eval_support(monkeypatch)
    fd = by_cycle["20"].to_dict()
    for key in ("support_date", "is_supported", "lts", "status"):
        assert key in fd, f"Missing finding key: {key}"
    rd = report.to_dict()
    for key in ("active_count", "security_only_count", "unknown_count"):
        assert key in rd, f"Missing report key: {key}"


def test_per_product_network_error_skips_component(monkeypatch):
    """A network error fetching a single product's cycles is swallowed;
    the overall run still completes without raising."""
    monkeypatch.setattr(
        "cra_evidence_cli.local.eol.fetch_products",
        lambda **kwargs: {"python", "brokenlib"},
    )

    def _fetch_cycles(product, **kwargs):
        if product == "brokenlib":
            msg = "simulated network failure"
            raise RuntimeError(msg)
        return PYTHON_CYCLES

    monkeypatch.setattr("cra_evidence_cli.local.eol.fetch_cycles", _fetch_cycles)

    components = [
        _make_component("python", "3.7.17"),
        _make_component("brokenlib", "1.2.3"),
    ]
    # Should not raise.
    report = evaluate_components(components, today=date(2026, 1, 1))

    # python is evaluated normally; brokenlib is skipped silently.
    assert report.total_components == 2
    assert report.eol_count == 1
    python_findings = [f for f in report.findings if f.component == "python"]
    assert python_findings[0].is_eol is True
