"""Tests for cra_evidence_cli.local.egress (no network, no Syft)."""

from __future__ import annotations

from pathlib import Path

from cra_evidence_cli.local.egress import (
    EgressReport,
    _extract_host,
    evaluate,
    match_sbom,
    scan_source,
)
from cra_evidence_cli.local.models import Component

# match_sbom


def _make_component(name: str, version: str | None = None, purl: str | None = None) -> Component:
    return Component(name=name, version=version, purl=purl)


def test_match_sbom_detects_sentry_sdk():
    components = [_make_component("sentry-sdk", "1.44.0", "pkg:pypi/sentry-sdk@1.44.0")]
    sdk_hits, net_libs = match_sbom(components)
    names = [h.name for h in sdk_hits]
    assert "sentry-sdk" in names, "sentry-sdk must be detected as an SDK hit"
    matching = next(h for h in sdk_hits if h.name == "sentry-sdk")
    assert matching.category == "error-reporting"
    assert net_libs == []


def test_match_sbom_detects_boto3():
    components = [_make_component("boto3", "1.34.0")]
    sdk_hits, net_libs = match_sbom(components)
    names = [h.name for h in sdk_hits]
    assert "boto3" in names, "boto3 must be detected as an SDK hit"
    matching = next(h for h in sdk_hits if h.name == "boto3")
    assert matching.category == "cloud"


def test_match_sbom_detects_requests_as_network_lib():
    components = [_make_component("requests", "2.31.0")]
    sdk_hits, net_libs = match_sbom(components)
    assert sdk_hits == [], "requests should not appear as an SDK hit"
    assert "requests" in net_libs, "requests must appear in network_libs"


def test_match_sbom_ignores_unknown_package():
    components = [_make_component("leftpad", "1.0.0")]
    sdk_hits, net_libs = match_sbom(components)
    assert sdk_hits == []
    assert net_libs == []


def test_match_sbom_multiple_components():
    components = [
        _make_component("sentry-sdk", "1.44.0"),
        _make_component("boto3", "1.34.0"),
        _make_component("requests", "2.31.0"),
        _make_component("leftpad", "1.0.0"),
    ]
    sdk_hits, net_libs = match_sbom(components)
    hit_names = {h.name for h in sdk_hits}
    assert "sentry-sdk" in hit_names
    assert "boto3" in hit_names
    assert "leftpad" not in hit_names
    assert "requests" in net_libs
    assert "leftpad" not in net_libs


def test_match_sbom_network_libs_are_sorted_and_unique():
    components = [
        _make_component("requests"),
        _make_component("httpx"),
        _make_component("requests"),  # duplicate
    ]
    _, net_libs = match_sbom(components)
    assert net_libs == sorted(set(net_libs)), "network_libs must be sorted and unique"


# scan_source


def test_scan_source_finds_external_url(tmp_path: Path):
    src = tmp_path / "app.py"
    src.write_text('url = "https://api.acme-telemetry.com/collect"\n', encoding="utf-8")

    hits = scan_source(tmp_path)

    hosts = [h.host for h in hits]
    assert "api.acme-telemetry.com" in hosts, "external host must be detected"

    matching = next(h for h in hits if h.host == "api.acme-telemetry.com")
    assert matching.file == "app.py"
    assert matching.line == 1


def test_scan_source_excludes_localhost(tmp_path: Path):
    src = tmp_path / "server.py"
    src.write_text("base = 'https://localhost:8000/x'\n", encoding="utf-8")

    hits = scan_source(tmp_path)
    hosts = [h.host for h in hits]
    assert "localhost" not in hosts, "localhost must be excluded"


def test_scan_source_excludes_example_com(tmp_path: Path):
    src = tmp_path / "docs.py"
    src.write_text("docs = 'https://example.com/y'\n", encoding="utf-8")

    hits = scan_source(tmp_path)
    hosts = [h.host for h in hits]
    assert "example.com" not in hosts, "example.com must be excluded"


def test_extract_host_rejects_degenerate_host():
    assert _extract_host("https://./x") == ""
    assert _extract_host("https://api.example.test/x") == "api.example.test"
    assert _extract_host("https://user:pass@api.example.test/x") == "api.example.test"


def test_scan_source_skips_node_modules(tmp_path: Path):
    nm = tmp_path / "node_modules" / "lib"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("fetch('https://api.evil-tracker.io/t')\n", encoding="utf-8")

    hits = scan_source(tmp_path)
    hosts = [h.host for h in hits]
    assert "api.evil-tracker.io" not in hosts, "node_modules must be skipped"


def test_scan_source_skips_large_file(tmp_path: Path):
    big = tmp_path / "huge.txt"
    # Write slightly more than 1 MiB; the file contains a URL but must be skipped.
    payload = "https://api.telemetry-big.io/x\n"
    big.write_bytes((payload * (1024 * 1024 // len(payload) + 2)).encode("utf-8"))
    assert big.stat().st_size > 1024 * 1024, "fixture file must exceed 1 MiB"

    hits = scan_source(tmp_path)
    hosts = [h.host for h in hits]
    assert "api.telemetry-big.io" not in hosts, "files larger than 1 MiB must be skipped"


def test_scan_source_skips_binary_file_with_nul(tmp_path: Path):
    bin_file = tmp_path / "binary.dat"
    bin_file.write_bytes(b"https://api.binary-host.com/x\x00\xff\xfe binary content")

    hits = scan_source(tmp_path)
    hosts = [h.host for h in hits]
    assert "api.binary-host.com" not in hosts, "files containing NUL bytes must be skipped"


def test_scan_source_deduplicates_same_location(tmp_path: Path):
    src = tmp_path / "dup.py"
    # Same URL appearing twice on the same line via two regex matches should
    # only be recorded once per (host, file, line) triple.
    src.write_text(
        'x = "https://api.dup-check.com/a" + "https://api.dup-check.com/b"\n', encoding="utf-8"
    )
    hits = scan_source(tmp_path)
    # Both URLs have the same host but different URLs - the (host, file, line)
    # dedup key should produce one or two entries, but not more than 2.
    matching = [h for h in hits if h.host == "api.dup-check.com"]
    # Two different URLs on the same line -> at most 2 hits (different urls but
    # same host/file/line -> deduped to 1 by the (host,file,line) key)
    assert len(matching) <= 1, "same (host, file, line) must not be duplicated"


# evaluate


def test_evaluate_without_source_root():
    components = [_make_component("sentry-sdk", "1.0.0")]
    report = evaluate(components, source_root=None)

    assert isinstance(report, EgressReport)
    assert report.source_scanned is False
    assert report.endpoints == []
    assert any(h.name == "sentry-sdk" for h in report.sdks)


def test_evaluate_with_source_root(tmp_path: Path):
    src = tmp_path / "main.py"
    src.write_text('endpoint = "https://api.custom-cloud.io/ingest"\n', encoding="utf-8")

    components = [_make_component("boto3", "1.0.0")]
    report = evaluate(components, source_root=tmp_path)

    assert report.source_scanned is True
    assert any(h.host == "api.custom-cloud.io" for h in report.endpoints)
    assert any(h.name == "boto3" for h in report.sdks)


def test_evaluate_total_components():
    components = [
        _make_component("sentry-sdk"),
        _make_component("leftpad"),
        _make_component("requests"),
    ]
    report = evaluate(components, source_root=None)
    assert report.total_components == 3
