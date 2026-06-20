"""OSV.dev fallback client for local no-key checks."""

from __future__ import annotations

import json
import random
import time
from typing import Any

import httpx

from cra_evidence_cli.local.models import Component, CoverageSource, Finding, normalize_severity

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_HTTP1_RESPONSE_BYTES = 32 * 1024 * 1024


class OSVClientError(RuntimeError):
    """Raised when the OSV query cannot be completed."""


class OSVClient:
    def __init__(self, timeout: float = 30.0, max_batch_bytes: int = 28 * 1024 * 1024) -> None:
        self.timeout = timeout
        self.max_batch_bytes = max_batch_bytes

    def query_components(
        self,
        components: list[Component],
    ) -> tuple[list[Finding], CoverageSource]:
        queries = [self._query_for(component) for component in components if component.purl]
        if not queries:
            return [], CoverageSource("osv.dev", "skipped", detail="No component PURLs found")

        findings: list[Finding] = []
        skipped = 0
        # HTTP/1.1 only: enabling http2 would require the optional `h2` package,
        # which is not a declared dependency, so the no-key OSV.dev fallback must
        # not assume it. OSV.dev serves these queries fine over HTTP/1.1.
        try:
            with httpx.Client(timeout=self.timeout) as client:
                for batch in self._batches(queries):
                    batch_findings, batch_skipped = self._query_batch(client, batch)
                    findings.extend(batch_findings)
                    skipped += batch_skipped
        except httpx.HTTPError as exc:
            msg = f"OSV.dev request failed: {exc}"
            raise OSVClientError(msg) from exc
        if skipped:
            detail = f"{skipped} component(s) skipped: OSV.dev rejected the identifier"
            return findings, CoverageSource("osv.dev", "partial", detail=detail)
        return findings, CoverageSource("osv.dev", "present")

    def _query_batch(
        self, client: httpx.Client, queries: list[dict[str, Any]]
    ) -> tuple[list[Finding], int]:
        """Run one batch of queries; return (findings, skipped_count).

        OSV.dev rejects a whole querybatch with a 400 when any single identifier
        is malformed. To keep one bad purl from dropping every other component, a
        400 on a multi-item batch is retried per item, and only the offending
        identifiers are skipped and counted.
        """
        api_queries = [self._api_query(query) for query in queries]
        try:
            data = self._post_with_retries(client, {"queries": api_queries})
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 400:
                raise
            if len(queries) == 1:
                return [], 1
            findings: list[Finding] = []
            skipped = 0
            for query in queries:
                sub_findings, sub_skipped = self._query_batch(client, [query])
                findings.extend(sub_findings)
                skipped += sub_skipped
            return findings, skipped
        return self._parse_results(queries, data.get("results") or []), 0

    def _query_for(self, component: Component) -> dict[str, Any]:
        return {
            "package": {"purl": component.purl},
            "version": component.version or "",
            "_component_name": component.name,
            "_component_purl": component.purl,
        }

    def _api_query(self, query: dict[str, Any]) -> dict[str, Any]:
        """Build the OSV payload for one query, dropping internal bookkeeping.

        Internal keys (prefixed with '_') are never sent to OSV. OSV returns 400
        if a version is supplied both inside the purl and in the separate version
        field, so the version is only sent when the purl carries none.
        """
        purl = query.get("_component_purl") or query["package"].get("purl") or ""
        api: dict[str, Any] = {"package": {"purl": purl}}
        version = query.get("version")
        if version and "@" not in purl:
            api["version"] = version
        return api

    def _batches(self, queries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        batches: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        for query in queries:
            candidate = [*current, query]
            size = len(json.dumps({"queries": candidate}).encode())
            if current and size > self.max_batch_bytes:
                batches.append(current)
                current = [query]
            else:
                current = candidate
        if current:
            batches.append(current)
        return batches

    def _post_with_retries(self, client: httpx.Client, payload: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(4):
            response = client.post(OSV_QUERYBATCH_URL, json=payload)
            if response.status_code not in {429, 500, 502, 503, 504}:
                response.raise_for_status()
                if len(response.content) > MAX_HTTP1_RESPONSE_BYTES:
                    msg = "OSV response exceeded 32 MiB cap; local scan is incomplete"
                    raise OSVClientError(msg)
                data = response.json()
                if "next_page_token" in data or data.get("truncated"):
                    msg = "OSV response was paginated/truncated; local scan is incomplete"
                    raise OSVClientError(msg)
                return data
            retry_after = response.headers.get("Retry-After")
            # Jitter for retry backoff; not security-sensitive.
            jitter = random.random() / 10  # noqa: S311
            delay = float(retry_after) if retry_after else (0.5 * (2**attempt) + jitter)
            time.sleep(delay)
        msg = "OSV.dev did not return a complete response after retries"
        raise OSVClientError(msg)

    def _parse_results(
        self,
        queries: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for query, result in zip(queries, results, strict=False):
            package = str(query.get("_component_name") or "unknown")
            purl = query.get("_component_purl")
            for vuln in result.get("vulns") or []:
                vuln_id = str(vuln.get("id") or "UNKNOWN")
                aliases = {str(item) for item in vuln.get("aliases") or [] if item}
                aliases.discard(vuln_id)
                findings.append(
                    Finding(
                        id=vuln_id,
                        package=package,
                        version=query.get("version"),
                        severity=_severity_from_osv(vuln),
                        aliases=aliases,
                        fixed_versions=_fixed_versions(vuln),
                        purl=purl if isinstance(purl, str) else None,
                        title=vuln.get("summary") or vuln.get("details"),
                        references=[
                            str(ref.get("url"))
                            for ref in vuln.get("references") or []
                            if isinstance(ref, dict) and ref.get("url")
                        ],
                        known_exploited=None,
                        source="osv",
                    )
                )
        return findings


def _severity_from_osv(vuln: dict[str, Any]) -> str:
    # OSV's severity[].score is a CVSS vector string, not a qualitative label; the
    # reliable qualitative label comes from database_specific/ecosystem_specific
    # (present for GitHub Advisory records). When absent, severity is "unknown".
    for block in ("database_specific", "ecosystem_specific"):
        label = (vuln.get(block) or {}).get("severity")
        if label:
            return normalize_severity(label)
    return "unknown"


def _fixed_versions(vuln: dict[str, Any]) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        for event_range in affected.get("ranges") or []:
            for event in event_range.get("events") or []:
                if "fixed" in event:
                    fixed.append(str(event["fixed"]))
    return sorted(set(fixed))
