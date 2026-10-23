"""Local Grype scanner wrapper for no-key checks."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cra_evidence_cli.engine import (
    EngineIdentity,
    EngineInspection,
    engine_installation_message,
    inspect_engine,
)
from cra_evidence_cli.exceptions import ScanEngineUnavailable
from cra_evidence_cli.local.enrich import _date_text
from cra_evidence_cli.local.models import (
    CoverageSource,
    Finding,
    SearchedDistro,
    UnassessedPackage,
    normalize_severity,
)
from cra_evidence_cli.local.version_applicability import classify_occurrence


class GrypeLocalScanner:
    """Small Grype wrapper for the local no-key scan."""

    def __init__(self, cache_dir: str | None = None, timeout: int = 300) -> None:
        self.cache_dir = cache_dir or os.getenv("GRYPE_DB_CACHE_DIR")
        self.timeout = timeout
        self._inspection: EngineInspection | None = None

    def _engine_inspection(self) -> EngineInspection:
        if self._inspection is None:
            self._inspection = inspect_engine()
        return self._inspection

    @property
    def identity(self) -> EngineIdentity:
        inspection = self._engine_inspection()
        if inspection.identity is None:
            raise ScanEngineUnavailable(engine_installation_message(inspection.reason))
        return inspection.identity

    @property
    def path(self) -> str:
        return self.identity.path

    def is_available(self) -> bool:
        return self._engine_inspection().identity is not None

    def unavailable_reason(self) -> str:
        """Why no supported engine was used, or "" when one was.

        Callers that fall back to OSV.dev print this so the downgrade is never
        silent. Stock Grype, an unstamped build and an older CRA Evidence engine
        without SBOM generation are all rejected here, and each has a distinct
        reason.
        """
        inspection = self._engine_inspection()
        if inspection.identity is not None:
            return ""
        return inspection.reason

    def is_db_available(self) -> bool:
        if not self.cache_dir:
            return False
        cache_path = Path(self.cache_dir)
        if not cache_path.exists():
            return False
        return any(
            item.is_dir() and (item / "vulnerability.db").exists()
            for item in cache_path.iterdir()
        )

    def get_version(self) -> str:
        try:
            return self.identity.version
        except ScanEngineUnavailable:
            return "unknown"

    def get_db_metadata(self) -> dict[str, Any] | None:
        env = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false"}
        # Point grype at this scanner's cache dir so the reported build date
        # reflects the DB we actually manage, not grype's global default.
        if self.cache_dir:
            env["GRYPE_DB_CACHE_DIR"] = self.cache_dir
        try:
            result = subprocess.run(  # noqa: S603
                [self.path, "db", "status", "--output", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
            )
            if result.returncode != 0:
                return None
            data = json.loads(result.stdout)
        except Exception:
            return None
        schema_raw = str(data.get("schemaVersion") or "")
        schema_version = schema_raw.lstrip("v").split(".")[0] or None
        return {
            "built": data.get("built"),
            "schema_version": schema_version,
            "status": "valid" if data.get("valid") is True else data.get("status"),
        }

    def scan_sbom(self, sbom_path: Path) -> tuple[list[Finding], CoverageSource]:
        cmd = [
            self.path,
            f"sbom:{sbom_path}",
            "--output",
            "json",
            "--add-cpes-if-none",
            "--by-cve",
        ]
        env = {
            **os.environ,
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        }
        # An explicit GRYPE_DB_AUTO_UPDATE from the caller's environment (for
        # example "false" on an air-gapped runner) must stay in force, so the
        # auto-update default is only applied when the variable is absent.
        env.setdefault("GRYPE_DB_AUTO_UPDATE", "true")
        try:
            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            message = "Grype scan timed out"
            raise ScanEngineUnavailable(message) from exc
        except OSError as exc:
            message = "Grype scan could not be started"
            raise ScanEngineUnavailable(message) from exc
        if result.returncode not in {0, 1}:
            raise ScanEngineUnavailable(result.stderr.strip() or "Grype scan failed")
        if result.returncode == 1 and not result.stdout.strip():
            raise ScanEngineUnavailable(result.stderr.strip() or "Grype scan failed")
        try:
            findings, document = _parse_grype_document(result.stdout)
        except (TypeError, ValueError, AttributeError, KeyError, IndexError, RecursionError) as exc:
            message = "scanner returned malformed match data"
            raise ScanEngineUnavailable(message) from exc
        partial_detail = None
        unassessed: list[UnassessedPackage] = []
        if result.returncode == 1:
            partial_detail, unassessed = _incomplete_assessment(document.get("assessment"))
        elif document.get("assessment") is not None:
            message = "scanner returned an assessment with a successful exit"
            raise ScanEngineUnavailable(message)
        metadata = self.get_db_metadata() or {}
        return findings, CoverageSource(
            "grype-db",
            "partial" if partial_detail is not None else "present",
            as_of=metadata.get("built"),
            detail=partial_detail or f"schema={metadata.get('schema_version') or 'unknown'}",
            unassessed_packages=unassessed,
        )

    def _db_mtime_offline(self) -> str | None:
        """Newest cached vulnerability.db mtime as an ISO date, without any network call."""
        if not self.cache_dir:
            return None
        cache_path = Path(self.cache_dir)
        if not cache_path.exists():
            return None
        mtimes = [
            (item / "vulnerability.db").stat().st_mtime
            for item in cache_path.iterdir()
            if item.is_dir() and (item / "vulnerability.db").exists()
        ]
        if not mtimes:
            return None
        return datetime.fromtimestamp(max(mtimes), UTC).date().isoformat()


def parse_grype_output(raw: str) -> list[Finding]:
    findings, _ = _parse_grype_document(raw)
    return findings


def _incomplete_assessment(assessment: Any) -> tuple[str, list[UnassessedPackage]]:
    message = "scanner did not return an actionable incomplete assessment"
    if not isinstance(assessment, dict) or assessment.get("status") != "incomplete":
        raise ScanEngineUnavailable(message)
    packages = assessment.get("unassessablePackages")
    if not isinstance(packages, list) or not packages:
        raise ScanEngineUnavailable(message)
    details = []
    unassessed = []
    for entry in packages:
        if not isinstance(entry, dict):
            raise ScanEngineUnavailable(message)
        package = entry.get("package")
        if not isinstance(package, dict):
            raise ScanEngineUnavailable(message)
        identities = [package.get("purl"), package.get("name")]
        identity = next(
            (value for value in identities if isinstance(value, str) and value.strip()), None
        )
        matcher = entry.get("matcher")
        reason = entry.get("reasonCode")
        if (
            identity is None
            or not isinstance(matcher, str)
            or not matcher.strip()
            or not isinstance(reason, str)
            or not reason.strip()
        ):
            raise ScanEngineUnavailable(message)
        version = package.get("version")
        label = f"{identity}@{version}" if identity == package.get("name") and version else identity
        details.append(f"{label} ({matcher}: {reason})")
        searched, searched_ok = _searched_distros(entry, reason)
        candidate_count, candidate_ids, candidates_ok = _candidates(entry, reason)
        unassessed.append(
            UnassessedPackage(
                name=package.get("name"),
                version=package.get("version"),
                purl=package.get("purl"),
                reason=reason,
                matcher=matcher,
                searched_distros=searched,
                candidate_count=candidate_count,
                candidate_ids=candidate_ids,
                malformed_detail=not (searched_ok and candidates_ok),
            )
        )
    return "Incomplete vulnerability assessment: " + "; ".join(details), unassessed


_MAX_CANDIDATE_IDS = 20
_SEARCHED_DISTRO_TEXT_KEYS = ("name", "version", "label", "channel")


def _searched_distros(
    entry: dict[str, Any], reason: str
) -> tuple[tuple[SearchedDistro, ...], bool]:
    """Searched operating-system scopes and whether the engine data was well-formed.

    These details only explain an entry, so malformed data is dropped from the
    report instead of rejecting the scan.
    """
    if "searchedDistros" not in entry:
        return (), True
    value = entry["searchedDistros"]
    if (
        reason != "distro-release-not-in-db"
        or not isinstance(value, list)
        or not value
        or any(
            not isinstance(item, dict)
            or any(not isinstance(item.get(k), str) for k in _SEARCHED_DISTRO_TEXT_KEYS)
            or not item["name"].strip()
            or not isinstance(item.get("exact"), bool)
            for item in value
        )
    ):
        return (), False
    return tuple(
        SearchedDistro(
            name=item["name"],
            version=item["version"],
            label=item["label"],
            channel=item["channel"],
            exact=item["exact"],
        )
        for item in value
    ), True


def _candidates(
    entry: dict[str, Any], reason: str
) -> tuple[int | None, tuple[str, ...] | None, bool]:
    """Candidate vulnerability count and IDs, or None when not computed.

    The engine writes both keys together, only for an unknown package version, with
    at most 20 IDs. Anything else is malformed and reported as not computed, never
    as a count of 0.
    """
    has_count = "candidateVulnerabilityCount" in entry
    has_ids = "candidateVulnerabilityIds" in entry
    if not has_count and not has_ids:
        return None, None, True
    count = entry.get("candidateVulnerabilityCount")
    ids = entry.get("candidateVulnerabilityIds")
    if (
        not (has_count and has_ids)
        or reason != "unknown-package-version"
        or type(count) is not int
        or count < 0
        or not isinstance(ids, list)
        or len(ids) > _MAX_CANDIDATE_IDS
        or len(ids) > count
        or any(not isinstance(item, str) or not item.strip() for item in ids)
    ):
        return None, None, False
    return count, tuple(ids), True


def _parse_grype_document(raw: str) -> tuple[list[Finding], dict[str, Any]]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        message = "scanner returned output that could not be parsed"
        raise ScanEngineUnavailable(message) from exc
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("matches"), list)
        or any(not isinstance(match, dict) for match in data["matches"])
    ):
        message = "scanner returned malformed match data"
        raise ScanEngineUnavailable(message)
    parsed: list[tuple[Finding, tuple[Any, ...]]] = []
    evidence: dict[tuple[Any, ...], tuple[list[Any], set[str]]] = {}
    for match in data.get("matches", []):
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        aliases = set()
        # Grype reports related identifiers (for example the CVE behind a GHSA
        # finding) on the match, not inside the vulnerability object.
        for related in match.get("relatedVulnerabilities") or []:
            related_id = related.get("id") if isinstance(related, dict) else related
            if related_id:
                aliases.add(str(related_id))
        vuln_id = str(vulnerability.get("id") or "UNKNOWN")
        aliases.discard(vuln_id)
        known_exploited_raw = vulnerability.get("knownExploited") or []
        fix = vulnerability.get("fix") or {}
        epss_probability, epss_cve, epss_date = _first_epss(vulnerability.get("epss") or [])
        finding = Finding(
            id=vuln_id,
            package=str(artifact.get("name") or "unknown"),
            version=artifact.get("version"),
            severity=normalize_severity(vulnerability.get("severity")),
            aliases=aliases,
            fixed_versions=[str(item) for item in fix.get("versions") or []],
            purl=artifact.get("purl"),
            title=vulnerability.get("description"),
            references=_references(vulnerability.get("urls") or []),
            epss_probability=epss_probability,
            epss_cve=epss_cve,
            epss_date=epss_date,
            epss_source="grype-db" if epss_probability is not None else None,
            known_exploited=True if known_exploited_raw else None,
            source="grype",
        )
        # Matches of one vulnerability on one package occurrence share a single
        # classification computed from all of their match details.
        key = (vuln_id, artifact.get("name"), artifact.get("version"), artifact.get("purl"))
        details, cpes = evidence.setdefault(key, ([], set()))
        if isinstance(match.get("matchDetails"), list):
            details.extend(match["matchDetails"])
        if isinstance(artifact.get("cpes"), list):
            cpes.update(cpe for cpe in artifact["cpes"] if isinstance(cpe, str))
        parsed.append((finding, key))
    classifications = {
        key: classify_occurrence(key[2], key[3], details, sorted(cpes))
        for key, (details, cpes) in evidence.items()
    }
    findings = []
    for finding, key in parsed:
        classification = classifications[key]
        if classification.status == "indicative":
            finding.indicative_reason = classification.reason
            finding.applicability_evidence = classification.evidence
        findings.append(finding)
    return findings, data


def _first_epss(items: list[Any]) -> tuple[float | None, str | None, str | None]:
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            probability = float(item["epss"])
        except (KeyError, TypeError, ValueError):
            continue
        raw_cve = item.get("cve")
        cve = raw_cve.strip().upper() if isinstance(raw_cve, str) and raw_cve.strip() else None
        return probability, cve, _date_text(item.get("date"))
    return None, None, None


def _references(items: list[Any]) -> list[str]:
    refs: list[str] = []
    for item in items:
        if isinstance(item, str) and item:
            refs.append(item)
        elif isinstance(item, dict) and item.get("url"):
            refs.append(str(item["url"]))
    return refs
