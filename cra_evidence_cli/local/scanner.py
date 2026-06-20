"""Local Grype scanner wrapper for no-key checks."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cra_evidence_cli.exceptions import ScanEngineUnavailable
from cra_evidence_cli.local.models import CoverageSource, Finding, normalize_severity


class GrypeLocalScanner:
    """Small Grype wrapper for the local no-key scan."""

    def __init__(self, cache_dir: str | None = None, timeout: int = 300) -> None:
        self.cache_dir = cache_dir or os.getenv("GRYPE_DB_CACHE_DIR")
        self.timeout = timeout
        self._path: str | None = None

    @property
    def path(self) -> str:
        if self._path is None:
            found = shutil.which("grype")
            if not found:
                msg = (
                    "Grype is not installed; OSV.dev is used as a fallback over the network."
                )
                raise ScanEngineUnavailable(
                    msg
                )
            self._path = found
        return self._path

    def is_available(self) -> bool:
        return shutil.which("grype") is not None

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
            result = subprocess.run(  # noqa: S603
                [self.path, "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception:
            return "unknown"
        for line in result.stdout.splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
        return result.stdout.strip().splitlines()[0] if result.stdout.strip() else "unknown"

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
            "GRYPE_DB_AUTO_UPDATE": "true",
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        }
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            env=env,
        )
        if result.returncode != 0:
            raise ScanEngineUnavailable(result.stderr.strip() or "Grype scan failed")
        findings = parse_grype_output(result.stdout)
        metadata = self.get_db_metadata() or {}
        return findings, CoverageSource(
            "grype-db",
            "present",
            as_of=metadata.get("built"),
            detail=f"schema={metadata.get('schema_version') or 'unknown'}",
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
    data = json.loads(raw)
    findings: list[Finding] = []
    for match in data.get("matches", []):
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        aliases = set()
        for related in vulnerability.get("relatedVulnerabilities") or []:
            related_id = related.get("id") if isinstance(related, dict) else related
            if related_id:
                aliases.add(str(related_id))
        vuln_id = str(vulnerability.get("id") or "UNKNOWN")
        aliases.update(str(item) for item in vulnerability.get("aliases") or [])
        aliases.discard(vuln_id)
        known_exploited_raw = vulnerability.get("knownExploited") or []
        fix = vulnerability.get("fix") or {}
        findings.append(
            Finding(
                id=vuln_id,
                package=str(artifact.get("name") or "unknown"),
                version=artifact.get("version"),
                severity=normalize_severity(vulnerability.get("severity")),
                aliases=aliases,
                fixed_versions=[str(item) for item in fix.get("versions") or []],
                purl=artifact.get("purl"),
                title=vulnerability.get("description"),
                references=_references(vulnerability.get("urls") or []),
                epss_probability=_first_epss(vulnerability.get("epss") or []),
                known_exploited=True if known_exploited_raw else None,
                source="grype",
            )
        )
    return findings


def _first_epss(items: list[Any]) -> float | None:
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            return float(item["epss"])
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _references(items: list[Any]) -> list[str]:
    refs: list[str] = []
    for item in items:
        if isinstance(item, str) and item:
            refs.append(item)
        elif isinstance(item, dict) and item.get("url"):
            refs.append(str(item["url"]))
    return refs
