"""Local-only scan for remote data-processing indicators.

Answers "does this product phone home / send data somewhere?" by examining an
SBOM for known telemetry, analytics, and cloud-provider SDKs, and (optionally)
walking source files for hard-coded external URLs.

No network calls are made here. The SDK catalog is an in-repo curated list and
is documented as non-exhaustive. Findings are advisory only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# In-repo curated catalog of data-collecting SDKs.
# Keys are lowercased package names as they appear in SBOMs / package manifests.
# Values are (category, short_description) pairs.
# This list is non-exhaustive; new SDKs emerge continuously.

KNOWN_SDKS: dict[str, tuple[str, str]] = {
    # Error reporting / crash diagnostics
    "sentry-sdk": (
        "error-reporting",
        "Sentry Python SDK; reports exceptions and performance data",
    ),
    "sentry": ("error-reporting", "Sentry SDK; reports exceptions and performance data"),
    "@sentry/node": (
        "error-reporting",
        "Sentry Node.js SDK; reports exceptions and performance data",
    ),
    "@sentry/browser": (
        "error-reporting",
        "Sentry browser SDK; reports exceptions and performance data",
    ),
    "bugsnag": (
        "error-reporting",
        "Bugsnag error monitoring; sends crash reports to bugsnag.com",
    ),
    "rollbar": (
        "error-reporting",
        "Rollbar error tracking; sends error payloads to rollbar.com",
    ),
    "@rollbar/react": (
        "error-reporting",
        "Rollbar React SDK; sends error payloads to rollbar.com",
    ),
    # Analytics / product telemetry
    "analytics-python": (
        "analytics",
        "Segment analytics SDK; batches and sends events to segment.io",
    ),
    "segment": ("analytics", "Segment analytics SDK; batches and sends events to segment.io"),
    "mixpanel": ("analytics", "Mixpanel analytics SDK; sends event data to mixpanel.com"),
    "amplitude": ("analytics", "Amplitude analytics SDK; sends event data to amplitude.com"),
    "@amplitude/analytics-browser": (
        "analytics",
        "Amplitude browser SDK; sends event data to amplitude.com",
    ),
    "posthog": ("analytics", "PostHog product analytics; sends events to a PostHog instance"),
    "google-analytics": (
        "analytics",
        "Google Analytics; sends page-view and event data to google-analytics.com",
    ),
    "gtag": ("analytics", "Google gtag.js wrapper; sends analytics data to Google"),
    "fullstory": (
        "analytics",
        "FullStory session recording; captures and streams user sessions",
    ),
    "hotjar": (
        "analytics",
        "Hotjar heatmap/session tool; streams interaction data to hotjar.com",
    ),
    "heap": ("analytics", "Heap auto-capture analytics; sends interaction data to heap.io"),
    "statsig": ("analytics", "Statsig feature flags and experiments; contacts statsig.com"),
    "launchdarkly": (
        "analytics",
        "LaunchDarkly feature flags; contacts launchdarkly.com for flag evaluation",
    ),
    "logrocket": (
        "analytics",
        "LogRocket session replay; streams session data to logrocket.com",
    ),
    # APM / observability
    "ddtrace": ("telemetry", "Datadog APM tracer; sends traces and metrics to datadoghq.com"),
    "datadog": ("telemetry", "Datadog agent/client; sends metrics and logs to datadoghq.com"),
    "dd-trace": ("telemetry", "Datadog Node.js tracer; sends traces to datadoghq.com"),
    "newrelic": ("telemetry", "New Relic APM agent; sends telemetry to newrelic.com"),
    "elastic-apm": (
        "telemetry",
        "Elastic APM Python agent; sends traces to an Elastic APM server",
    ),
    "elastic-apm-node": (
        "telemetry",
        "Elastic APM Node.js agent; sends traces to an Elastic APM server",
    ),
    "opentelemetry-sdk": (
        "telemetry",
        "OpenTelemetry SDK; exports traces/metrics to a configured endpoint",
    ),
    "@opentelemetry/sdk-node": (
        "telemetry",
        "OpenTelemetry Node.js SDK; exports traces/metrics to a configured endpoint",
    ),
    "appsignal": (
        "telemetry",
        "AppSignal APM; sends performance data and errors to appsignal.com",
    ),
    "honeycomb": (
        "telemetry",
        "Honeycomb observability SDK; sends traces to api.honeycomb.io",
    ),
    # Cloud / storage providers (data may leave to a third-party provider)
    "boto3": ("cloud", "AWS SDK for Python; may upload or transmit data to AWS services"),
    "aws-sdk": ("cloud", "AWS SDK for JavaScript; may upload or transmit data to AWS services"),
    "@aws-sdk/client-s3": (
        "cloud",
        "AWS S3 client; may store or retrieve objects from AWS S3",
    ),
    "google-cloud-storage": (
        "cloud",
        "Google Cloud Storage client; may store or retrieve objects from GCS",
    ),
    "@google-cloud/storage": (
        "cloud",
        "Google Cloud Storage Node.js client; may store or retrieve objects from GCS",
    ),
    "azure-storage-blob": (
        "cloud",
        "Azure Blob Storage client; may store or retrieve objects from Azure",
    ),
    "@azure/storage-blob": (
        "cloud",
        "Azure Blob Storage JS client; may store or retrieve objects from Azure",
    ),
    "firebase": ("cloud", "Firebase JS SDK; contacts Firebase/Google services"),
    "firebase-admin": ("cloud", "Firebase Admin SDK; contacts Firebase/Google services"),
    "@supabase/supabase-js": (
        "cloud",
        "Supabase JS client; contacts a Supabase project endpoint",
    ),
    # Payments (transmit payment data to a third party)
    "stripe": ("payments", "Stripe SDK; transmits payment data to api.stripe.com"),
    # Messaging / notifications (transmit content to third parties)
    "twilio": ("messaging", "Twilio SDK; sends SMS/voice data through twilio.com"),
    "sendgrid": ("messaging", "SendGrid SDK; sends email through sendgrid.com"),
}

# General network-capable libraries (not inherently telemetry, but indicate
# that the product can make outbound HTTP/gRPC connections).
# Non-exhaustive.

NETWORK_LIBS: set[str] = {
    "requests",
    "httpx",
    "urllib3",
    "aiohttp",
    "node-fetch",
    "axios",
    "got",
    "superagent",
    "okhttp",
    "grpcio",
    "grpc",
    "websockets",
    "@grpc/grpc-js",
}

# URL scanning constants

_URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "vendor",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}
_NOISE_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",  # noqa: S104
    "::1",
    "example.com",
    "example.org",
    "www.example.com",
    "w3.org",
    "www.w3.org",
    "schemastore.org",
    "www.schemastore.org",
    "spdx.org",
    "json-schema.org",
    "purl.org",
}
_MAX_FILE_BYTES = 1024 * 1024  # 1 MiB
_MAX_ENDPOINTS = 500


# Dataclasses


@dataclass
class SdkHit:
    """An SDK matched from the SBOM against the curated catalog."""

    name: str
    version: str | None
    category: str
    description: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable representation."""
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "description": self.description,
        }


@dataclass
class EndpointHit:
    """An external URL found in source code."""

    host: str
    url: str
    file: str
    line: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable representation."""
        return {
            "host": self.host,
            "url": self.url,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class EgressReport:
    """Aggregated advisory report of remote data-processing indicators."""

    sdks: list[SdkHit]
    network_libs: list[str]
    endpoints: list[EndpointHit]
    source_scanned: bool
    total_components: int
    endpoints_capped: bool = field(default=False)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable representation."""
        return {
            "total_components": self.total_components,
            "sdks": [sdk.to_dict() for sdk in self.sdks],
            "network_libs": self.network_libs,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
            "endpoints_capped": self.endpoints_capped,
            "source_scanned": self.source_scanned,
        }


# Core functions


def _purl_name(purl: str | None) -> str | None:
    """Extract the package name from a purl string, lowercased."""
    if not purl:
        return None
    # purl form: pkg:<type>/<namespace>/<name>@<version>
    # We want the final name segment before the @
    try:
        after_scheme = purl.split(":", 1)[1]  # "<type>/..."
        path_part = after_scheme.split("@")[0]  # strip version
        name = path_part.split("/")[-1]  # last path segment is the package name
        return name.lower() if name else None
    except (IndexError, AttributeError):
        return None


def match_sbom(
    components: list,
) -> tuple[list[SdkHit], list[str]]:
    """Match SBOM components against the curated SDK and network-lib catalogs.

    Performs exact, case-insensitive matching on the component name and the
    purl-derived package name. Returns a tuple of (sdk_hits, network_lib_names).
    The network_lib_names list is sorted and deduplicated.
    """
    sdk_hits: list[SdkHit] = []
    net_lib_names: set[str] = set()

    for component in components:
        candidate_names: set[str] = set()
        if component.name:
            candidate_names.add(component.name.lower())
        purl_n = _purl_name(component.purl)
        if purl_n:
            candidate_names.add(purl_n)

        for name in candidate_names:
            if name in KNOWN_SDKS:
                category, description = KNOWN_SDKS[name]
                sdk_hits.append(
                    SdkHit(
                        name=component.name,
                        version=component.version,
                        category=category,
                        description=description,
                    )
                )
                break  # one hit per component is enough
        else:
            for name in candidate_names:
                if name in NETWORK_LIBS:
                    net_lib_names.add(component.name)
                    break

    return sdk_hits, sorted(net_lib_names)


def scan_source(root: Path) -> list[EndpointHit]:
    """Walk source files under *root* and collect external URLs.

    Skips hidden/build directories, files larger than 1 MiB, non-UTF-8 files,
    and binary files (detected by a NUL byte in the first chunk). De-duplicates
    by (host, file, line). Caps total results at 500.

    Hosts that are loopback addresses, .local domains, or well-known
    documentation noise (example.com, schema registries) are excluded.
    """
    hits: list[EndpointHit] = []
    seen: set[tuple[str, str, int]] = set()
    capped = False

    for path in _walk(root):
        if len(hits) >= _MAX_ENDPOINTS:
            capped = True
            break
        try:
            stat = path.stat()
        except OSError:
            continue
        if stat.st_size > _MAX_FILE_BYTES:
            continue

        try:
            with path.open(encoding="utf-8", errors="ignore") as fh:
                first_chunk = fh.read(8192)
                if "\x00" in first_chunk:
                    continue
                rest = fh.read()
            text = first_chunk + rest
        except OSError:
            continue

        rel = str(path.relative_to(root))
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(hits) >= _MAX_ENDPOINTS:
                capped = True
                break
            for match in _URL_RE.finditer(line):
                url = match.group(0)
                host = _extract_host(url)
                if not host or _is_noise(host):
                    continue
                dedup_key = (host, rel, lineno)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                hits.append(
                    EndpointHit(
                        host=host,
                        url=url[:120],
                        file=rel,
                        line=lineno,
                    )
                )
                if len(hits) >= _MAX_ENDPOINTS:
                    capped = True
                    break

    # Store the cap flag on a sentinel value so callers can detect it without
    # an extra return value; the EgressReport carries it explicitly.
    scan_source._last_capped = capped  # type: ignore[attr-defined]
    return hits


scan_source._last_capped = False  # type: ignore[attr-defined]


def evaluate(components: list, source_root: Path | None) -> EgressReport:
    """Run all layers and return an advisory EgressReport.

    Layer 1+2: match the SBOM against KNOWN_SDKS and NETWORK_LIBS.
    Layer 3: if *source_root* is provided, scan source files for external URLs.
    """
    sdk_hits, net_lib_names = match_sbom(components)

    if source_root is not None:
        endpoints = scan_source(source_root)
        capped = getattr(scan_source, "_last_capped", False)
        source_scanned = True
    else:
        endpoints = []
        capped = False
        source_scanned = False

    return EgressReport(
        sdks=sdk_hits,
        network_libs=net_lib_names,
        endpoints=endpoints,
        source_scanned=source_scanned,
        total_components=len(components),
        endpoints_capped=capped,
    )


# Internal helpers


def _walk(root: Path):
    """Yield all file paths under *root*, skipping noisy directories."""
    try:
        entries = list(root.iterdir())
    except (PermissionError, OSError):
        return
    for entry in entries:
        if entry.is_symlink():
            continue
        if entry.is_dir():
            if entry.name in _SKIP_DIRS:
                continue
            yield from _walk(entry)
        elif entry.is_file():
            yield entry


def _extract_host(url: str) -> str:
    """Return the lowercased hostname from a URL string."""
    try:
        after_scheme = url.split("://", 1)[1]
        host_part = after_scheme.split("/")[0].split("?")[0].split("#")[0]
        if host_part.startswith("["):
            # IPv6 literal: the host is inside the brackets, e.g. [::1]:8080.
            end = host_part.find("]")
            host = host_part[1:end] if end != -1 else host_part[1:]
        else:
            if "@" in host_part:
                host_part = host_part.rsplit("@", 1)[1]
            host = host_part.split(":")[0]  # strip port
        host = host.lower().strip()
        if ":" in host:
            return host
        labels = host.split(".")
        if len(labels) < 2 or any(not label for label in labels):
            return ""
        return host
    except IndexError:
        return ""


def _is_noise(host: str) -> bool:
    """Return True if the host is a loopback, .local, or known documentation domain."""
    if host in _NOISE_HOSTS:
        return True
    if host.endswith((".local", ".schemastore.org")):
        return True
    return False
