"""Pure, network-free RFC 9116 security.txt validation for the no-key pipeline.

Parses an existing security.txt and reports structural issues: a missing
mandatory Contact field, a missing or stale Expires field, an unparseable
Expires timestamp, and leftover placeholder values from a template. No network,
no subprocess, no exit codes, no printing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

# An Expires date within this many days of now is reported as a refresh-soon warning.
EXPIRES_SOON_DAYS = 30

# Substrings that mark an unedited template value (RFC 9116 placeholders).
_PLACEHOLDER_MARKERS = ("example.com", "replace")

# A leading URI scheme, e.g. "mailto:", "tel:", "https:". RFC 9116 Contact values
# must be URIs, not bare email addresses.
_URI_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")

# RFC 3339 timestamp: full-date, a 'T' (or space) separator, full-time, and a
# required 'Z' or numeric offset that includes a colon. A bare date, a missing
# offset, or a colon-less offset matches nothing and is rejected, since RFC 9116
# requires the Expires value to be a valid RFC 3339 timestamp.
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)

# RFC 9116 field names mapped to their canonical capitalisation for messages.
_CANONICAL_FIELDS = {
    "contact": "Contact",
    "expires": "Expires",
    "encryption": "Encryption",
    "acknowledgments": "Acknowledgments",
    "preferred-languages": "Preferred-Languages",
    "canonical": "Canonical",
    "policy": "Policy",
    "hiring": "Hiring",
    "csaf": "CSAF",
}


@dataclass
class SecurityTxtIssue:
    """A single validation finding: an error or a warning carrying a message."""

    severity: str  # "error" or "warning"
    message: str


@dataclass
class SecurityTxtReport:
    """Result of validating a security.txt document."""

    issues: list[SecurityTxtIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[SecurityTxtIssue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[SecurityTxtIssue]:
        return [issue for issue in self.issues if issue.severity == "warning"]

    @property
    def ok(self) -> bool:
        """True when there are no errors. Warnings do not make a file invalid."""
        return not self.errors


def _parse_fields(text: str) -> dict[str, list[str]]:
    """Collect lowercased field name -> list of values, skipping comments and blanks."""
    fields: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition(":")
        if not sep:
            continue
        fields.setdefault(name.strip().lower(), []).append(value.strip())
    return fields


def _parse_expires(value: str) -> datetime | None:
    """Parse an Expires value, or return None if it is not a valid RFC 3339 timestamp.

    RFC 3339 requires a timezone offset (``Z`` or ``+hh:mm``), so a bare date or a
    timestamp without an offset is rejected.
    """
    candidate = value.strip()
    if not _RFC3339.match(candidate):
        return None
    normalized = candidate[:-1] + "+00:00" if candidate[-1:] in ("Z", "z") else candidate
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _canonical_field(lower_name: str) -> str:
    return _CANONICAL_FIELDS.get(lower_name, lower_name)


def validate_security_txt(text: str, *, now: datetime | None = None) -> SecurityTxtReport:
    """Validate an RFC 9116 security.txt document.

    Reports a missing mandatory Contact field as an error, and a missing,
    unparseable, or stale Expires field plus any leftover placeholder values as
    warnings. ``now`` defaults to the current UTC time and is injectable so the
    expiry checks are deterministic in tests.
    """
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)

    report = SecurityTxtReport()
    fields = _parse_fields(text)

    contacts = fields.get("contact", [])
    if not contacts:
        report.issues.append(
            SecurityTxtIssue(
                "error",
                "Contact field is missing. RFC 9116 requires at least one Contact "
                "field; it is the single point of contact for vulnerability reports.",
            )
        )
    else:
        _check_contact(contacts, report)

    _check_expires(fields.get("expires", []), moment, report)
    _check_placeholders(fields, report)
    return report


def _check_contact(contacts: list[str], report: SecurityTxtReport) -> None:
    for value in contacts:
        stripped = value.strip()
        if not _URI_SCHEME.match(stripped):
            report.issues.append(
                SecurityTxtIssue(
                    "error",
                    f"Contact value {value!r} is not a URI. RFC 9116 requires URI "
                    "syntax (RFC 3986), such as a mailto:, tel:, or https: address.",
                )
            )
        elif stripped.lower().startswith("http://"):
            report.issues.append(
                SecurityTxtIssue(
                    "error",
                    f"Contact value {value!r} uses http. RFC 9116 requires a web URI "
                    "to begin with https://.",
                )
            )


def _check_expires(
    expires_values: list[str], moment: datetime, report: SecurityTxtReport
) -> None:
    # RFC 9116 clients treat an expired file as stale, so expired Expires is an
    # error. A future date that is close to expiry remains a refresh warning.
    if not expires_values:
        report.issues.append(
            SecurityTxtIssue(
                "error",
                "Expires field is missing. RFC 9116 requires it exactly once.",
            )
        )
        return

    if len(expires_values) > 1:
        report.issues.append(
            SecurityTxtIssue(
                "error",
                "Expires field appears more than once. RFC 9116 allows it only once.",
            )
        )

    expires_raw = expires_values[0]
    parsed = _parse_expires(expires_raw)
    if parsed is None:
        report.issues.append(
            SecurityTxtIssue(
                "error",
                f"Expires value is not a valid RFC 3339 timestamp: {expires_raw!r}.",
            )
        )
        return

    if parsed <= moment:
        report.issues.append(
            SecurityTxtIssue(
                "error",
                f"Expires date {expires_raw} is in the past. Refresh the file; clients "
                "treat an expired security.txt as stale.",
            )
        )
    elif parsed - moment <= timedelta(days=EXPIRES_SOON_DAYS):
        days = (parsed - moment).days
        report.issues.append(
            SecurityTxtIssue(
                "warning",
                f"Expires date {expires_raw} is within {days} day(s). Refresh it "
                "before it lapses.",
            )
        )


def _check_placeholders(fields: dict[str, list[str]], report: SecurityTxtReport) -> None:
    for name, values in fields.items():
        for value in values:
            lowered = value.lower()
            if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
                report.issues.append(
                    SecurityTxtIssue(
                        "warning",
                        f"{_canonical_field(name)} still holds a placeholder value "
                        f"({value!r}). Replace it before publishing.",
                    )
                )
