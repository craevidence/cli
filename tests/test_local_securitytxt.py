"""Tests for the pure RFC 9116 security.txt validator (no API key, no network)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cra_evidence_cli.local.securitytxt import (
    SecurityTxtIssue,
    SecurityTxtReport,
    validate_security_txt,
)

# A fixed reference time so the Expires checks are deterministic.
NOW = datetime(2026, 6, 15, tzinfo=UTC)


def _doc(**fields: str) -> str:
    """Render an ordered security.txt body from field=value keyword arguments."""
    return "\n".join(f"{name}: {value}" for name, value in fields.items()) + "\n"


def test_valid_document_has_no_issues():
    text = _doc(
        Contact="mailto:security@acme.test",
        Expires="2027-01-01T00:00:00Z",
        Policy="https://acme.test/cvd",
    )
    report = validate_security_txt(text, now=NOW)
    assert report.ok
    assert report.issues == []


def test_missing_contact_is_error():
    report = validate_security_txt(_doc(Expires="2027-01-01T00:00:00Z"), now=NOW)
    assert not report.ok
    assert any("Contact field is missing" in issue.message for issue in report.errors)


def test_missing_expires_is_error():
    report = validate_security_txt(_doc(Contact="mailto:security@acme.test"), now=NOW)
    assert not report.ok  # RFC 9116 requires Expires
    assert any("Expires field is missing" in issue.message for issue in report.errors)


def test_expired_expires_is_error():
    text = _doc(Contact="mailto:security@acme.test", Expires="2025-01-01T00:00:00Z")
    report = validate_security_txt(text, now=NOW)
    assert not report.ok
    assert any("in the past" in issue.message for issue in report.errors)


def test_expiring_soon_is_warning():
    soon = (NOW + timedelta(days=10)).isoformat().replace("+00:00", "Z")
    report = validate_security_txt(
        _doc(Contact="mailto:security@acme.test", Expires=soon), now=NOW
    )
    assert report.ok
    assert any("within" in issue.message for issue in report.warnings)


def test_far_future_expires_is_not_flagged():
    text = _doc(Contact="mailto:security@acme.test", Expires="2099-01-01T00:00:00Z")
    report = validate_security_txt(text, now=NOW)
    assert report.ok
    assert all("Expires" not in issue.message for issue in report.warnings)


def test_unparseable_expires_is_error():
    text = _doc(Contact="mailto:security@acme.test", Expires="not-a-date")
    report = validate_security_txt(text, now=NOW)
    assert not report.ok
    assert any("not a valid RFC 3339 timestamp" in issue.message for issue in report.errors)


def test_duplicate_expires_is_error():
    text = (
        "Contact: mailto:security@acme.test\n"
        "Expires: 2027-01-01T00:00:00Z\n"
        "Expires: 2028-01-01T00:00:00Z\n"
    )
    report = validate_security_txt(text, now=NOW)
    assert not report.ok
    assert any("appears more than once" in issue.message for issue in report.errors)


def test_naive_expires_without_offset_is_error():
    text = _doc(Contact="mailto:security@acme.test", Expires="2027-01-01T00:00:00")
    report = validate_security_txt(text, now=NOW)
    assert not report.ok  # RFC 3339 requires a timezone offset
    assert any("not a valid RFC 3339 timestamp" in issue.message for issue in report.errors)


def test_placeholder_values_warn_per_field():
    text = _doc(
        Contact="mailto:security@example.com",
        Expires="2027-01-01T00:00:00Z",
        Policy="https://example.com/cvd",
    )
    report = validate_security_txt(text, now=NOW)
    placeholder_warnings = [w for w in report.warnings if "placeholder" in w.message]
    assert len(placeholder_warnings) == 2  # Contact and Policy, not Expires


def test_replace_marker_is_flagged_as_placeholder():
    text = _doc(Contact="REPLACE WITH A REAL CONTACT", Expires="2027-01-01T00:00:00Z")
    report = validate_security_txt(text, now=NOW)
    assert any("placeholder" in issue.message for issue in report.warnings)


def test_comments_and_blank_lines_are_ignored():
    text = (
        "# a comment line\n"
        "\n"
        "Contact: mailto:security@acme.test\n"
        "   \n"
        "# another comment\n"
        "Expires: 2027-01-01T00:00:00Z\n"
    )
    report = validate_security_txt(text, now=NOW)
    assert report.ok
    assert report.issues == []


def test_field_names_are_case_insensitive():
    text = "CONTACT: mailto:security@acme.test\nexpires: 2027-01-01T00:00:00Z\n"
    report = validate_security_txt(text, now=NOW)
    assert report.ok
    assert report.issues == []


def test_contact_without_uri_scheme_is_error():
    text = _doc(Contact="security@acme.test", Expires="2099-01-01T00:00:00Z")
    report = validate_security_txt(text, now=NOW)
    assert not report.ok  # RFC 9116 requires Contact to be a URI
    assert any("is not a URI" in issue.message for issue in report.errors)


def test_contact_http_uri_is_error():
    text = _doc(Contact="http://acme.test/security", Expires="2099-01-01T00:00:00Z")
    report = validate_security_txt(text, now=NOW)
    assert not report.ok  # RFC 9116 requires a web URI to use https
    assert any("uses http" in issue.message for issue in report.errors)


def test_mailto_contact_is_not_flagged():
    text = _doc(Contact="mailto:security@acme.test", Expires="2099-01-01T00:00:00Z")
    report = validate_security_txt(text, now=NOW)
    assert all("URI" not in issue.message for issue in report.issues)


def test_date_only_expires_is_error():
    text = _doc(Contact="mailto:security@acme.test", Expires="2027-01-01")
    report = validate_security_txt(text, now=NOW)
    assert not report.ok
    assert any("not a valid RFC 3339 timestamp" in issue.message for issue in report.errors)


def test_colonless_offset_expires_is_error():
    text = _doc(Contact="mailto:security@acme.test", Expires="2027-01-01T00:00:00+0000")
    report = validate_security_txt(text, now=NOW)
    assert not report.ok
    assert any("not a valid RFC 3339 timestamp" in issue.message for issue in report.errors)


def test_ok_is_false_only_when_errors_present():
    report = SecurityTxtReport()
    assert report.ok
    report.issues.append(SecurityTxtIssue("warning", "just a warning"))
    assert report.ok
    report.issues.append(SecurityTxtIssue("error", "a real error"))
    assert not report.ok
