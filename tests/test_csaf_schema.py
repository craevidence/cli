"""Validate every CSAF document the CLI emits against the official CSAF 2.0 schema.

The schema in ``tests/fixtures/csaf_json_schema.json`` is the normative OASIS CSAF
2.0 JSON schema. The ``uri`` format is only enforced when jsonschema's format
extras are installed, so this module skips when they are absent, and a negative
control proves the validator really rejects a malformed document when they are
present (so the passing cases are not silently vacuous).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cra_evidence_cli.local.csaf import build_csaf_advisory, build_csaf_vex
from cra_evidence_cli.local.models import Finding

pytest.importorskip("jsonschema")

_SCHEMA = json.loads(
    (Path(__file__).parent / "fixtures" / "csaf_json_schema.json").read_text(encoding="utf-8")
)


def _validator():
    from jsonschema.validators import validator_for

    cls = validator_for(_SCHEMA)
    if "uri" not in cls.FORMAT_CHECKER.checkers:
        pytest.skip("jsonschema[format] extras not installed; uri format is not enforced")
    return cls(_SCHEMA, format_checker=cls.FORMAT_CHECKER)


def _errors(doc: dict) -> list[str]:
    return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in _validator().iter_errors(doc)]


def _findings() -> list[Finding]:
    """A with-purl finding (plus alias and reference), a no-purl finding, and another with-purl."""
    return [
        Finding(
            id="CVE-2021-44228",
            package="log4j-core",
            version="2.14.1",
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            aliases={"GHSA-jfh8-c2jp-5v3q"},
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
        Finding(id="GHSA-aaaa-bbbb-cccc", package="left-pad", version="1.0.0", purl=None),
        Finding(id="CVE-2024-5678", package="acme", version="2.0.0", purl="pkg:pypi/acme@2.0.0"),
    ]


def test_advisory_is_schema_valid_csaf():
    errors = _errors(build_csaf_advisory(_findings()))
    assert errors == [], errors


def test_vex_csaf_is_schema_valid_csaf():
    errors = _errors(build_csaf_vex(_findings()))
    assert errors == [], errors


def test_advisory_single_no_purl_finding_is_schema_valid():
    # The product-less branch (omitted product_status / product_tree) must stay valid.
    errors = _errors(build_csaf_advisory([_findings()[1]]))
    assert errors == [], errors


def test_vex_csaf_single_no_purl_finding_is_schema_valid():
    errors = _errors(build_csaf_vex([_findings()[1]]))
    assert errors == [], errors


def test_finding_without_purl_or_package_is_schema_valid():
    # The rare finding with neither a purl nor a package carries no product reference,
    # so product_status and product_tree are omitted and the document stays valid.
    finding = Finding(id="CVE-2024-9999", package="", version=None, purl=None)
    doc = build_csaf_advisory([finding])
    assert "product_status" not in doc["vulnerabilities"][0]
    assert "product_tree" not in doc
    assert _errors(doc) == []


def test_validator_rejects_a_known_bad_document():
    # Negative control: a non-uri remediation url must be rejected, which proves the
    # uri format check is active and the passing cases above are meaningful.
    doc = build_csaf_advisory([_findings()[0]])
    doc["vulnerabilities"][0]["remediations"][0]["url"] = "REPLACE WITH A URL"
    assert _errors(doc), "schema accepted a non-uri remediation url; format checking is not active"
