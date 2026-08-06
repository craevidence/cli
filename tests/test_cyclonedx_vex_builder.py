"""Tests for the CycloneDX VEX skeleton builder."""

from __future__ import annotations

from cra_evidence_cli.local.cyclonedx_vex import build_cyclonedx_vex
from cra_evidence_cli.local.models import Finding


def _finding(vuln_id: str, package: str, version: str, **kwargs) -> Finding:
    return Finding(
        id=vuln_id,
        package=package,
        version=version,
        purl=kwargs.pop("purl", f"pkg:pypi/{package}@{version}"),
        **kwargs,
    )


class TestDocumentShape:
    def test_emits_a_cyclonedx_document(self):
        doc = build_cyclonedx_vex([_finding("CVE-2024-0001", "requests", "2.0.0")])

        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"
        assert doc["serialNumber"].startswith("urn:uuid:")
        assert doc["version"] == 1

    def test_carries_metadata_with_timestamp_and_tool(self):
        """A document with no metadata records neither when nor by what it was made."""
        doc = build_cyclonedx_vex([_finding("CVE-2024-0001", "requests", "2.0.0")])

        assert doc["metadata"]["timestamp"]
        tools = doc["metadata"]["tools"]["components"]
        assert any(t.get("name") for t in tools)

    def test_no_findings_yields_an_empty_but_valid_document(self):
        doc = build_cyclonedx_vex([])

        assert doc["bomFormat"] == "CycloneDX"
        assert doc["vulnerabilities"] == []
        assert doc["components"] == []


class TestAffectsResolve:
    def test_every_affects_ref_resolves_to_a_component_bom_ref(self):
        """A ref that names nothing in the document cannot be resolved by a reader."""
        findings = [
            _finding("CVE-2024-0001", "requests", "2.0.0"),
            _finding("CVE-2024-0002", "urllib3", "1.0.0"),
        ]
        doc = build_cyclonedx_vex(findings)

        bom_refs = {c["bom-ref"] for c in doc["components"]}
        for vuln in doc["vulnerabilities"]:
            for affected in vuln["affects"]:
                assert affected["ref"] in bom_refs, affected["ref"]

    def test_component_carries_its_package_url(self):
        doc = build_cyclonedx_vex([_finding("CVE-2024-0001", "requests", "2.0.0")])

        component = doc["components"][0]
        assert component["purl"] == "pkg:pypi/requests@2.0.0"
        assert component["bom-ref"] == component["purl"]


class TestCollapsing:
    def test_repeated_reports_of_one_vulnerability_collapse(self):
        """The same package reported 5 times must not produce 5 statements."""
        findings = [_finding("CVE-2024-0001", "requests", "2.0.0") for _ in range(5)]
        doc = build_cyclonedx_vex(findings)

        assert len(doc["vulnerabilities"]) == 1
        assert len(doc["vulnerabilities"][0]["affects"]) == 1
        assert len(doc["components"]) == 1

    def test_one_vulnerability_across_two_packages_lists_both(self):
        findings = [
            _finding("CVE-2024-0001", "requests", "2.0.0"),
            _finding("CVE-2024-0001", "requests", "1.0.0"),
        ]
        doc = build_cyclonedx_vex(findings)

        assert len(doc["vulnerabilities"]) == 1
        refs = {a["ref"] for a in doc["vulnerabilities"][0]["affects"]}
        assert refs == {"pkg:pypi/requests@2.0.0", "pkg:pypi/requests@1.0.0"}

    def test_two_vulnerabilities_stay_separate(self):
        findings = [
            _finding("CVE-2024-0001", "requests", "2.0.0"),
            _finding("CVE-2024-0002", "requests", "2.0.0"),
        ]
        doc = build_cyclonedx_vex(findings)

        assert len(doc["vulnerabilities"]) == 2
        assert len(doc["components"]) == 1, "one package, one component"


class TestHonestStartingPosition:
    def test_every_statement_starts_as_in_triage(self):
        """Nothing has been evaluated yet, so nothing may claim a verdict."""
        findings = [
            _finding("CVE-2024-0001", "requests", "2.0.0"),
            _finding("CVE-2024-0002", "urllib3", "1.0.0"),
        ]
        doc = build_cyclonedx_vex(findings)

        states = {v["analysis"]["state"] for v in doc["vulnerabilities"]}
        assert states == {"in_triage"}

    def test_no_statement_claims_not_affected(self):
        doc = build_cyclonedx_vex([_finding("CVE-2024-0001", "requests", "2.0.0")])

        for vuln in doc["vulnerabilities"]:
            assert vuln["analysis"]["state"] != "not_affected"
            assert "justification" not in vuln["analysis"]

    def test_carries_the_review_disclaimer(self):
        doc = build_cyclonedx_vex([_finding("CVE-2024-0001", "requests", "2.0.0")])

        assert "review" in doc["vulnerabilities"][0]["analysis"]["detail"].lower()


class TestFindingDetail:
    def test_severity_is_carried_when_known(self):
        doc = build_cyclonedx_vex(
            [_finding("CVE-2024-0001", "requests", "2.0.0", severity="high")]
        )

        assert doc["vulnerabilities"][0]["ratings"][0]["severity"] == "high"

    def test_unknown_severity_is_omitted_rather_than_asserted(self):
        doc = build_cyclonedx_vex(
            [_finding("CVE-2024-0001", "requests", "2.0.0", severity="unknown")]
        )

        assert "ratings" not in doc["vulnerabilities"][0]

    def test_fix_versions_become_a_recommendation(self):
        doc = build_cyclonedx_vex(
            [
                _finding(
                    "CVE-2024-0001", "requests", "2.0.0", fixed_versions=["2.1.0", "3.0.0"]
                )
            ]
        )

        assert "2.1.0" in doc["vulnerabilities"][0]["recommendation"]
