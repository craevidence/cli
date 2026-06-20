"""Regression test for CLI/platform document-type drift.

Snapshots the document-type values the CLI accepts. If the set changes,
this test fails loudly until someone updates both this snapshot AND
`cra_evidence_cli/commands/upload.py:VALID_DOCUMENT_TYPES`.

"""

from cra_evidence_cli.commands.upload import VALID_DOCUMENT_TYPES

# Snapshot of the document-type values the CLI accepts.
# When the accepted set changes, update both this snapshot and the
# CLI's VALID_DOCUMENT_TYPES list so they stay in lockstep.
API_DOCUMENT_TYPES_SNAPSHOT = [
    "architecture_diagram",
    "conformity_certificate",
    "coordinated_disclosure_policy",
    "eu_declaration_of_conformity",
    "harmonised_standards",
    "other",
    "penetration_test_report",
    "risk_assessment",
    "secure_development_policy",
    "security_advisory",
    "supplier_due_diligence",
    "support_period_justification",
    "technical_documentation",
    "test_report",
    "third_party_audit",
    "threat_model",
    "uii",
    "update_mechanism_documentation",
    "user_manual",
    "vulnerability_policy",
]


def test_cli_document_types_match_api_snapshot():
    """CLI's VALID_DOCUMENT_TYPES must equal the API document type set."""
    assert sorted(VALID_DOCUMENT_TYPES) == API_DOCUMENT_TYPES_SNAPSHOT, (
        "CLI document-type drift detected.\n"
        f"  CLI has:      {sorted(VALID_DOCUMENT_TYPES)}\n"
        f"  Snapshot has: {API_DOCUMENT_TYPES_SNAPSHOT}\n"
        "Update cra_evidence_cli/commands/upload.py:VALID_DOCUMENT_TYPES "
        "and this snapshot together."
    )


def test_cli_document_types_count_is_20():
    """Pin the count so accidental additions/deletions are caught."""
    assert len(VALID_DOCUMENT_TYPES) == 20
