"""
Pytest configuration and fixtures for CLI tests.
"""

import pytest

from cra_evidence_cli.config import CRAEvidenceConfig


@pytest.fixture
def test_config() -> CRAEvidenceConfig:
    return CRAEvidenceConfig(
        api_key="test_key_12345",
        url="https://api.test.craevidence.com",
        output_format="json",
    )


@pytest.fixture
def mock_api_response() -> dict:
    return {
        "artifact_id": "abc123-def456",
        "artifact_type": "sbom",
        "product": {
            "id": "prod-123",
            "name": "Test Product",
            "slug": "test-product",
            "created": False,
        },
        "version": {
            "id": "ver-456",
            "number": "1.2.3",
            "created": True,
            "cra_status": "incomplete",
            "release_state": "draft",
        },
        "quality_score": 85,
        "component_count": 142,
        "scan_results": {
            "status": "completed",
            "vulnerabilities": {
                "critical": 0,
                "high": 2,
                "medium": 5,
                "low": 12,
            },
        },
    }
