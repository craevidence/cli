"""Tests for API key masking format and X-CLI-Version header."""


from cra_evidence_cli.client import CRAEvidenceClient, mask_api_key
from cra_evidence_cli.config import CRAEvidenceConfig


class TestMaskApiKey:
    """Tests for API key masking."""

    def test_normal_key(self):
        """Keys longer than 8 chars are masked to first4****last4."""
        assert mask_api_key("cra_abcdef123456") == "cra_****3456"

    def test_short_key(self):
        """Keys of 8 chars or fewer are fully replaced with '****'."""
        assert mask_api_key("short") == "****"
        assert mask_api_key("12345678") == "****"

    def test_empty_key(self):
        """Empty string returns '****'."""
        assert mask_api_key("") == "****"

    def test_nine_char_key(self):
        """9-char key is partially masked (first 4 and last 4 preserved)."""
        result = mask_api_key("123456789")
        assert result == "1234****6789"

    def test_cra_prefix_preserved(self):
        """'cra_' prefix remains visible and '****' follows immediately."""
        result = mask_api_key("cra_key_abc123def456")
        assert result.startswith("cra_")
        assert "****" in result


class TestClientInit:
    """Tests for client initialization."""

    def test_headers_include_cli_version(self):
        """X-CLI-Version header is present and non-empty."""
        config = CRAEvidenceConfig(
            api_key="test_key_12345",
            url="https://api.test.craevidence.com",
        )
        client = CRAEvidenceClient(config)
        headers = client._get_headers()
        assert "X-CLI-Version" in headers
        assert headers["X-CLI-Version"]  # Not empty
