"""Tests for config loading: env vars, CLI flags, YAML files, and priority ordering."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from cra_evidence_cli.config import (
    CRAEvidenceConfig,
    get_config_file_path,
    load_config,
    load_config_file,
    validate_config,
)
from cra_evidence_cli.exceptions import ConfigurationError

_CRA_ENV_KEYS = [
    "CRA_EVIDENCE_API_KEY",
    "CRA_EVIDENCE_URL",
    "CRA_EVIDENCE_ORG",
    "CRA_EVIDENCE_TIMEOUT",
    "CRA_EVIDENCE_PRODUCT",
    "CRA_EVIDENCE_VERSION",
    "CRA_EVIDENCE_COMPONENT",
]


@pytest.fixture(autouse=True)
def _clear_cra_env(monkeypatch):
    """Remove ambient CRA_EVIDENCE_* env vars so each test starts from a clean slate."""
    for key in _CRA_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


class TestCRAEvidenceConfig:
    """Tests for CRAEvidenceConfig Pydantic model."""

    def test_default_values(self):
        """Defaults: api_key=None, url=craevidence.com, output_format=text, timeout=60."""
        config = CRAEvidenceConfig()

        assert config.api_key is None
        assert config.url == "https://api.craevidence.com"
        assert config.default_org is None
        assert config.output_format == "text"
        assert config.timeout == 60

    def test_custom_values(self):
        """All fields accept explicit values that override defaults."""
        config = CRAEvidenceConfig(
            api_key="test_key_123",
            url="https://custom.api.com",
            default_org="my-org",
            output_format="json",
            timeout=120,
        )

        assert config.api_key == "test_key_123"
        assert config.url == "https://custom.api.com"
        assert config.default_org == "my-org"
        assert config.output_format == "json"
        assert config.timeout == 120


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_config_from_env_vars(self):
        """CRA_EVIDENCE_* env vars are read into the config object."""
        env_vars = {
            "CRA_EVIDENCE_API_KEY": "env_api_key",
            "CRA_EVIDENCE_URL": "https://env.api.com",
            "CRA_EVIDENCE_ORG": "env-org",
            "CRA_EVIDENCE_TIMEOUT": "90",
        }

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("cra_evidence_cli.config.load_config_file", return_value={}):
                config = load_config()

        assert config.api_key == "env_api_key"
        assert config.url == "https://env.api.com"
        assert config.default_org == "env-org"
        assert config.timeout == 90

    def test_load_config_cli_overrides_env(self):
        """Explicit api_key/url kwargs override matching env vars."""
        env_vars = {
            "CRA_EVIDENCE_API_KEY": "env_api_key",
            "CRA_EVIDENCE_URL": "https://env.api.com",
        }

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("cra_evidence_cli.config.load_config_file", return_value={}):
                config = load_config(
                    api_key="cli_api_key",
                    url="https://cli.api.com",
                )

        assert config.api_key == "cli_api_key"
        assert config.url == "https://cli.api.com"

    def test_load_config_invalid_timeout(self):
        """Non-numeric CRA_EVIDENCE_TIMEOUT raises ConfigurationError."""
        env_vars = {"CRA_EVIDENCE_TIMEOUT": "not_a_number"}

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("cra_evidence_cli.config.load_config_file", return_value={}):
                with pytest.raises(ConfigurationError) as exc_info:
                    load_config()

        assert "Invalid timeout" in str(exc_info.value)

    def test_load_config_file_priority(self):
        """Env vars override file config; file config is used for keys absent from env."""
        file_config = {
            "api_key": "file_api_key",
            "url": "https://file.api.com",
        }
        env_vars = {"CRA_EVIDENCE_API_KEY": "env_api_key"}

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("cra_evidence_cli.config.load_config_file", return_value=file_config):
                config = load_config()

        # Env should override file
        assert config.api_key == "env_api_key"
        # File should be used for URL (not in env)
        assert config.url == "https://file.api.com"


class TestValidateConfig:
    """Tests for validate_config function."""

    def test_validate_missing_api_key(self):
        """validate_config raises ConfigurationError when api_key is None."""
        config = CRAEvidenceConfig(api_key=None)

        with pytest.raises(ConfigurationError) as exc_info:
            validate_config(config)

        assert "API key is required" in str(exc_info.value)

    def test_validate_invalid_url(self):
        """validate_config raises ConfigurationError for a non-URL string."""
        config = CRAEvidenceConfig(api_key="test_key", url="not-a-valid-url")

        with pytest.raises(ConfigurationError) as exc_info:
            validate_config(config)

        assert "Invalid API URL" in str(exc_info.value)

    def test_validate_valid_config(self):
        """validate_config does not raise for a complete, well-formed config."""
        config = CRAEvidenceConfig(
            api_key="test_key_123",
            url="https://api.craevidence.com",
        )

        # Should not raise
        validate_config(config)

    def test_validate_http_url_allowed(self):
        """HTTP URLs (e.g. localhost) are accepted for local development."""
        config = CRAEvidenceConfig(
            api_key="test_key_123",
            url="http://localhost:8000",
        )

        # Should not raise
        validate_config(config)


class TestConfigFilePath:
    """Tests for config file path handling."""

    def test_config_file_path(self):
        """Config file resolves to ~/.cra-evidence/config.yaml."""
        path = get_config_file_path()

        assert path == Path.home() / ".cra-evidence" / "config.yaml"


class TestLoadConfigFile:
    """Tests for loading config from file."""

    def test_load_nonexistent_file(self):
        """Returns empty dict when the config file does not exist."""
        with patch("cra_evidence_cli.config.get_config_file_path") as mock_path:
            mock_path.return_value = Path("/nonexistent/path/config.yaml")
            result = load_config_file()

        assert result == {}

    def test_load_valid_yaml_file(self):
        """Reads api_key, url, and timeout from a valid YAML file."""
        config_data = {
            "api_key": "file_key",
            "url": "https://file.api.com",
            "timeout": 45,
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            with patch("cra_evidence_cli.config.get_config_file_path", return_value=temp_path):
                result = load_config_file()

            assert result["api_key"] == "file_key"
            assert result["url"] == "https://file.api.com"
            assert result["timeout"] == 45
        finally:
            temp_path.unlink()

    def test_load_invalid_yaml_file(self):
        """Malformed YAML raises ConfigurationError with a descriptive message."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [")
            temp_path = Path(f.name)

        try:
            with patch("cra_evidence_cli.config.get_config_file_path", return_value=temp_path):
                with pytest.raises(ConfigurationError) as exc_info:
                    load_config_file()

            assert "Failed to load config file" in str(exc_info.value)
        finally:
            temp_path.unlink()

    def test_load_empty_yaml_file(self):
        """Empty YAML file returns {} without raising."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            temp_path = Path(f.name)

        try:
            with patch("cra_evidence_cli.config.get_config_file_path", return_value=temp_path):
                result = load_config_file()

            assert result == {}
        finally:
            temp_path.unlink()
