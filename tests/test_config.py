"""Tests for config loading: env vars, CLI flags, YAML files, and priority ordering."""

import os
import tempfile
import warnings
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl

import httpx
import pytest
import yaml
from click.testing import CliRunner
from pydantic import ValidationError

from cra_evidence_cli.cli import cli
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
    "CRA_EVIDENCE_TRUSTED_ORIGIN",
    "CRA_EVIDENCE_CA_BUNDLE",
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
        assert config.trusted_origin is None
        assert config.ca_bundle is None
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

    @pytest.mark.parametrize("timeout", [0, -1])
    def test_timeout_must_be_positive(self, timeout):
        with pytest.raises(ValidationError):
            CRAEvidenceConfig(timeout=timeout)


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_config_from_env_vars(self):
        """CRA_EVIDENCE_* env vars are read into the config object."""
        env_vars = {
            "CRA_EVIDENCE_API_KEY": "env_api_key",
            "CRA_EVIDENCE_URL": "https://env.api.com",
            "CRA_EVIDENCE_TRUSTED_ORIGIN": "https://env.api.com",
            "CRA_EVIDENCE_CA_BUNDLE": "/etc/ssl/certs/internal.pem",
            "CRA_EVIDENCE_ORG": "env-org",
            "CRA_EVIDENCE_TIMEOUT": "90",
        }

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("cra_evidence_cli.config.load_config_file", return_value={}):
                config = load_config()

        assert config.api_key == "env_api_key"
        assert config.url == "https://env.api.com"
        assert config.trusted_origin == "https://env.api.com"
        assert config.ca_bundle == Path("/etc/ssl/certs/internal.pem")
        assert config.default_org == "env-org"
        assert config.timeout == 90

    def test_load_config_cli_overrides_env(self):
        """Explicit api_key/url kwargs override matching env vars."""
        env_vars = {
            "CRA_EVIDENCE_API_KEY": "env_api_key",
            "CRA_EVIDENCE_URL": "https://env.api.com",
            "CRA_EVIDENCE_TRUSTED_ORIGIN": "https://env.api.com",
            "CRA_EVIDENCE_CA_BUNDLE": "/env/ca.pem",
        }

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("cra_evidence_cli.config.load_config_file", return_value={}):
                config = load_config(
                    api_key="cli_api_key",
                    url="https://cli.api.com",
                    trusted_origin="https://cli.api.com",
                    ca_bundle=Path("/cli/ca.pem"),
                )

        assert config.api_key == "cli_api_key"
        assert config.url == "https://cli.api.com"
        assert config.trusted_origin == "https://cli.api.com"
        assert config.ca_bundle == Path("/cli/ca.pem")

    def test_load_config_invalid_timeout(self):
        """Non-numeric CRA_EVIDENCE_TIMEOUT raises ConfigurationError."""
        env_vars = {"CRA_EVIDENCE_TIMEOUT": "not_a_number"}

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("cra_evidence_cli.config.load_config_file", return_value={}):
                with pytest.raises(ConfigurationError) as exc_info:
                    load_config()

        assert "Invalid CRA_EVIDENCE_TIMEOUT" in str(exc_info.value)

    def test_invalid_environment_timeout_does_not_echo_value(self):
        marker = "TIMEOUT_SECRET_MARKER"
        with patch.dict(os.environ, {"CRA_EVIDENCE_TIMEOUT": marker}, clear=False):
            with patch("cra_evidence_cli.config.load_config_file", return_value={}):
                with pytest.raises(ConfigurationError) as exc_info:
                    load_config()

        assert marker not in str(exc_info.value)
        assert "CRA_EVIDENCE_TIMEOUT" in str(exc_info.value)

    def test_invalid_model_value_does_not_echo_value(self):
        marker = "MODEL_SECRET_MARKER"
        with patch(
            "cra_evidence_cli.config.load_config_file",
            return_value={"timeout": marker},
        ):
            with pytest.raises(ConfigurationError) as exc_info:
                load_config()

        assert marker not in str(exc_info.value)
        assert "timeout" in str(exc_info.value)

    def test_nested_model_input_diagnostic_omits_value(self):
        marker = "NESTED_CREDENTIAL_MARKER"
        with patch(
            "cra_evidence_cli.config.load_config_file",
            return_value={"api_key": {"nested": marker}},
        ):
            with pytest.raises(ConfigurationError) as exc_info:
                load_config()

        assert marker not in str(exc_info.value)
        assert "api_key" in str(exc_info.value)

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

    def test_cli_default_does_not_override_config_file_url(self, tmp_path):
        config_dir = tmp_path / ".cra-evidence"
        config_dir.mkdir()
        config_path = config_dir / "config.yaml"
        config_path.write_text("url: https://selfhost.example\n", encoding="utf-8")
        config_path.chmod(0o600)

        result = CliRunner().invoke(
            cli,
            ["--verbose", "version"],
            env={"HOME": str(tmp_path)},
        )

        assert result.exit_code == 0
        assert "API URL: https://selfhost.example" in result.output

    def test_cli_help_lists_self_host_tls_options(self):
        result = CliRunner().invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "--trusted-origin" in result.output
        assert "--ca-bundle" in result.output
        assert "https://api.craevidence.com" in result.output


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

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            validate_config(config)

        assert captured == []

    def test_validate_http_url_allowed(self):
        """HTTP URLs (e.g. localhost) are accepted for local development."""
        config = CRAEvidenceConfig(
            api_key="test_key_123",
            url="http://localhost:8000",
        )

        # Should not raise
        validate_config(config)

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ],
    )
    def test_validate_http_ip_loopback_allowed(self, url):
        config = CRAEvidenceConfig(api_key="test_key_123", url=url)

        with pytest.warns(UserWarning, match="uses HTTP"):
            validate_config(config)

    @pytest.mark.parametrize(
        ("url", "message"),
        [
            ("http://selfhost.example", "must use HTTPS"),
            ("https://user@selfhost.example", "user information"),
            ("https://selfhost.example/api", "must not contain a path"),
            ("https://selfhost.example?tenant=one", "must not contain a query"),
            ("https://selfhost.example#api", "must not contain a fragment"),
        ],
    )
    def test_validate_api_url_rejects_non_origin_values(self, url, message):
        config = CRAEvidenceConfig(api_key="test_key_123", url=url)

        with pytest.raises(ConfigurationError, match=message):
            validate_config(config)

    def test_invalid_url_error_does_not_echo_embedded_credentials(self):
        config = CRAEvidenceConfig(
            api_key="test_key_123",
            url="https://operator:private-value@selfhost.example:bad",
        )

        with pytest.raises(ConfigurationError) as raised:
            validate_config(config)

        assert "operator" not in str(raised.value)
        assert "private-value" not in str(raised.value)

    @pytest.mark.parametrize(
        ("trusted_origin", "message"),
        [
            ("http://selfhost.example", "must use HTTPS"),
            ("https://user@selfhost.example", "user information"),
            ("https://selfhost.example/api", "must not contain a path"),
            ("https://selfhost.example?tenant=one", "must not contain a query"),
            ("https://selfhost.example#api", "must not contain a fragment"),
        ],
    )
    def test_validate_trusted_origin_rejects_non_origin_values(
        self, trusted_origin, message
    ):
        config = CRAEvidenceConfig(
            api_key="test_key_123",
            url="https://selfhost.example",
            trusted_origin=trusted_origin,
        )

        with pytest.raises(ConfigurationError, match=message):
            validate_config(config)

    def test_exact_normalized_trusted_origin_suppresses_custom_host_warning(self):
        config = CRAEvidenceConfig(
            api_key="test_key_123",
            url="https://SELFHOST.example:443/",
            trusted_origin="https://selfhost.example",
        )

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            validate_config(config)

        assert not any("unintended server" in str(item.message) for item in captured)

    def test_trusted_origin_mismatch_keeps_custom_host_warning(self):
        config = CRAEvidenceConfig(
            api_key="test_key_123",
            url="https://selfhost-typo.example",
            trusted_origin="https://selfhost.example",
        )

        with pytest.warns(UserWarning, match="unintended server"):
            validate_config(config)

    def test_missing_explicit_ca_bundle_is_rejected(self, tmp_path):
        config = CRAEvidenceConfig(
            api_key="test_key_123",
            ca_bundle=tmp_path / "missing.pem",
        )

        with pytest.raises(ConfigurationError, match="CA bundle is not a readable file"):
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

    def test_invalid_yaml_date_raises_safe_configuration_error(self, monkeypatch):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("date: 2024-02-30\n")
            temp_path = Path(f.name)

        try:
            monkeypatch.setattr("cra_evidence_cli.config.get_config_file_path", lambda: temp_path)
            with pytest.raises(
                ConfigurationError, match="Failed to load config file: invalid YAML"
            ):
                load_config_file()
        finally:
            temp_path.unlink()

    def test_malformed_yaml_diagnostic_omits_nearby_credential(self, monkeypatch):
        marker = "YAML_CREDENTIAL_MARKER"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(f"api_key: {marker}\ninvalid: [\n")
            temp_path = Path(f.name)

        try:
            monkeypatch.setattr("cra_evidence_cli.config.get_config_file_path", lambda: temp_path)
            with pytest.raises(ConfigurationError) as exc_info:
                load_config_file()
        finally:
            temp_path.unlink()

        message = str(exc_info.value)
        assert marker not in message
        assert "line 3" in message
        assert "column" in message

    def test_cli_malformed_yaml_diagnostic_is_safe_on_stdout(self, tmp_path):
        marker = "YAML_CREDENTIAL_MARKER"
        config_dir = tmp_path / ".cra-evidence"
        config_dir.mkdir()
        config_path = config_dir / "config.yaml"
        config_path.write_text(f"api_key: {marker}\ninvalid: [\n", encoding="utf-8")
        config_path.chmod(0o600)

        result = CliRunner().invoke(
            cli,
            ["components", "list", "--product", "sample"],
            env={"HOME": str(tmp_path)},
        )

        assert result.exit_code == 6
        assert marker not in result.stdout
        assert "line 3" in result.stdout
        assert result.stderr == ""

    def test_invalid_text_encoding_diagnostic_does_not_echo_file_bytes(self, monkeypatch):
        marker = b"ENCODING_CREDENTIAL_MARKER"
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".yaml", delete=False) as f:
            f.write(b"api_key: " + marker + b"\n\xff")
            temp_path = Path(f.name)

        try:
            monkeypatch.setattr("cra_evidence_cli.config.get_config_file_path", lambda: temp_path)
            with pytest.raises(ConfigurationError) as exc_info:
                load_config_file()
        finally:
            temp_path.unlink()

        assert marker.decode() not in str(exc_info.value)
        assert "invalid text encoding" in str(exc_info.value)


class TestOIDCBootstrap:
    """OIDC bootstrap uses a bounded, redirect-disabled request."""

    def _set_runner_env(self, monkeypatch, request_url="https://runner.example/token?run=1"):
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", request_url)
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "RUNNER_TOKEN_MARKER")

    def _use_transport(self, monkeypatch, handler):
        client_options = []
        requests = []
        original_client = httpx.Client

        def client_factory(*, timeout, follow_redirects):
            client_options.append({"timeout": timeout, "follow_redirects": follow_redirects})

            def capture(request):
                requests.append(request)
                return handler(request)

            return original_client(
                transport=httpx.MockTransport(capture),
                timeout=timeout,
                follow_redirects=follow_redirects,
            )

        monkeypatch.setattr("cra_evidence_cli.config.httpx.Client", client_factory)
        return client_options, requests

    def test_valid_runner_token_uses_https_once_and_validates_response(self, monkeypatch):
        self._set_runner_env(monkeypatch)
        monkeypatch.setenv("CRA_EVIDENCE_TIMEOUT", "37")
        expected_value = "OIDC_RESPONSE_MARKER"
        options, requests = self._use_transport(
            monkeypatch,
            lambda request: httpx.Response(200, json={"value": expected_value}),
        )

        config = load_config(oidc_mode=True)

        assert config.oidc_token == expected_value
        assert len(requests) == 1
        assert requests[0].headers["Authorization"] == "bearer RUNNER_TOKEN_MARKER"
        assert "audience=https%3A%2F%2Fgithub.com%2Fcraevidence" in str(requests[0].url)
        assert options == [{"timeout": 37, "follow_redirects": False}]

    def test_runner_url_audience_is_replaced_with_one_fixed_value(self, monkeypatch):
        self._set_runner_env(
            monkeypatch,
            "https://runner.example/token?run=1&audience=other&audience=stale",
        )
        _options, requests = self._use_transport(
            monkeypatch,
            lambda request: httpx.Response(200, json={"value": "OIDC_RESPONSE_MARKER"}),
        )

        load_config(oidc_mode=True)

        query = parse_qsl(requests[0].url.query.decode(), keep_blank_values=True)
        assert query.count(("audience", "https://github.com/craevidence")) == 1
        assert not any(
            key == "audience" and value != "https://github.com/craevidence" for key, value in query
        )
        assert ("run", "1") in query

    @pytest.mark.parametrize(
        "request_url",
        [
            "http://runner.example/token?marker=URL_SECRET_MARKER",
            "https://user:password@runner.example/token?marker=URL_SECRET_MARKER",
            "https://runner.example/token?marker=URL_SECRET_MARKER#fragment",
            "https://bad host/token?marker=URL_SECRET_MARKER",
        ],
    )
    def test_invalid_runner_url_is_rejected_before_sending_token(self, monkeypatch, request_url):
        self._set_runner_env(monkeypatch, request_url)
        options, requests = self._use_transport(
            monkeypatch,
            lambda request: httpx.Response(200, json={"value": "OIDC_TOKEN_MARKER"}),
        )

        with pytest.raises(ConfigurationError) as exc_info:
            load_config(oidc_mode=True)

        assert not options
        assert not requests
        assert "URL_SECRET_MARKER" not in str(exc_info.value)
        assert "RUNNER_TOKEN_MARKER" not in str(exc_info.value)

    def test_cli_configuration_error_does_not_echo_runner_credentials(self, monkeypatch):
        marker = "RUNNER_CREDENTIAL_MARKER"
        monkeypatch.setenv(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "http://runner.example/token?value=OIDC_URL_MARKER",
        )
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", marker)
        with patch("cra_evidence_cli.config.load_config_file", return_value={}):
            result = CliRunner().invoke(
                cli,
                ["--oidc", "components", "list", "--product", "sample"],
            )

        assert result.exit_code == 6
        assert "OIDC_URL_MARKER" not in result.output
        assert marker not in result.output
        assert "Invalid GitHub Actions OIDC request URL" in result.output

    def test_redirect_is_not_followed_and_diagnostic_is_safe(self, monkeypatch):
        self._set_runner_env(monkeypatch, "https://runner.example/token?marker=URL_SECRET_MARKER")
        options, requests = self._use_transport(
            monkeypatch,
            lambda request: httpx.Response(
                302,
                headers={"Location": "https://redirect.example/token"},
            ),
        )

        with pytest.raises(ConfigurationError) as exc_info:
            load_config(oidc_mode=True)

        assert options == [{"timeout": 60, "follow_redirects": False}]
        assert len(requests) == 1
        assert "URL_SECRET_MARKER" not in str(exc_info.value)
        assert "RUNNER_TOKEN_MARKER" not in str(exc_info.value)

    @pytest.mark.parametrize(
        "payload",
        [[], None, {"value": ""}, {"value": 12}, {}],
    )
    def test_invalid_oidc_response_shape_is_a_safe_configuration_error(self, monkeypatch, payload):
        self._set_runner_env(monkeypatch)
        self._use_transport(
            monkeypatch,
            lambda request: httpx.Response(200, json=payload),
        )

        with pytest.raises(ConfigurationError, match="OIDC response") as exc_info:
            load_config(oidc_mode=True)

        assert "RUNNER_TOKEN_MARKER" not in str(exc_info.value)

    def test_transport_error_does_not_echo_runner_url_or_token(self, monkeypatch):
        self._set_runner_env(monkeypatch, "https://runner.example/token?marker=URL_SECRET_MARKER")

        def fail(request):
            message = "URL_SECRET_MARKER RUNNER_TOKEN_MARKER"
            raise httpx.ConnectError(message, request=request)

        self._use_transport(monkeypatch, fail)
        with pytest.raises(ConfigurationError) as exc_info:
            load_config(oidc_mode=True)

        assert "URL_SECRET_MARKER" not in str(exc_info.value)
        assert "RUNNER_TOKEN_MARKER" not in str(exc_info.value)

    @pytest.mark.parametrize(
        "body",
        [b"not-json-RUNNER_TOKEN_MARKER", b"\xff-RUNNER_TOKEN_MARKER"],
    )
    def test_invalid_json_response_has_safe_diagnostic(self, monkeypatch, body):
        self._set_runner_env(monkeypatch)
        self._use_transport(
            monkeypatch,
            lambda request: httpx.Response(200, content=body),
        )

        with pytest.raises(ConfigurationError) as exc_info:
            load_config(oidc_mode=True)

        assert "valid JSON" in str(exc_info.value)
        assert "RUNNER_TOKEN_MARKER" not in str(exc_info.value)

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
