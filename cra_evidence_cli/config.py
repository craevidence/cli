"""
Configuration handling for CRA Evidence CLI.

Supports configuration from:
1. Command-line flags (highest priority)
2. Environment variables
3. Config file (~/.cra-evidence/config.yaml)
"""

import os
import warnings
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from cra_evidence_cli.exceptions import ConfigurationError

_TRUSTED_URL_SUFFIX = ".craevidence.com"

# Per-repository identity env vars (consumed by repo_config.resolve_identity).
# These override .cra/evidence.yaml but lose to explicit CLI flags.
ENV_PRODUCT = "CRA_EVIDENCE_PRODUCT"
ENV_VERSION = "CRA_EVIDENCE_VERSION"
ENV_COMPONENT = "CRA_EVIDENCE_COMPONENT"


class CRAEvidenceConfig(BaseModel):
    """Configuration for CRA Evidence CLI."""

    api_key: str | None = Field(default=None, description="API key for authentication")
    url: str = Field(
        default="https://api.craevidence.com",
        description="CRA Evidence API URL",
    )
    default_org: str | None = Field(default=None, description="Default organization slug")
    output_format: str = Field(
        default="text",
        description="Default output format (text|json|sarif|markdown)",
    )
    timeout: int = Field(default=60, description="HTTP request timeout in seconds")
    oidc_mode: bool = Field(default=False, description="Use OIDC authentication (GitHub Actions)")
    oidc_token: str | None = Field(default=None, description="GitHub Actions OIDC token")


def get_config_file_path() -> Path:
    config_dir = Path.home() / ".cra-evidence"
    return config_dir / "config.yaml"


def load_config_file() -> dict[str, Any]:
    config_path = get_config_file_path()
    if not config_path.exists():
        return {}

    mode = config_path.stat().st_mode & 0o777
    if mode & 0o077:
        warnings.warn(
            f"Config file {config_path} has permissions {oct(mode)} which allow group or "
            "other users to read it. Consider restricting to 0o600 (chmod 600).",
            stacklevel=2,
        )

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return {}
            if "verify_ssl" in data:
                warnings.warn(
                    "The 'verify_ssl' config key is deprecated and has no effect. "
                    "Remove it from ~/.cra-evidence/config.yaml.",
                    DeprecationWarning,
                    stacklevel=2,
                )
                data.pop("verify_ssl")
            return data
    except Exception as e:
        msg = f"Failed to load config file: {e}"
        raise ConfigurationError(msg) from e


def load_config(
    api_key: str | None = None,
    url: str | None = None,
    output_format: str | None = None,
    oidc_mode: bool = False,
) -> CRAEvidenceConfig:
    """
    Load configuration from multiple sources.

    Priority (highest to lowest):
    1. Command-line arguments
    2. Environment variables
    3. Config file
    4. Defaults

    Args:
        api_key: API key from command-line flag
        url: API URL from command-line flag
        output_format: Output format from command-line flag

    Returns:
        CRAEvidenceConfig: Merged configuration

    Raises:
        ConfigurationError: If configuration is invalid
    """
    config_data = load_config_file()

    if env_key := os.getenv("CRA_EVIDENCE_API_KEY"):
        config_data["api_key"] = env_key
    if env_url := os.getenv("CRA_EVIDENCE_URL"):
        config_data["url"] = env_url
    if env_org := os.getenv("CRA_EVIDENCE_ORG"):
        config_data["default_org"] = env_org
    if env_timeout := os.getenv("CRA_EVIDENCE_TIMEOUT"):
        try:
            config_data["timeout"] = int(env_timeout)
        except ValueError:
            msg = f"Invalid timeout value: {env_timeout}"
            raise ConfigurationError(msg) from None

    if oidc_mode:
        config_data["oidc_mode"] = True
        if token_url := os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL"):
            if token_request := os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
                try:
                    import urllib.parse
                    import urllib.request

                    req = urllib.request.Request(  # noqa: S310
                        token_url + "&audience=https://github.com/craevidence",
                        headers={"Authorization": f"bearer {token_request}"}
                    )
                    with urllib.request.urlopen(req) as response:  # noqa: S310
                        import json
                        token_data = json.load(response)
                        config_data["oidc_token"] = token_data["value"]
                except Exception as e:
                    msg = (
                        f"Failed to get GitHub Actions OIDC token: {e}. "
                        f"Ensure this is running in a GitHub Actions workflow with "
                        f"id-token: write permission."
                    )
                    raise ConfigurationError(
                        msg
                    ) from e
            else:
                msg = (
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not found. "
                    "Ensure this is running in a GitHub Actions workflow with "
                    "id-token: write permission."
                )
                raise ConfigurationError(
                    msg
                )
        else:
            msg = (
                "ACTIONS_ID_TOKEN_REQUEST_URL environment variable not found. "
                "OIDC mode only works in GitHub Actions workflows with id-token: write permission."
            )
            raise ConfigurationError(
                msg
            )

    if api_key is not None:
        config_data["api_key"] = api_key
    if url is not None:
        config_data["url"] = url
    if output_format is not None:
        config_data["output_format"] = output_format

    try:
        return CRAEvidenceConfig(**config_data)
    except Exception as e:
        msg = f"Invalid configuration: {e}"
        raise ConfigurationError(msg) from e


def _extract_hostname(url: str) -> str:
    """Extract the hostname from a URL string (no stdlib urllib dependency)."""
    # Strip scheme
    after_scheme = url.split("://", 1)[-1]
    # Strip path, query, fragment
    hostname = after_scheme.split("/")[0].split("?")[0].split("#")[0]
    # Strip port
    hostname = hostname.split(":")[0]
    return hostname.lower()


def validate_config(config: CRAEvidenceConfig) -> None:
    """
    Validate that required configuration is present.

    Args:
        config: Configuration to validate

    Raises:
        ConfigurationError: If required configuration is missing
    """
    if config.oidc_mode:
        if not config.oidc_token:
            msg = (
                "OIDC token is required in OIDC mode. "
                "Ensure this is running in a GitHub Actions workflow with "
                "id-token: write permission."
            )
            raise ConfigurationError(
                msg
            )
    else:
        if not config.api_key:
            msg = (
                "API key is required. Set CRA_EVIDENCE_API_KEY environment variable, "
                "use --api-key flag, or add 'api_key' to ~/.cra-evidence/config.yaml"
            )
            raise ConfigurationError(
                msg
            )

    if not config.url:
        msg = "API URL is required"
        raise ConfigurationError(msg)

    # Validate URL format
    if not config.url.startswith(("http://", "https://")):
        msg = f"Invalid API URL: {config.url}"
        raise ConfigurationError(msg)

    if not os.environ.get("CRA_NO_WARN"):
        if config.url.startswith("http://"):
            warnings.warn(
                f"API URL '{config.url}' uses HTTP instead of HTTPS. "
                "Credentials and data will be transmitted in plaintext.",
                stacklevel=2,
            )

        # Warn when URL does not point to a known craevidence.com host (URL redirect exfiltration)
        hostname = _extract_hostname(config.url)
        if hostname != "craevidence.com" and not hostname.endswith(_TRUSTED_URL_SUFFIX):
            warnings.warn(
                f"API URL '{config.url}' does not point to a *.craevidence.com host. "
                "Ensure this is intentional; a misconfigured URL can exfiltrate API keys "
                "to an unintended server.",
                stacklevel=2,
            )
