"""
Configuration handling for CRA Evidence CLI.

Supports configuration from:
1. Command-line flags (highest priority)
2. Environment variables
3. Config file (~/.cra-evidence/config.yaml)
"""

import os
import ssl
import warnings
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
    trusted_origin: str | None = Field(
        default=None,
        description="Exact trusted CRA Evidence API origin",
    )
    ca_bundle: Path | None = Field(
        default=None,
        description="PEM CA bundle for CRA Evidence API TLS verification",
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
    trusted_origin: str | None = None,
    ca_bundle: Path | None = None,
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
        trusted_origin: Exact trusted API origin from command-line flag
        ca_bundle: PEM CA bundle from command-line flag
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
    if env_trusted_origin := os.getenv("CRA_EVIDENCE_TRUSTED_ORIGIN"):
        config_data["trusted_origin"] = env_trusted_origin
    if env_ca_bundle := os.getenv("CRA_EVIDENCE_CA_BUNDLE"):
        config_data["ca_bundle"] = env_ca_bundle
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
    if trusted_origin is not None:
        config_data["trusted_origin"] = trusted_origin
    if ca_bundle is not None:
        config_data["ca_bundle"] = ca_bundle
    if output_format is not None:
        config_data["output_format"] = output_format

    try:
        return CRAEvidenceConfig(**config_data)
    except Exception as e:
        msg = f"Invalid configuration: {e}"
        raise ConfigurationError(msg) from e


def _normalize_origin(value: str, *, setting_name: str) -> str:
    """Validate and normalize an HTTP(S) origin."""
    if not value or value != value.strip() or any(character.isspace() for character in value):
        msg = f"{setting_name} must be an exact HTTP(S) origin"
        raise ConfigurationError(msg)

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        msg = f"Invalid {setting_name}"
        raise ConfigurationError(msg) from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.netloc or parsed.hostname is None:
        msg = f"Invalid {setting_name}"
        raise ConfigurationError(msg)
    if parsed.username is not None or parsed.password is not None:
        msg = f"{setting_name} must not contain user information"
        raise ConfigurationError(msg)
    try:
        port = parsed.port
    except ValueError as exc:
        msg = f"Invalid {setting_name}"
        raise ConfigurationError(msg) from exc
    if parsed.path not in {"", "/"}:
        msg = f"{setting_name} must not contain a path"
        raise ConfigurationError(msg)
    if parsed.query:
        msg = f"{setting_name} must not contain a query"
        raise ConfigurationError(msg)
    if parsed.fragment:
        msg = f"{setting_name} must not contain a fragment"
        raise ConfigurationError(msg)
    if "\\" in parsed.netloc:
        msg = f"Invalid {setting_name}"
        raise ConfigurationError(msg)

    hostname = parsed.hostname.rstrip(".").lower()
    if not hostname:
        msg = f"Invalid {setting_name}"
        raise ConfigurationError(msg)

    try:
        parsed_address = ip_address(hostname)
    except ValueError:
        try:
            normalized_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            msg = f"Invalid {setting_name}"
            raise ConfigurationError(msg) from exc
        is_loopback = normalized_hostname == "localhost"
    else:
        normalized_hostname = parsed_address.compressed
        is_loopback = parsed_address.is_loopback

    if scheme == "http" and not is_loopback:
        msg = f"{setting_name} must use HTTPS unless it is a loopback origin"
        raise ConfigurationError(msg)

    default_port = 443 if scheme == "https" else 80
    authority_host = (
        f"[{normalized_hostname}]" if ":" in normalized_hostname else normalized_hostname
    )
    authority = authority_host if port in {None, default_port} else f"{authority_host}:{port}"
    return f"{scheme}://{authority}"


def _build_tls_context(ca_bundle: Path | None) -> ssl.SSLContext | None:
    """Build the explicit API trust context when a CA bundle is configured."""
    if ca_bundle is None:
        return None

    if not ca_bundle.is_file():
        msg = f"CA bundle is not a readable file: {ca_bundle}"
        raise ConfigurationError(msg)
    try:
        return ssl.create_default_context(cafile=str(ca_bundle))
    except (OSError, ssl.SSLError) as exc:
        msg = f"Failed to load CA bundle {ca_bundle}: {exc}"
        raise ConfigurationError(msg) from exc


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

    api_origin = _normalize_origin(config.url, setting_name="API URL")
    trusted_origin = None
    if config.trusted_origin is not None:
        trusted_origin = _normalize_origin(
            config.trusted_origin,
            setting_name="trusted origin",
        )
    _build_tls_context(config.ca_bundle)

    if not os.environ.get("CRA_NO_WARN"):
        if api_origin.startswith("http://"):
            warnings.warn(
                f"API URL '{api_origin}' uses HTTP instead of HTTPS. "
                "Credentials and data will be transmitted in plaintext.",
                stacklevel=2,
            )

        hostname = urlsplit(api_origin).hostname or ""
        is_craevidence_origin = (
            api_origin.startswith("https://")
            and (hostname == "craevidence.com" or hostname.endswith(_TRUSTED_URL_SUFFIX))
        )
        if not is_craevidence_origin and trusted_origin != api_origin:
            warnings.warn(
                f"API URL '{api_origin}' is not the configured trusted origin. "
                "Ensure this is intentional; a misconfigured URL can exfiltrate API keys "
                "to an unintended server.",
                stacklevel=2,
            )
