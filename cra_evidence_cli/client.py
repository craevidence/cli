"""
HTTP client for CRA Evidence API.
"""

import asyncio
import re
from pathlib import Path
from typing import Any

import httpx

from cra_evidence_cli import __version__
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.exceptions import APIError, AuthenticationError, ValidationError

# Regex for stripping HTML tags from error responses
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_PRIVATE_KEY_PEM_RE = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----",
    re.IGNORECASE,
)


def mask_api_key(key: str) -> str:
    """
    Return a masked version of an API key showing first 4 and last 4 chars.

    Example: 'cra_EXAMPLEonly_not_a_real_key_000000000_KEY'
             -> 'cra_****_KEY'

    Args:
        key: The full API key string

    Returns:
        Masked API key string
    """
    if not key or len(key) <= 8:
        return "****"
    return f"{key[:4]}****{key[-4:]}"


class CRAEvidenceClient:
    """HTTP client for CRA Evidence API."""

    def __init__(self, config: CRAEvidenceConfig) -> None:
        self.config = config
        self.base_url = config.url.rstrip("/")
        self.timeout = httpx.Timeout(config.timeout)
        self._access_token: str | None = None

    async def _ensure_access_token(self) -> None:
        """Ensure we have a valid access token for OIDC mode."""
        if not self.config.oidc_mode:
            return

        if self._access_token:
            return

        # Exchange OIDC token for CRA Evidence access token
        oidc_url = f"{self.base_url}/api/v1/oidc/token"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    oidc_url,
                    json={"github_token": self.config.oidc_token},
                    headers={
                        "User-Agent": f"craevidence-cli/{__version__}",
                        "X-CLI-Version": __version__,
                    }
                )
            except httpx.RequestError as exc:
                raise APIError(
                    message=f"Network error contacting {oidc_url}: {exc}",
                ) from exc

            if response.status_code != 200:
                error_detail = "OIDC token exchange failed"
                try:
                    error_data = response.json()
                    nested = error_data.get("error", {})
                    error_detail = (
                        nested.get("detail")
                        or nested.get("message")
                        or error_data.get("detail")
                        or error_detail
                    )
                except Exception:  # noqa: S110
                    pass

                if response.status_code == 401:
                    msg = f"GitHub OIDC token rejected: {error_detail}"
                    raise AuthenticationError(msg)
                elif response.status_code == 403:
                    msg = f"OIDC not authorized: {error_detail}"
                    raise AuthenticationError(msg)
                else:
                    msg = f"OIDC token exchange failed: {error_detail}"
                    raise APIError(msg)

            try:
                token_data = response.json()
                self._access_token = token_data["access_token"]
            except Exception as e:
                msg = f"Invalid OIDC token response: {e}"
                raise APIError(msg) from e

    def _get_headers(self) -> dict[str, str]:
        if self.config.oidc_mode:
            if not self._access_token:
                msg = (
                    "No access token available. Ensure OIDC authentication "
                    "completed before making requests."
                )
                raise AuthenticationError(msg)
            auth_header = f"Bearer {self._access_token}"
        else:
            auth_header = f"Bearer {self.config.api_key}"

        return {
            "Authorization": auth_header,
            "User-Agent": f"craevidence-cli/{__version__}",
            "X-CLI-Version": __version__,
        }

    def _handle_response(self, response: httpx.Response) -> Any:
        """
        Handle HTTP response and raise appropriate exceptions.

        Args:
            response: HTTP response

        Returns:
            Response JSON data

        Raises:
            AuthenticationError: If authentication fails (401/403)
            APIError: If API returns an error
        """
        request_id = response.headers.get("X-Request-ID")

        if response.status_code in (401, 403):
            if self.config.oidc_mode:
                error_detail = "OIDC token authentication failed"
            elif response.status_code == 403:
                error_detail = (
                    "Request forbidden. The API key was accepted, but it does not "
                    "have access to this operation, organization, product, or team "
                    f"(key: {mask_api_key(self.config.api_key)})"
                )
            else:
                error_detail = (
                    f"Invalid or expired API key (key: {mask_api_key(self.config.api_key)})"
                )

            try:
                error_data = response.json()
                nested = error_data.get("error", {})
                raw_detail = (
                    nested.get("detail")
                    or nested.get("message")
                    or error_data.get("detail")
                )
                if raw_detail:
                    if self.config.oidc_mode:
                        error_detail = f"{raw_detail}"
                    else:
                        error_detail = f"{raw_detail} (key: {mask_api_key(self.config.api_key)})"
            except Exception:  # noqa: S110
                pass
            raise AuthenticationError(error_detail)

        if response.status_code >= 400:
            error_message = f"API error: {response.status_code}"
            error_code: str | None = None
            error_details: dict[str, Any] | None = None
            try:
                error_data = response.json()
                nested = error_data.get("error", {})
                error_message = (
                    nested.get("detail")
                    or nested.get("message")
                    or error_data.get("detail")
                    or error_message
                )
                # Preserved as-is so callers can discriminate error shapes
                # that share a status code (e.g. which resource a 404 was
                # about) without re-parsing the message text.
                error_code = nested.get("code")
                error_details = nested.get("details")
            except Exception:
                raw_text = response.text or error_message
                stripped = _HTML_TAG_RE.sub("", raw_text).strip()
                error_message = stripped[:500] if len(stripped) > 500 else stripped

            retry_after: float | None = None
            if response.status_code == 429:
                retry_after_header = response.headers.get("Retry-After")
                if retry_after_header:
                    try:
                        retry_after = float(retry_after_header)
                    except ValueError:
                        # Malformed Retry-After header; leave retry_after unset.
                        pass

            raise APIError(
                message=error_message,
                status_code=response.status_code,
                request_id=request_id,
                retry_after=retry_after,
                error_code=error_code,
                error_details=error_details,
            )

        try:
            return response.json()
        except Exception:
            # If response is not JSON, return empty dict
            return {}

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """
        Execute an HTTP request with retry logic for GET requests.

        Retries up to 3 times on 429 or 5xx responses with exponential
        backoff (1s, 2s, 4s). Honours the Retry-After header when present,
        capped at 60 seconds per attempt.

        Authentication headers are built here, after the OIDC access token
        exchange has completed, so callers must not pass their own headers.

        Args:
            method: HTTP method (intended for GET requests)
            url: Full URL to request
            **kwargs: Additional arguments forwarded to httpx.AsyncClient.request

        Returns:
            httpx.Response on success (2xx/4xx that are not retryable)

        Raises:
            The last httpx.Response-based error after all retries are exhausted
        """
        await self._ensure_access_token()

        headers = kwargs.pop("headers", None)
        if headers is None:
            headers = self._get_headers()

        max_retries = 3
        backoff_seconds = [1, 2, 4]

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            last_response: httpx.Response | None = None
            for attempt in range(max_retries + 1):
                try:
                    response = await client.request(method, url, headers=headers, **kwargs)
                except httpx.RequestError as exc:
                    raise APIError(
                        message=f"Network error contacting {url}: {exc}",
                    ) from exc
                last_response = response

                if response.status_code == 429 or response.status_code >= 500:
                    if attempt < max_retries:
                        retry_after_header = response.headers.get("Retry-After")
                        if retry_after_header:
                            try:
                                wait = min(float(retry_after_header), 60.0)
                            except ValueError:
                                wait = float(backoff_seconds[attempt])
                        else:
                            wait = float(backoff_seconds[attempt])
                        await asyncio.sleep(wait)
                        continue

                return response

            return last_response  # type: ignore[return-value]

    async def upload_sbom(
        self,
        product: str,
        version: str,
        file_path: Path,
        format_type: str | None = None,
        create_product: bool = False,
        create_version: bool = False,
        scan: bool = False,
        no_inherit: bool = False,
        supersedes: str | None = None,
        # CRA classification
        category: str | None = None,
        subcategory: str | None = None,
        product_type: str | None = None,
        cra_role: str | None = None,
        product_group: str | None = None,
        target_markets: str | None = None,
        # Version metadata
        environment: str | None = None,
        tags: str | None = None,
        # CI metadata
        commit_sha: str | None = None,
        branch: str | None = None,
        pipeline_id: str | None = None,
        repository: str | None = None,
        repo_path: str | None = None,
        source_type: str | None = None,
        # Multi-repo provenance: manual override slug for the
        # platform's auto-attribution by repository URL.
        component: str | None = None,
        component_version: str | None = None,
        # Optional kernel config for CVE filtering
        kernel_config_path: Path | None = None,
        # Upload metadata (parity with CI components)
        release_notes: str | None = None,
        release_date: str | None = None,
        external_url: str | None = None,
        release_state: str | None = None,
    ) -> dict[str, Any]:
        """
        Upload an SBOM to CRA Evidence.

        Args:
            product: Product slug or ID
            version: Version number
            file_path: Path to SBOM file
            format_type: SBOM format (cyclonedx or spdx), auto-detected if None
            create_product: Create product if it doesn't exist
            create_version: Create version if it doesn't exist
            scan: Trigger vulnerability scan after upload
            no_inherit: Skip inheriting CRA compliance artifacts from the previous version
            category: CRA product category
            subcategory: CRA Annex III/IV subcategory
            product_type: Product type (software, hardware, mixed)
            cra_role: CRA economic operator role
            product_group: Product group slug
            target_markets: Comma-separated EU country codes required when auto-creating a product
            environment: Environment slug for this version
            tags: Comma-separated list of tags to apply to this version
            commit_sha: Git commit SHA (auto-detected in CI)
            branch: Git branch name (auto-detected in CI)
            pipeline_id: CI pipeline ID (auto-detected in CI)
            repository: Repository URL or name (auto-detected in CI)
            repo_path: Repository subdirectory (monorepo support)
            source_type: How the SBOM was generated: build_time, binary_analysis,
                vendor, manifest, manual, import.
            component_version: Component repository release version for this SBOM
            kernel_config_path: Optional path to kernel .config file for CVE filtering
            release_notes: Release notes for this version (max 5000 chars, only
                applied on version creation)
            release_date: Release date in YYYY-MM-DD format (only applied on version creation)
            external_url: External URL e.g. GitHub release URL (max 512 chars,
                only applied on version creation)
            release_state: Release lifecycle state (draft, pending_review,
                approved, released, deprecated, end_of_life). Server enforces
                the same transition validation as the release command.

        Returns:
            Upload response data

        Raises:
            FileNotFoundError: If file doesn't exist
            APIError: If upload fails
        """
        if not file_path.exists():
            raise FileNotFoundError(str(file_path))
        suffix = file_path.suffix.lower()
        content_types = {
            ".json": "application/json",
            ".xml": "application/xml",
        }
        if suffix not in content_types:
            raise APIError(
                message="SBOM file must use a .json or .xml extension.",
                status_code=422,
            )

        # Client-side validation for upload metadata
        if release_notes and len(release_notes) > 5000:
            raise APIError(
                message="release_notes exceeds maximum length of 5000 characters.",
                status_code=422,
            )
        if release_date:
            import datetime
            try:
                datetime.date.fromisoformat(release_date)
            except ValueError:
                raise APIError(
                    message=f"release_date must be in YYYY-MM-DD format, got '{release_date}'.",
                    status_code=422,
                ) from None
        if external_url and len(external_url) > 512:
            raise APIError(
                message="external_url exceeds maximum length of 512 characters.",
                status_code=422,
            )

        await self._ensure_access_token()

        kernel_f = None
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(file_path, "rb") as sbom_f:
                files: dict[str, Any] = {"file": (file_path.name, sbom_f, content_types[suffix])}

                # Attach kernel config as a separate multipart field if provided
                if kernel_config_path is not None:
                    kernel_f = open(kernel_config_path, "rb")
                    files["kernel_config"] = (kernel_config_path.name, kernel_f, "text/plain")

                data = {
                    "product": product,
                    "version": version,
                    "artifact_type": "sbom",
                    "create_product": str(create_product).lower(),
                    "create_version": str(create_version).lower(),
                    "scan": str(scan).lower(),
                }

                if no_inherit:
                    data["no_inherit"] = "true"
                if supersedes:
                    data["supersedes"] = supersedes

                if category:
                    data["category"] = category
                if subcategory:
                    data["subcategory"] = subcategory
                if product_type:
                    data["product_type"] = product_type
                if cra_role:
                    data["cra_role"] = cra_role
                if product_group:
                    data["product_group"] = product_group
                if target_markets:
                    data["target_markets"] = target_markets

                if environment:
                    data["environment"] = environment
                if tags:
                    data["tags"] = tags

                if commit_sha:
                    data["commit_sha"] = commit_sha
                if branch:
                    data["branch"] = branch
                if pipeline_id:
                    data["pipeline_id"] = pipeline_id
                if repository:
                    data["repository"] = repository
                if repo_path is not None:
                    # Empty string means the repo root; None means unset.
                    data["repo_path"] = repo_path
                if source_type:
                    data["source_type"] = source_type
                if component:
                    data["component"] = component
                if component_version:
                    data["component_version"] = component_version

                if release_notes:
                    data["release_notes"] = release_notes
                if release_date:
                    data["release_date"] = release_date
                if external_url:
                    data["external_url"] = external_url
                if release_state:
                    data["release_state"] = release_state

                try:
                    response = await client.post(
                        f"{self.base_url}/api/v1/ci/upload",
                        headers=self._get_headers(),
                        files=files,
                        data=data,
                    )
                except httpx.RequestError as exc:
                    raise APIError(
                        message=f"Network error contacting {self.base_url}/api/v1/ci/upload: {exc}",
                    ) from exc
                finally:
                    if kernel_f is not None:
                        kernel_f.close()

                return self._handle_response(response)

    async def upload_hbom(
        self,
        product: str,
        version: str,
        file_path: Path,
        create_product: bool = False,
        create_version: bool = False,
        no_inherit: bool = False,
        # CRA classification
        category: str | None = None,
        subcategory: str | None = None,
        product_type: str | None = None,
        cra_role: str | None = None,
        product_group: str | None = None,
        target_markets: str | None = None,
        # Version metadata
        environment: str | None = None,
        tags: str | None = None,
        # CI metadata
        commit_sha: str | None = None,
        branch: str | None = None,
        pipeline_id: str | None = None,
        repository: str | None = None,
        repo_path: str | None = None,
        # Upload metadata (parity with CI components)
        release_notes: str | None = None,
        release_date: str | None = None,
        external_url: str | None = None,
        release_state: str | None = None,
    ) -> dict[str, Any]:
        """
        Upload an HBOM (Hardware BOM) to CRA Evidence.

        Args:
            product: Product slug or ID
            version: Version number
            file_path: Path to HBOM file
            create_product: Create product if it doesn't exist
            create_version: Create version if it doesn't exist
            no_inherit: Skip inheriting CRA compliance artifacts from the previous version
            category: CRA product category
            subcategory: CRA Annex III/IV subcategory
            product_type: Product type (software, hardware, mixed)
            cra_role: CRA economic operator role
            product_group: Product group slug
            target_markets: Comma-separated EU country codes required when auto-creating a product
            environment: Environment slug for this version
            tags: Comma-separated list of tags to apply to this version
            commit_sha: Git commit SHA (auto-detected in CI)
            branch: Git branch name (auto-detected in CI)
            pipeline_id: CI pipeline ID (auto-detected in CI)
            repository: Repository URL or name (auto-detected in CI)
            repo_path: Repository subdirectory (monorepo support)
            release_notes: Release notes for this version (max 5000 chars, only
                applied on version creation)
            release_date: Release date in YYYY-MM-DD format (only applied on version creation)
            external_url: External URL e.g. GitHub release URL (max 512 chars,
                only applied on version creation)
            release_state: Release lifecycle state (draft, pending_review,
                approved, released, deprecated, end_of_life)

        Returns:
            Upload response data
        """
        if not file_path.exists():
            raise FileNotFoundError(str(file_path))

        # Client-side validation for upload metadata
        if release_notes and len(release_notes) > 5000:
            raise APIError(
                message="release_notes exceeds maximum length of 5000 characters.",
                status_code=422,
            )
        if release_date:
            import datetime
            try:
                datetime.date.fromisoformat(release_date)
            except ValueError:
                raise APIError(
                    message=f"release_date must be in YYYY-MM-DD format, got '{release_date}'.",
                    status_code=422,
                ) from None
        if external_url and len(external_url) > 512:
            raise APIError(
                message="external_url exceeds maximum length of 512 characters.",
                status_code=422,
            )

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(file_path, "rb") as f:
                # Content-type follows the file format.
                content_type = (
                    "text/csv" if str(file_path).lower().endswith(".csv")
                    else "application/json"
                )
                files = {"file": (file_path.name, f, content_type)}
                data = {
                    "product": product,
                    "version": version,
                    "artifact_type": "hbom",
                    "create_product": str(create_product).lower(),
                    "create_version": str(create_version).lower(),
                }

                if no_inherit:
                    data["no_inherit"] = "true"

                if category:
                    data["category"] = category
                if subcategory:
                    data["subcategory"] = subcategory
                if product_type:
                    data["product_type"] = product_type
                if cra_role:
                    data["cra_role"] = cra_role
                if product_group:
                    data["product_group"] = product_group
                if target_markets:
                    data["target_markets"] = target_markets

                if environment:
                    data["environment"] = environment
                if tags:
                    data["tags"] = tags

                if commit_sha:
                    data["commit_sha"] = commit_sha
                if branch:
                    data["branch"] = branch
                if pipeline_id:
                    data["pipeline_id"] = pipeline_id
                if repository:
                    data["repository"] = repository
                if repo_path is not None:
                    data["repo_path"] = repo_path

                if release_notes:
                    data["release_notes"] = release_notes
                if release_date:
                    data["release_date"] = release_date
                if external_url:
                    data["external_url"] = external_url
                if release_state:
                    data["release_state"] = release_state

                try:
                    response = await client.post(
                        f"{self.base_url}/api/v1/ci/upload",
                        headers=self._get_headers(),
                        files=files,
                        data=data,
                    )
                except httpx.RequestError as exc:
                    raise APIError(
                        message=f"Network error contacting {self.base_url}/api/v1/ci/upload: {exc}",
                    ) from exc

                return self._handle_response(response)

    async def upload_vex(
        self,
        product: str,
        version: str,
        file_path: Path,
        create_product: bool = False,
        create_version: bool = False,
        no_inherit: bool = False,
        # CRA classification
        category: str | None = None,
        subcategory: str | None = None,
        product_type: str | None = None,
        cra_role: str | None = None,
        product_group: str | None = None,
        # Version metadata
        environment: str | None = None,
        tags: str | None = None,
        # CI metadata
        commit_sha: str | None = None,
        branch: str | None = None,
        pipeline_id: str | None = None,
        repository: str | None = None,
        repo_path: str | None = None,
    ) -> dict[str, Any]:
        """
        Upload a VEX document (CycloneDX JSON with vulnerabilities[]) to CRA Evidence.

        POSTs multipart form data to /api/v1/ci/upload with artifact_type=vex.

        Args:
            product: Product slug or ID
            version: Version number
            file_path: Path to VEX file
            create_product: Create product if it doesn't exist
            create_version: Create version if it doesn't exist
            no_inherit: Skip inheriting CRA compliance artifacts from the previous version
            category: CRA product category
            subcategory: CRA Annex III/IV subcategory
            product_type: Product type (software, hardware, mixed)
            cra_role: CRA economic operator role
            product_group: Product group slug
            environment: Environment slug for this version
            tags: Comma-separated list of tags to apply to this version
            commit_sha: Git commit SHA (auto-detected in CI)
            branch: Git branch name (auto-detected in CI)
            pipeline_id: CI pipeline ID (auto-detected in CI)
            repository: Repository URL or name (auto-detected in CI)
            repo_path: Repository subdirectory (monorepo support)

        Returns:
            Upload response data

        Raises:
            FileNotFoundError: If file doesn't exist
            APIError: If product/version not found or upload fails
        """
        if not file_path.exists():
            raise FileNotFoundError(str(file_path))

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, "application/json")}
                data = {
                    "product": product,
                    "version": version,
                    "artifact_type": "vex",
                    "create_product": str(create_product).lower(),
                    "create_version": str(create_version).lower(),
                }

                if no_inherit:
                    data["no_inherit"] = "true"

                if category:
                    data["category"] = category
                if subcategory:
                    data["subcategory"] = subcategory
                if product_type:
                    data["product_type"] = product_type
                if cra_role:
                    data["cra_role"] = cra_role
                if product_group:
                    data["product_group"] = product_group

                if environment:
                    data["environment"] = environment
                if tags:
                    data["tags"] = tags

                if commit_sha:
                    data["commit_sha"] = commit_sha
                if branch:
                    data["branch"] = branch
                if pipeline_id:
                    data["pipeline_id"] = pipeline_id
                if repository:
                    data["repository"] = repository
                if repo_path is not None:
                    data["repo_path"] = repo_path

                try:
                    response = await client.post(
                        f"{self.base_url}/api/v1/ci/upload",
                        headers=self._get_headers(),
                        files=files,
                        data=data,
                    )
                except httpx.RequestError as exc:
                    raise APIError(
                        message=f"Network error contacting {self.base_url}/api/v1/ci/upload: {exc}",
                    ) from exc

                return self._handle_response(response)

    async def validate_sbom(
        self,
        file_path: Path,
    ) -> dict[str, Any]:
        """
        Validate an SBOM file against the CRA Evidence ingestion pipeline.

        POSTs the file as multipart to /api/v1/sboms/validate.

        Args:
            file_path: Path to SBOM file to validate

        Returns:
            Dict with keys: valid, format, spec_version, component_count,
            purl_coverage_pct, versionless_count, warnings, errors

        Raises:
            FileNotFoundError: If file doesn't exist
            APIError: If validation request fails
        """
        if not file_path.exists():
            raise FileNotFoundError(str(file_path))
        suffix = file_path.suffix.lower()
        content_types = {
            ".json": "application/json",
            ".xml": "application/xml",
        }
        if suffix not in content_types:
            raise APIError(
                message="SBOM file must use a .json or .xml extension.",
                status_code=422,
            )

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, content_types[suffix])}

                endpoint = f"{self.base_url}/api/v1/sboms/validate"
                try:
                    response = await client.post(
                        endpoint,
                        headers=self._get_headers(),
                        files=files,
                    )
                except httpx.RequestError as exc:
                    message = f"Network error contacting {endpoint}: {exc}"
                    raise APIError(message=message) from exc

                return self._handle_response(response)

    async def upload_sarif(
        self,
        product: str,
        version: str,
        file_path: Path,
    ) -> dict[str, Any]:
        """
        Upload a SARIF security scan report to a product version.

        Resolves product slug -> product_id and version string -> version_id, then
        POSTs to /api/v1/versions/{version_id}/sarif.

        Args:
            product: Product slug or UUID
            version: Version number string
            file_path: Path to SARIF file (.json or .sarif)

        Returns:
            Upload response data

        Raises:
            FileNotFoundError: If file doesn't exist
            APIError: If product/version not found or upload fails
        """
        if not file_path.exists():
            raise FileNotFoundError(str(file_path))

        product_id = await self._resolve_product_id(product)

        version_response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/versions",
        )
        versions = self._handle_response(version_response)
        version_id: str | None = None
        if isinstance(versions, list):
            for v in versions:
                if v.get("version_number") == version:
                    version_id = str(v["id"])
                    break
        if version_id is None:
            raise APIError(
                message=f"Version '{version}' not found for product '{product}'.",
                status_code=404,
            )

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, "application/json")}

                endpoint = f"{self.base_url}/api/v1/versions/{version_id}/sarif"
                try:
                    response = await client.post(
                        endpoint,
                        headers=self._get_headers(),
                        files=files,
                    )
                except httpx.RequestError as exc:
                    message = f"Network error contacting {endpoint}: {exc}"
                    raise APIError(message=message) from exc

                return self._handle_response(response)

    async def upload_attestation(
        self,
        product: str,
        version: str,
        file_path: Path,
    ) -> dict[str, Any]:
        """
        Upload a Cosign/Sigstore bundle or DSSE in-toto attestation.

        Resolves product slug -> product_id and version string -> version_id, then
        POSTs to /api/v1/attestations/upload using multipart form data.

        Args:
            product: Product slug or UUID
            version: Version number string
            file_path: Path to one attestation JSON file

        Returns:
            Upload response data

        Raises:
            FileNotFoundError: If file doesn't exist
            APIError: If product/version not found or upload fails
        """
        if not file_path.exists():
            raise FileNotFoundError(str(file_path))

        product_id = await self._resolve_product_id(product)

        version_response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/versions",
        )
        versions = self._handle_response(version_response)
        version_id: str | None = None
        if isinstance(versions, list):
            for v in versions:
                if v.get("version_number") == version:
                    version_id = str(v["id"])
                    break
        if version_id is None:
            raise APIError(
                message=f"Version '{version}' not found for product '{product}'.",
                status_code=404,
            )

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, "application/json")}
                data = {"version_id": version_id}

                endpoint = f"{self.base_url}/api/v1/attestations/upload"
                try:
                    response = await client.post(
                        endpoint,
                        headers=self._get_headers(),
                        files=files,
                        data=data,
                    )
                except httpx.RequestError as exc:
                    message = f"Network error contacting {endpoint}: {exc}"
                    raise APIError(message=message) from exc

                return self._handle_response(response)

    async def trust_attestation_key(
        self,
        name: str,
        public_key_path: Path,
    ) -> dict[str, Any]:
        """Register a public-only Cosign key for attestation verification."""
        if not public_key_path.exists():
            raise FileNotFoundError(str(public_key_path))

        try:
            public_key_pem = public_key_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise APIError(
                message=f"Could not read public key file: {exc}"
            ) from exc

        if _PRIVATE_KEY_PEM_RE.search(public_key_pem):
            message = (
                "Refusing to send a private key. Pass cosign.pub, not cosign.key."
            )
            raise ValidationError(message)

        await self._ensure_access_token()
        endpoint = f"{self.base_url}/api/v1/signing/attestation-trust-keys"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    endpoint,
                    headers=self._get_headers(),
                    json={
                        "name": name,
                        "public_key_pem": public_key_pem,
                    },
                )
            except httpx.RequestError as exc:
                raise APIError(
                    message=f"Network error contacting {endpoint}: {exc}"
                ) from exc

        return self._handle_response(response)

    async def verify_attestation(
        self,
        product: str,
        version: str,
        attestation_id: str | None = None,
    ) -> dict[str, Any]:
        """Verify a stored Build Provenance attestation."""
        product_id = await self._resolve_product_id(product)
        version_id = await self._resolve_version_id(
            product_id,
            version,
            product,
        )

        selected_id = attestation_id
        if selected_id is None:
            list_response = await self._request_with_retry(
                "GET",
                f"{self.base_url}/api/v1/attestations/version/{version_id}",
            )
            attestations = self._handle_response(list_response)
            if not isinstance(attestations, list) or not attestations:
                raise APIError(
                    message=(
                        f"No Build Provenance attestation found for product "
                        f"'{product}' version '{version}'."
                    ),
                    status_code=404,
                )
            selected_id = str(attestations[0]["id"])

        verify_response = await self._request_with_retry(
            "POST",
            f"{self.base_url}/api/v1/attestations/{selected_id}/verify",
            json={},
        )
        result = self._handle_response(verify_response)
        if isinstance(result, dict):
            result.setdefault("product", product)
            result.setdefault("version", version)
        return result

    async def verify_sbom_signature(
        self,
        sbom_id: str,
        bundle_path: Path,
        expected_identity: str,
        expected_issuer: str,
    ) -> dict[str, Any]:
        """
        Verify a Sigstore/Cosign bundle against an SBOM stored by CRA Evidence.

        The API fetches the stored SBOM bytes by ``sbom_id`` and verifies
        the bundle against those bytes. The CLI does not upload a second SBOM
        copy for verification.
        """
        if not bundle_path.exists():
            raise FileNotFoundError(str(bundle_path))

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(bundle_path, "rb") as bundle_f:
                files = {
                    "signature_bundle": (
                        bundle_path.name,
                        bundle_f,
                        "application/json",
                    )
                }
                data = {
                    "expected_identity": expected_identity,
                    "expected_issuer": expected_issuer,
                }

                endpoint = f"{self.base_url}/api/v1/signatures/sboms/{sbom_id}/verify"
                try:
                    response = await client.post(
                        endpoint,
                        headers=self._get_headers(),
                        files=files,
                        data=data,
                    )
                except httpx.RequestError as exc:
                    message = f"Network error contacting {endpoint}: {exc}"
                    raise APIError(message=message) from exc

                return self._handle_response(response)

    async def upload_document(
        self,
        product: str,
        version: str,
        file_path: Path,
        document_type: str,
        create_product: bool = False,
        create_version: bool = False,
        no_inherit: bool = False,
        # CRA classification
        category: str | None = None,
        subcategory: str | None = None,
        product_type: str | None = None,
        cra_role: str | None = None,
        product_group: str | None = None,
        target_markets: str | None = None,
        # Version metadata
        environment: str | None = None,
        tags: str | None = None,
        # CI metadata
        commit_sha: str | None = None,
        branch: str | None = None,
        pipeline_id: str | None = None,
        repository: str | None = None,
        repo_path: str | None = None,
        # Upload metadata (parity with CI components)
        release_notes: str | None = None,
        release_date: str | None = None,
        external_url: str | None = None,
        release_state: str | None = None,
    ) -> dict[str, Any]:
        """
        Upload a CRA compliance document to CRA Evidence.

        Args:
            product: Product slug or ID
            version: Version number
            file_path: Path to document file
            document_type: Document type (e.g., risk_assessment, user_manual)
            create_product: Create product if it doesn't exist
            create_version: Create version if it doesn't exist
            no_inherit: Skip inheriting CRA compliance artifacts from the previous version
            category: CRA product category
            subcategory: CRA Annex III/IV subcategory
            product_type: Product type (software, hardware, mixed)
            cra_role: CRA economic operator role
            product_group: Product group slug
            target_markets: Comma-separated EU country codes required when auto-creating a product
            environment: Environment slug for this version
            tags: Comma-separated list of tags to apply to this version
            commit_sha: Git commit SHA (auto-detected in CI)
            branch: Git branch name (auto-detected in CI)
            pipeline_id: CI pipeline ID (auto-detected in CI)
            repository: Repository URL or name (auto-detected in CI)
            repo_path: Repository subdirectory (monorepo support)
            release_notes: Release notes for this version (max 5000 chars, only
                applied on version creation)
            release_date: Release date in YYYY-MM-DD format (only applied on version creation)
            external_url: External URL e.g. GitHub release URL (max 512 chars,
                only applied on version creation)
            release_state: Release lifecycle state (draft, pending_review,
                approved, released, deprecated, end_of_life)

        Returns:
            Upload response data
        """
        if not file_path.exists():
            raise FileNotFoundError(str(file_path))

        # Client-side validation for upload metadata
        if release_notes and len(release_notes) > 5000:
            raise APIError(
                message="release_notes exceeds maximum length of 5000 characters.",
                status_code=422,
            )
        if release_date:
            import datetime
            try:
                datetime.date.fromisoformat(release_date)
            except ValueError:
                raise APIError(
                    message=f"release_date must be in YYYY-MM-DD format, got '{release_date}'.",
                    status_code=422,
                ) from None
        if external_url and len(external_url) > 512:
            raise APIError(
                message="external_url exceeds maximum length of 512 characters.",
                status_code=422,
            )

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, "application/octet-stream")}
                data = {
                    "product": product,
                    "version": version,
                    "artifact_type": "document",
                    "document_type": document_type,
                    "create_product": str(create_product).lower(),
                    "create_version": str(create_version).lower(),
                }

                if no_inherit:
                    data["no_inherit"] = "true"

                if category:
                    data["category"] = category
                if subcategory:
                    data["subcategory"] = subcategory
                if product_type:
                    data["product_type"] = product_type
                if cra_role:
                    data["cra_role"] = cra_role
                if product_group:
                    data["product_group"] = product_group
                if target_markets:
                    data["target_markets"] = target_markets

                if environment:
                    data["environment"] = environment
                if tags:
                    data["tags"] = tags

                if commit_sha:
                    data["commit_sha"] = commit_sha
                if branch:
                    data["branch"] = branch
                if pipeline_id:
                    data["pipeline_id"] = pipeline_id
                if repository:
                    data["repository"] = repository
                if repo_path is not None:
                    data["repo_path"] = repo_path

                if release_notes:
                    data["release_notes"] = release_notes
                if release_date:
                    data["release_date"] = release_date
                if external_url:
                    data["external_url"] = external_url
                if release_state:
                    data["release_state"] = release_state

                try:
                    response = await client.post(
                        f"{self.base_url}/api/v1/ci/upload",
                        headers=self._get_headers(),
                        files=files,
                        data=data,
                    )
                except httpx.RequestError as exc:
                    raise APIError(
                        message=f"Network error contacting {self.base_url}/api/v1/ci/upload: {exc}",
                    ) from exc

                return self._handle_response(response)

    async def upload_product_document_gemara(
        self,
        product: str,
        document_type: str,
        file_path: Path,
    ) -> dict[str, Any]:
        """
        Upload a Gemara YAML file as a product-level document template.

        Routes to `POST /api/v1/products/{product_id}/documents` so the doc is
        attached to the product (not a version). Suitable for Policy,
        GuidanceCatalog and ControlCatalog types.

        CRA Evidence renders the YAML to PDF (CUE vet + WeasyPrint), stores the
        PDF, and cascades the template to newly-created versions.

        Args:
            product: Product slug or UUID.
            document_type: One of the product-level DocumentType values
                (vulnerability_policy, coordinated_disclosure_policy,
                 update_mechanism_documentation, secure_development_policy).
            file_path: Path to the Gemara YAML file.

        Returns:
            ProductDocumentUploadResult-shaped dict.
        """
        if not file_path.exists():
            raise FileNotFoundError(str(file_path))

        product_id = await self._resolve_product_id(product)

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, "application/x-yaml")}
                data = {"doc_type": document_type}
                endpoint = f"{self.base_url}/api/v1/products/{product_id}/documents"
                try:
                    response = await client.post(
                        endpoint,
                        headers=self._get_headers(),
                        files=files,
                        data=data,
                    )
                except httpx.RequestError as exc:
                    message = f"Network error contacting {endpoint}: {exc}"
                    raise APIError(message=message) from exc
                return self._handle_response(response)

    async def get_version_status(
        self,
        product: str,
        version: str,
    ) -> dict[str, Any]:
        """
        Get CRA compliance status for a version.

        Args:
            product: Product slug or ID
            version: Version number
        """
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/ci/status",
            params={"product": product, "version": version},
        )
        return self._handle_response(response)

    async def get_risk_assessment(
        self,
        product: str,
        version: str,
    ) -> dict[str, Any]:
        """
        Get the structured risk assessment summary for a product version.

        Returns assessment status, review status, completion, sign-off
        summary, asset/threat/risk counts, and Part II process coverage when
        the server includes it in the response.

        Args:
            product: Product slug or ID
            version: Version number

        Raises:
            APIError: With status_code 404 when no risk assessment has been
                recorded yet for the version.
        """
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/ci/risk-assessment",
            params={"product": product, "version": version},
        )
        return self._handle_response(response)

    async def get_ra_delta(
        self,
        product: str,
        version: str,
    ) -> dict[str, Any]:
        """
        Get the current review-cycle delta for a product version.

        Returns the open review cycle (with its pinned items and resolution
        progress) when one exists, or an unpersisted preview of what opening
        a cycle now would contain when none is open yet.

        Args:
            product: Product slug or ID
            version: Version number

        Returns:
            Dict with keys including preview, id, digest, state, items,
            resolution (id/state/resolution are null when preview is true).
        """
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/ci/risk-assessment/delta",
            params={"product": product, "version": version},
        )
        return self._handle_response(response)

    async def open_ra_review_cycle(
        self,
        product: str,
        version: str,
    ) -> dict[str, Any]:
        """
        Open, or idempotently refresh, the review cycle for a product version.

        Calling this repeatedly with an unchanged delta returns the same
        cycle. When the delta has moved, the previous open cycle is
        superseded and a new one is opened.

        Args:
            product: Product slug or ID
            version: Version number

        Returns:
            Dict with keys id, digest, state, items, resolution, created.

        Raises:
            APIError: With status_code 422 when there is no risk assessment
                for this version, or it is not currently flagged for review
                and no cycle is already open.
        """
        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            endpoint = f"{self.base_url}/api/v1/ci/risk-assessment/review-cycles"
            try:
                response = await client.post(
                    endpoint,
                    headers=self._get_headers(),
                    json={"product": product, "version": version},
                )
            except httpx.RequestError as exc:
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc

            return self._handle_response(response)

    async def record_ra_disposition(
        self,
        product: str,
        version: str,
        cycle_id: str,
        expected_digest: str,
        item_id: str,
        disposition: str,
        justification: str | None = None,
    ) -> dict[str, Any]:
        """
        Record one disposition for one review-cycle item.

        Append-only: recording again for the same item is a new revision,
        not an overwrite of the earlier one.

        Args:
            product: Product slug or ID
            version: Version number
            cycle_id: Review cycle UUID this disposition targets
            expected_digest: Digest last seen for this cycle (optimistic
                concurrency; a stale digest fails with 409)
            item_id: Review item id within the cycle
            disposition: One of accepted, edited, added_risk, not_affected
                (release-question items only accept accepted/added_risk/edited)
            justification: Required substantive text when disposition is
                not_affected; optional otherwise

        Returns:
            Dict with keys id, cycle_id, item_id, revision, disposition,
            justification, resolution.

        Raises:
            APIError: Status_code 422 (raised client-side, before any network
                call) when disposition is not_affected and justification is
                empty or missing. Status_code 409 when the cycle changed
                since it was read (re-open the cycle and retry with the new
                digest).
        """
        if disposition == "not_affected" and not (justification or "").strip():
            raise APIError(
                message=(
                    "A 'not_affected' disposition requires a justification "
                    "explaining why the product is not affected."
                ),
                status_code=422,
            )

        payload: dict[str, Any] = {
            "product": product,
            "version": version,
            "cycle_id": cycle_id,
            "expected_digest": expected_digest,
            "item_id": item_id,
            "disposition": disposition,
        }
        if justification is not None:
            payload["justification"] = justification

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            endpoint = f"{self.base_url}/api/v1/ci/risk-assessment/review"
            try:
                response = await client.post(
                    endpoint,
                    headers=self._get_headers(),
                    json=payload,
                )
            except httpx.RequestError as exc:
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc

            return self._handle_response(response)

    async def finalize_ra_review(
        self,
        product: str,
        version: str,
        cycle_id: str,
    ) -> dict[str, Any]:
        """
        Finalize an open review cycle for a product version.

        Requires an organisation admin or owner role, and either a human
        session or an API key holding the ra:finalize scope. Requires every
        item in the cycle to already carry a disposition.

        Args:
            product: Product slug or ID
            version: Version number
            cycle_id: Review cycle UUID to finalize

        Returns:
            Dict with keys assessment_id, assessment_status,
            assessment_review_status, cycle_id, cycle_state.
        """
        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            endpoint = f"{self.base_url}/api/v1/ci/risk-assessment/finalize"
            try:
                response = await client.post(
                    endpoint,
                    headers=self._get_headers(),
                    json={
                        "product": product,
                        "version": version,
                        "cycle_id": cycle_id,
                    },
                )
            except httpx.RequestError as exc:
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc

            return self._handle_response(response)

    async def create_product_version(
        self,
        product: str,
        version: str,
        *,
        release_type: str | None = None,
        environment: str | None = None,
        release_notes: str | None = None,
        release_date: str | None = None,
        end_of_support_date: str | None = None,
        external_url: str | None = None,
        inherit_from: str | None = None,
        reuse_existing: bool = False,
    ) -> dict[str, Any]:
        """
        Create a draft product version. Uploads no new evidence and releases
        nothing. The server may link reusable product-level documents and
        templates to the new version.

        The product must already exist; it is never created here. Only the
        arguments the caller passed are sent, so server-side defaults stay
        authoritative for everything else.

        With ``reuse_existing``, the version is looked up first and returned
        as-is when it already exists, so no create is attempted. Without it, an
        existing version number is left to the API, which rejects it.

        Args:
            product: Product slug or UUID of an existing product
            version: Version number to create
            release_type: feature, security_patch, or maintenance
            environment: Environment slug for the version
            release_notes: Free-text release notes
            release_date: Release date as YYYY-MM-DD
            end_of_support_date: End-of-support date as YYYY-MM-DD
            external_url: External link for the version
            inherit_from: Version number or UUID whose eligible compliance
                artifacts should be carried over. Inheritance happens only
                when this is set.
            reuse_existing: Return an existing version instead of creating one

        Returns:
            Dict with keys id, product_id, version_number, release_state, and
            created. ``created`` is False when an existing version was returned.

        Raises:
            APIError: If the product does not exist, the version already exists
                and reuse_existing was not requested, or the API rejects the
                request
        """
        product_id = await self._resolve_product_id(product)

        if reuse_existing:
            existing = await self._find_version_by_number(product_id, version)
            if existing is not None:
                return self._version_result(existing, product_id, created=False)

        payload: dict[str, Any] = {"version_number": version}
        if release_type is not None:
            payload["release_type"] = release_type
        if environment is not None:
            payload["environment_override"] = environment
        if release_notes is not None:
            payload["release_notes"] = release_notes
        if release_date is not None:
            payload["release_date"] = release_date
        if end_of_support_date is not None:
            payload["end_of_support_date"] = end_of_support_date
        if external_url is not None:
            payload["external_url"] = external_url
        if inherit_from is not None:
            payload["inherit_from_version_id"] = await self._resolve_version_id(
                product_id, inherit_from, product
            )

        await self._ensure_access_token()

        endpoint = f"{self.base_url}/api/v1/products/{product_id}/versions"
        # Deliberately not routed through _request_with_retry: that helper
        # replays 429 and 5xx responses, which is right for the reads above but
        # would risk repeating a create.
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    endpoint,
                    headers=self._get_headers(),
                    json=payload,
                )
            except httpx.RequestError as exc:
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc

            try:
                created_version = self._handle_response(response)
            except APIError as exc:
                if not (
                    reuse_existing
                    and exc.status_code == 409
                    and exc.error_code == "RESOURCE_ALREADY_EXISTS"
                ):
                    raise

                # Another writer may create the same version after the
                # pre-create lookup. Re-read only for the API's exact duplicate
                # resource contract; unrelated conflicts remain errors.
                existing = await self._find_version_by_number(product_id, version)
                if existing is None:
                    raise
                return self._version_result(
                    existing,
                    product_id,
                    created=False,
                )

        return self._version_result(created_version, product_id, created=True)

    @staticmethod
    def _version_result(
        version_data: dict[str, Any],
        product_id: str,
        *,
        created: bool,
    ) -> dict[str, Any]:
        """Normalize a created or existing version into one stable shape.

        The create response and the version list entry carry different fields
        (the list entry has no product_id), so callers get the same keys either
        way. ``release_state`` is whatever the server reported, never assumed.
        """
        return {
            "id": str(version_data.get("id", "")),
            "product_id": str(version_data.get("product_id") or product_id),
            "version_number": str(version_data.get("version_number", "")),
            "release_state": str(version_data.get("release_state") or "unknown"),
            "created": created,
        }

    async def set_release_state(
        self,
        product: str,
        version: str,
        state: str,
        superseded_by: str | None = None,
    ) -> dict[str, Any]:
        """
        Set release state for a version.

        Args:
            product: Product slug or ID
            version: Version number
            state: Release state (draft, pending_review, approved, released,
                deprecated, end_of_life)
            superseded_by: Version number of the successor version (optional)
        """
        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            form_data: dict[str, str] = {
                "product": product,
                "version": version,
                "state": state,
            }
            if superseded_by:
                form_data["superseded_by"] = superseded_by

            try:
                response = await client.post(
                    f"{self.base_url}/api/v1/ci/release-state",
                    headers=self._get_headers(),
                    data=form_data,
                )
            except httpx.RequestError as exc:
                endpoint = f"{self.base_url}/api/v1/ci/release-state"
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc

            return self._handle_response(response)

    async def trigger_scan(
        self,
        product: str,
        version: str,
        component: str | None = None,
    ) -> dict[str, Any]:
        """
        Trigger vulnerability scan for a version.

        Args:
            product: Product slug or ID
            version: Version number
            component: Optional component slug. Restricts the scan to the
                latest SBOM attributed to this component (multi-repo
                products). If omitted, the latest SBOM for the version is
                used regardless of component.

        Returns:
            Scan results or job status
        """
        await self._ensure_access_token()

        payload: dict[str, str] = {
            "product": product,
            "version": version,
        }
        if component:
            payload["component"] = component

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/api/v1/ci/scan",
                    headers=self._get_headers(),
                    data=payload,
                )
            except httpx.RequestError as exc:
                raise APIError(
                    message=f"Network error contacting {self.base_url}/api/v1/ci/scan: {exc}",
                ) from exc

            return self._handle_response(response)

    async def download_export(
        self,
        product: str,
        version: str,
        export_format: str,
        output_path: Path,
    ) -> dict[str, Any]:
        """
        Download technical file export.

        Args:
            product: Product slug or ID
            version: Version number
            export_format: Export format (technical-file, compliance-report, sbom-data)
            output_path: Path to save the exported file
        """
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/ci/export",
            params={
                "product": product,
                "version": version,
                "format": export_format,
            },
        )

        if response.status_code >= 400:
            return self._handle_response(response)

        # Save file
        with open(output_path, "wb") as f:
            f.write(response.content)

        return {
            "status": "success",
            "file_path": str(output_path),
            "size_bytes": len(response.content),
            "format": export_format,
        }

    async def download_gemara_source(
        self,
        document_id: str,
        output_path: Path,
    ) -> dict[str, Any]:
        """
        Download retained original Gemara YAML for a rendered document.

        Args:
            document_id: Document UUID returned by upload or API workflows
            output_path: Path to save the retained YAML source

        Returns:
            Download metadata
        """
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/documents/{document_id}/gemara-source/download",
        )

        if response.status_code >= 400:
            return self._handle_response(response)

        with open(output_path, "wb") as f:
            f.write(response.content)

        return {
            "status": "success",
            "document_id": document_id,
            "file_path": str(output_path),
            "size_bytes": len(response.content),
            "provenance_only": True,
        }

    async def compare_versions(
        self,
        product: str,
        version_a: str,
        version_b: str,
    ) -> dict[str, Any]:
        """
        Compare two versions of a product.

        Args:
            product: Product slug or ID
            version_a: First version number
            version_b: Second version number

        Returns:
            Comparison data (added/removed/modified components)
        """
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/ci/compare",
            params={
                "product": product,
                "version_a": version_a,
                "version_b": version_b,
            },
        )
        return self._handle_response(response)

    async def list_hboms(self, product: str, version: str) -> list[dict[str, Any]]:
        """
        List HBOM metadata for a product version.

        Uses the existing HBOM read endpoint; document bytes are not downloaded.
        """
        product_id = await self._resolve_product_id(product)
        version_id = await self._resolve_version_id(product_id, version, product)
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/versions/{version_id}/hboms",
        )
        result = self._handle_response(response)
        return result if isinstance(result, list) else []

    async def list_vex_documents(self, product: str, version: str) -> list[dict[str, Any]]:
        """
        List VEX document metadata for a product version.

        Uses the existing VEX read endpoint; document bytes are not downloaded.
        """
        product_id = await self._resolve_product_id(product)
        version_id = await self._resolve_version_id(product_id, version, product)
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/versions/{version_id}/vex",
        )
        result = self._handle_response(response)
        return result if isinstance(result, list) else []

    async def get_product_maturity(self, product: str) -> dict[str, Any]:
        """Get advisory CRA secure-development maturity for a product."""
        product_id = await self._resolve_product_id(product)
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/maturity",
        )
        return self._handle_response(response)

    async def get_version_maturity(self, product: str, version: str) -> dict[str, Any]:
        """Get advisory CRA secure-development maturity for a version."""
        product_id = await self._resolve_product_id(product)
        version_id = await self._resolve_version_id(product_id, version, product)
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/versions/{version_id}/maturity",
        )
        return self._handle_response(response)

    async def list_static_analysis_results(
        self,
        product: str,
        version: str,
        *,
        limit: int = 100,
        offset: int = 0,
        tool_name: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        file_path: str | None = None,
        suppressed: bool | None = None,
        min_severity_rank: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        List static-analysis finding metadata for a product version.

        Uses the existing SARIF/static-analysis read endpoint.
        """
        product_id = await self._resolve_product_id(product)
        version_id = await self._resolve_version_id(product_id, version, product)
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        optional_params = {
            "tool_name": tool_name,
            "severity": severity,
            "rule_id": rule_id,
            "file_path": file_path,
            "suppressed": suppressed,
            "min_severity_rank": min_severity_rank,
        }
        params.update({key: value for key, value in optional_params.items() if value is not None})
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/versions/{version_id}/static-analysis",
            params=params,
        )
        result = self._handle_response(response)
        return result if isinstance(result, list) else []

    async def get_static_analysis_summary(self, product: str, version: str) -> dict[str, Any]:
        """
        Get static-analysis summary metadata for a product version.

        Uses the existing SARIF/static-analysis summary endpoint.
        """
        product_id = await self._resolve_product_id(product)
        version_id = await self._resolve_version_id(product_id, version, product)
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/versions/{version_id}/static-analysis/summary",
        )
        result = self._handle_response(response)
        return result if isinstance(result, dict) else {}

    # Distributor Verification (CRA Article 20)

    async def create_distributor_verification(
        self,
        product: str | None = None,
        version: str | None = None,
        external_product_name: str | None = None,
        external_manufacturer_name: str | None = None,
        product_identifier: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a new distributor verification checklist.

        Args:
            product: Product slug or ID (for internal products)
            version: Version number (for internal products)
            external_product_name: Name for external products
            external_manufacturer_name: Manufacturer name for external products
            product_identifier: SKU or model number

        Returns:
            Created verification data
        """
        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            payload: dict[str, Any] = {}

            if product:
                product_id = await self._resolve_product_id(product)
                payload["product_id"] = product_id

                if version:
                    version_response = await self._request_with_retry(
                        "GET",
                        f"{self.base_url}/api/v1/products/{product_id}/versions",
                    )
                    versions = self._handle_response(version_response)
                    version_id: str | None = None
                    if isinstance(versions, list):
                        for v in versions:
                            if v.get("version_number") == version:
                                version_id = str(v["id"])
                                break
                    if version_id is None:
                        raise APIError(
                            message=f"Version '{version}' not found for product '{product}'.",
                            status_code=404,
                        )
                    payload["version_id"] = version_id

            if external_product_name:
                payload["external_product_name"] = external_product_name
            if external_manufacturer_name:
                payload["external_manufacturer_name"] = external_manufacturer_name
            if product_identifier:
                payload["external_product_identifier"] = product_identifier

            try:
                response = await client.post(
                    f"{self.base_url}/api/v1/distributor/verifications",
                    headers=self._get_headers(),
                    json=payload,
                )
            except httpx.RequestError as exc:
                endpoint = f"{self.base_url}/api/v1/distributor/verifications"
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc

            return self._handle_response(response)

    async def update_distributor_verification(
        self,
        verification_id: str,
        update_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Update a distributor verification checklist.

        Args:
            verification_id: Verification ID or number
            update_data: Fields to update

        Returns:
            Updated verification data
        """
        await self._ensure_access_token()

        # PATCH uses a JSON body.
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            endpoint = (
                f"{self.base_url}/api/v1/distributor/verifications/{verification_id}"
            )
            try:
                response = await client.patch(
                    endpoint,
                    headers=self._get_headers(),
                    json=update_data,
                )
            except httpx.RequestError as exc:
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc

            return self._handle_response(response)

    async def complete_distributor_verification(
        self,
        verification_id: str,
    ) -> dict[str, Any]:
        """
        Mark a distributor verification as complete.

        Args:
            verification_id: Verification ID or number

        Returns:
            Updated verification data
        """
        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            endpoint = (
                f"{self.base_url}/api/v1/distributor/verifications/"
                f"{verification_id}/complete"
            )
            try:
                response = await client.post(
                    endpoint,
                    headers=self._get_headers(),
                )
            except httpx.RequestError as exc:
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc

            return self._handle_response(response)

    async def stop_ship_verification(
        self,
        verification_id: str,
        reason: str,
    ) -> dict[str, Any]:
        """
        Mark a product for stop-ship due to significant risk.

        Args:
            verification_id: Verification ID or number
            reason: Reason for stop-ship

        Returns:
            Updated verification data
        """
        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            endpoint = (
                f"{self.base_url}/api/v1/distributor/verifications/"
                f"{verification_id}/stop-ship"
            )
            try:
                response = await client.post(
                    endpoint,
                    headers=self._get_headers(),
                    json={"reason": reason},
                )
            except httpx.RequestError as exc:
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc

            return self._handle_response(response)

    async def list_distributor_verifications(
        self,
        status: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        List distributor verifications.

        Args:
            status: Filter by status
            limit: Maximum number of results

        Returns:
            List of verification summaries
        """
        params: dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status

        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/distributor/verifications",
            params=params,
        )

        data = self._handle_response(response)
        return data.get("items", data) if isinstance(data, dict) else data

    async def get_distributor_verification(
        self,
        verification_id: str,
    ) -> dict[str, Any]:
        """
        Get details of a specific verification.

        Args:
            verification_id: Verification ID or number

        Returns:
            Verification details
        """
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/distributor/verifications/{verification_id}",
        )
        return self._handle_response(response)

    # CRA Profile (Product-level compliance defaults)

    async def _resolve_product_id(self, product: str) -> str:
        """
        Resolve a product slug or UUID to a product UUID string.

        Args:
            product: Product slug or UUID string

        Returns:
            Product UUID string

        Raises:
            APIError: If product not found
        """
        uuid_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )

        if uuid_re.match(product):
            return product

        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products",
        )
        products = self._handle_response(response)

        if isinstance(products, list):
            for p in products:
                if p.get("slug") == product or p.get("id") == product:
                    return str(p["id"])

        raise APIError(
            message=f"Product '{product}' not found.",
            status_code=404,
        )

    async def _resolve_version_id(
        self,
        product_id: str,
        version: str,
        product_label: str,
    ) -> str:
        """
        Resolve a product version number or UUID to a version UUID string.

        Args:
            product_id: Product UUID string
            version: Version number or UUID string
            product_label: Original product label for error messages

        Returns:
            Version UUID string

        Raises:
            APIError: If version not found
        """
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/versions",
        )
        versions = self._handle_response(response)

        matches: dict[str, dict[str, Any]] = {}
        if isinstance(versions, list):
            for item in versions:
                item_id = str(item.get("id", ""))
                item_number = item.get("version_number") or item.get("number")
                if item_id == version or item_number == version:
                    matches[item_id] = item

        if len(matches) == 1:
            return next(iter(matches))
        if len(matches) > 1:
            raise APIError(
                message=(
                    f"Version reference '{version}' is ambiguous for product "
                    f"'{product_label}': it matches both a version id and a "
                    "different version number."
                ),
                status_code=409,
            )

        raise APIError(
            message=f"Version '{version}' not found for product '{product_label}'.",
            status_code=404,
        )

    async def _find_version_by_number(
        self,
        product_id: str,
        version: str,
    ) -> dict[str, Any] | None:
        """
        Return the version entry with this version number, or None.

        Unlike _resolve_version_id this returns the whole entry (so callers can
        read the release state), treats a version number as a version number
        rather than accepting a UUID, and reports absence instead of raising.

        Args:
            product_id: Product UUID string
            version: Version number string

        Returns:
            The matching version entry, or None when the product has no version
            with that number
        """
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/versions",
        )
        versions = self._handle_response(response)

        if isinstance(versions, list):
            for item in versions:
                if item.get("version_number") == version:
                    return item

        return None

    async def get_cra_profile(self, product: str) -> dict[str, Any]:
        """
        Get the CRA compliance profile for a product.

        Args:
            product: Product slug or UUID

        Returns:
            CRAProfileResponse dict with keys: product_id, cra_profile, message
        """
        product_id = await self._resolve_product_id(product)
        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/cra-profile",
        )
        return self._handle_response(response)

    async def update_cra_profile(self, product: str, profile: dict[str, Any]) -> dict[str, Any]:
        """
        Set or update the CRA compliance profile for a product.

        Args:
            product: Product slug or UUID
            profile: Dict with profile fields to update. Supported keys:
                - default_conformity_assessment_type (str)
                - default_support_period_years (int)
                - support_period_communicated (bool)
                - secure_by_default_confirmed (bool)

        Returns:
            CRAProfileResponse dict with keys: product_id, cra_profile, message
        """
        product_id = await self._resolve_product_id(product)

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            endpoint = f"{self.base_url}/api/v1/products/{product_id}/cra-profile"
            try:
                response = await client.put(
                    endpoint,
                    headers=self._get_headers(),
                    json=profile,
                )
            except httpx.RequestError as exc:
                message = f"Network error contacting {endpoint}: {exc}"
                raise APIError(message=message) from exc
            return self._handle_response(response)

    async def get_version_cra_settings(self, product: str, version: str) -> dict[str, Any]:
        """
        Get CRA compliance settings for a specific version.

        Used by setup-profile --from-version to seed the profile from an
        existing version's compliance state.

        Args:
            product: Product slug or UUID
            version: Version number string

        Returns:
            Dict with CRA fields from the version:
                - conformity_assessment_type
                - ce_marking_applied
                - support_period_communicated
                - secure_by_default_confirmed
        """
        product_id = await self._resolve_product_id(product)

        response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/versions",
        )
        versions = self._handle_response(response)

        version_id: str | None = None
        if isinstance(versions, list):
            for v in versions:
                if v.get("version_number") == version:
                    version_id = str(v["id"])
                    break

        if version_id is None:
            raise APIError(
                message=f"Version '{version}' not found for product '{product}'.",
                status_code=404,
            )

        version_response = await self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/products/{product_id}/versions/{version_id}",
        )
        version_detail = self._handle_response(version_response)

        return {
            "conformity_assessment_type": version_detail.get("conformity_assessment_type"),
            "ce_marking_applied": version_detail.get("ce_marking_applied"),
            "support_period_communicated": version_detail.get("support_period_communicated"),
            "secure_by_default_confirmed": version_detail.get("secure_by_default_confirmed"),
        }

    async def verify_sbom(
        self,
        version_id: str,
        binary_sbom_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Call POST /api/v1/sboms/verify to compare a binary SBOM against the declared SBOM.

        Args:
            version_id: Version UUID string
            binary_sbom_id: Optional specific binary SBOM UUID. If None, server uses latest.

        Returns:
            Verification response with coverage_ratio and discrepancy lists.
        """
        payload: dict[str, Any] = {"version_id": version_id}
        if binary_sbom_id:
            payload["binary_sbom_id"] = binary_sbom_id

        await self._ensure_access_token()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/api/v1/sboms/verify",
                    json=payload,
                    headers=self._get_headers(),
                )
            except httpx.RequestError as exc:
                raise APIError(
                    message=f"Network error contacting {self.base_url}/api/v1/sboms/verify: {exc}",
                ) from exc
        return self._handle_response(response)
