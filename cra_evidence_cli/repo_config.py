"""Per-repository identity file loader for ``.cra/evidence.yaml``.

A repository can commit a ``.cra/evidence.yaml`` file so that CI commands do
not need ``--product``, ``--version``, and ``--component`` on every invocation.
Discovery walks from the current working directory; the git root is the
fallback. Explicit CLI flags always win over env vars, which always win over
the file.

YAML schema
-----------
``schema_version`` is required and must equal 1. Unknown keys are rejected
(a typo must not silently disable identity resolution).

==================  ================================================  =========
Key                 Type / allowed values                             Default
==================  ================================================  =========
``schema_version``  integer (must be 1)                               required
``product``         string                                            none
``component``       string                                            none
``component_kind``  one of frontend|service|datastore|firmware|       none
                    library|other
``version_from``    string (git-tag|file:<path>|pyproject|            none
                    package.json|env:<VAR>)
==================  ================================================  =========

Example ``.cra/evidence.yaml``::

    schema_version: 1
    product: my-product
    component: api-server
    component_kind: service
    version_from: git-tag
"""

from __future__ import annotations

import json
import os
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from cra_evidence_cli.exceptions import ConfigurationError, CRAEvidenceError

_DEFAULT_CONFIG_PATH = Path(".cra/evidence.yaml")

_ALLOWED_KEYS = {"schema_version", "product", "component", "component_kind", "version_from"}

_VALID_COMPONENT_KINDS = {"frontend", "service", "datastore", "firmware", "library", "other"}


@dataclass
class RepoConfig:
    """Parsed contents of a ``.cra/evidence.yaml`` file."""

    product: str | None = None
    component: str | None = None
    component_kind: str | None = None
    version_from: str | None = None


def find_repo_config(start: Path | None = None) -> Path | None:
    """Return the path to ``.cra/evidence.yaml`` or ``None`` if absent.

    Searches in ``start`` (defaults to CWD) first, then falls back to the
    git repository root. Returns ``None`` when neither exists and when called
    outside a git repository.
    """
    base = start if start is not None else Path.cwd()
    candidate = base / _DEFAULT_CONFIG_PATH
    if candidate.exists():
        return candidate

    # git-root fallback
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "--show-toplevel"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
        git_root = Path(result.stdout.strip())
        git_candidate = git_root / _DEFAULT_CONFIG_PATH
        if git_candidate.exists():
            return git_candidate
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return None


def load_repo_config(path: Path) -> RepoConfig:
    """Parse and validate ``.cra/evidence.yaml`` at ``path``.

    Raises ``ConfigurationError`` when schema_version is missing or not 1,
    when unknown keys are present, or when component_kind is not a recognised
    value.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"Failed to read repo config {path}: {exc}"
        raise ConfigurationError(msg) from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"Failed to parse repo config {path}: {exc}"
        raise ConfigurationError(msg) from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        msg = (
            f"Repo config {path} must contain a YAML mapping at the top level, "
            f"got {type(data).__name__}."
        )
        raise ConfigurationError(msg)

    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        msg = (
            f"Unknown key(s) in repo config {path}: {', '.join(unknown)}. "
            f"Allowed keys: {', '.join(sorted(_ALLOWED_KEYS))}."
        )
        raise ConfigurationError(msg)

    schema_version = data.get("schema_version")
    if schema_version is None:
        msg = (
            f"Repo config {path} is missing required key 'schema_version'. "
            "Add 'schema_version: 1' at the top of the file."
        )
        raise ConfigurationError(msg)
    if schema_version != 1:
        msg = (
            f"Repo config {path} has unsupported schema_version {schema_version!r}. "
            "Only schema_version: 1 is supported."
        )
        raise ConfigurationError(msg)

    component_kind = data.get("component_kind")
    if component_kind is not None and component_kind not in _VALID_COMPONENT_KINDS:
        msg = (
            f"Repo config {path}: component_kind {component_kind!r} is not valid. "
            f"Allowed values: {', '.join(sorted(_VALID_COMPONENT_KINDS))}."
        )
        raise ConfigurationError(msg)

    return RepoConfig(
        product=data.get("product"),
        component=data.get("component"),
        component_kind=component_kind,
        version_from=data.get("version_from"),
    )


def resolve_version(version_from: str) -> str:
    """Resolve a version string from the ``version_from`` directive.

    Supported directives:

    - ``git-tag``: uses ``git describe --tags --exact-match HEAD``; falls back
      to ``GITHUB_REF_NAME`` when ``GITHUB_REF_TYPE`` is ``"tag"``.
    - ``file:<path>``: first non-empty line of the file at ``<path>``.
    - ``pyproject``: ``[project].version`` or ``[tool.poetry].version`` from
      ``./pyproject.toml``.
    - ``package.json``: ``.version`` from ``./package.json``.
    - ``env:<VAR>``: value of environment variable ``<VAR>``.

    Raises ``CRAEvidenceError`` with an actionable message on any failure.
    """
    if version_from == "git-tag":
        try:
            result = subprocess.run(  # noqa: S603
                ["git", "describe", "--tags", "--exact-match", "HEAD"],  # noqa: S607
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        ref_type = os.environ.get("GITHUB_REF_TYPE", "")
        ref_name = os.environ.get("GITHUB_REF_NAME", "")
        if ref_type == "tag" and ref_name:
            return ref_name

        msg = (
            "version_from: git-tag could not resolve a tag: no tag at HEAD and "
            "GITHUB_REF_TYPE is not 'tag'. "
            "Pass --version explicitly or push from a tagged commit."
        )
        raise CRAEvidenceError(msg)

    if version_from.startswith("file:"):
        file_path = Path(version_from[5:])
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"version_from: file:{file_path}: {exc}"
            raise CRAEvidenceError(msg) from exc
        for line in content.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped
        msg = f"version_from: file:{file_path}: file is empty or has no non-empty lines."
        raise CRAEvidenceError(msg)

    if version_from == "pyproject":
        pyproject_path = Path("pyproject.toml")
        try:
            content = pyproject_path.read_bytes()
        except OSError as exc:
            msg = f"version_from: pyproject: {exc}"
            raise CRAEvidenceError(msg) from exc
        try:
            data: Any = tomllib.loads(content.decode("utf-8"))
        except Exception as exc:
            msg = f"version_from: pyproject: failed to parse pyproject.toml: {exc}"
            raise CRAEvidenceError(msg) from exc
        version = (
            (data.get("project") or {}).get("version")
            or (data.get("tool", {}).get("poetry") or {}).get("version")
        )
        if not version:
            msg = (
                "version_from: pyproject: no version found under [project].version "
                "or [tool.poetry].version in pyproject.toml."
            )
            raise CRAEvidenceError(msg)
        return str(version)

    if version_from == "package.json":
        pkg_path = Path("package.json")
        try:
            content = pkg_path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"version_from: package.json: {exc}"
            raise CRAEvidenceError(msg) from exc
        try:
            pkg: Any = json.loads(content)
        except json.JSONDecodeError as exc:
            msg = f"version_from: package.json: failed to parse: {exc}"
            raise CRAEvidenceError(msg) from exc
        version = pkg.get("version")
        if not version:
            msg = "version_from: package.json: no 'version' field found."
            raise CRAEvidenceError(msg)
        return str(version)

    if version_from.startswith("env:"):
        var = version_from[4:]
        value = os.environ.get(var)
        if not value:
            msg = (
                f"version_from: env:{var}: environment variable {var!r} is not set "
                "or is empty. Set it before running this command."
            )
            raise CRAEvidenceError(msg)
        return value

    msg = (
        f"Unknown version_from directive {version_from!r}. "
        "Valid values: git-tag, file:<path>, pyproject, package.json, env:<VAR>."
    )
    raise CRAEvidenceError(msg)


def resolve_identity(
    product: str | None,
    version: str | None,
    component: str | None,
) -> tuple[str, str, str | None]:
    """Return ``(product, version, component)`` after applying resolution precedence.

    Precedence (highest to lowest):
    1. Explicit flag value (caller passes non-None)
    2. ``CRA_EVIDENCE_PRODUCT`` / ``CRA_EVIDENCE_VERSION`` / ``CRA_EVIDENCE_COMPONENT``
    3. ``.cra/evidence.yaml`` (discovered via ``find_repo_config``)

    When ``version`` is absent but the file specifies ``version_from``,
    ``resolve_version`` is called to derive it.

    Raises ``CRAEvidenceError`` if ``product`` or ``version`` cannot be resolved.
    """
    effective_product = product
    effective_version = version
    effective_component = component

    env_product = os.environ.get("CRA_EVIDENCE_PRODUCT")
    env_version = os.environ.get("CRA_EVIDENCE_VERSION")
    env_component = os.environ.get("CRA_EVIDENCE_COMPONENT")

    if effective_product is None and env_product:
        effective_product = env_product
    if effective_version is None and env_version:
        effective_version = env_version
    if effective_component is None and env_component:
        effective_component = env_component

    config_path = find_repo_config()
    repo_cfg: RepoConfig | None = None
    if config_path is not None:
        repo_cfg = load_repo_config(config_path)

    if repo_cfg is not None:
        if effective_product is None and repo_cfg.product:
            effective_product = repo_cfg.product
        if effective_component is None and repo_cfg.component:
            effective_component = repo_cfg.component

        if effective_version is None:
            if repo_cfg.version_from:
                effective_version = resolve_version(repo_cfg.version_from)

    if not effective_product:
        msg = (
            "Product is required. Pass --product, set CRA_EVIDENCE_PRODUCT, "
            "or add 'product' to .cra/evidence.yaml."
        )
        raise CRAEvidenceError(msg)

    if not effective_version:
        msg = (
            "Version is required. Pass --version, set CRA_EVIDENCE_VERSION, "
            "or add 'version_from' to .cra/evidence.yaml."
        )
        raise CRAEvidenceError(msg)

    return effective_product, effective_version, effective_component
