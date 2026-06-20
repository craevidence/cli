"""Committed-policy-file loader for ``craevidence check``.

A repository can commit a ``.cra/check.yaml`` file (auto-discovered in the
current working directory) or point at an explicit file with ``--policy-file
<path>``. The file supplies DEFAULTS for the ``check`` command. Explicit CLI
flags always WIN over file values; the override is applied by the command
layer using ``click``'s parameter-source machinery, not here. This module's
only job is to read, validate, and normalize the policy file.

Findings for CVEs listed under ``ignore`` are still SHOWN in the report
(marked as ignored); they are never silently dropped. ``ignored_set`` exposes
the normalized ids so the command layer can tag those findings.

YAML schema
-----------
All keys are optional. Unknown keys are rejected (a typo must not silently
disable a gate).

==================  ==================================================  ========
Key                 Type / allowed values                               Default
==================  ==================================================  ========
``fail_on``         one of ``critical|high|medium|known-exploited``      none
``fail_on_new``     one of ``critical|high|medium|any``                  none
``deny_license``    list of SPDX id strings (a bare string is coerced    ``[]``
                    to a one-item list)
``vex``             string (path to a VEX document)                      none
``sbom_quality``    bool                                                 none
``fail_on_score``   int in ``0..100``                                    none
``ignore``          list of CVE id strings (bare string coerced); the    ``[]``
                    ids are uppercased, stripped, de-duped, and sorted
==================  ==================================================  ========

Example ``.cra/check.yaml``::

    fail_on: high
    fail_on_new: any
    deny_license:
      - AGPL-3.0-only
      - GPL-3.0-only
    vex: security/openvex.json
    sbom_quality: true
    fail_on_score: 70
    ignore:
      - CVE-2023-0001
      - cve-2023-0002   # uppercased and sorted on load
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cra_evidence_cli.exceptions import ConfigurationError

DEFAULT_POLICY_PATH = Path(".cra/check.yaml")

_FAIL_ON_CHOICES = {"critical", "high", "medium", "known-exploited"}
_FAIL_ON_NEW_CHOICES = {"critical", "high", "medium", "any"}

_ALLOWED_KEYS = {
    "fail_on",
    "fail_on_new",
    "deny_license",
    "vex",
    "sbom_quality",
    "fail_on_score",
    "ignore",
}


@dataclass
class Policy:
    """Parsed and normalized contents of a check policy file."""

    fail_on: str | None = None
    fail_on_new: str | None = None
    deny_license: list[str] = field(default_factory=list)
    vex: str | None = None
    sbom_quality: bool | None = None
    fail_on_score: int | None = None
    ignore: list[str] = field(default_factory=list)
    source_path: Path | None = None


def _coerce_str_list(value: Any, key: str) -> list[str]:
    """Accept a bare string (-> one-item list) or a list of strings."""
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        msg = (
            f"Policy key '{key}' must be a string or a list of strings, "
            f"got {type(value).__name__}."
        )
        raise ConfigurationError(
            msg
        )
    result: list[str] = []
    for item in items:
        if not isinstance(item, str):
            msg = (
                f"Policy key '{key}' must contain only strings, "
                f"got {type(item).__name__}."
            )
            raise ConfigurationError(
                msg
            )
        result.append(item)
    return result


def _validate(data: dict[str, Any], source_path: Path) -> Policy:
    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        msg = (
            f"Unknown key(s) in policy file {source_path}: {', '.join(unknown)}. "
            f"Allowed keys: {', '.join(sorted(_ALLOWED_KEYS))}."
        )
        raise ConfigurationError(
            msg
        )

    policy = Policy(source_path=source_path)

    if "fail_on" in data and data["fail_on"] is not None:
        value = data["fail_on"]
        if not isinstance(value, str) or value.lower() not in _FAIL_ON_CHOICES:
            msg = (
                f"Policy key 'fail_on' must be one of "
                f"{', '.join(sorted(_FAIL_ON_CHOICES))}; got {value!r}."
            )
            raise ConfigurationError(
                msg
            )
        policy.fail_on = value.lower()

    if "fail_on_new" in data and data["fail_on_new"] is not None:
        value = data["fail_on_new"]
        if not isinstance(value, str) or value.lower() not in _FAIL_ON_NEW_CHOICES:
            msg = (
                f"Policy key 'fail_on_new' must be one of "
                f"{', '.join(sorted(_FAIL_ON_NEW_CHOICES))}; got {value!r}."
            )
            raise ConfigurationError(
                msg
            )
        policy.fail_on_new = value.lower()

    if "deny_license" in data and data["deny_license"] is not None:
        raw = _coerce_str_list(data["deny_license"], "deny_license")
        policy.deny_license = [item.strip() for item in raw if item.strip()]

    if "vex" in data and data["vex"] is not None:
        value = data["vex"]
        if not isinstance(value, str):
            msg = f"Policy key 'vex' must be a string, got {type(value).__name__}."
            raise ConfigurationError(
                msg
            )
        policy.vex = value

    if "sbom_quality" in data and data["sbom_quality"] is not None:
        value = data["sbom_quality"]
        if not isinstance(value, bool):
            msg = (
                f"Policy key 'sbom_quality' must be a boolean (true/false), "
                f"got {type(value).__name__}."
            )
            raise ConfigurationError(
                msg
            )
        policy.sbom_quality = value

    if "fail_on_score" in data and data["fail_on_score"] is not None:
        value = data["fail_on_score"]
        # bool is a subclass of int; reject it explicitly.
        if isinstance(value, bool) or not isinstance(value, int):
            msg = (
                f"Policy key 'fail_on_score' must be an integer in 0..100, "
                f"got {type(value).__name__}."
            )
            raise ConfigurationError(
                msg
            )
        if not (0 <= value <= 100):
            msg = f"Policy key 'fail_on_score' must be in 0..100; got {value}."
            raise ConfigurationError(
                msg
            )
        policy.fail_on_score = value

    if "ignore" in data and data["ignore"] is not None:
        raw = _coerce_str_list(data["ignore"], "ignore")
        normalized = {item.strip().upper() for item in raw if item.strip()}
        policy.ignore = sorted(normalized)

    return policy


def load_policy(explicit_path: Path | None) -> Policy | None:
    """Load a check policy file.

    If ``explicit_path`` is given it MUST exist (otherwise ``ConfigurationError``)
    and is parsed. Otherwise, if ``DEFAULT_POLICY_PATH`` exists relative to the
    current working directory it is parsed; if not, ``None`` is returned.

    Returns ``None`` only when no policy file is present (auto-discovery miss).
    An empty file yields a ``Policy`` with all defaults and ``source_path`` set.
    """
    if explicit_path is not None:
        path = explicit_path
        if not path.exists():
            msg = f"Policy file not found: {path}"
            raise ConfigurationError(msg)
    else:
        path = DEFAULT_POLICY_PATH
        if not path.exists():
            return None

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"Failed to read policy file {path}: {exc}"
        raise ConfigurationError(msg) from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"Failed to parse policy file {path}: {exc}"
        raise ConfigurationError(msg) from exc

    if data is None:
        return Policy(source_path=path)

    if not isinstance(data, dict):
        msg = (
            f"Policy file {path} must contain a YAML mapping at the top level, "
            f"got {type(data).__name__}."
        )
        raise ConfigurationError(
            msg
        )

    return _validate(data, path)


def ignored_set(policy: Policy | None) -> set[str]:
    """Return the normalized (uppercased) ignore ids from a policy.

    Accepts ``None`` (no policy) and returns an empty set.
    """
    if policy is None:
        return set()
    return {item.upper() for item in policy.ignore}
