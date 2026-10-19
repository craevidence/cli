"""Concrete-version applicability classifier (policy ``concrete-v1``).

A Grype match is only trustworthy when the shipped component version is known
concretely. Grype substitutes an empty, wildcard or placeholder version with a
match-all criterion, so an unversioned CPE or PURL returns the whole catalogue
for a product. It also prefers a declared CPE version over the component
version, so a CPE at ``1.10`` on a component shipped as ``1.20`` reports the
``1.10`` findings against the wrong version.

This module decides, per component occurrence, whether a candidate is
version-anchored (``confirmed``) or not (``indicative``), and whether the
occurrence's own declarations contradict each other (``version_conflict``). It
is pure: no I/O, no subprocess and no vulnerability knowledge.

Two concepts are kept apart, following the engine's match semantics:

* Declaration agreement for the same occurrence. The shipped version is declared
  by the component version, its PURL version, its declared (input) CPEs and, for
  a same-package match, the engine's searched CPE and direct-match package
  version. These must agree. RPM direct matching adds a ``0:`` epoch to the
  searched copy and a CPE binding escapes or percent-encodes the version, so the
  comparison is canonical, not raw string equality.
* Engine evidence proving the match. A match detail anchors the finding only
  when it carries a concrete searched version. An ``exact-indirect-match``
  searches an upstream or source package that differs from the result artifact,
  so its searched version anchors the match but never enters the occurrence's
  version-conflict set.

An unknown or missing match-detail type, a finding with no match details, or a
``cpe-match`` without parseable CPE evidence is malformed and raises
:class:`MalformedMatchDetail`; the caller treats the engine output as malformed
rather than reclassifying it. No SemVer equivalence is imposed: firmware, OS and
ecosystem versions have different grammars, so ``1.0`` and ``1.0.0`` are
distinct.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote

# CPE 2.3 logical values ANY and NA. A version segment holding either is not a
# concrete shipped version.
_WFN_ANY = "*"
_WFN_NA = "-"

# Case-insensitive placeholder strings treated as "no real version".
_PLACEHOLDER_VERSIONS = frozenset({"unknown", "na", "n/a", "noassertion"})

POLICY = "concrete-v1"

# Closed match-detail type enum reported by the engine.
MATCH_TYPE_DIRECT = "exact-direct-match"
MATCH_TYPE_INDIRECT = "exact-indirect-match"
MATCH_TYPE_CPE = "cpe-match"
VALID_MATCH_TYPES = frozenset({MATCH_TYPE_DIRECT, MATCH_TYPE_INDIRECT, MATCH_TYPE_CPE})

# Closed reason enum for indicative candidates.
REASON_UNVERSIONED = "unversioned"
REASON_VERSION_CONFLICT = "version_conflict"

# A leading RPM-style epoch: one or more digits, then a colon.
_EPOCH_RE = re.compile(r"^(\d+):(.+)$")


class MalformedMatchDetail(ValueError):  # noqa: N818
    """A finding carried an unknown, missing or malformed match shape.

    Raised for an unknown or missing ``matchDetails[].type``, a finding with no
    match details, or a ``cpe-match`` with no parseable CPE evidence.
    """


class InvalidPurlEpoch(MalformedMatchDetail):  # noqa: N818
    """An RPM PURL carries an invalid or ambiguous epoch declaration."""


def _has_unescaped_wildcard(value: str) -> bool:
    """True if ``value`` contains a ``*`` or ``?`` not escaped by a backslash."""
    i = 0
    length = len(value)
    while i < length:
        char = value[i]
        if char == "\\":
            i += 2
            continue
        if char in ("*", "?"):
            return True
        i += 1
    return False


def is_concrete_version(value: object) -> bool:
    """Return True only when ``value`` is a concrete shipped version.

    All of the following must hold:
    1. it is a string and remains nonempty after trimming;
    2. it is not CPE ANY (``*``) or CPE NA (``-``);
    3. it contains no unescaped wildcard character (``*`` or ``?``);
    4. it is not a case-insensitive placeholder (``unknown``, ``NA``, ``N/A``,
       or ``NOASSERTION``, which SPDX writes when no version is asserted).

    ``0`` is concrete. No SemVer canonicalization is applied. Callers pass the
    logical (unbound or decoded) version, so CPE binding escapes are already gone.
    """
    if not isinstance(value, str):
        return False
    trimmed = value.strip()
    if not trimmed:
        return False
    if trimmed in (_WFN_ANY, _WFN_NA):
        return False
    if _has_unescaped_wildcard(trimmed):
        return False
    return trimmed.lower() not in _PLACEHOLDER_VERSIONS


def canonical_conflict_version(value: str) -> str:
    """Canonicalise a concrete version for same-occurrence conflict comparison.

    Normalises a zero epoch so the ``0:`` epoch the engine adds to an RPM direct
    match does not contradict the un-epoched artifact version:
    ``0:3.79.0-17.el9_1`` and ``3.79.0-17.el9_1`` compare equal. A non-zero
    epoch is preserved because it delimits a distinct version lineage, so
    ``1:2.3`` and ``2.3`` still differ.
    """
    trimmed = value.strip()
    match = _EPOCH_RE.match(trimmed)
    if match and int(match.group(1)) == 0:
        return match.group(2)
    return trimmed


def _split_unescaped(value: str, sep: str) -> list[str]:
    """Split ``value`` on ``sep``, honouring backslash escapes."""
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        char = value[i]
        if char == "\\" and i + 1 < n:
            buf.append(value[i : i + 2])
            i += 2
            continue
        if char == sep:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(char)
        i += 1
    parts.append("".join(buf))
    return parts


def _unescape_fs(value: str) -> str:
    """Unbind a CPE 2.3 formatted-string value: drop one backslash per escape."""
    out: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        if value[i] == "\\" and i + 1 < n:
            out.append(value[i + 1])
            i += 2
            continue
        out.append(value[i])
        i += 1
    return "".join(out)


def parse_cpe_version(cpe: object) -> str | None:
    """Return the logical version of a CPE 2.3 or 2.2 string, else ``None``.

    Structurally strict and binding-aware. A CPE 2.3 formatted string must carry
    all 13 colon-separated components; a truncated string returns ``None``
    instead of a shifted field. The extracted version is unbound to its logical
    value: CPE 2.3 escapes are removed (``1\\:3.2`` becomes ``1:3.2``) and CPE
    2.2 URI percent-encoding is decoded (``%241.0`` becomes ``$1.0``), so a
    version bound in a CPE compares equal to the same version declared plainly.
    Grype rewrites a searched CPE to its effective version, so this reads the
    post-substitution value, which may be ``*``, ``-`` or empty.
    """
    if not isinstance(cpe, str) or not cpe:
        return None
    if cpe.startswith("cpe:2.3:"):
        parts = _split_unescaped(cpe, ":")
        # cpe + 2.3 + 11 attributes = 13 tokens for a well-formed string.
        if len(parts) != 13:
            return None
        return _unescape_fs(parts[5])
    if cpe.startswith("cpe:/"):
        parts = _split_unescaped(cpe[len("cpe:/") :], ":")
        if 4 <= len(parts) <= 7:
            return unquote(parts[3])
        return None
    return None


def parse_purl_version(purl: object) -> str | None:
    """Return the version of a package URL (the ``@version`` segment), else None.

    Stops at the qualifier (``?``) or subpath (``#``) delimiter, then
    percent-decodes the token: the PURL specification percent-encodes the version
    component (a Debian ``2.41-12+deb13u3`` is encoded ``2.41-12%2Bdeb13u3``)
    while the component and searched package versions are plain strings, so
    decoding is required to compare them without a false conflict.
    """
    if not isinstance(purl, str) or "@" not in purl:
        return None
    after = purl.split("@", 1)[1]
    for delimiter in ("?", "#"):
        if delimiter in after:
            after = after.split(delimiter, 1)[0]
    if not after:
        return None
    return unquote(after)


def is_rpm_purl(purl: object) -> bool:
    if not isinstance(purl, str):
        return False
    scheme, separator, remainder = purl.partition(":")
    return (
        separator == ":"
        and scheme.lower() == "pkg"
        and remainder.lstrip("/").split("/", 1)[0].lower() == "rpm"
    )


def canonical_rpm_conflict_version(value: str) -> str:
    """Canonicalise decimal RPM epochs without changing other version text."""
    trimmed = value.strip()
    match = re.fullmatch(r"([0-9]+):(.+)", trimmed)
    if not match:
        return trimmed
    epoch = match.group(1).lstrip("0") or "0"
    return match.group(2) if epoch == "0" else f"{epoch}:{match.group(2)}"


def effective_purl_version(purl: object) -> str | None:
    """Include RPM's separate epoch qualifier in its comparison version."""
    version = parse_purl_version(purl)
    if not is_rpm_purl(purl):
        return version
    before_query, _, query = purl.split("#", 1)[0].partition("?")
    token = before_query.split("@", 1)[1] if "@" in before_query else ""
    version = unquote(token) if token else None
    epochs = [
        unquote(value)
        for qualifier in query.split("&")
        for key, _, value in [qualifier.partition("=")]
        if unquote(key).lower() == "epoch"
    ]
    if not epochs:
        return version
    if len(epochs) != 1 or re.fullmatch(r"[0-9]+", epochs[0]) is None:
        msg = "RPM PURL has an invalid or ambiguous epoch"
        raise InvalidPurlEpoch(msg)
    epoch = epochs[0].lstrip("0") or "0"
    prefix = re.fullmatch(r"([0-9]+):(.+)", version) if version is not None else None
    if prefix and (prefix.group(1).lstrip("0") or "0") != epoch:
        msg = "RPM PURL has contradictory epoch declarations"
        raise InvalidPurlEpoch(msg)
    if prefix and not is_concrete_version(prefix.group(2)):
        return prefix.group(2)
    if not is_concrete_version(version):
        return version
    if prefix:
        return f"{epoch}:{prefix.group(2)}"
    return f"{epoch}:{version}"


@dataclass
class _DetailFacts:
    """Per-match-detail facts, computed fail-closed and match-type-aware.

    ``conflict_values`` are canonical concrete versions that describe the same
    occurrence (empty for an indirect match, whose searched package differs).
    ``anchored`` is True when the detail carries a concrete searched version.
    ``retained_detail`` is the detail to keep as confirmed evidence (a cpe-match
    is pruned to its concrete CPEs), or ``None`` when the detail does not anchor.
    ``cpes``, ``cpe_versions`` and ``package_version`` feed the evidence record.
    """

    conflict_values: list[str] = field(default_factory=list)
    anchored: bool = False
    retained_detail: object | None = None
    cpes: list[str] = field(default_factory=list)
    cpe_versions: list[str] = field(default_factory=list)
    package_version: str | None = None


def _detail_facts(detail: object) -> _DetailFacts:
    """Extract version facts from one Grype match detail, match-type-aware.

    Raises :class:`MalformedMatchDetail` for an unknown or missing type, or a
    ``cpe-match`` with no parseable CPE evidence.
    """
    if not isinstance(detail, dict):
        msg = "match detail is not an object"
        raise MalformedMatchDetail(msg)
    mtype = detail.get("type")
    if mtype not in VALID_MATCH_TYPES:
        msg = f"unknown match-detail type {mtype!r}"
        raise MalformedMatchDetail(msg)

    searched = detail.get("searchedBy")
    searched = searched if isinstance(searched, dict) else {}

    if mtype == MATCH_TYPE_CPE:
        raw_cpes = searched.get("cpes")
        if not isinstance(raw_cpes, list) or not raw_cpes:
            msg = "cpe-match carries no CPE evidence"
            raise MalformedMatchDetail(msg)
        parseable_any = False
        concrete_cpes: list[str] = []
        cpe_versions: list[str] = []
        conflict_values: list[str] = []
        for entry in raw_cpes:
            if not isinstance(entry, str):
                continue
            version = parse_cpe_version(entry)
            if version is None:
                # Structurally unparseable CPE: drop it, do not vouch for it.
                continue
            parseable_any = True
            cpe_versions.append(version)
            if is_concrete_version(version):
                # Classify per CPE: a concrete CPE anchors the detail; a wildcard
                # CPE in the same detail neither anchors nor is retained.
                concrete_cpes.append(entry)
                conflict_values.append(canonical_conflict_version(version))
        if not parseable_any:
            msg = "cpe-match has no valid CPE evidence"
            raise MalformedMatchDetail(msg)
        anchored = bool(concrete_cpes)
        retained = None
        if anchored:
            pruned = dict(detail)
            pruned_searched = dict(searched)
            pruned_searched["cpes"] = concrete_cpes
            pruned["searchedBy"] = pruned_searched
            retained = pruned
        return _DetailFacts(
            conflict_values=conflict_values,
            anchored=anchored,
            retained_detail=retained,
            cpes=[c for c in raw_cpes if isinstance(c, str)],
            cpe_versions=cpe_versions,
        )

    # exact-direct-match / exact-indirect-match: keyed on the searched package.
    package = searched.get("package")
    raw_version = package.get("version") if isinstance(package, dict) else None
    package_version = raw_version if isinstance(raw_version, str) else None
    anchored = is_concrete_version(package_version)
    # A direct match searches the same package as the artifact, so its version
    # participates in conflict detection (epoch-normalised). An indirect match
    # searches a different upstream or source package, so its version anchors
    # the match but never contradicts the artifact version.
    conflict_values = (
        [canonical_conflict_version(package_version)]
        if anchored and mtype == MATCH_TYPE_DIRECT
        else []
    )
    return _DetailFacts(
        conflict_values=conflict_values,
        anchored=anchored,
        retained_detail=detail if anchored else None,
        package_version=package_version,
    )


@dataclass
class ApplicabilityResult:
    """Outcome of classifying one merged finding's component occurrence.

    ``status`` is ``"confirmed"`` or ``"indicative"``. ``reason`` is ``None`` for
    a confirmed finding, else ``"unversioned"`` or ``"version_conflict"``.
    ``anchored_details`` is the subset of the finding's match details that
    independently anchored it (confirmed only; unanchored details are discarded
    and a mixed cpe-match is pruned to its concrete CPEs). ``evidence`` explains
    the decision.
    """

    status: str
    reason: str | None
    anchored_details: list[object]
    evidence: dict


def classify_occurrence(
    component_version: object,
    purl: object,
    match_details: object,
    declared_cpes: object = None,
) -> ApplicabilityResult:
    """Classify one merged finding under ``concrete-v1``.

    ``component_version`` is the artifact version, ``purl`` the artifact PURL,
    ``match_details`` the finding's merged Grype match details and
    ``declared_cpes`` the artifact's own declared CPEs. The occurrence is a
    ``version_conflict`` when two or more of its concrete same-package
    declarations (component version, PURL version, declared CPE versions,
    searched CPE versions, direct-match package versions) disagree after
    canonicalisation; then no candidate is confirmed. Otherwise the finding is
    confirmed when at least one match detail is independently version-anchored
    (unanchored details are dropped from the confirmed evidence), and
    indicative (``unversioned``) when none is.

    Raises :class:`MalformedMatchDetail` when ``match_details`` is empty or not a
    list, or when any detail has an unknown type or a ``cpe-match`` with no
    valid CPE evidence.
    """
    if not isinstance(match_details, list) or not match_details:
        msg = "finding has no match details"
        raise MalformedMatchDetail(msg)

    facts = [_detail_facts(detail) for detail in match_details]

    # Same-occurrence declarations (canonical concrete values).
    conflict_values: list[str] = []
    if is_concrete_version(component_version):
        conflict_values.append(canonical_conflict_version(component_version))
    purl_version = effective_purl_version(purl)
    if is_concrete_version(purl_version):
        conflict_values.append(canonical_conflict_version(purl_version))

    declared_cpe_list: list[str] = []
    if isinstance(declared_cpes, list | tuple):
        declared_cpe_list = [c for c in declared_cpes if isinstance(c, str)]
    declared_cpe_versions: list[str] = []
    for entry in declared_cpe_list:
        version = parse_cpe_version(entry)
        if version is None:
            continue
        declared_cpe_versions.append(version)
        if is_concrete_version(version):
            conflict_values.append(canonical_conflict_version(version))

    searched_cpes: list[str] = []
    searched_cpe_versions: list[str] = []
    package_versions: list[str] = []
    for fact in facts:
        searched_cpes.extend(fact.cpes)
        searched_cpe_versions.extend(fact.cpe_versions)
        if fact.package_version is not None:
            package_versions.append(fact.package_version)
        conflict_values.extend(fact.conflict_values)

    if is_rpm_purl(purl):
        conflict_values = [canonical_rpm_conflict_version(value) for value in conflict_values]
    distinct = sorted(set(conflict_values))

    evidence = {
        "component_version": (
            component_version if isinstance(component_version, str) and component_version else None
        ),
        "purl": purl if isinstance(purl, str) and purl else None,
        "declared_cpes": sorted(set(declared_cpe_list)),
        "searched_cpes": sorted(set(searched_cpes)),
        "searched_cpe_versions": sorted(set(searched_cpe_versions)),
        "declared_cpe_versions": sorted(set(declared_cpe_versions)),
        "package_versions": sorted(set(package_versions)),
        "concrete_versions": distinct,
    }

    if len(distinct) > 1:
        return ApplicabilityResult(
            status="indicative",
            reason=REASON_VERSION_CONFLICT,
            anchored_details=[],
            evidence=evidence,
        )

    anchored = [fact.retained_detail for fact in facts if fact.anchored]
    if anchored:
        return ApplicabilityResult(
            status="confirmed",
            reason=None,
            anchored_details=anchored,
            evidence=evidence,
        )
    return ApplicabilityResult(
        status="indicative",
        reason=REASON_UNVERSIONED,
        anchored_details=[],
        evidence=evidence,
    )
