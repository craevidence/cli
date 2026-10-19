"""Golden vectors for the concrete-v1 version-applicability classifier.

The vectors are fixed inputs with fixed expected outcomes, so another
implementation of the same policy can be compared against them. The shared
cases live in ``fixtures/version-applicability-shared.json``.
"""

import json
from pathlib import Path

import pytest

from cra_evidence_cli.local.version_applicability import (
    POLICY,
    ApplicabilityResult,
    InvalidPurlEpoch,
    MalformedMatchDetail,
    canonical_conflict_version,
    classify_occurrence,
    effective_purl_version,
    is_concrete_version,
    parse_cpe_version,
    parse_purl_version,
)


def test_policy_identifier():
    """Fails if the policy name drifts, which would make reports incomparable."""
    assert POLICY == "concrete-v1"


# --- is_concrete_version -------------------------------------------------


def test_is_concrete_version_accepts_real_versions():
    """Fails if 0 or dotted-zero versions are treated as missing or equated."""
    assert is_concrete_version("1.20") is True
    assert is_concrete_version("4.17.21") is True
    assert is_concrete_version("0") is True
    assert is_concrete_version("1.0") is True
    assert is_concrete_version("1.0.0") is True


def test_is_concrete_version_rejects_empty_and_whitespace():
    """Fails if a blank version is accepted and anchors a match-all result."""
    assert is_concrete_version("") is False
    assert is_concrete_version("   ") is False


def test_is_concrete_version_rejects_wfn_logical_values():
    """Fails if the CPE ANY or NA values count as a shipped version."""
    assert is_concrete_version("*") is False
    assert is_concrete_version("-") is False


def test_is_concrete_version_rejects_unescaped_wildcards():
    """Fails if a pattern version such as 1.* is treated as one version."""
    assert is_concrete_version("1.*") is False
    assert is_concrete_version("1.2?") is False


def test_is_concrete_version_allows_escaped_wildcard():
    """Fails if an escaped, literal wildcard character is rejected."""
    assert is_concrete_version(r"a\*b") is True


@pytest.mark.parametrize("value", ["unknown", "UNKNOWN", "Unknown", "NA", "na", "N/A", "n/a"])
def test_is_concrete_version_rejects_placeholders_case_insensitive(value):
    """Fails if a placeholder spelling is accepted as a version."""
    assert is_concrete_version(value) is False


@pytest.mark.parametrize("value", [None, 5, ["1.0"]])
def test_is_concrete_version_rejects_non_strings(value):
    """Fails if a non-string value is coerced into a version."""
    assert is_concrete_version(value) is False


# --- parse_cpe_version ---------------------------------------------------


def test_parse_cpe_version_23_formatted_string():
    """Fails if the version field of a CPE 2.3 string is read from the wrong position."""
    cpe = "cpe:2.3:o:hp:integrated_lights-out_firmware:1.20:*:*:*:*:*:*:*"
    assert parse_cpe_version(cpe) == "1.20"


def test_parse_cpe_version_23_wildcard_and_na():
    """Fails if wildcard and NA CPE versions are replaced by an empty or concrete value."""
    assert parse_cpe_version("cpe:2.3:o:hp:integrated_lights-out_firmware:*:*:*:*:*:*:*:*") == "*"
    assert parse_cpe_version("cpe:2.3:o:hp:integrated_lights-out_firmware:-:*:*:*:*:*:*:*") == "-"


def test_parse_cpe_version_escape_aware():
    """Fails if an escaped colon splits a field and shifts the version."""
    cpe = r"cpe:2.3:a:vendor:pro\:duct:2.5:*:*:*:*:*:*:*"
    assert parse_cpe_version(cpe) == "2.5"


def test_parse_cpe_version_22_uri_binding():
    """Fails if the CPE 2.2 URI binding is unsupported or invents a missing version."""
    assert parse_cpe_version("cpe:/o:hp:integrated_lights-out_firmware:1.10") == "1.10"
    assert parse_cpe_version("cpe:/o:hp:integrated_lights-out_firmware") is None


@pytest.mark.parametrize("value", ["not-a-cpe", "cpe:2.3:o:hp", "", None])
def test_parse_cpe_version_malformed_returns_none(value):
    """Fails if a malformed CPE yields a guessed version instead of None."""
    assert parse_cpe_version(value) is None


def test_parse_cpe_version_22_percent_decodes():
    """Fails if CPE 2.2 percent-encoding is left undecoded."""
    assert parse_cpe_version("cpe:/o:v:p:%241.0") == "$1.0"


def test_parse_cpe_version_truncated_23_rejected():
    """Fails if a truncated CPE 2.3 string yields a shifted field."""
    assert parse_cpe_version("cpe:2.3:o:hp:product:1.20") is None
    assert parse_cpe_version("cpe:2.3:o:hp:product:1.20:*:*") is None


# --- parse_purl_version --------------------------------------------------


def test_parse_purl_version():
    """Fails if qualifiers or subpaths leak into the version, or a missing one is invented."""
    assert parse_purl_version("pkg:npm/lodash@4.17.21") == "4.17.21"
    assert parse_purl_version("pkg:npm/lodash") is None
    assert parse_purl_version("pkg:npm/lodash@4.17.21?arch=x64") == "4.17.21"
    assert parse_purl_version("pkg:golang/x@v1.2.3#subpath") == "v1.2.3"
    assert parse_purl_version(None) is None


def test_parse_purl_version_percent_decodes():
    """Fails if an encoded PURL version is not decoded before comparison."""
    assert (
        parse_purl_version("pkg:deb/debian/libc6@2.41-12%2Bdeb13u3%2Bdhi1")
        == "2.41-12+deb13u3+dhi1"
    )


def test_classify_encoded_purl_agrees_with_plain_component_version():
    """Fails if an encoded PURL version is reported as a conflict with the plain version."""
    detail = {
        "type": "exact-direct-match",
        "searchedBy": {"package": {"name": "libc6", "version": "2.41-12+deb13u3+dhi1"}},
    }
    result = classify_occurrence(
        "2.41-12+deb13u3+dhi1",
        "pkg:deb/debian/libc6@2.41-12%2Bdeb13u3%2Bdhi1",
        [detail],
    )
    assert result.status == "confirmed"
    assert result.reason is None


# --- RPM epoch handling --------------------------------------------------


@pytest.mark.parametrize("epoch", ["2", "%32", "0002"])
@pytest.mark.parametrize("match_type", ["exact-direct-match", "exact-indirect-match"])
def test_rpm_epoch_qualifier_agrees_with_shipped_version(epoch, match_type):
    """Fails if the RPM epoch qualifier is ignored and an authentic shape is demoted."""
    version = "2:1.34-13.el9_8"
    purl = f"pkg:rpm/redhat/tar@1.34-13.el9_8?arch=x86_64&epoch={epoch}"
    detail = {"type": match_type, "searchedBy": {"package": {"version": version}}}
    cpe = r"cpe:2.3:a:redhat:tar:2\:1.34-13.el9_8:*:*:*:*:*:*:*"
    result = classify_occurrence(version, purl, [detail], [cpe])
    assert result.status == "confirmed"
    assert result.anchored_details == [detail]
    assert result.evidence["purl"] == purl
    assert result.evidence["concrete_versions"] == [version]
    assert parse_purl_version(purl) == "1.34-13.el9_8"


@pytest.mark.parametrize("qualifier", ["", "?epoch=0", "?epoch=%30", "?epoch=000"])
def test_rpm_zero_epoch_still_agrees_with_implicit_zero(qualifier):
    """Fails if an explicit zero epoch contradicts the engine-added 0: prefix."""
    detail = {
        "type": "exact-direct-match",
        "searchedBy": {"package": {"version": "0:1.34-13.el9_8"}},
    }
    result = classify_occurrence(
        "1.34-13.el9_8", "pkg:rpm/redhat/tar@1.34-13.el9_8" + qualifier, [detail]
    )
    assert result.status == "confirmed"


def test_rpm_decimal_epoch_spelling_agrees_across_all_declarations():
    """Fails if leading-zero epochs in version, PURL and CPE are compared as raw text."""
    version = "02:1.34-13.el9_8"
    purl = "pkg:rpm/redhat/tar@1.34-13.el9_8?epoch=2"
    cpe = r"cpe:2.3:a:redhat:tar:02\:1.34-13.el9_8:*:*:*:*:*:*:*"
    details = [
        {"type": "exact-direct-match", "searchedBy": {"package": {"version": version}}},
        {"type": "cpe-match", "searchedBy": {"cpes": [cpe]}},
    ]
    result = classify_occurrence(version, purl, details, [cpe])
    assert result.status == "confirmed"
    assert result.evidence["component_version"] == version
    assert result.evidence["concrete_versions"] == ["2:1.34-13.el9_8"]


@pytest.mark.parametrize(
    "purl",
    ["pkg:deb/debian/tar@1%3A1.34?epoch=2", "pkg:pypi/tar@1%3A1.34?epoch=2"],
)
def test_debian_and_python_epoch_qualifiers_keep_their_existing_semantics(purl):
    """Fails if the RPM epoch rule is applied to non-RPM ecosystems."""
    detail = {
        "type": "exact-direct-match",
        "searchedBy": {"package": {"version": "1:1.34"}},
    }
    assert classify_occurrence("1:1.34", purl, [detail]).status == "confirmed"


def test_rpm_different_positive_epoch_remains_a_conflict():
    """Fails if two different non-zero epochs are normalised into agreement."""
    detail = {
        "type": "exact-direct-match",
        "searchedBy": {"package": {"version": "2:1.34-13.el9_8"}},
    }
    result = classify_occurrence(
        "2:1.34-13.el9_8", "pkg:rpm/redhat/tar@1.34-13.el9_8?epoch=1", [detail]
    )
    assert result.status == "indicative"
    assert result.reason == "version_conflict"


@pytest.mark.parametrize(
    "qualifier",
    [
        "epoch=",
        "epoch",
        "epoch=-1",
        "epoch=+1",
        "epoch=%201",
        "epoch=one",
        "epoch=١",
        "epoch=1&epoch=1",
        "epoch=1&epoch=2",
        "epoch=1&%65poch=1",
    ],
)
def test_malformed_rpm_epoch_cannot_be_ignored(qualifier):
    """Fails if an invalid or repeated RPM epoch qualifier is silently skipped."""
    detail = {
        "type": "exact-direct-match",
        "searchedBy": {"package": {"version": "1.34-13.el9_8"}},
    }
    with pytest.raises(InvalidPurlEpoch):
        classify_occurrence(
            "1.34-13.el9_8", "pkg:rpm/redhat/tar@1.34-13.el9_8?" + qualifier, [detail]
        )


def test_epoch_interpretation_does_not_change_non_rpm_or_make_a_version():
    """Fails if an epoch qualifier alters a non-RPM version or invents a missing one."""
    assert effective_purl_version("pkg:npm/widget@1.2.3?epoch=2") == "1.2.3"
    assert effective_purl_version("pkg:rpm/redhat/tar?epoch=2") is None
    assert effective_purl_version("pkg:rpm/redhat/tar@1.34#subpath?epoch=2") == "1.34"


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:rpm/redhat/tar?upstream=source@1.34&epoch=2",
        "pkg:rpm/redhat/tar?epoch=2#source@1.34",
    ],
)
def test_rpm_qualifier_or_subpath_at_sign_is_not_a_version(purl):
    """Fails if an at sign inside a qualifier or subpath is read as the version."""
    assert effective_purl_version(purl) is None


@pytest.mark.parametrize("version", ["unknown", "NA", "N/A", "*", "-"])
def test_rpm_epoch_does_not_make_a_placeholder_version_concrete(version):
    """Fails if adding an epoch qualifier turns a placeholder into a concrete version."""
    value = effective_purl_version(f"pkg:rpm/redhat/tar@{version}?epoch=2")
    assert value == version
    assert not is_concrete_version(value)


@pytest.mark.parametrize(
    ("token", "expected"),
    [("2%3Aunknown", "unknown"), ("02%3ANA", "NA"), ("2%3A%2A", "*")],
)
def test_matching_rpm_epoch_prefix_does_not_make_placeholder_concrete(token, expected):
    """Fails if a matching epoch prefix hides a placeholder behind a concrete-looking value."""
    value = effective_purl_version(f"pkg:rpm/redhat/tar@{token}?epoch=2")
    assert value == expected
    assert not is_concrete_version(value)


def test_canonical_conflict_version_strips_zero_epoch_only():
    """Fails if a non-zero epoch is stripped or a zero epoch is kept."""
    assert canonical_conflict_version("0:3.79.0-17.el9_1") == "3.79.0-17.el9_1"
    assert canonical_conflict_version("3.79.0-17.el9_1") == "3.79.0-17.el9_1"
    assert canonical_conflict_version("1:2.3") == "1:2.3"


# --- shared occurrence vectors -------------------------------------------

_SHARED_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "version-applicability-shared.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", _SHARED_VECTORS, ids=lambda case: case["id"])
def test_shared_occurrence_version_contract(case):
    """Fails if any shared vector's status, reason or refusal differs from the policy."""
    args = (
        case["component_version"],
        case["purl"],
        case["match_details"],
        case.get("declared_cpes"),
    )
    expected = case["expected"]
    if "error" in expected:
        errors = {
            "InvalidPurlEpoch": InvalidPurlEpoch,
            "MalformedMatchDetail": MalformedMatchDetail,
        }
        with pytest.raises(errors[expected["error"]]):
            classify_occurrence(*args)
    else:
        result = classify_occurrence(*args)
        assert (result.status, result.reason) == (expected["status"], expected["reason"])


# --- classify_occurrence: CPE ---------------------------------------------


def _cpe_detail(cpe, package_version):
    return {
        "type": "cpe-match",
        "searchedBy": {
            "namespace": "nvd:cpe",
            "cpes": [cpe],
            "package": {"name": "ilo-fw", "version": package_version},
        },
    }


_ILO_120 = "cpe:2.3:o:hp:integrated_lights-out_firmware:1.20:*:*:*:*:*:*:*"
_ILO_110 = "cpe:2.3:o:hp:integrated_lights-out_firmware:1.10:*:*:*:*:*:*:*"
_ILO_ANY = "cpe:2.3:o:hp:integrated_lights-out_firmware:*:*:*:*:*:*:*:*"


def test_classify_confirmed_concrete_cpe():
    """Fails if a concrete CPE match is not confirmed or loses its detail."""
    detail = _cpe_detail(_ILO_120, "1.20")
    result = classify_occurrence("1.20", None, [detail])
    assert result.status == "confirmed"
    assert result.reason is None
    assert result.anchored_details == [detail]


def test_classify_confirmed_by_cpe_even_when_component_version_absent():
    """Fails if a concrete CPE alone cannot anchor a component without a version."""
    detail = _cpe_detail(_ILO_120, "")
    result = classify_occurrence("", None, [detail])
    assert result.status == "confirmed"
    assert result.anchored_details == [detail]


def test_classify_indicative_unversioned_cpe():
    """Fails if a wildcard CPE on an unversioned component is confirmed."""
    detail = _cpe_detail(_ILO_ANY, "")
    result = classify_occurrence("", None, [detail])
    assert result.status == "indicative"
    assert result.reason == "unversioned"
    assert result.anchored_details == []


def test_classify_version_conflict_cpe_vs_component():
    """Fails if a CPE at 1.10 on a component shipped as 1.20 is confirmed."""
    detail = _cpe_detail(_ILO_110, "1.20")
    result = classify_occurrence("1.20", None, [detail])
    assert result.status == "indicative"
    assert result.reason == "version_conflict"
    assert result.anchored_details == []
    assert result.evidence["concrete_versions"] == ["1.10", "1.20"]


def test_classify_merged_concrete_plus_wildcard_keeps_only_anchored_detail():
    """Fails if a match-all detail stays as evidence beside a concrete one."""
    concrete = _cpe_detail(_ILO_120, "1.20")
    wildcard = _cpe_detail(_ILO_ANY, "")
    result = classify_occurrence("1.20", None, [concrete, wildcard])
    assert result.status == "confirmed"
    assert result.anchored_details == [concrete]
    assert wildcard not in result.anchored_details


def test_classify_exact_only_wildcard_supported_finding_is_indicative():
    """Fails if a declared component version lets a wildcard-only match be confirmed."""
    wildcard = _cpe_detail(_ILO_ANY, "")
    result = classify_occurrence("1.20", None, [wildcard])
    assert result.status == "indicative"
    assert result.reason == "unversioned"


def test_classify_mixed_cpe_in_one_detail_confirms_and_retains_only_concrete():
    """Fails if the wildcard CPE of a mixed detail is kept as confirmed support."""
    detail = {"type": "cpe-match", "searchedBy": {"cpes": [_ILO_ANY, _ILO_120]}}
    result = classify_occurrence(None, None, [detail])
    assert result.status == "confirmed"
    assert result.reason is None
    assert len(result.anchored_details) == 1
    assert result.anchored_details[0]["searchedBy"]["cpes"] == [_ILO_120]


def test_classify_wildcard_only_cpe_detail_is_indicative():
    """Fails if a detail with only a wildcard CPE anchors the finding."""
    detail = {"type": "cpe-match", "searchedBy": {"cpes": [_ILO_ANY]}}
    result = classify_occurrence(None, None, [detail])
    assert result.status == "indicative"
    assert result.reason == "unversioned"


def test_classify_cpe_escaped_colon_agrees_with_plain_component():
    """Fails if an escaped colon in a CPE version is reported as a false conflict."""
    detail = {
        "type": "cpe-match",
        "searchedBy": {"cpes": [r"cpe:2.3:a:v:p:1\:3.2:*:*:*:*:*:*:*"]},
    }
    result = classify_occurrence("1:3.2", None, [detail])
    assert result.status == "confirmed"
    assert result.reason is None


# --- classify_occurrence: PURL / ecosystem ---------------------------------


def _purl_detail(package_version):
    return {
        "type": "exact-direct-match",
        "searchedBy": {
            "language": "javascript",
            "namespace": "github:language:javascript",
            "package": {"name": "lodash", "version": package_version},
        },
    }


def test_classify_confirmed_concrete_purl():
    """Fails if a concrete PURL match is not confirmed."""
    detail = _purl_detail("4.17.21")
    result = classify_occurrence("4.17.21", "pkg:npm/lodash@4.17.21", [detail])
    assert result.status == "confirmed"
    assert result.anchored_details == [detail]


def test_classify_indicative_unversioned_purl():
    """Fails if a versionless PURL with an empty searched version is confirmed."""
    detail = _purl_detail("")
    result = classify_occurrence("", "pkg:npm/lodash", [detail])
    assert result.status == "indicative"
    assert result.reason == "unversioned"


def test_classify_version_conflict_purl_vs_component():
    """Fails if a PURL version that contradicts the component version is confirmed."""
    detail = _purl_detail("4.17.20")
    result = classify_occurrence("4.17.20", "pkg:npm/lodash@99.0.0", [detail])
    assert result.status == "indicative"
    assert result.reason == "version_conflict"
    assert result.evidence["concrete_versions"] == ["4.17.20", "99.0.0"]


# --- match-type-aware occurrence set ---------------------------------------


def test_classify_rpm_direct_epoch_normalized_is_confirmed():
    """Fails if the engine-added 0: epoch on an RPM direct match causes a conflict."""
    detail = {
        "type": "exact-direct-match",
        "searchedBy": {"package": {"name": "nss", "version": "0:3.79.0-17.el9_1"}},
    }
    result = classify_occurrence(
        "3.79.0-17.el9_1", "pkg:rpm/rhel/nss@3.79.0-17.el9_1?arch=x86_64", [detail]
    )
    assert result.status == "confirmed"
    assert result.reason is None
    assert result.evidence["concrete_versions"] == ["3.79.0-17.el9_1"]


def test_classify_rpm_indirect_upstream_version_excluded_from_conflict():
    """Fails if an upstream source package version counts as a conflict with the artifact."""
    detail = {
        "type": "exact-indirect-match",
        "searchedBy": {"package": {"name": "nss", "version": "3.79.0-17.el9_1"}},
    }
    result = classify_occurrence(
        "4.34.0-17.el9_1", "pkg:rpm/rhel/nspr@4.34.0-17.el9_1?arch=x86_64", [detail]
    )
    assert result.status == "confirmed"
    assert result.reason is None
    assert result.evidence["concrete_versions"] == ["4.34.0-17.el9_1"]
    assert result.anchored_details == [detail]


# --- declared (input) CPEs --------------------------------------------------


def test_classify_declared_cpe_conflict_is_observable():
    """Fails if a declared CPE that contradicts the version is ignored."""
    detail = {
        "type": "exact-direct-match",
        "searchedBy": {"package": {"name": "lodash", "version": "4.17.21"}},
    }
    result = classify_occurrence(
        "4.17.21", "pkg:npm/lodash@4.17.21", [detail], declared_cpes=[_ILO_110]
    )
    assert result.status == "indicative"
    assert result.reason == "version_conflict"
    assert result.evidence["concrete_versions"] == ["1.10", "4.17.21"]


def test_classify_declared_wildcard_cpe_does_not_conflict():
    """Fails if a wildcard declared CPE is treated as a concrete, conflicting version."""
    detail = {
        "type": "exact-direct-match",
        "searchedBy": {"package": {"name": "lodash", "version": "4.17.21"}},
    }
    result = classify_occurrence(
        "4.17.21",
        "pkg:npm/lodash@4.17.21",
        [detail],
        declared_cpes=["cpe:2.3:a:acme:lodash:*:*:*:*:*:*:*:*"],
    )
    assert result.status == "confirmed"


# --- fail closed on missing, malformed or unknown shapes ---------------------


@pytest.mark.parametrize("details", [[], None, "not-a-list"])
def test_classify_missing_or_non_list_details_fail_closed(details):
    """Fails if a finding without usable match details is confirmed or dropped."""
    with pytest.raises(MalformedMatchDetail):
        classify_occurrence("1.20", None, details)


def test_classify_unknown_match_type_fails_closed():
    """Fails if a future match type is quietly treated as a known one."""
    detail = {"type": "future-unknown-match", "searchedBy": {"package": {"version": "1.0"}}}
    with pytest.raises(MalformedMatchDetail):
        classify_occurrence("1.0", None, [detail])


def test_classify_missing_match_type_fails_closed():
    """Fails if a detail without a type is accepted."""
    detail = {"searchedBy": {"package": {"version": "1.0"}}}
    with pytest.raises(MalformedMatchDetail):
        classify_occurrence("1.0", None, [detail])


def test_classify_non_dict_detail_fails_closed():
    """Fails if a detail that is not an object is skipped."""
    with pytest.raises(MalformedMatchDetail):
        classify_occurrence("1.20", None, ["garbage"])


def test_classify_cpe_match_without_cpes_fails_closed():
    """Fails if a cpe-match without CPE evidence is accepted."""
    with pytest.raises(MalformedMatchDetail):
        classify_occurrence("1.20", None, [{"type": "cpe-match"}])


def test_classify_cpe_match_no_valid_cpe_evidence_fails_closed():
    """Fails if a cpe-match whose CPEs are all unparseable is accepted."""
    detail = {"type": "cpe-match", "searchedBy": {"cpes": ["not-a-cpe", 12345]}}
    with pytest.raises(MalformedMatchDetail):
        classify_occurrence("", None, [detail])


def test_classify_direct_match_missing_version_is_indicative_not_fatal():
    """Fails if an exact match without a searched version aborts instead of being indicative."""
    detail = {"type": "exact-direct-match", "searchedBy": {"package": {}}}
    result = classify_occurrence("", None, [detail])
    assert result.status == "indicative"
    assert result.reason == "unversioned"


def test_result_is_dataclass_shape():
    """Fails if the evidence record loses or renames a field another copy compares."""
    detail = {"type": "exact-direct-match", "searchedBy": {"package": {"version": "1.20"}}}
    result = classify_occurrence("1.20", None, [detail])
    assert isinstance(result, ApplicabilityResult)
    assert set(result.evidence) == {
        "component_version",
        "purl",
        "declared_cpes",
        "searched_cpes",
        "searched_cpe_versions",
        "declared_cpe_versions",
        "package_versions",
        "concrete_versions",
    }
