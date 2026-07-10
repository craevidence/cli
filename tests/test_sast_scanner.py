"""Unit tests for the local SAST scanner module. No opengrep binary required."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cra_evidence_cli.local.sast_scanner import (
    _DEFAULT_EXCLUDES,
    _parse_cwe_tags,
    _parse_sarif,
    get_version,
    run_scan,
)

_BINARY = "/usr/bin/opengrep"
_OPENGREP_PATH_PATCH = "cra_evidence_cli.local.sast_scanner.opengrep_path"
_SUBPROCESS_PATCH = "cra_evidence_cli.local.sast_scanner.subprocess.run"
_GET_VERSION_PATCH = "cra_evidence_cli.local.sast_scanner.get_version"


# ---------------------------------------------------------------------------
# A1. SARIF structural edge cases
# ---------------------------------------------------------------------------


def test_parse_sarif_missing_runs_key():
    findings = _parse_sarif({})
    assert findings == []


def test_parse_sarif_empty_runs_list():
    findings = _parse_sarif({"runs": []})
    assert findings == []


def test_parse_sarif_run_missing_results_key():
    doc = {"runs": [{"tool": {"driver": {"name": "x", "rules": []}}}]}
    findings = _parse_sarif(doc)
    assert findings == []


def test_parse_sarif_run_empty_results_list():
    doc = {"runs": [{"tool": {"driver": {"name": "x", "rules": []}}, "results": []}]}
    findings = _parse_sarif(doc)
    assert findings == []


# ---------------------------------------------------------------------------
# A2. Engine exits 0 but SARIF file missing or invalid JSON -> scan_failed
# ---------------------------------------------------------------------------




def test_sarif_file_missing_after_exit_zero_is_scan_failed(tmp_path):
    """Engine exits 0 but writes no SARIF file -> scan_failed, not a clean result."""
    import tempfile

    captured: list[Path] = []
    original_ntf = tempfile.NamedTemporaryFile

    def capturing_ntf(*a, **kw):
        f = original_ntf(*a, **kw)
        captured.append(Path(f.name))
        return f

    def patched_run(cmd, **kwargs):
        # Delete the temp SARIF file before the scanner reads it.
        if captured:
            captured[-1].unlink(missing_ok=True)
        r = MagicMock()
        r.returncode = 0
        r.stdout = r.stderr = ""
        return r

    with (
        patch(_OPENGREP_PATH_PATCH, return_value=_BINARY),
        patch(_GET_VERSION_PATCH, return_value="1.25.0"),
        patch("cra_evidence_cli.local.sast_scanner.tempfile.NamedTemporaryFile", capturing_ntf),
        patch(_SUBPROCESS_PATCH, side_effect=patched_run),
    ):
        report = run_scan(path=tmp_path, rules=tmp_path)

    assert report.scan_failed is True
    assert "not found" in (report.failure_reason or "")
    assert report.findings == []


def test_sarif_invalid_json_after_exit_zero_is_scan_failed(tmp_path):
    """Engine exits 0 but SARIF file contains invalid JSON -> scan_failed, not a clean result."""
    import tempfile

    captured: list[Path] = []
    original_ntf = tempfile.NamedTemporaryFile

    def capturing_ntf(*a, **kw):
        f = original_ntf(*a, **kw)
        captured.append(Path(f.name))
        return f

    def patched_run(cmd, **kwargs):
        if captured:
            captured[-1].write_text("not valid json {{{{", encoding="utf-8")
        r = MagicMock()
        r.returncode = 0
        r.stdout = r.stderr = ""
        return r

    with (
        patch(_OPENGREP_PATH_PATCH, return_value=_BINARY),
        patch(_GET_VERSION_PATCH, return_value="1.25.0"),
        patch("cra_evidence_cli.local.sast_scanner.tempfile.NamedTemporaryFile", capturing_ntf),
        patch(_SUBPROCESS_PATCH, side_effect=patched_run),
    ):
        report = run_scan(path=tmp_path, rules=tmp_path)

    assert report.scan_failed is True
    assert report.failure_reason is not None
    assert "SARIF" in report.failure_reason
    assert report.findings == []


# ---------------------------------------------------------------------------
# A3. TimeoutExpired -> scan_failed with "timed out"; temp file cleaned up
# ---------------------------------------------------------------------------


def test_timeout_expired_sets_scan_failed(tmp_path):
    import tempfile

    captured: list[Path] = []
    original_ntf = tempfile.NamedTemporaryFile

    def capturing_ntf(*a, **kw):
        f = original_ntf(*a, **kw)
        captured.append(Path(f.name))
        return f

    def patched_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 300)

    with (
        patch(_OPENGREP_PATH_PATCH, return_value=_BINARY),
        patch(_GET_VERSION_PATCH, return_value="1.25.0"),
        patch("cra_evidence_cli.local.sast_scanner.tempfile.NamedTemporaryFile", capturing_ntf),
        patch(_SUBPROCESS_PATCH, side_effect=patched_run),
    ):
        report = run_scan(path=tmp_path, rules=tmp_path)

    assert report.scan_failed is True
    assert "timed out" in (report.failure_reason or "")
    # Temp file must be cleaned up regardless of timeout.
    for p in captured:
        assert not p.exists(), f"temp file leaked: {p}"


# ---------------------------------------------------------------------------
# A4. Nonzero exit codes -> scan_failed with stderr excerpt; long stderr truncated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rc", [2, 5, 7])
def test_nonzero_exit_sets_scan_failed(tmp_path, rc):
    def patched_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = rc
        r.stdout = ""
        r.stderr = f"fatal error from engine (code {rc})"
        return r

    with (
        patch(_OPENGREP_PATH_PATCH, return_value=_BINARY),
        patch(_GET_VERSION_PATCH, return_value="1.25.0"),
        patch(_SUBPROCESS_PATCH, side_effect=patched_run),
    ):
        report = run_scan(path=tmp_path, rules=tmp_path)

    assert report.scan_failed is True
    assert str(rc) in (report.failure_reason or "")
    assert "fatal error" in (report.failure_reason or "")


def test_long_stderr_truncated_to_400_chars(tmp_path):
    long_stderr = "e" * 800

    def patched_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 2
        r.stdout = ""
        r.stderr = long_stderr
        return r

    with (
        patch(_OPENGREP_PATH_PATCH, return_value=_BINARY),
        patch(_GET_VERSION_PATCH, return_value="1.25.0"),
        patch(_SUBPROCESS_PATCH, side_effect=patched_run),
    ):
        report = run_scan(path=tmp_path, rules=tmp_path)

    assert report.scan_failed is True
    reason = report.failure_reason or ""
    # The full 800-char stderr must not appear verbatim; only a 400-char excerpt is kept.
    assert long_stderr not in reason
    # But the excerpt must still be present (non-empty).
    assert "e" * 10 in reason


# ---------------------------------------------------------------------------
# A5. Result with missing / empty locations -> line is None, no crash
# ---------------------------------------------------------------------------


def test_result_no_locations_key_line_is_none():
    doc = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "cra-x",
                        "message": {"text": "msg"},
                        # no "locations" key at all
                    }
                ],
            }
        ]
    }
    findings = _parse_sarif(doc)
    assert len(findings) == 1
    assert findings[0].line is None
    assert findings[0].rule_id == "cra-x"


def test_result_empty_locations_list_line_is_none():
    doc = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "cra-y",
                        "message": {"text": "msg"},
                        "locations": [],
                    }
                ],
            }
        ]
    }
    findings = _parse_sarif(doc)
    assert len(findings) == 1
    assert findings[0].line is None


def test_result_physical_location_missing_region_line_is_none():
    doc = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "cra-z",
                        "message": {"text": "msg"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "foo.py"}
                                    # no "region" key
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    findings = _parse_sarif(doc)
    assert len(findings) == 1
    assert findings[0].line is None
    assert findings[0].file == "foo.py"


# ---------------------------------------------------------------------------
# A6. ruleId not in driver.rules -> severity "warning", cwe_list empty
# ---------------------------------------------------------------------------


def test_unknown_rule_id_falls_back_to_warning_and_empty_cwe():
    doc = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "cra-known", "defaultConfiguration": {"level": "error"}}
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "cra-unknown-rule",
                        "message": {"text": "some message"},
                        "locations": [],
                    }
                ],
            }
        ]
    }
    findings = _parse_sarif(doc)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "warning"
    assert f.cwe_list == []


# ---------------------------------------------------------------------------
# A7. Severity resolution (result.level > rule.defaultConfiguration > "warning")
#     (partial overlap with existing tests; these are different sub-cases)
# ---------------------------------------------------------------------------


def test_severity_both_absent_falls_back_to_warning():
    doc = {
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "cra-q"}]}},
                "results": [
                    {
                        "ruleId": "cra-q",
                        "message": {"text": "m"},
                        "locations": [],
                        # no "level" on result
                        # rule has no defaultConfiguration
                    }
                ],
            }
        ]
    }
    findings = _parse_sarif(doc)
    assert findings[0].severity == "warning"


def test_severity_default_configuration_used_when_result_level_absent():
    doc = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "cra-q", "defaultConfiguration": {"level": "note"}}
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "cra-q",
                        "message": {"text": "m"},
                        "locations": [],
                        # no "level" on result
                    }
                ],
            }
        ]
    }
    findings = _parse_sarif(doc)
    assert findings[0].severity == "note"


# ---------------------------------------------------------------------------
# A8. Missing fingerprints dict -> fingerprint is None
# ---------------------------------------------------------------------------


def test_missing_fingerprints_dict_gives_none():
    doc = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "cra-nofp",
                        "message": {"text": "m"},
                        "locations": [],
                        # no "fingerprints" key
                    }
                ],
            }
        ]
    }
    findings = _parse_sarif(doc)
    assert findings[0].fingerprint is None


# ---------------------------------------------------------------------------
# A9. CWE tag parsing edge cases
# ---------------------------------------------------------------------------


def test_cwe_tags_non_cwe_strings_only_returns_empty():
    assert _parse_cwe_tags(["security", "HIGH CONFIDENCE", "injection"]) == []


def test_cwe_tags_malformed_cwe_prefix_without_digits_not_matched():
    # "CWE-" alone or "CWE-abc" must not match the pattern.
    assert _parse_cwe_tags(["CWE-: no digits", "CWE-abc: bad"]) == []


def test_cwe_tags_multiple_valid_cwe_all_captured():
    tags = [
        "CWE-89: SQL Injection",
        "security",
        "CWE-78: OS Command Injection",
        "CWE-502: Deserialization",
    ]
    result = _parse_cwe_tags(tags)
    assert result == [
        "CWE-89: SQL Injection",
        "CWE-78: OS Command Injection",
        "CWE-502: Deserialization",
    ]


def test_cwe_tags_empty_list_returns_empty():
    assert _parse_cwe_tags([]) == []


# ---------------------------------------------------------------------------
# A10. Replacement characters in stdout/stderr -> no crash
# ---------------------------------------------------------------------------


def test_replacement_chars_in_stderr_no_crash(tmp_path):
    """stdout/stderr containing Unicode replacement chars must not crash the scanner."""
    replacement = "output with � replacement char"

    def patched_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 2
        r.stdout = replacement
        r.stderr = replacement
        return r

    with (
        patch(_OPENGREP_PATH_PATCH, return_value=_BINARY),
        patch(_GET_VERSION_PATCH, return_value="1.25.0"),
        patch(_SUBPROCESS_PATCH, side_effect=patched_run),
    ):
        report = run_scan(path=tmp_path, rules=tmp_path)

    assert report.scan_failed is True
    assert report.failure_reason is not None


# ---------------------------------------------------------------------------
# A11. get_version edge cases
# ---------------------------------------------------------------------------


def test_get_version_empty_stdout_returns_unknown():
    def patched_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        r.stdout = ""
        r.stderr = ""
        return r

    with (
        patch(_OPENGREP_PATH_PATCH, return_value=_BINARY),
        patch(_SUBPROCESS_PATCH, side_effect=patched_run),
    ):
        assert get_version() == "unknown"


def test_get_version_subprocess_raises_returns_unknown():
    with (
        patch(_OPENGREP_PATH_PATCH, return_value=_BINARY),
        patch(_SUBPROCESS_PATCH, side_effect=OSError("not found")),
    ):
        assert get_version() == "unknown"


def test_get_version_binary_absent_returns_unknown():
    with patch(_OPENGREP_PATH_PATCH, return_value=None):
        assert get_version() == "unknown"


# ---------------------------------------------------------------------------
# A12. Default excludes passed as --exclude args; custom excludes replace defaults
# ---------------------------------------------------------------------------


def _capture_cmd(tmp_path: Path, excludes=None) -> list[str]:
    """Run run_scan and capture the command passed to subprocess."""
    import tempfile

    captured_cmd: list[list[str]] = []
    original_ntf = tempfile.NamedTemporaryFile

    captured_paths: list[Path] = []

    def capturing_ntf(*a, **kw):
        f = original_ntf(*a, **kw)
        captured_paths.append(Path(f.name))
        return f

    def patched_run(cmd, **kwargs):
        captured_cmd.append(list(cmd))
        # Write valid empty SARIF so the scanner doesn't fail on missing file.
        if captured_paths:
            captured_paths[-1].write_text(json.dumps({"runs": []}), encoding="utf-8")
        r = MagicMock()
        r.returncode = 0
        r.stdout = r.stderr = ""
        return r

    with (
        patch(_OPENGREP_PATH_PATCH, return_value=_BINARY),
        patch(_GET_VERSION_PATCH, return_value="1.25.0"),
        patch("cra_evidence_cli.local.sast_scanner.tempfile.NamedTemporaryFile", capturing_ntf),
        patch(_SUBPROCESS_PATCH, side_effect=patched_run),
    ):
        run_scan(path=tmp_path, rules=tmp_path, excludes=excludes)

    return captured_cmd[0] if captured_cmd else []


def test_default_excludes_present_in_command(tmp_path):
    cmd = _capture_cmd(tmp_path, excludes=None)
    exclude_values = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--exclude"]
    for default in _DEFAULT_EXCLUDES:
        assert default in exclude_values, f"expected default exclude {default!r} in command"


def test_custom_excludes_replace_defaults(tmp_path):
    custom = ("my_vendor", "generated")
    cmd = _capture_cmd(tmp_path, excludes=custom)
    exclude_values = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--exclude"]
    for custom_exc in custom:
        assert custom_exc in exclude_values
    for default in _DEFAULT_EXCLUDES:
        assert default not in exclude_values, f"default exclude {default!r} should be absent"
