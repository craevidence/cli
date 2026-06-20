"""Tests for custom exceptions: exit code taxonomy, message format, and inheritance."""


from cra_evidence_cli.exceptions import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    CRAEvidenceError,
    CRANonCompliantError,
    FileNotFoundError,
    KevGateExceeded,
    LicensePolicyExceeded,
    SbomqsThresholdExceeded,
    ScanEngineUnavailable,
    StructuredEvidenceMappingRequired,
    ValidationError,
    VulnerabilityThresholdExceeded,
)


class TestCRAEvidenceError:
    """Tests for base CRAEvidenceError."""

    def test_default_exit_code(self):
        """Default exit_code is 1 and str() returns the message."""
        error = CRAEvidenceError("Test error")

        assert error.exit_code == 1
        assert str(error) == "Test error"

    def test_custom_exit_code(self):
        """exit_code kwarg is stored on the exception."""
        error = CRAEvidenceError("Test error", exit_code=42)

        assert error.exit_code == 42


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_default_message(self):
        """Default message is 'Authentication failed' and exit_code is 2."""
        error = AuthenticationError()

        assert str(error) == "Authentication failed"
        assert error.exit_code == 2

    def test_custom_message(self):
        """Custom message is preserved and exit_code remains 2."""
        error = AuthenticationError("Invalid API key")

        assert str(error) == "Invalid API key"
        assert error.exit_code == 2


class TestAPIError:
    """Tests for APIError."""

    def test_basic_error(self):
        """exit_code is 3; status_code and request_id default to None."""
        error = APIError("Server error")

        assert str(error) == "Server error"
        assert error.exit_code == 3
        assert error.status_code is None
        assert error.request_id is None

    def test_error_with_details(self):
        """status_code and request_id are stored when provided."""
        error = APIError(
            "Not found",
            status_code=404,
            request_id="req-12345",
        )

        assert str(error) == "Not found"
        assert error.status_code == 404
        assert error.request_id == "req-12345"

    def test_error_status_codes(self):
        """APIError accepts any HTTP status code and stores it."""
        status_codes = [400, 401, 403, 404, 500, 502, 503]

        for code in status_codes:
            error = APIError(f"Error {code}", status_code=code)
            assert error.status_code == code


class TestValidationError:
    """Tests for ValidationError."""

    def test_validation_error(self):
        """Message is preserved and exit_code is 4."""
        error = ValidationError("Invalid input format")

        assert str(error) == "Invalid input format"
        assert error.exit_code == 4


class TestFileNotFoundError:
    """Tests for FileNotFoundError."""

    def test_file_not_found_error(self):
        """Message contains 'File not found' and the supplied path; exit_code is 5."""
        error = FileNotFoundError("/path/to/missing/file.json")

        assert "File not found" in str(error)
        assert "/path/to/missing/file.json" in str(error)
        assert error.exit_code == 5

    def test_file_not_found_relative_path(self):
        """Relative paths are included verbatim in the error message."""
        error = FileNotFoundError("./sbom.json")

        assert "./sbom.json" in str(error)


class TestVulnerabilityThresholdExceeded:
    """Tests for VulnerabilityThresholdExceeded."""

    def test_critical_threshold(self):
        """Severity and count are stored; exit_code matches the supplied value."""
        error = VulnerabilityThresholdExceeded("critical", 5, exit_code=10)

        assert "5" in str(error)
        assert "critical" in str(error)
        assert error.severity == "critical"
        assert error.count == 5
        assert error.exit_code == 10

    def test_high_threshold(self):
        """High-severity error stores severity='high' and the supplied exit_code."""
        error = VulnerabilityThresholdExceeded("high", 3, exit_code=11)

        assert error.severity == "high"
        assert error.count == 3
        assert error.exit_code == 11

    def test_medium_threshold(self):
        """Medium-severity error stores severity='medium' and the supplied exit_code."""
        error = VulnerabilityThresholdExceeded("medium", 10, exit_code=12)

        assert error.severity == "medium"
        assert error.count == 10
        assert error.exit_code == 12

    def test_exit_codes_distinct(self):
        """critical/high/medium exit codes are three distinct values."""
        critical = VulnerabilityThresholdExceeded("critical", 1, exit_code=10)
        high = VulnerabilityThresholdExceeded("high", 1, exit_code=11)
        medium = VulnerabilityThresholdExceeded("medium", 1, exit_code=12)

        exit_codes = {critical.exit_code, high.exit_code, medium.exit_code}
        assert len(exit_codes) == 3  # All distinct


class TestConfigurationError:
    """Tests for ConfigurationError."""

    def test_configuration_error(self):
        """Message is preserved and exit_code is 6."""
        error = ConfigurationError("Missing required field")

        assert str(error) == "Missing required field"
        assert error.exit_code == 6

    def test_configuration_error_inheritance(self):
        """ConfigurationError is a subclass of CRAEvidenceError."""
        error = ConfigurationError("Test")

        assert isinstance(error, CRAEvidenceError)


class TestCRANonCompliantError:
    """Tests for CRANonCompliantError."""

    def test_non_compliant_error(self):
        """cra_status is stored and exit_code is 20."""
        error = CRANonCompliantError("incomplete")

        assert "incomplete" in str(error)
        assert error.exit_code == 20
        assert error.cra_status == "incomplete"

    def test_non_compliant_error_partial(self):
        """'partial' status is stored and exit_code remains 20."""
        error = CRANonCompliantError("partial")

        assert error.cra_status == "partial"
        assert error.exit_code == 20


class TestSbomqsThresholdExceeded:
    """Tests for SbomqsThresholdExceeded."""

    def test_threshold_error(self):
        error = SbomqsThresholdExceeded(score=47.9, threshold=60.0)

        assert "47.9" in str(error)
        assert "60.0" in str(error)
        assert error.score == 47.9
        assert error.threshold == 60.0
        assert error.exit_code == 14

    def test_inherits_from_cra_evidence_error(self):
        error = SbomqsThresholdExceeded(score=10.0, threshold=20.0)

        assert isinstance(error, CRAEvidenceError)


class TestLocalCheckExceptions:
    def test_known_exploited_gate(self):
        error = KevGateExceeded(2)

        assert "2" in str(error)
        assert error.count == 2
        assert error.exit_code == 17

    def test_scan_engine_unavailable(self):
        error = ScanEngineUnavailable("missing grype")

        assert "missing grype" in str(error)
        assert error.exit_code == 15

    def test_license_policy_exceeded(self):
        error = LicensePolicyExceeded("AGPL denied")

        assert "AGPL denied" in str(error)
        assert error.exit_code == 16


class TestStructuredEvidenceMappingRequired:
    """Tests for opt-in structured evidence mapping failure."""

    def test_mapping_required_error(self):
        error = StructuredEvidenceMappingRequired("accepted_document_only")

        assert "mapped fields were not confirmed" in str(error)
        assert "Upload completed" in str(error)
        assert error.parser_outcome == "accepted_document_only"
        assert error.exit_code == 21

    def test_inherits_from_cra_evidence_error(self):
        error = StructuredEvidenceMappingRequired("accepted_needs_review")

        assert isinstance(error, CRAEvidenceError)


class TestExitCodeTaxonomy:
    """Tests ensuring exit codes follow the stable taxonomy."""

    def test_all_exit_codes_distinct(self):
        """Every exception type has a distinct exit code."""
        codes = {
            "base": CRAEvidenceError("test").exit_code,  # 1
            "auth": AuthenticationError().exit_code,  # 2
            "api": APIError("test").exit_code,  # 3
            "validation": ValidationError("test").exit_code,  # 4
            "file_not_found": FileNotFoundError("/test").exit_code,  # 5
            "config": ConfigurationError("test").exit_code,  # 6
            "vuln_critical": VulnerabilityThresholdExceeded("critical", 1, 10).exit_code,  # 10
            "vuln_high": VulnerabilityThresholdExceeded("high", 1, 11).exit_code,  # 11
            "vuln_medium": VulnerabilityThresholdExceeded("medium", 1, 12).exit_code,  # 12
            "sbomqs_threshold": SbomqsThresholdExceeded(0.0, 60.0).exit_code,  # 14
            "scan_engine": ScanEngineUnavailable().exit_code,  # 15
            "license_policy": LicensePolicyExceeded().exit_code,  # 16
            "known_exploited": KevGateExceeded(1).exit_code,  # 17
            "non_compliant": CRANonCompliantError("incomplete").exit_code,  # 20
            "structured_mapping": StructuredEvidenceMappingRequired("missing").exit_code,  # 21
        }

        # All exit codes must be unique
        assert len(set(codes.values())) == len(codes)

    def test_exit_code_values(self):
        """Exact exit code values match the stable taxonomy (1-6, 10-12, 14-17, 20-21)."""
        assert CRAEvidenceError("test").exit_code == 1
        assert AuthenticationError().exit_code == 2
        assert APIError("test").exit_code == 3
        assert ValidationError("test").exit_code == 4
        assert FileNotFoundError("/test").exit_code == 5
        assert ConfigurationError("test").exit_code == 6
        assert KevGateExceeded(1).exit_code == 17
        assert ScanEngineUnavailable().exit_code == 15
        assert LicensePolicyExceeded().exit_code == 16
        assert VulnerabilityThresholdExceeded("critical", 1, 10).exit_code == 10
        assert VulnerabilityThresholdExceeded("high", 1, 11).exit_code == 11
        assert VulnerabilityThresholdExceeded("medium", 1, 12).exit_code == 12
        assert SbomqsThresholdExceeded(0.0, 60.0).exit_code == 14
        assert CRANonCompliantError("test").exit_code == 20
        assert StructuredEvidenceMappingRequired("missing").exit_code == 21
