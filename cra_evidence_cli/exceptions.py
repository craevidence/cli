"""
Custom exceptions for CRA Evidence CLI.
"""


class CRAEvidenceError(Exception):
    """Base exception for all CRA Evidence CLI errors."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class AuthenticationError(CRAEvidenceError):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message, exit_code=2)


class APIError(CRAEvidenceError):
    """Raised when the API returns an error response."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        request_id: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, exit_code=3)
        self.status_code = status_code
        self.request_id = request_id
        self.retry_after = retry_after


class ValidationError(CRAEvidenceError):
    """Raised when input validation fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=4)


class FileNotFoundError(CRAEvidenceError):
    """Raised when a required file is not found."""

    def __init__(self, file_path: str) -> None:
        super().__init__(f"File not found: {file_path}", exit_code=5)


class VulnerabilityThresholdExceeded(CRAEvidenceError):
    """Raised when vulnerability threshold is exceeded."""

    def __init__(
        self,
        severity: str,
        count: int,
        exit_code: int,
    ) -> None:
        super().__init__(
            f"Found {count} {severity} vulnerabilities (threshold exceeded)",
            exit_code=exit_code,
        )
        self.severity = severity
        self.count = count


class KevGateExceeded(CRAEvidenceError):
    """Raised when the known-exploited vulnerability gate is exceeded."""

    def __init__(self, count: int) -> None:
        super().__init__(
            f"Found {count} known-exploited vulnerabilities (threshold exceeded)",
            exit_code=17,
        )
        self.count = count


class ScanEngineUnavailable(CRAEvidenceError):
    """Raised when no local/allowed vulnerability engine can run."""

    def __init__(self, message: str = "No vulnerability scan engine is available") -> None:
        super().__init__(message, exit_code=15)


class LicensePolicyExceeded(CRAEvidenceError):
    """Raised when a local license policy gate is exceeded."""

    def __init__(self, message: str = "License policy threshold exceeded") -> None:
        super().__init__(message, exit_code=16)


class ConfigurationError(CRAEvidenceError):
    """Raised when configuration is invalid or missing."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=6)


class CRANonCompliantError(CRAEvidenceError):
    """Raised when CRA status is not ready (used by --fail-on in status command)."""

    def __init__(self, cra_status: str) -> None:
        super().__init__(
            f"CRA status is '{cra_status}', not ready",
            exit_code=20,
        )
        self.cra_status = cra_status


class ReleasePolicyNotMetError(CRAEvidenceError):
    """Raised when the CRA legal floor IS met but the configured release policy is not.

    Distinct from CRANonCompliantError (exit 20, the legal floor): exit 24 signals a
    failure of the organisation's release policy that sits above the floor.
    """

    def __init__(self, release_policy_status: str) -> None:
        super().__init__(
            f"CRA legal floor is met, but release policy status is "
            f"'{release_policy_status}', not ready",
            exit_code=24,
        )
        self.release_policy_status = release_policy_status


class StructuredEvidenceMappingRequired(CRAEvidenceError):
    """Raised when an opt-in structured evidence upload did not map fields."""

    def __init__(self, parser_outcome: str) -> None:
        super().__init__(
            "Structured evidence mapping was required, but mapped fields were not "
            "confirmed. Upload completed; review the structured evidence summary "
            "and add manual evidence where needed.",
            exit_code=21,
        )
        self.parser_outcome = parser_outcome


class SignatureVerificationUntrusted(CRAEvidenceError):
    """Raised when --fail-untrusted sees non-trusted SBOM signature evidence."""

    def __init__(self, status: str) -> None:
        super().__init__(
            "SBOM upload completed, but signature verification was required to be trusted, "
            f"but result was '{status}'.",
            exit_code=22,
        )
        self.status = status


class SbomqsThresholdExceeded(CRAEvidenceError):
    """Raised when sbomqs BSI TR-03183-2 v2 score is below --fail-on-score."""

    def __init__(self, score: float, threshold: float) -> None:
        super().__init__(
            f"sbomqs BSI TR-03183-2 v2 score {score:.1f} is below "
            f"threshold {threshold:.1f}",
            exit_code=14,
        )
        self.score = score
        self.threshold = threshold
