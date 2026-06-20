"""Sigstore signing for SBOM upload."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cra_evidence_cli.exceptions import CRAEvidenceError

SIGSTORE_IDENTITY_TOKEN_ENV = "CRA_EVIDENCE_SIGSTORE_IDENTITY_TOKEN"  # noqa: S105
SIGSTORE_IDENTITY_TOKEN_ALT_ENV = "SIGSTORE_ID_TOKEN"  # noqa: S105

_OIDC_ISSUER_OID = "1.3.6.1.4.1.57264.1.1"
_OTHERNAME_OID = "1.3.6.1.4.1.57264.1.7"
_OIDC_ISSUER_V2_OID = "1.3.6.1.4.1.57264.1.8"


class SBOMSigningError(CRAEvidenceError):
    """Error during Sigstore SBOM signing."""

    def __init__(self, message: str, exit_code: int = 23) -> None:
        super().__init__(message, exit_code)


@dataclass(frozen=True)
class SBOMSigningResult:
    """Result of signing an SBOM with Sigstore."""

    bundle_path: Path
    signer_identity: str
    signer_issuer: str
    transparency_log_index: int | None = None


def sign_sbom_with_sigstore(
    *,
    sbom_path: Path,
    bundle_path: Path,
    overwrite: bool = False,
) -> SBOMSigningResult:
    """Sign ``sbom_path`` and write a Sigstore bundle to ``bundle_path``."""
    if not sbom_path.is_file():
        msg = f"SBOM file does not exist: {sbom_path}"
        raise SBOMSigningError(msg)

    if bundle_path.exists() and not overwrite:
        msg = (
            f"Signature bundle already exists: {bundle_path}. "
            "Remove it or pass a different --signature-bundle path."
        )
        raise SBOMSigningError(
            msg
        )

    bundle_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        from sigstore.models import ClientTrustConfig
        from sigstore.oidc import IdentityToken, detect_credential
        from sigstore.sign import SigningContext
    except ImportError as exc:
        msg = (
            "Sigstore signing support is not installed. Install a CLI build with "
            "sigstore support or run `pip install sigstore>=4.0.0,<5.0.0`."
        )
        raise SBOMSigningError(
            msg
        ) from exc

    identity_token_raw = os.getenv(SIGSTORE_IDENTITY_TOKEN_ENV) or os.getenv(
        SIGSTORE_IDENTITY_TOKEN_ALT_ENV
    )
    if identity_token_raw:
        identity_token = IdentityToken(identity_token_raw, client_id="sigstore")
    else:
        detected = detect_credential("sigstore")
        if not detected:
            msg = (
                "No ambient Sigstore OIDC identity was detected. In GitHub Actions, "
                "set `permissions: id-token: write`. In GitLab/Buildkite/CircleCI/GCP, "
                "ensure OIDC identity tokens are available, or provide an existing "
                "bundle with --signature-on / --signature-bundle."
            )
            raise SBOMSigningError(
                msg
            )
        identity_token = IdentityToken(detected, client_id="sigstore")

    try:
        trust_config = ClientTrustConfig.production()
        signing_context = SigningContext.from_trust_config(trust_config)
        with signing_context.signer(identity_token) as signer:
            bundle = signer.sign_artifact(input_=sbom_path.read_bytes())
    except Exception as exc:
        msg = f"Sigstore signing failed: {exc}"
        raise SBOMSigningError(msg) from exc

    bundle_path.write_text(bundle.to_json(), encoding="utf-8")

    signer_identity = _extract_signer_identity(bundle)
    signer_issuer = _extract_signer_issuer(bundle)
    if not signer_identity or not signer_issuer:
        msg = (
            "Sigstore bundle was created, but signer identity or issuer could not "
            "be read from the signing certificate."
        )
        raise SBOMSigningError(
            msg
        )

    return SBOMSigningResult(
        bundle_path=bundle_path,
        signer_identity=signer_identity,
        signer_issuer=signer_issuer,
        transparency_log_index=_extract_log_index(bundle),
    )


def _extract_log_index(bundle: object) -> int | None:
    try:
        log_index = getattr(bundle.log_entry, "log_index", None)
        if log_index is not None:
            return int(log_index)
        return int(bundle.log_entry._inner.log_index)
    except Exception:
        return None


def _extract_signer_identity(bundle: object) -> str | None:
    try:
        from cryptography.x509 import (
            OtherName,
            RFC822Name,
            SubjectAlternativeName,
            UniformResourceIdentifier,
        )
    except ImportError:
        return None

    cert = bundle.signing_certificate
    try:
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
    except Exception:
        return None

    uris = san.get_values_for_type(UniformResourceIdentifier)
    if uris:
        return str(uris[0])

    emails = san.get_values_for_type(RFC822Name)
    if emails:
        return str(emails[0])

    for other_name in san.get_values_for_type(OtherName):
        if other_name.type_id.dotted_string == _OTHERNAME_OID:
            decoded = _decode_sigstore_der_string(other_name.value)
            if decoded:
                return decoded

    return None


def _extract_signer_issuer(bundle: object) -> str | None:
    try:
        from cryptography.x509 import ObjectIdentifier
    except ImportError:
        return None

    cert = bundle.signing_certificate
    for oid in (_OIDC_ISSUER_OID, _OIDC_ISSUER_V2_OID):
        try:
            extension = cert.extensions.get_extension_for_oid(ObjectIdentifier(oid)).value
        except Exception:  # noqa: S112
            continue

        value = getattr(extension, "value", b"")
        if isinstance(value, bytes):
            decoded = _decode_sigstore_der_string(value)
            if decoded:
                return decoded
            try:
                return value.decode()
            except UnicodeDecodeError:
                continue

    return None


def _decode_sigstore_der_string(value: bytes) -> str | None:
    """Decode the simple DER UTF8String shape used by newer Sigstore extensions."""
    if not value:
        return None

    if len(value) >= 2 and value[0] == 0x0C:
        length_byte = value[1]
        if length_byte < 0x80:
            length = length_byte
            offset = 2
        else:
            length_size = length_byte & 0x7F
            if len(value) < 2 + length_size:
                return None
            length = int.from_bytes(value[2 : 2 + length_size], "big")
            offset = 2 + length_size

        if len(value) >= offset + length:
            try:
                return value[offset : offset + length].decode()
            except UnicodeDecodeError:
                return None

    try:
        return value.decode()
    except UnicodeDecodeError:
        return None
